#!/usr/bin/env python3
"""Give the ARM64 Clang fixture indexed function ranges without changing code.

Clang 18 cannot emit basic-block sections on AArch64. Keep its real line,
location and type information, but replace function low/high PC attributes
with reversed two-part range lists and an explicit entry PC. Fail closed if
Clang changes the expected DWARF encoding; do not silently reduce coverage.
"""
import os
import pathlib
import struct
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile


def uleb(data, offset):
    value, shift = 0, 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
        shift += 7


def patch(binary):
    with open(binary, 'rb') as stream:
        elf = ELFFile(stream)
        assert elf['e_machine'] == 'EM_AARCH64'
        dwarf = elf.get_dwarf_info()
        units = list(dwarf.iter_CUs())
        assert len(units) == 1 and units[0]['version'] == 5
        unit = units[0]
        dies = list(unit.iter_DIEs())
        target = next(die for die in dies if die.attributes.get('DW_AT_name')
                      and die.attributes['DW_AT_name'].value == b'partitioned_target')
        code = target.abbrev_code
        info = bytearray(elf.get_section_by_name('.debug_info').data())
        abbrev = bytearray(elf.get_section_by_name('.debug_abbrev').data())
        ranges = elf.get_section_by_name('.debug_rnglists').data()
        length, version, address_size, segment_size, count = struct.unpack_from('<IHBBI', ranges)
        assert length + 4 == len(ranges) and (version, address_size, segment_size) == (5, 8, 0)
        assert unit.get_top_DIE().attributes['DW_AT_rnglists_base'].value == 12
        additions = []
        for die in dies:
            if die.abbrev_code != code:
                continue
            low, high = die.attributes['DW_AT_low_pc'], die.attributes['DW_AT_high_pc']
            assert low.form == 'DW_FORM_addrx' and high.form == 'DW_FORM_data4'
            assert high.offset == low.offset + 1 and low.raw_value < 128
            index = count + len(additions)
            assert index < 128 and high.value >= 8
            start, end = low.value, low.value + high.value
            middle = start + ((high.value // 2) & ~3)
            # DW_RLE_start_end; second half first exercises entry selection.
            additions.append(b'\x06' + struct.pack('<QQ', middle, end)
                             + b'\x06' + struct.pack('<QQ', start, middle) + b'\x00')
            info[low.offset] = index
            struct.pack_into('<I', info, high.offset, low.raw_value)
        assert additions
        cursor = unit['debug_abbrev_offset']
        changed = 0
        while True:
            abbrev_code, cursor = uleb(abbrev, cursor)
            if not abbrev_code:
                break
            _, cursor = uleb(abbrev, cursor)  # tag
            cursor += 1  # children
            while True:
                name_offset = cursor
                name, cursor = uleb(abbrev, cursor)
                form_offset = cursor
                form, cursor = uleb(abbrev, cursor)
                if name == 0 and form == 0:
                    break
                if abbrev_code == code and name == 0x11:  # low_pc -> ranges
                    assert form == 0x1b
                    abbrev[name_offset] = 0x55
                    abbrev[form_offset] = 0x23  # rnglistx
                    changed += 1
                if abbrev_code == code and name == 0x12:  # high_pc -> entry_pc
                    assert form == 0x06
                    abbrev[name_offset] = 0x52
                    abbrev[form_offset] = 0x2c  # addrx4
                    changed += 1
                if form == 0x21:  # implicit_const (signed LEB has same length)
                    _, cursor = uleb(abbrev, cursor)
        assert changed == 2
        old_offsets = struct.unpack_from('<' + 'I' * count, ranges, 12)
        payload = bytearray(ranges[12 + 4 * count:])
        new_count = count + len(additions)
        offsets = [offset + 4 * len(additions) for offset in old_offsets]
        for addition in additions:
            offsets.append(4 * new_count + len(payload))
            payload.extend(addition)
        body = struct.pack('<HBBI', 5, 8, 0, new_count)
        body += struct.pack('<' + 'I' * new_count, *offsets) + payload
        new_ranges = struct.pack('<I', len(body)) + body
    with tempfile.TemporaryDirectory() as directory:
        command = [os.environ.get('OBJCOPY', 'objcopy')]
        for name, data in [('.debug_info', info), ('.debug_abbrev', abbrev),
                           ('.debug_rnglists', new_ranges)]:
            path = pathlib.Path(directory) / name
            path.write_bytes(data)
            command.extend(['--update-section', f'{name}={path}'])
        subprocess.run([*command, str(binary)], check=True)


if __name__ == '__main__':
    patch(pathlib.Path(sys.argv[1]))
