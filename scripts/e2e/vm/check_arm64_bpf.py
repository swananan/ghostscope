#!/usr/bin/env python3
"""Guest preflight: load a minimal BPF program on an ARM64 Linux kernel.

This checks the BPF syscall/verifier, not GhostScope or uprobe attachment.
Run as root inside the disposable test VM.
"""
import ctypes
import os
import platform


class ProgLoad(ctypes.Structure):
    _fields_ = [
        ("prog_type", ctypes.c_uint32),
        ("insn_cnt", ctypes.c_uint32),
        ("insns", ctypes.c_uint64),
        ("license", ctypes.c_uint64),
        ("log_level", ctypes.c_uint32),
        ("log_size", ctypes.c_uint32),
        ("log_buf", ctypes.c_uint64),
    ]


def main():
    if platform.system() != "Linux" or platform.machine() != "aarch64":
        raise SystemExit("this preflight requires an ARM64 Linux guest")
    # BPF_MOV64_IMM R0, 0; BPF_EXIT, a minimal socket filter.
    insns = ctypes.create_string_buffer(bytes.fromhex("b7000000000000009500000000000000"))
    license_text = ctypes.create_string_buffer(b"GPL")
    log = ctypes.create_string_buffer(65536)
    attr = ProgLoad(1, 2, ctypes.addressof(insns), ctypes.addressof(license_text),
                    1, ctypes.sizeof(log), ctypes.addressof(log))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # Linux AArch64 uses the asm-generic syscall table: __NR_bpf = 280.
    fd = libc.syscall(ctypes.c_long(280), ctypes.c_int(5), ctypes.byref(attr),
                      ctypes.c_uint(ctypes.sizeof(attr)))  # BPF_PROG_LOAD
    if fd < 0:
        error = ctypes.get_errno()
        raise SystemExit(f"BPF_PROG_LOAD failed: {os.strerror(error)}\n{log.value.decode(errors='replace')}")
    os.close(fd)
    print("ARM64 BPF_PROG_LOAD: passed (minimal socket filter; no uprobe attached)")


if __name__ == "__main__":
    main()
