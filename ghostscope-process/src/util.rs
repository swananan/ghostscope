use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Return true if `path` looks like a shared object (ELF ET_DYN without PT_INTERP).
/// Returns false for executables (ET_EXEC, or ET_DYN with PT_INTERP i.e. PIE).
pub fn is_shared_object(path: &Path) -> bool {
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    const PT_INTERP: u32 = 3;

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut ehdr = [0u8; 64];
    if f.read(&mut ehdr).ok().filter(|&n| n >= 52).is_none() {
        return false;
    }
    if &ehdr[0..4] != b"\x7FELF" {
        return false;
    }
    let class = ehdr[4]; // EI_CLASS
    let data = ehdr[5]; // EI_DATA
    let is_le = data == 1;
    let rd16 = |b: &[u8]| -> u16 {
        if is_le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    };
    let rd32 = |b: &[u8]| -> u32 {
        if is_le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let rd64 = |b: &[u8]| -> u64 {
        if is_le {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        }
    };

    let e_type = rd16(&ehdr[16..18]);
    if e_type == ET_EXEC {
        return false;
    }

    let (e_phoff, e_phentsize, e_phnum) = match class {
        1 => {
            let phoff = rd32(&ehdr[28..32]) as u64;
            let entsz = rd16(&ehdr[42..44]) as u64;
            let phnum = rd16(&ehdr[44..46]) as u64;
            (phoff, entsz, phnum)
        }
        2 => {
            let phoff = rd64(&ehdr[32..40]);
            let entsz = rd16(&ehdr[54..56]) as u64;
            let phnum = rd16(&ehdr[56..58]) as u64;
            (phoff, entsz, phnum)
        }
        _ => return false,
    };

    if e_type == ET_DYN {
        if e_phoff == 0 || e_phentsize < 4 || e_phnum == 0 {
            return true; // conservative: treat as shared lib
        }
        for i in 0..e_phnum {
            let off = e_phoff + i * e_phentsize;
            if f.seek(SeekFrom::Start(off)).is_err() {
                return true;
            }
            let mut p = [0u8; 8];
            if f.read(&mut p[..4]).ok().filter(|&n| n == 4).is_none() {
                return true;
            }
            let p_type = rd32(&p[..4]);
            if p_type == PT_INTERP {
                return false; // PIE executable
            }
        }
        return true; // ET_DYN w/o PT_INTERP => shared library
    }

    // Unknown types: default to not shared
    false
}
