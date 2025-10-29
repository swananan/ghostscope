fn main() {
    use std::path::PathBuf;
    use std::{env, fs, io::Write};

    println!("cargo:rerun-if-changed=ebpf/obj/sysmon-bpf.bpfel.o");
    println!("cargo:rerun-if-changed=ebpf/obj/sysmon-bpf.bpfeb.o");

    // Tolerate missing prebuilt objects: if absent, write empty placeholders and warn.
    // Default builds don't fail; at runtime sysmon will run in stub mode and log a warning.
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let obj_le = manifest.join("ebpf/obj/sysmon-bpf.bpfel.o");
    let obj_be = manifest.join("ebpf/obj/sysmon-bpf.bpfeb.o");

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);
    fs::create_dir_all(&out_dir).expect("create OUT_DIR failed");

    // Helper to copy and validate ELF, else write empty and warn
    fn copy_elf_or_empty(src: &PathBuf, dst: &PathBuf, label: &str) {
        use std::{fs, io::Write};
        if src.exists() {
            match fs::read(src) {
                Ok(bytes)
                    if bytes.len() >= 4
                        && bytes[0] == 0x7f
                        && bytes[1] == b'E'
                        && bytes[2] == b'L'
                        && bytes[3] == b'F' =>
                {
                    fs::write(dst, bytes).expect("write OUT_DIR file failed");
                }
                _ => {
                    let mut f = fs::File::create(dst).expect("create placeholder failed");
                    let _ = f.write_all(&[]);
                    println!(
                        "cargo:warning=Invalid {} object at {} (not ELF). Running in stub mode.",
                        label,
                        src.display()
                    );
                }
            }
        } else {
            let mut f = fs::File::create(dst).expect("create placeholder failed");
            let _ = f.write_all(&[]);
            println!(
                "cargo:warning=Missing {} object at {}. Running in stub mode if selected.",
                label,
                src.display()
            );
        }
    }

    let out_le = out_dir.join("sysmon-bpf.bpfel.o");
    let out_be = out_dir.join("sysmon-bpf.bpfeb.o");

    // Expect dual artifacts; copy if present, else placeholders + warning.
    if obj_le.exists() || obj_be.exists() {
        copy_elf_or_empty(&obj_le, &out_le, "bpfel");
        copy_elf_or_empty(&obj_be, &out_be, "bpfeb");
    } else {
        // Neither exists — write placeholders
        let _ = fs::File::create(&out_le).and_then(|mut f| f.write_all(&[]));
        let _ = fs::File::create(&out_be).and_then(|mut f| f.write_all(&[]));
        println!("cargo:warning=No sysmon-bpf artifacts (bpfel/bpfeb) found; sysmon will run in stub mode.");
    }
}
