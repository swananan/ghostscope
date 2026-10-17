use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::process::Command;

#[test]
fn rejects_relative_target_in_non_utf8_directory() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().join(OsString::from_vec(b"cwd-\xff".to_vec()));
    std::fs::create_dir(&cwd).unwrap();
    std::fs::write(cwd.join("target"), b"placeholder").unwrap();

    for target in ["target", "missing-target"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ghostscope"))
            .current_dir(&cwd)
            .args(["--target", target, "--dry-run", "--script", "trace main {}"])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("module path is not valid UTF-8"),
            "expected an encoding error for {target}, got: {stderr}"
        );
        assert!(stderr.contains("\\xFF"), "raw path byte missing: {stderr}");
    }
}
