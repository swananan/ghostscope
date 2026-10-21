mod common;
#[path = "../../ghostscope-dwarf/tests/support/supplementary.rs"]
mod fixture;

async fn trace_supplementary(standard: bool) -> anyhow::Result<()> {
    common::init();
    let _fixtures = &*common::FIXTURES;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let dir = tempfile::Builder::new()
        .prefix("supplementary-dwarf-")
        .tempdir_in(root)?;
    let fixture = fixture::build(dir.path(), standard, false)?;
    anyhow::ensure!(
        fixture.supplementary.exists(),
        "supplementary fixture is absent"
    );
    let target = common::targets::TargetLauncher::binary(&fixture.binary)
        .current_dir(dir.path())
        .spawn()
        .await?;
    let result = common::runner::GhostscopeRunner::new().attach_to(&target)
        .with_script("trace tick { print \"SUPPLEMENTARY first={} second={}\", payload.first, payload.second; }")
        .timeout_secs(3).run().await;
    target.terminate().await?;
    let (code, stdout, stderr) = result?;
    anyhow::ensure!(code == 0 && stdout.contains("SUPPLEMENTARY first=1234 second=5678"), "supplementary trace failed (standard={standard}, exit={code})\nstdout: {stdout}\nstderr: {stderr}");
    Ok(())
}

#[tokio::test]
async fn test_gnu_supplementary_dwarf_member_execution() -> anyhow::Result<()> {
    trace_supplementary(false).await
}

#[tokio::test]
async fn test_standard_supplementary_dwarf_member_execution() -> anyhow::Result<()> {
    trace_supplementary(true).await
}

#[tokio::test]
async fn test_supplementary_rust_tuple_and_string_execution() -> anyhow::Result<()> {
    common::init();
    let _fixtures = &*common::FIXTURES;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for standard in [false, true] {
        let dir = tempfile::Builder::new()
            .prefix("supplementary-rust-")
            .tempdir_in(&root)?;
        let fixture = fixture::build_rust(dir.path(), standard, false)?;
        let target = common::targets::TargetLauncher::binary(&fixture.binary)
            .current_dir(dir.path())
            .spawn()
            .await?;
        let result = common::runner::GhostscopeRunner::new()
            .attach_to(&target)
            .with_script("trace tick { print \"RUST_SUP tuple={} str={}\", payload.0, message; }")
            .timeout_secs(3)
            .run()
            .await;
        target.terminate().await?;
        let (code, stdout, stderr) = result?;
        anyhow::ensure!(code == 0 && stdout.contains("RUST_SUP tuple=1234 str=\"supplement\""),
            "supplementary Rust trace failed (standard={standard}, exit={code})\nstdout: {stdout}\nstderr: {stderr}");
    }
    Ok(())
}
