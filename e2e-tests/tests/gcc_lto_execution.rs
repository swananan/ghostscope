#[allow(dead_code)]
mod common;

use anyhow::Context;
use common::{init, runner::GhostscopeRunner, targets::TargetLauncher};
use gimli::Reader;
use object::{Object, ObjectSection, ObjectSymbol};
use std::{collections::HashSet, fs, path::Path, process::Command};

fn build_lto_fixture(directory: &Path, version: u16) -> anyhow::Result<std::path::PathBuf> {
    fs::write(
        directory.join("lto_main.c"),
        "#include <unistd.h>\n\
         void lto_alpha(void);\n\
         void lto_beta(void);\n\
         int main(void) { for (;;) { lto_alpha(); lto_beta(); usleep(10000); } }\n",
    )?;
    fs::write(
        directory.join("lto_shared.h"),
        "static __attribute__((always_inline)) inline void lto_touch(volatile int *counter) {\n\
         #line 501\n\
             *counter += 7;\n\
         }\n",
    )?;
    fs::write(
        directory.join("lto_padding.h"),
        "static __attribute__((always_inline)) inline void lto_padding(volatile int *counter) {\n\
             *counter += 3;\n\
         }\n",
    )?;
    for (name, line) in [("alpha", 101), ("beta", 201)] {
        let (include, call) = if name == "beta" {
            ("#include \"lto_padding.h\"\n", "lto_padding(&beta_count);")
        } else {
            ("", "")
        };
        fs::write(
            directory.join(format!("lto_{name}.c")),
            format!(
                "{include}#include \"lto_shared.h\"\n\
                 volatile int {name}_count;\n\
                 __attribute__((noinline, noclone)) void lto_{name}(void) {{\n\
                 #line {line}\n\
                     {name}_count++;\n\
                     {call}\n\
                     lto_touch(&{name}_count);\n\
                 }}\n"
            ),
        )?;
    }
    let binary = directory.join("lto_program");
    let output = Command::new("gcc")
        .current_dir(directory)
        .args(["-g", "-O2", "-flto=2", "-flto-partition=1to1"])
        .arg(format!("-gdwarf-{version}"))
        .args(["lto_main.c", "lto_alpha.c", "lto_beta.c", "-o"])
        .arg(&binary)
        .output()
        .context("failed to compile GCC LTO fixture")?;
    anyhow::ensure!(
        output.status.success(),
        "GCC LTO compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(binary)
}

fn assert_lto_file_index_conflict(binary: &Path) -> anyhow::Result<()> {
    let bytes = fs::read(binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    let dwarf = gimli::Dwarf::load(|id| -> anyhow::Result<_> {
        let data = object
            .section_by_name(id.name())
            .map(|section| section.uncompressed_data())
            .transpose()?
            .unwrap_or_default();
        Ok(gimli::EndianArcSlice::new(
            std::sync::Arc::from(data.as_ref()),
            if object.is_little_endian() {
                gimli::RunTimeEndian::Little
            } else {
                gimli::RunTimeEndian::Big
            },
        ))
    })?;
    let mut partitions = 0;
    let mut shared_indices = HashSet::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let Some(name) = unit.name.as_ref() else {
            continue;
        };
        if name.to_string_lossy()?.as_ref() != "<artificial>" {
            continue;
        }
        partitions += 1;
        let header = unit
            .line_program
            .as_ref()
            .context("partition has no line table")?
            .header();
        for (index, file) in header.file_names().iter().enumerate() {
            let name = dwarf.attr_string(&unit, file.path_name())?;
            if name.to_string_lossy()?.as_ref() == "lto_shared.h" {
                shared_indices.insert(index);
            }
        }
    }
    anyhow::ensure!(partitions >= 2, "fixture must have duplicate CU names");
    anyhow::ensure!(
        shared_indices.len() >= 2,
        "shared header must have different partition-local file indices"
    );
    Ok(())
}

async fn assert_lto_source_line_tracing(version: u16) -> anyhow::Result<()> {
    init();
    let directory = tempfile::Builder::new()
        .prefix("gcc-lto-")
        .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))?;
    let binary = build_lto_fixture(directory.path(), version)?;
    assert_lto_file_index_conflict(&binary)?;
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let result = GhostscopeRunner::new()
        .with_script("trace lto_shared.h:501 { print \"GCC_LTO_SHARED\"; bt noinline; }")
        .attach_to(&target)
        .timeout_secs(3)
        .run()
        .await;
    target.terminate().await?;
    let (code, stdout, stderr) = result?;
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("GCC_LTO_SHARED"),
        "stdout={stdout}\nstderr={stderr}"
    );
    for function in ["lto_alpha", "lto_beta"] {
        assert!(
            stdout.contains(function),
            "missing runtime hit in {function}: stdout={stdout}\nstderr={stderr}"
        );
    }

    // Loading both partitions for one source must preserve both reverse lookup
    // entries and the forward lookup after all per-CU tables have been merged.
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
    let addresses = analyzer.lookup_addresses_by_source_line("lto_shared.h", 501);
    let bytes = fs::read(&binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    for (function, file, line) in [
        ("lto_alpha", "lto_alpha.c", 101),
        ("lto_beta", "lto_beta.c", 201),
    ] {
        let symbol = object
            .symbols()
            .find(|symbol| symbol.name() == Ok(function))
            .with_context(|| format!("missing {function}"))?;
        assert!(
            addresses.iter().any(|address| {
                address.module_path == binary
                    && (symbol.address()..symbol.address() + symbol.size())
                        .contains(&address.address)
            }),
            "missing lto_shared.h:501 in {function}: {addresses:?}"
        );
        let body = analyzer.lookup_addresses_by_source_line(file, line);
        assert!(!body.is_empty(), "missing {file}:{line}");
        for address in body {
            let location = analyzer
                .lookup_source_location(&address)
                .context("missing source location")?;
            assert!(location.file_path.ends_with(file), "{location:?}");
            assert_eq!(location.line_number, line, "{location:?}");
        }
        for address in addresses.iter().filter(|address| {
            (symbol.address()..symbol.address() + symbol.size()).contains(&address.address)
        }) {
            let context = analyzer.resolve_pc(address)?;
            let frame = context
                .inline_chain
                .iter()
                .find(|frame| frame.function_name.as_deref() == Some("lto_touch"))
                .with_context(|| format!("missing lto_touch inline frame: {context:?}"))?;
            let call_site = frame
                .call_site
                .as_ref()
                .context("missing inline call site")?;
            assert!(call_site.file_path.ends_with(file), "{call_site:?}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_gcc_lto_partition_source_line_tracing_dwarf4() -> anyhow::Result<()> {
    assert_lto_source_line_tracing(4).await
}

#[tokio::test]
async fn test_gcc_lto_partition_source_line_tracing_dwarf5() -> anyhow::Result<()> {
    assert_lto_source_line_tracing(5).await
}
