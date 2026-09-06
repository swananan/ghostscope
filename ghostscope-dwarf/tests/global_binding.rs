use ghostscope_dwarf::{
    AddressExpr, DwarfAnalyzer, VariableAccessPath, VariableAccessSegment, VariableLocation,
};
use object::{Object, ObjectSymbol};

#[tokio::test]
async fn global_binding_precedes_projection_and_prefers_the_pc_compilation_unit() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.c");
    let second = dir.path().join("second.c");
    let binary = dir.path().join("globals");
    std::fs::write(
        &first,
        "static struct { int own; int common; } cfg = {11, 1};\n\
         int tick(void) { return cfg.own; }\n\
         int main(void) { return tick(); }\n",
    )
    .unwrap();
    std::fs::write(
        &second,
        "static struct { int other; int common; } cfg = {99, 2};\n\
         int other_tick(void) { return cfg.other; }\n",
    )
    .unwrap();
    let output = std::process::Command::new("cc")
        .args(["-g", "-O0"])
        .args([&first, &second])
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let analyzer = DwarfAnalyzer::from_exec_path(&binary).await.unwrap();
    let field =
        |name: &str| VariableAccessPath::new(vec![VariableAccessSegment::Field(name.to_string())]);
    // Only one of the two structs has `other`; that must not resolve ambiguity.
    let error = analyzer
        .plan_global_access_read_plan(&binary, "cfg", &field("other"))
        .unwrap_err();
    assert!(error.to_string().contains("Ambiguous global 'cfg'"));

    for (function, own, foreign) in [("tick", "own", "other"), ("other_tick", "other", "own")] {
        let pc = analyzer.lookup_function_addresses(function).remove(0);
        let context = analyzer.resolve_pc(&pc).unwrap();
        let (_, plan) = analyzer
            .plan_global_access_read_plan_at_address(&pc, "cfg", &field(own))
            .unwrap()
            .unwrap();
        assert_eq!(Some(plan.declaration.unwrap().cu), context.cu);
        assert!(analyzer
            .plan_global_access_read_plan_at_address(&pc, "cfg", &field(foreign))
            .is_err());
        let (_, common) = analyzer
            .plan_global_access_read_plan_at_address(&pc, "cfg", &field("common"))
            .unwrap()
            .unwrap();
        assert_eq!(common.declaration, plan.declaration);
    }
}

#[tokio::test]
async fn global_binding_excludes_static_locals_outside_the_pc_scope() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.c");
    let second = dir.path().join("second.c");
    let binary = dir.path().join("globals");
    std::fs::write(
        &first,
        "extern int state;\n\
         int unrelated(void) { static int state = 999; static int hidden = 7; return state + hidden; }\n\
         int tick(void) { return state; }\n\
         int scoped(int enabled) {\n\
             if (enabled) {\n\
                 static int state = 333;\n\
                 return state; /* inside */\n\
             }\n\
             return state; /* outside */\n\
         }\n\
         int main(void) { return tick() + unrelated(); }\n",
    )
    .unwrap();
    std::fs::write(&second, "int state = 11;\n").unwrap();
    let output = std::process::Command::new("cc")
        .args(["-g", "-O0"])
        .args([&first, &second])
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");

    let bytes = std::fs::read(&binary).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let global_address = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("state"))
        .unwrap()
        .address();
    let analyzer = DwarfAnalyzer::from_exec_path(&binary).await.unwrap();
    let path = VariableAccessPath::default();
    let pc = analyzer.lookup_function_addresses("tick").remove(0);
    let context = analyzer.resolve_pc(&pc).unwrap();
    assert!(analyzer
        .plan_variable_by_name(&context, "state")
        .unwrap()
        .is_none());
    let (_, plan) = analyzer
        .plan_global_access_read_plan_at_address(&pc, "state", &path)
        .unwrap()
        .unwrap();
    assert_eq!(
        plan.location,
        VariableLocation::Address(AddressExpr::constant(global_address))
    );
    assert!(analyzer
        .plan_global_access_read_plan_at_address(&pc, "hidden", &path)
        .unwrap()
        .is_none());

    // Discovery still includes static locals, and their own scope can read them.
    assert_eq!(analyzer.find_global_variables_by_name("state").len(), 3);
    assert!(analyzer
        .plan_global_access_read_plan(&binary, "hidden", &path)
        .unwrap()
        .is_some());
    let local_pc = analyzer.lookup_function_addresses("unrelated").remove(0);
    let local_context = analyzer.resolve_pc(&local_pc).unwrap();
    let local = analyzer
        .plan_variable_by_name(&local_context, "state")
        .unwrap()
        .unwrap();
    assert_ne!(local.location, plan.location);
    let (_, local_global) = analyzer
        .plan_global_access_read_plan_at_address(&local_pc, "state", &path)
        .unwrap()
        .unwrap();
    assert_eq!(local_global.location, local.location);

    for (marker, is_global) in [("/* inside */", false), ("/* outside */", true)] {
        let line = std::fs::read_to_string(&first)
            .unwrap()
            .lines()
            .position(|line| line.contains(marker))
            .unwrap() as u32
            + 1;
        let addresses = analyzer.lookup_addresses_by_source_line(first.to_str().unwrap(), line);
        assert!(!addresses.is_empty());
        for address in addresses {
            let (_, scoped) = analyzer
                .plan_global_access_read_plan_at_address(&address, "state", &path)
                .unwrap()
                .unwrap();
            assert_eq!(scoped.location == plan.location, is_global, "{marker}");
        }
    }
}

#[tokio::test]
async fn inline_static_binding_preserves_origin_and_unknown_scope_candidates() {
    for compiler in ["cc", "clang"] {
        if compiler == "clang"
            && !std::process::Command::new(compiler)
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success())
        {
            eprintln!("Skipping inline static binding with unavailable clang");
            continue;
        }
        for collision in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let first = dir.path().join("first.c");
            let second = dir.path().join("second.c");
            let binary = dir.path().join("inline");
            std::fs::write(
                &first,
                "static inline __attribute__((always_inline)) int inc(void) {\n\
                     static volatile int count = 4;\n\
                     count++;\n\
                     return count;\n\
                 }\n\
                 __attribute__((noinline)) int tick(void) { return inc(); }\n\
                 int main(void) { return tick(); }\n",
            )
            .unwrap();
            std::fs::write(
                &second,
                if collision {
                    "int count = 99;\n"
                } else {
                    "int unrelated = 99;\n"
                },
            )
            .unwrap();
            let output = std::process::Command::new(compiler)
                .args(["-g", "-O2"])
                .args([&first, &second])
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(output.status.success(), "{compiler}: {output:?}");
            let analyzer = DwarfAnalyzer::from_exec_path(&binary).await.unwrap();
            let pc = analyzer.lookup_function_addresses("inc").remove(0);
            let context = analyzer.resolve_pc(&pc).unwrap();
            assert!(!context.inline_chain.is_empty());
            let count = analyzer
                .find_global_variables_by_name("count")
                .into_iter()
                .find(|(_, info)| info.lexical_scope.is_some())
                .unwrap()
                .1;
            let result = analyzer.plan_global_access_read_plan_at_address(
                &pc,
                "count",
                &VariableAccessPath::default(),
            );
            match result {
                Ok(Some((_, plan))) => {
                    assert_eq!(plan.availability, ghostscope_dwarf::Availability::Available);
                    assert_eq!(
                        plan.location,
                        VariableLocation::Address(AddressExpr::constant(
                            count.link_address.unwrap()
                        ))
                    );
                }
                Err(error) if collision => {
                    assert!(error.to_string().starts_with("Ambiguous global 'count'"));
                }
                other => panic!("{compiler}, collision={collision}: {other:?}"),
            }
            if collision && compiler == "clang" {
                // Clang's anonymous owner cannot establish a CU preference.
                assert!(analyzer
                    .plan_global_access_read_plan_at_address(
                        &pc,
                        "count",
                        &VariableAccessPath::default(),
                    )
                    .unwrap_err()
                    .to_string()
                    .starts_with("Ambiguous global 'count'"));
            }
        }
    }
}
