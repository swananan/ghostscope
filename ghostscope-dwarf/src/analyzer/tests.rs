use super::DwarfAnalyzer;
use crate::{
    core::{AddressExpr, Availability, Provenance, VariableLocation},
    semantics::{VariableReadPlan, VisibleVariable},
};
use std::path::{Path, PathBuf};

fn global_plan(name: &str, address: u64) -> VariableReadPlan {
    VariableReadPlan {
        name: name.to_string(),
        type_name: "int".to_string(),
        access_path: crate::VariableAccessPath::default(),
        module_path: None,
        dwarf_type: Some(crate::TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        }),
        declaration: None,
        type_id: None,
        location: VariableLocation::Address(AddressExpr::constant(address)),
        availability: Availability::Available,
        scope_depth: 0,
        is_parameter: false,
        is_artificial: false,
        pc_range: None,
        inline_context: None,
        provenance: Provenance::Synthesized {
            detail: "test".to_string(),
        },
    }
}

fn visible_var(name: &str, scope_depth: usize) -> VisibleVariable {
    VisibleVariable {
        name: name.to_string(),
        type_name: "int".to_string(),
        dwarf_type: Some(crate::TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        }),
        declaration: None,
        type_id: None,
        location: VariableLocation::RegisterValue { dwarf_reg: 0 },
        availability: Availability::Available,
        scope_depth,
        is_parameter: false,
        is_artificial: false,
    }
}

fn diagnostic(
    name: &str,
    scope_depth: usize,
    detail: &str,
) -> crate::semantics::VariableQueryDiagnostic {
    crate::semantics::VariableQueryDiagnostic {
        pc: 0x1234,
        name: Some(name.to_string()),
        scope_depth,
        availability: Availability::Unsupported(crate::UnsupportedReason::ExpressionShape {
            detail: detail.to_string(),
        }),
        detail: detail.to_string(),
    }
}

#[test]
fn variable_selection_rejects_inner_diagnostic_over_outer_match() {
    let err = DwarfAnalyzer::select_visible_variable_by_name(
        0x1234,
        "state",
        vec![visible_var("state", 1)],
        &[diagnostic("state", 2, "DW_OP_bad is unsupported")],
    )
    .expect_err("inner unavailable variable should block outer fallback");

    assert!(err.to_string().contains("Unavailable variable 'state'"));
    assert!(err.to_string().contains("DW_OP_bad is unsupported"));
}

#[test]
fn variable_selection_keeps_inner_match_over_outer_diagnostic() {
    let selected = DwarfAnalyzer::select_visible_variable_by_name(
        0x1234,
        "state",
        vec![visible_var("state", 2)],
        &[diagnostic("state", 1, "outer variable is unavailable")],
    )
    .expect("outer diagnostic should not block inner match")
    .expect("inner match should be returned");

    assert_eq!(selected.name, "state");
    assert_eq!(selected.scope_depth, 2);
}

#[test]
fn global_plan_selection_rejects_ambiguous_matches() {
    let err = DwarfAnalyzer::select_unambiguous_global_plan(
        "state",
        vec![
            (PathBuf::from("/tmp/a"), global_plan("state", 0x1000)),
            (PathBuf::from("/tmp/b"), global_plan("state", 0x2000)),
        ],
    )
    .expect_err("multiple global candidates should be ambiguous");

    assert!(err.to_string().contains("Ambiguous global 'state'"));
    assert!(err.to_string().contains("2 matches"));
}

#[test]
fn global_plan_selection_accepts_single_match() {
    let selected = DwarfAnalyzer::select_unambiguous_global_plan(
        "state",
        vec![(PathBuf::from("/tmp/a"), global_plan("state", 0x1000))],
    )
    .expect("single global candidate should be accepted")
    .expect("single global candidate should be returned");

    assert_eq!(selected.0, PathBuf::from("/tmp/a"));
    assert_eq!(selected.1.name, "state");
}

#[test]
fn global_plan_selection_prefers_current_module_match() {
    let selected = DwarfAnalyzer::select_global_plan_with_preferred_module(
        "state",
        Path::new("/tmp/current"),
        vec![
            (PathBuf::from("/tmp/other"), global_plan("state", 0x2000)),
            (PathBuf::from("/tmp/current"), global_plan("state", 0x1000)),
        ],
    )
    .expect("current module candidate should be accepted")
    .expect("current module candidate should be returned");

    assert_eq!(selected.0, PathBuf::from("/tmp/current"));
    assert_eq!(
        selected.1.location,
        VariableLocation::Address(AddressExpr::constant(0x1000))
    );
}

#[test]
fn global_plan_selection_rejects_ambiguous_current_module_matches() {
    let err = DwarfAnalyzer::select_global_plan_with_preferred_module(
        "state",
        Path::new("/tmp/current"),
        vec![
            (PathBuf::from("/tmp/current"), global_plan("state", 0x1000)),
            (PathBuf::from("/tmp/current"), global_plan("state", 0x1004)),
            (PathBuf::from("/tmp/other"), global_plan("state", 0x2000)),
        ],
    )
    .expect_err("duplicate current-module candidates should be ambiguous");

    assert!(err.to_string().contains("Ambiguous global 'state'"));
    assert!(err.to_string().contains("2 matches"));
    assert!(err.to_string().contains("/tmp/current"));
    assert!(!err.to_string().contains("/tmp/other"));
}
