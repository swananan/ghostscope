use super::*;
use ghostscope_dwarf::{ValueNestedPlan, ValueReadPlan};
use ghostscope_protocol::{ValueDiagnostic, ValueDiagnosticReason};

/// Compare requested semantic children with the bounded capture actually
/// compiled. This observes lowering; it never changes reads to obtain a note.
pub(in crate::ebpf::codegen) fn collect_capture_diagnostics(
    plan: &ValueReadPlan,
    source: &NestedValueSource,
    path: &str,
    budget: usize,
    notes: &mut Vec<ValueDiagnostic>,
) {
    let mut unsupported_conditions = Vec::new();
    let mut child = |plan: &ValueReadPlan, actual: Option<&NestedValueSource>, suffix: &str| {
        let path = format!("{path}{suffix}");
        if let Some(actual) = actual {
            collect_capture_diagnostics(plan, actual, &path, budget, notes);
        } else {
            notes.push(ValueDiagnostic {
                path, type_name: plan.root_type.summary.type_name(),
                reason: ValueDiagnosticReason::CaptureBudget,
                detail: format!("Nested capture did not fit ebpf.mem_dump_cap = {budget} bytes; the available root fields are retained"),
            });
        }
    };
    match (&plan.nested, &source.children) {
        (
            Some(ValueNestedPlan::ProjectedValue { value }),
            NestedValueChildrenSource::ProjectedValue { child: actual, .. },
        ) => child(value, Some(actual), ".value"),
        (
            Some(ValueNestedPlan::ProjectedView { fields }),
            NestedValueChildrenSource::ProjectedView { fields: actual },
        ) => {
            for field in fields {
                child(
                    &field.value,
                    actual
                        .iter()
                        .find(|f| f.field_index == field.field_index)
                        .map(|f| f.child.as_ref()),
                    &plan.field_path(field.field_index),
                );
            }
        }
        (
            Some(ValueNestedPlan::HashTable { fields }),
            NestedValueChildrenSource::HashTable { fields: actual, .. },
        ) => {
            for field in fields {
                child(
                    &field.value,
                    actual
                        .iter()
                        .find(|f| f.field_index == field.field_index)
                        .map(|f| f.child.as_ref()),
                    plan.hash_field_path(field.field_index),
                );
            }
        }
        (
            Some(ValueNestedPlan::Variant { fields }),
            NestedValueChildrenSource::Variant { fields: actual },
        ) => {
            for field in fields {
                if compile_nested_variant_condition(&field.condition).is_none() {
                    unsupported_conditions.push(ValueDiagnostic {
                        path: format!("{path}{}", plan.variant_field_path(field)),
                        type_name: field.value.root_type.summary.type_name(),
                        reason: ValueDiagnosticReason::ReadPlanUnsupported,
                        detail: "The enum discriminant cannot select this nested capture"
                            .to_string(),
                    });
                    continue;
                }

                child(
                    &field.value,
                    actual
                        .iter()
                        .find(|f| {
                            f.part_index == field.part_index
                                && f.variant_index == field.variant_index
                                && f.member_index == field.member_index
                                && f.payload_field_index == field.payload_field_index
                        })
                        .map(|f| f.field.child.as_ref()),
                    &plan.variant_field_path(field),
                );
            }
        }
        (
            Some(ValueNestedPlan::Sequence { element }),
            NestedValueChildrenSource::Sequence {
                element: actual, ..
            },
        ) => child(element, Some(actual), "[]"),
        _ => {}
    }
    notes.extend(unsupported_conditions);
}
