mod access;
mod plan;
mod value;
mod variant;

pub(super) use value::{ValueLayout, ValueLayoutResolution};

pub(super) fn resolve_tuple_index(index: u32) -> crate::VariableAccessSegment {
    access::resolve_tuple_index(index)
}

pub(super) fn annotate_type_info(type_info: &mut crate::TypeInfo) {
    variant::annotate_type_info(type_info);
}

pub(super) fn resolve_value_layout(
    current: &crate::ResolvedType,
    dwarf_qualified_name: Option<&str>,
) -> ValueLayoutResolution {
    value::diagnose_value_layout(current, dwarf_qualified_name)
}

pub(super) fn requires_dwarf_qualified_name(current: &crate::ResolvedType) -> bool {
    value::requires_dwarf_qualified_name(current)
}

pub(super) fn build_value_read_plan(
    context: &dyn crate::language::adapter::ValueAdapterContext,
    current: &crate::ResolvedType,
    layout: ValueLayout,
    type_module_path: Option<&std::path::Path>,
) -> crate::Result<Option<crate::ValueReadPlan>> {
    plan::build_value_read_plan(context, current, layout, type_module_path)
}
