pub(crate) mod expr;
pub(crate) mod origins;
pub(crate) mod pc;
pub(crate) mod types;

pub(crate) use expr::eval_member_offset_expr;
pub(crate) use origins::{
    resolve_attr_with_unit_origins, resolve_name_with_origins, resolve_origin_entry,
};
pub(crate) use pc::{range_contains_pc, ranges_contain_pc};
pub(crate) use types::{
    resolve_type_ref_in_same_unit_with_origins, resolve_type_ref_with_origins,
    strip_typedef_qualified, TypeLoc,
};
