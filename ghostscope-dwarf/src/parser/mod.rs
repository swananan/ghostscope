//! Unified DWARF parser - single-pass parsing for all DWARF information

pub(crate) mod detailed_parser;
pub(crate) mod fast_parser;
pub(crate) mod range_extractor;
// Full type resolver removed; shallow resolver lives in detailed_parser

// Internal parser output consumed by the semantic planning layer.
pub(crate) use detailed_parser::VariableWithEvaluation;

// Internal re-exports for crate use
pub(crate) use crate::dwarf_expr::ExpressionEvaluator;
pub(crate) use detailed_parser::DetailedParser;
pub(crate) use fast_parser::*;
pub(crate) use range_extractor::RangeExtractor;
