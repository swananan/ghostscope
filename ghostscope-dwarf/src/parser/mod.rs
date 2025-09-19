//! Unified DWARF parser - single-pass parsing for all DWARF information

pub(crate) mod detailed_parser;
pub(crate) mod expression_evaluator;
pub(crate) mod fast_parser;
pub(crate) mod range_extractor;
pub(crate) mod type_resolver;

// Re-export what's needed externally
pub use detailed_parser::VariableWithEvaluation;

// Internal re-exports for crate use
pub(crate) use detailed_parser::DetailedParser;
pub(crate) use expression_evaluator::ExpressionEvaluator;
pub(crate) use fast_parser::*;
pub(crate) use range_extractor::RangeExtractor;
pub(crate) use type_resolver::TypeResolver;
