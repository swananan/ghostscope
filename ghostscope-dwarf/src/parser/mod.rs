//! Unified DWARF parser - single-pass parsing for all DWARF information

pub(crate) mod detailed_parser;
pub(crate) mod expression_evaluator;
pub(crate) mod fast_parser;
pub(crate) mod range_extractor;
// Full type resolver removed; shallow resolver lives in detailed_parser

// Re-export what's needed externally
pub use detailed_parser::VariableWithEvaluation;

// Internal re-exports for crate use
pub(crate) use detailed_parser::DetailedParser;
pub(crate) use expression_evaluator::ExpressionEvaluator;
pub(crate) use fast_parser::*;
pub(crate) use range_extractor::RangeExtractor;
