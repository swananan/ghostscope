use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest::RuleType;
use pest_derive::Parser;

use crate::script::ast::Program;
use tracing::debug;

mod diagnostics;
mod expr;
mod statement;

use diagnostics::{
    detect_backtrace_depth_argument, detect_unclosed_print_string, detect_unknown_keyword,
};
use statement::parse_statement;

#[derive(Parser)]
#[grammar = "script/grammar.pest"]
pub struct GhostScopeParser;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Pest parser error: {0}")]
    Pest(#[from] Box<pest::error::Error<Rule>>),

    #[error("Unexpected token: {0:?}")]
    UnexpectedToken(Rule),

    #[error("Invalid expression")]
    InvalidExpression,

    #[error("Syntax error: {0}")]
    SyntaxError(String),

    #[error("Type error: {0}")]
    TypeError(String),

    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),
}

impl From<pest::error::Error<Rule>> for ParseError {
    fn from(err: pest::error::Error<Rule>) -> Self {
        ParseError::Pest(Box::new(err))
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;

// Custom chunks function with RuleType constraint
fn chunks_of_two<'a, T: RuleType>(pairs: Pairs<'a, T>) -> Vec<Vec<Pair<'a, T>>> {
    let pairs_vec: Vec<_> = pairs.collect();
    let mut result = Vec::new();

    let mut i = 0;
    // Only produce full (op, rhs) pairs; ignore any trailing leftover defensively
    while i + 1 < pairs_vec.len() {
        result.push(vec![pairs_vec[i].clone(), pairs_vec[i + 1].clone()]);
        i += 2;
    }

    result
}

pub fn parse(input: &str) -> Result<Program> {
    debug!("Starting to parse input: {}", input.trim());

    let pairs = match GhostScopeParser::parse(Rule::program, input) {
        Ok(p) => p,
        Err(e) => {
            // Heuristic: detect unclosed string in print lines to provide a clearer hint
            if let Some(msg) = detect_unclosed_print_string(input) {
                return Err(ParseError::SyntaxError(msg));
            }
            if let Some(msg) = detect_backtrace_depth_argument(input) {
                return Err(ParseError::SyntaxError(msg));
            }
            // Heuristic: detect likely misspelled or unknown keywords and suggest fixes
            if let Some(msg) = detect_unknown_keyword(input) {
                return Err(ParseError::SyntaxError(msg));
            }
            return Err(ParseError::Pest(Box::new(e)));
        }
    };
    let mut program = Program::new();

    for pair in pairs {
        debug!(
            "Parsing top-level rule: {:?} = '{}'",
            pair.as_rule(),
            pair.as_str().trim()
        );
        match pair.as_rule() {
            Rule::statement => {
                let statement = parse_statement(pair)?;
                program.add_statement(statement);
            }
            Rule::EOI => {}
            _ => return Err(ParseError::UnexpectedToken(pair.as_rule())),
        }
    }

    debug!("Parsing completed successfully");
    Ok(program)
}

#[cfg(test)]
mod tests;
