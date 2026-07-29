//! Format string validation for print statements
//!
//! This module validates format strings and their arguments during compilation,
//! ensuring correct placeholder count and syntax.

use crate::script::ast::Expr;
use crate::script::parser::ParseError;

pub struct FormatValidator;

impl FormatValidator {
    /// Validate that format string placeholders match the number of arguments
    pub fn validate_format_arguments(format: &str, args: &[Expr]) -> Result<(), ParseError> {
        let (placeholders, star_extras) = Self::count_required_args(format)?;
        let required_args = placeholders + star_extras;

        if required_args != args.len() {
            let args_len = args.len();
            return Err(ParseError::TypeError(format!(
                "Format string '{format}' expects {required_args} argument(s) but received {args_len} argument(s)"
            )));
        }

        // TODO (phase 2): validate expression types against format specifiers
        // e.g., {:x} requires integer or pointer; {:s} requires char*/bytes

        Ok(())
    }

    /// Count the number of placeholders in a format string
    /// Supports basic {} placeholders and escape sequences {{, }}
    /// Extended: supports {:x}, {:X}, {:p}, {:s}, and optional length suffixes .N or .*
    /// Returns (placeholders, star_extras) where star_extras is the number of additional
    /// dynamic-length arguments required by `.*` occurrences.
    fn count_required_args(format: &str) -> Result<(usize, usize), ParseError> {
        let template = ghostscope_protocol::FormatTemplate::parse(format).map_err(|error| {
            if error.is_structure_error() {
                ParseError::InvalidExpression
            } else {
                ParseError::TypeError(error.to_string())
            }
        })?;
        let placeholders = template.slot_count();
        let star_extras = template
            .script_argument_count()
            .saturating_sub(placeholders);
        Ok((placeholders, star_extras))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::ast::Expr;

    #[test]
    fn test_count_placeholders() -> Result<(), ParseError> {
        // Basic cases
        assert_eq!(FormatValidator::count_required_args("hello world")?, (0, 0));
        assert_eq!(FormatValidator::count_required_args("hello {}")?, (1, 0));
        assert_eq!(FormatValidator::count_required_args("{} {}")?, (2, 0));
        assert_eq!(
            FormatValidator::count_required_args("pid: {}, name: {}")?,
            (2, 0)
        );

        // Escape sequences
        assert_eq!(
            FormatValidator::count_required_args("use {{}} for braces")?,
            (0, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("value: {}, braces: {{}}")?,
            (1, 0)
        );

        // Error cases
        assert!(FormatValidator::count_required_args("unclosed {").is_err());
        assert!(FormatValidator::count_required_args("unmatched }").is_err());

        // Extended specifiers
        assert_eq!(FormatValidator::count_required_args("{:x}")?, (1, 0));
        assert_eq!(FormatValidator::count_required_args("{:X}")?, (1, 0));
        assert_eq!(FormatValidator::count_required_args("{:p}")?, (1, 0));
        assert_eq!(FormatValidator::count_required_args("{:s}")?, (1, 0));
        assert_eq!(FormatValidator::count_required_args("{:x.16}")?, (1, 0));
        assert_eq!(FormatValidator::count_required_args("{:s.*}")?, (1, 1));
        assert_eq!(FormatValidator::count_required_args("{:x.len$}")?, (1, 0));
        // Static length with hex/oct/bin
        assert_eq!(FormatValidator::count_required_args("{:x.0x10}")?, (1, 0));
        assert_eq!(FormatValidator::count_required_args("{:s.0o20}")?, (1, 0));
        assert_eq!(FormatValidator::count_required_args("{:X.0b1000}")?, (1, 0));
        assert!(FormatValidator::count_required_args("{:x.1a$}").is_err());
        Ok(())
    }

    #[test]
    fn test_validate_format_arguments() {
        let args_empty: Vec<Expr> = vec![];
        let args_one = vec![Expr::Variable("pid".to_string())];
        let args_two = vec![
            Expr::Variable("pid".to_string()),
            Expr::String("test".to_string()),
        ];

        // Matching cases
        assert!(FormatValidator::validate_format_arguments("no placeholders", &args_empty).is_ok());
        assert!(FormatValidator::validate_format_arguments("pid: {}", &args_one).is_ok());
        assert!(FormatValidator::validate_format_arguments("pid: {}, name: {}", &args_two).is_ok());

        // Mismatched cases
        assert!(FormatValidator::validate_format_arguments("need one: {}", &args_empty).is_err());
        assert!(FormatValidator::validate_format_arguments("no placeholders", &args_one).is_err());
        assert!(FormatValidator::validate_format_arguments("need two: {} {}", &args_one).is_err());
    }
}
