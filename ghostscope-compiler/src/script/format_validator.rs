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
        let placeholder_count = Self::count_placeholders(format)?;

        if placeholder_count != args.len() {
            return Err(ParseError::TypeError(format!(
                "Format string '{}' has {} placeholders {{}} but {} arguments provided",
                format,
                placeholder_count,
                args.len()
            )));
        }

        // TODO: Future enhancement - validate expression types against format specifiers
        // e.g., {:d} requires integer types, {:s} requires string types

        Ok(())
    }

    /// Count the number of placeholders in a format string
    /// Supports basic {} placeholders and escape sequences {{, }}
    fn count_placeholders(format: &str) -> Result<usize, ParseError> {
        let mut count = 0;
        let mut chars = format.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '{' => {
                    if chars.peek() == Some(&'{') {
                        chars.next(); // Skip escaped '{{'
                    } else {
                        // Found a placeholder, look for closing '}'
                        let mut found_closing = false;
                        let mut placeholder_content = String::new();

                        while let Some(inner_ch) = chars.next() {
                            if inner_ch == '}' {
                                found_closing = true;
                                break;
                            }
                            placeholder_content.push(inner_ch);
                        }

                        if !found_closing {
                            return Err(ParseError::InvalidExpression);
                        }

                        // TODO: Future enhancement - validate placeholder content
                        // For now, we only support empty placeholders: {}
                        if !placeholder_content.is_empty() {
                            return Err(ParseError::TypeError(format!(
                                "Complex format specifiers not yet supported: {{{}}}",
                                placeholder_content
                            )));
                        }

                        count += 1;
                    }
                }
                '}' => {
                    if chars.peek() == Some(&'}') {
                        chars.next(); // Skip escaped '}}'
                    } else {
                        return Err(ParseError::InvalidExpression); // Unmatched '}'
                    }
                }
                _ => {}
            }
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::ast::Expr;

    #[test]
    fn test_count_placeholders() {
        // Basic cases
        assert_eq!(
            FormatValidator::count_placeholders("hello world").unwrap(),
            0
        );
        assert_eq!(FormatValidator::count_placeholders("hello {}").unwrap(), 1);
        assert_eq!(FormatValidator::count_placeholders("{} {}").unwrap(), 2);
        assert_eq!(
            FormatValidator::count_placeholders("pid: {}, name: {}").unwrap(),
            2
        );

        // Escape sequences
        assert_eq!(
            FormatValidator::count_placeholders("use {{}} for braces").unwrap(),
            0
        );
        assert_eq!(
            FormatValidator::count_placeholders("value: {}, braces: {{}}").unwrap(),
            1
        );

        // Error cases
        assert!(FormatValidator::count_placeholders("unclosed {").is_err());
        assert!(FormatValidator::count_placeholders("unmatched }").is_err());
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
