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
        let mut placeholders = 0usize;
        let mut star_extras = 0usize;
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

                        for inner_ch in chars.by_ref() {
                            if inner_ch == '}' {
                                found_closing = true;
                                break;
                            }
                            placeholder_content.push(inner_ch);
                        }

                        if !found_closing {
                            return Err(ParseError::InvalidExpression);
                        }

                        // Accept: empty "{}" or extended forms like ":x", ":X", ":p", ":s", optionally with
                        // a length suffix ".N" (digits) or ".*" (dynamic length consumes one extra argument)
                        if placeholder_content.is_empty() {
                            placeholders += 1;
                        } else {
                            // Must start with ':'
                            if !placeholder_content.starts_with(':') {
                                return Err(ParseError::TypeError(format!(
                        "Invalid format specifier '{{{placeholder_content}}}': expected ':' prefix"
                    )));
                            }
                            // Extract conv and optional suffix
                            let tail = &placeholder_content[1..];
                            // conv is first char
                            let mut iter = tail.chars();
                            let conv = iter.next().ok_or_else(|| {
                                ParseError::TypeError("Empty format after ':'".to_string())
                            })?;
                            match conv {
                                'x' | 'X' | 'p' | 's' => {}
                                _ => {
                                    return Err(ParseError::TypeError(format!(
                                        "Unsupported format conversion '{{:{conv}}}'"
                                    )));
                                }
                            }
                            // Remaining should be empty or ".N" or ".*" or ".name$" (capture variable)
                            let rest: String = iter.collect();
                            if rest.is_empty() {
                                // ok
                            } else if let Some(rem) = rest.strip_prefix('.') {
                                if rem == "*" {
                                    star_extras += 1; // dynamic length consumes next arg
                                } else if let Some(name) = rem.strip_suffix('$') {
                                    // capture variable name: [A-Za-z_][A-Za-z0-9_]*$
                                    let mut chars = name.chars();
                                    let valid = if let Some(first) = chars.next() {
                                        (first.is_ascii_alphabetic() || first == '_')
                                            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
                                    } else {
                                        false
                                    };
                                    if !valid {
                                        return Err(ParseError::TypeError(format!(
                                            "Invalid capture variable in specifier '{{:{conv}.{rem}}}'"
                                        )));
                                    }
                                } else if rem.chars().all(|c| c.is_ascii_digit())
                                    || (rem.starts_with("0x")
                                        && rem.len() > 2
                                        && rem[2..].chars().all(|c| c.is_ascii_hexdigit()))
                                    || (rem.starts_with("0o")
                                        && rem.len() > 2
                                        && rem[2..].chars().all(|c| matches!(c, '0'..='7')))
                                    || (rem.starts_with("0b")
                                        && rem.len() > 2
                                        && rem[2..].chars().all(|c| matches!(c, '0' | '1')))
                                {
                                    // static length with base support: decimal / 0x.. / 0o.. / 0b..
                                } else {
                                    return Err(ParseError::TypeError(format!(
                                        "Invalid length in specifier '{{:{conv}{rest}}}'"
                                    )));
                                }
                            } else {
                                return Err(ParseError::TypeError(format!(
                                    "Invalid specifier syntax '{{:{conv}{rest}}}'"
                                )));
                            }
                            placeholders += 1;
                        }
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

        Ok((placeholders, star_extras))
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
            FormatValidator::count_required_args("hello world").unwrap(),
            (0, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("hello {}").unwrap(),
            (1, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("{} {}").unwrap(),
            (2, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("pid: {}, name: {}").unwrap(),
            (2, 0)
        );

        // Escape sequences
        assert_eq!(
            FormatValidator::count_required_args("use {{}} for braces").unwrap(),
            (0, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("value: {}, braces: {{}}").unwrap(),
            (1, 0)
        );

        // Error cases
        assert!(FormatValidator::count_required_args("unclosed {").is_err());
        assert!(FormatValidator::count_required_args("unmatched }").is_err());

        // Extended specifiers
        assert_eq!(
            FormatValidator::count_required_args("{:x}").unwrap(),
            (1, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("{:X}").unwrap(),
            (1, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("{:p}").unwrap(),
            (1, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("{:s}").unwrap(),
            (1, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("{:x.16}").unwrap(),
            (1, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("{:s.*}").unwrap(),
            (1, 1)
        );
        assert_eq!(
            FormatValidator::count_required_args("{:x.len$}").unwrap(),
            (1, 0)
        );
        // Static length with hex/oct/bin
        assert_eq!(
            FormatValidator::count_required_args("{:x.0x10}").unwrap(),
            (1, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("{:s.0o20}").unwrap(),
            (1, 0)
        );
        assert_eq!(
            FormatValidator::count_required_args("{:X.0b1000}").unwrap(),
            (1, 0)
        );
        assert!(FormatValidator::count_required_args("{:x.1a$}").is_err());
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
