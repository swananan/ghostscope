//! Shared parsing for GhostScope's formatted-print template syntax.

use std::fmt;

/// Conversion applied to one formatted-print value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatConversion {
    Default,
    LowerHex,
    UpperHex,
    Pointer,
    String,
}

impl FormatConversion {
    /// Whether the conversion consumes an optional capture length.
    pub const fn supports_length(self) -> bool {
        matches!(self, Self::LowerHex | Self::UpperHex | Self::String)
    }
}

/// Optional byte length attached to a format conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatLength {
    None,
    Static(u64),
    Dynamic,
    Capture(String),
}

/// One typed placeholder in a format template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatSlot {
    pub conversion: FormatConversion,
    pub length: FormatLength,
}

impl FormatSlot {
    /// Number of script expressions consumed by this placeholder.
    pub const fn script_argument_count(&self) -> usize {
        if matches!(self.length, FormatLength::Dynamic) {
            2
        } else {
            1
        }
    }

    /// Number of values encoded in the trace event for this placeholder.
    pub const fn wire_argument_count(&self) -> usize {
        if self.conversion.supports_length()
            && matches!(
                self.length,
                FormatLength::Dynamic | FormatLength::Capture(_)
            )
        {
            2
        } else {
            1
        }
    }
}

impl fmt::Display for FormatSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let conversion = match self.conversion {
            FormatConversion::Default => return formatter.write_str("{}"),
            FormatConversion::LowerHex => 'x',
            FormatConversion::UpperHex => 'X',
            FormatConversion::Pointer => 'p',
            FormatConversion::String => 's',
        };
        write!(formatter, "{{:{conversion}")?;
        match &self.length {
            FormatLength::None => {}
            FormatLength::Static(length) => write!(formatter, ".{length}")?,
            FormatLength::Dynamic => formatter.write_str(".*")?,
            FormatLength::Capture(name) => write!(formatter, ".{name}$")?,
        }
        formatter.write_str("}")
    }
}

/// A decoded literal or typed placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatPart {
    Literal(String),
    Slot(FormatSlot),
}

/// Parsed format string shared by validation, code generation, and rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatTemplate {
    parts: Vec<FormatPart>,
}

impl FormatTemplate {
    /// Parse a template and reject malformed syntax.
    pub fn parse(format: &str) -> Result<Self, FormatTemplateError> {
        Self::parse_with_mode(format, ParseMode::Strict)
    }

    /// Parse a template using the renderer's compatibility fallbacks.
    pub fn parse_lossy(format: &str) -> Self {
        Self::parse_with_mode(format, ParseMode::Lossy)
            .expect("lossy format parsing does not return errors")
    }

    fn parse_with_mode(format: &str, mode: ParseMode) -> Result<Self, FormatTemplateError> {
        let mut chars = format.chars().peekable();
        let mut parts = Vec::new();
        let mut literal = String::new();

        while let Some(ch) = chars.next() {
            match ch {
                '{' if chars.peek() == Some(&'{') => {
                    chars.next();
                    literal.push('{');
                }
                '{' => {
                    push_literal(&mut parts, &mut literal);
                    let mut content = String::new();
                    let mut found_closing = false;
                    for inner in chars.by_ref() {
                        if inner == '}' {
                            found_closing = true;
                            break;
                        }
                        content.push(inner);
                    }
                    if !found_closing {
                        if mode == ParseMode::Strict {
                            return Err(FormatTemplateError::UnclosedPlaceholder);
                        }
                        literal.push_str("<MALFORMED_PLACEHOLDER>");
                        break;
                    }
                    push_part(&mut parts, parse_part(&content, mode)?);
                }
                '}' if chars.peek() == Some(&'}') => {
                    chars.next();
                    literal.push('}');
                }
                '}' if mode == ParseMode::Strict => {
                    return Err(FormatTemplateError::UnmatchedClosingBrace);
                }
                '}' => literal.push('}'),
                _ => literal.push(ch),
            }
        }

        push_literal(&mut parts, &mut literal);
        Ok(Self { parts })
    }

    /// Return decoded literals and typed placeholders in source order.
    pub fn parts(&self) -> &[FormatPart] {
        &self.parts
    }

    /// Iterate over typed placeholders in source order.
    pub fn slots(&self) -> impl Iterator<Item = &FormatSlot> {
        self.parts.iter().filter_map(|part| match part {
            FormatPart::Literal(_) => None,
            FormatPart::Slot(slot) => Some(slot),
        })
    }

    /// Return the number of placeholders in the template.
    pub fn slot_count(&self) -> usize {
        self.slots().count()
    }

    /// Return the number of expressions required in the trace script.
    pub fn script_argument_count(&self) -> usize {
        self.slots().map(FormatSlot::script_argument_count).sum()
    }

    /// Return the number of values emitted into the trace event.
    pub fn wire_argument_count(&self) -> usize {
        self.slots().map(FormatSlot::wire_argument_count).sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseMode {
    Strict,
    Lossy,
}

/// Syntax error returned by strict format-template parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatTemplateError {
    UnclosedPlaceholder,
    UnmatchedClosingBrace,
    InvalidSpecifier { content: String },
    EmptyConversion,
    UnsupportedConversion { conversion: char },
    InvalidCaptureVariable { specifier: String },
    InvalidLength { specifier: String },
    InvalidSyntax { specifier: String },
}

impl FormatTemplateError {
    /// Whether the error is caused by unmatched template delimiters.
    pub const fn is_structure_error(&self) -> bool {
        matches!(
            self,
            Self::UnclosedPlaceholder | Self::UnmatchedClosingBrace
        )
    }
}

impl fmt::Display for FormatTemplateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnclosedPlaceholder => formatter.write_str("unclosed format placeholder"),
            Self::UnmatchedClosingBrace => formatter.write_str("unmatched closing brace"),
            Self::InvalidSpecifier { content } => write!(
                formatter,
                "Invalid format specifier '{{{content}}}': expected ':' prefix"
            ),
            Self::EmptyConversion => formatter.write_str("Empty format after ':'"),
            Self::UnsupportedConversion { conversion } => {
                write!(
                    formatter,
                    "Unsupported format conversion '{{:{conversion}}}'"
                )
            }
            Self::InvalidCaptureVariable { specifier } => {
                write!(
                    formatter,
                    "Invalid capture variable in specifier '{specifier}'"
                )
            }
            Self::InvalidLength { specifier } => {
                write!(formatter, "Invalid length in specifier '{specifier}'")
            }
            Self::InvalidSyntax { specifier } => {
                write!(formatter, "Invalid specifier syntax '{specifier}'")
            }
        }
    }
}

impl std::error::Error for FormatTemplateError {}

fn push_literal(parts: &mut Vec<FormatPart>, literal: &mut String) {
    if !literal.is_empty() {
        push_part(parts, FormatPart::Literal(std::mem::take(literal)));
    }
}

fn push_part(parts: &mut Vec<FormatPart>, part: FormatPart) {
    if let FormatPart::Literal(literal) = part {
        if let Some(FormatPart::Literal(previous)) = parts.last_mut() {
            previous.push_str(&literal);
        } else if !literal.is_empty() {
            parts.push(FormatPart::Literal(literal));
        }
    } else {
        parts.push(part);
    }
}

fn parse_part(content: &str, mode: ParseMode) -> Result<FormatPart, FormatTemplateError> {
    if content.is_empty() {
        return Ok(FormatPart::Slot(FormatSlot {
            conversion: FormatConversion::Default,
            length: FormatLength::None,
        }));
    }

    let Some(specifier) = content.strip_prefix(':') else {
        if mode == ParseMode::Lossy {
            return Ok(FormatPart::Literal("<INVALID_SPEC>".to_string()));
        }
        return Err(FormatTemplateError::InvalidSpecifier {
            content: content.to_string(),
        });
    };
    let mut chars = specifier.chars();
    let conversion_char = match chars.next() {
        Some(conversion) => conversion,
        None if mode == ParseMode::Lossy => ' ',
        None => return Err(FormatTemplateError::EmptyConversion),
    };
    let conversion = match conversion_char {
        'x' => FormatConversion::LowerHex,
        'X' => FormatConversion::UpperHex,
        'p' => FormatConversion::Pointer,
        's' => FormatConversion::String,
        _ if mode == ParseMode::Lossy => FormatConversion::Default,
        _ => {
            return Err(FormatTemplateError::UnsupportedConversion {
                conversion: conversion_char,
            });
        }
    };

    let suffix = chars.as_str();
    let length = if suffix.is_empty() {
        FormatLength::None
    } else if let Some(length) = suffix.strip_prefix('.') {
        parse_length(conversion_char, length, mode)?
    } else if mode == ParseMode::Lossy {
        FormatLength::None
    } else {
        return Err(FormatTemplateError::InvalidSyntax {
            specifier: format!("{{:{conversion_char}{suffix}}}"),
        });
    };

    Ok(FormatPart::Slot(FormatSlot { conversion, length }))
}

fn parse_length(
    conversion: char,
    length: &str,
    mode: ParseMode,
) -> Result<FormatLength, FormatTemplateError> {
    if length == "*" {
        return Ok(FormatLength::Dynamic);
    }
    if let Some(name) = length.strip_suffix('$') {
        if is_capture_name(name) || mode == ParseMode::Lossy {
            return Ok(FormatLength::Capture(name.to_string()));
        }
        return Err(FormatTemplateError::InvalidCaptureVariable {
            specifier: format!("{{:{conversion}.{length}}}"),
        });
    }

    match parse_static_length(length) {
        Some(Some(value)) => Ok(FormatLength::Static(value)),
        // Preserve the previous behavior for syntactically valid values that
        // do not fit the numeric parser: accept the slot without a usable
        // static bound.
        Some(None) => Ok(FormatLength::None),
        None if mode == ParseMode::Lossy => Ok(FormatLength::None),
        None => Err(FormatTemplateError::InvalidLength {
            specifier: format!("{{:{conversion}.{length}}}"),
        }),
    }
}

fn parse_static_length(length: &str) -> Option<Option<u64>> {
    if length.chars().all(|ch| ch.is_ascii_digit()) {
        return Some(length.parse::<u64>().ok());
    }
    if let Some(hex) = length.strip_prefix("0x") {
        if !hex.is_empty() && hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Some(u64::from_str_radix(hex, 16).ok());
        }
    }
    if let Some(octal) = length.strip_prefix("0o") {
        if !octal.is_empty() && octal.chars().all(|ch| matches!(ch, '0'..='7')) {
            return Some(u64::from_str_radix(octal, 8).ok());
        }
    }
    if let Some(binary) = length.strip_prefix("0b") {
        if !binary.is_empty() && binary.chars().all(|ch| matches!(ch, '0' | '1')) {
            return Some(u64::from_str_radix(binary, 2).ok());
        }
    }
    None
}

fn is_capture_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|first| {
        (first.is_ascii_alphabetic() || first == '_')
            && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_literals_escapes_and_default_slots() {
        let template =
            FormatTemplate::parse("prefix {{ {} }} suffix").expect("parse format template");

        assert_eq!(
            template.parts(),
            [
                FormatPart::Literal("prefix { ".to_string()),
                FormatPart::Slot(FormatSlot {
                    conversion: FormatConversion::Default,
                    length: FormatLength::None,
                }),
                FormatPart::Literal(" } suffix".to_string()),
            ]
        );
        assert_eq!(template.script_argument_count(), 1);
        assert_eq!(template.wire_argument_count(), 1);
    }

    #[test]
    fn parses_extended_conversions_and_lengths() {
        let template =
            FormatTemplate::parse("{:x.16} {:X.0x10} {:s.0o20} {:x.0b1000} {:s.*} {:x.len$} {:p}")
                .expect("parse extended format template");
        let slots = template.slots().cloned().collect::<Vec<_>>();

        assert_eq!(
            slots,
            [
                FormatSlot {
                    conversion: FormatConversion::LowerHex,
                    length: FormatLength::Static(16),
                },
                FormatSlot {
                    conversion: FormatConversion::UpperHex,
                    length: FormatLength::Static(16),
                },
                FormatSlot {
                    conversion: FormatConversion::String,
                    length: FormatLength::Static(16),
                },
                FormatSlot {
                    conversion: FormatConversion::LowerHex,
                    length: FormatLength::Static(8),
                },
                FormatSlot {
                    conversion: FormatConversion::String,
                    length: FormatLength::Dynamic,
                },
                FormatSlot {
                    conversion: FormatConversion::LowerHex,
                    length: FormatLength::Capture("len".to_string()),
                },
                FormatSlot {
                    conversion: FormatConversion::Pointer,
                    length: FormatLength::None,
                },
            ]
        );
        assert_eq!(template.script_argument_count(), 8);
        assert_eq!(template.wire_argument_count(), 9);
        assert_eq!(
            slots.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [
                "{:x.16}",
                "{:X.16}",
                "{:s.16}",
                "{:x.8}",
                "{:s.*}",
                "{:x.len$}",
                "{:p}",
            ]
        );
    }

    #[test]
    fn rejects_invalid_templates() {
        assert_eq!(
            FormatTemplate::parse("unclosed {"),
            Err(FormatTemplateError::UnclosedPlaceholder)
        );
        assert_eq!(
            FormatTemplate::parse("unmatched }"),
            Err(FormatTemplateError::UnmatchedClosingBrace)
        );
        assert!(matches!(
            FormatTemplate::parse("{value}"),
            Err(FormatTemplateError::InvalidSpecifier { .. })
        ));
        assert!(matches!(
            FormatTemplate::parse("{:q}"),
            Err(FormatTemplateError::UnsupportedConversion { conversion: 'q' })
        ));
        assert!(matches!(
            FormatTemplate::parse("{:x.1bad$}"),
            Err(FormatTemplateError::InvalidCaptureVariable { .. })
        ));
        assert!(matches!(
            FormatTemplate::parse("{:x.nope}"),
            Err(FormatTemplateError::InvalidLength { .. })
        ));
    }

    #[test]
    fn lossy_parsing_preserves_renderer_fallbacks() {
        assert_eq!(
            FormatTemplate::parse_lossy("prefix {").parts(),
            [FormatPart::Literal(
                "prefix <MALFORMED_PLACEHOLDER>".to_string()
            )]
        );
        assert_eq!(
            FormatTemplate::parse_lossy("bad {value} tail").parts(),
            [FormatPart::Literal("bad <INVALID_SPEC> tail".to_string())]
        );
        assert_eq!(
            FormatTemplate::parse_lossy("{:q}").parts(),
            [FormatPart::Slot(FormatSlot {
                conversion: FormatConversion::Default,
                length: FormatLength::None,
            })]
        );
        assert_eq!(
            FormatTemplate::parse_lossy("closing }").parts(),
            [FormatPart::Literal("closing }".to_string())]
        );
    }
}
