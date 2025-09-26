use ratatui::{
    style::{Color, Style},
    text::Span,
};
use regex::Regex;

/// Syntax highlighting for GhostScope script language
pub struct SyntaxHighlighter {
    // Compiled regex patterns for efficient matching
    keywords_regex: Regex,
    string_regex: Regex,
    comment_regex: Regex,
    number_regex: Regex,
    hex_address_regex: Regex,
    special_var_regex: Regex,
    operator_regex: Regex,
}

impl SyntaxHighlighter {
    pub fn new() -> Self {
        Self {
            // Keywords: trace, print, backtrace, bt, if, else, let
            keywords_regex: Regex::new(r"\b(trace|print|backtrace|bt|if|else|let)\b").unwrap(),

            // String literals: "..."
            string_regex: Regex::new(r#""([^"\\]|\\.)*""#).unwrap(),

            // Comments: // ... or /* ... */
            comment_regex: Regex::new(r"(//.*)|(/\*[\s\S]*?\*/)").unwrap(),

            // Numbers: integers and floats
            number_regex: Regex::new(r"\b\d+(\.\d+)?\b").unwrap(),

            // Hex addresses: 0x...
            hex_address_regex: Regex::new(r"\b0x[0-9a-fA-F]+\b").unwrap(),

            // Special variables: $variable
            special_var_regex: Regex::new(r"\$[a-zA-Z_][a-zA-Z0-9_]*").unwrap(),

            // Operators: +, -, *, /, ==, !=, <=, >=, <, >
            operator_regex: Regex::new(r"(==|!=|<=|>=|[+\-*/=<>])").unwrap(),
        }
    }

    /// Highlight a line of script code and return colored spans
    pub fn highlight_line(&self, line: &str) -> Vec<Span<'static>> {
        let mut spans = Vec::new();
        let mut last_end = 0;

        // Collect all matches with their positions and types
        let mut matches = Vec::new();

        // Find all pattern matches
        self.collect_matches(line, &mut matches);

        // Sort matches by position to process them in order
        matches.sort_by_key(|m| m.start);

        // Remove overlapping matches (prefer earlier ones)
        let mut filtered_matches = Vec::new();
        let mut last_match_end = 0;

        for m in matches {
            if m.start >= last_match_end {
                filtered_matches.push(m.clone());
                last_match_end = m.end;
            }
        }

        // Generate spans
        for m in filtered_matches {
            // Add unstyled text before this match
            if m.start > last_end {
                let text = &line[last_end..m.start];
                if !text.is_empty() {
                    spans.push(Span::styled(
                        text.to_string(),
                        Style::default().fg(Color::White),
                    ));
                }
            }

            // Add styled match
            let text = &line[m.start..m.end];
            spans.push(Span::styled(text.to_string(), m.style));

            last_end = m.end;
        }

        // Add remaining unstyled text
        if last_end < line.len() {
            let text = &line[last_end..];
            spans.push(Span::styled(
                text.to_string(),
                Style::default().fg(Color::White),
            ));
        }

        // If no matches found, return the whole line as default styled
        if spans.is_empty() {
            spans.push(Span::styled(
                line.to_string(),
                Style::default().fg(Color::White),
            ));
        }

        spans
    }

    /// Collect all regex matches with their positions and styles
    fn collect_matches(&self, line: &str, matches: &mut Vec<Match>) {
        // Comments have highest priority to avoid highlighting inside them
        for m in self.comment_regex.find_iter(line) {
            matches.push(Match {
                start: m.start(),
                end: m.end(),
                style: Style::default().fg(Color::DarkGray),
            });
        }

        // Strings have high priority
        for m in self.string_regex.find_iter(line) {
            matches.push(Match {
                start: m.start(),
                end: m.end(),
                style: Style::default().fg(Color::Green),
            });
        }

        // Hex addresses (should come before general numbers)
        for m in self.hex_address_regex.find_iter(line) {
            matches.push(Match {
                start: m.start(),
                end: m.end(),
                style: Style::default().fg(Color::Magenta),
            });
        }

        // Numbers
        for m in self.number_regex.find_iter(line) {
            matches.push(Match {
                start: m.start(),
                end: m.end(),
                style: Style::default().fg(Color::Magenta),
            });
        }

        // Keywords
        for m in self.keywords_regex.find_iter(line) {
            matches.push(Match {
                start: m.start(),
                end: m.end(),
                style: Style::default().fg(Color::Blue),
            });
        }

        // Special variables
        for m in self.special_var_regex.find_iter(line) {
            matches.push(Match {
                start: m.start(),
                end: m.end(),
                style: Style::default().fg(Color::Cyan),
            });
        }

        // Operators
        for m in self.operator_regex.find_iter(line) {
            matches.push(Match {
                start: m.start(),
                end: m.end(),
                style: Style::default().fg(Color::Yellow),
            });
        }
    }
}

impl Default for SyntaxHighlighter {
    fn default() -> Self {
        Self::new()
    }
}

/// A match found in the text with position and style information
#[derive(Clone)]
struct Match {
    start: usize,
    end: usize,
    style: Style,
}

/// Convenience function to highlight a single line
pub fn highlight_line(line: &str) -> Vec<Span<'static>> {
    // Use a static highlighter instance for efficiency
    use std::sync::OnceLock;
    static HIGHLIGHTER: OnceLock<SyntaxHighlighter> = OnceLock::new();

    let highlighter = HIGHLIGHTER.get_or_init(SyntaxHighlighter::new);
    highlighter.highlight_line(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyword_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let spans = highlighter.highlight_line("trace calculate_something {");

        // Should have at least one blue span for "trace"
        assert!(spans.iter().any(|span| span.style.fg == Some(Color::Blue)));
    }

    #[test]
    fn test_string_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let spans = highlighter.highlight_line(r#"print "Hello, world!";"#);

        // Should have a green span for the string
        assert!(spans.iter().any(|span| span.style.fg == Some(Color::Green)));
        // Should have a blue span for "print"
        assert!(spans.iter().any(|span| span.style.fg == Some(Color::Blue)));
    }

    #[test]
    fn test_comment_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let spans = highlighter.highlight_line("// This is a comment");

        // Should have a dark gray span for the comment
        assert!(spans
            .iter()
            .any(|span| span.style.fg == Some(Color::DarkGray)));
    }

    #[test]
    fn test_number_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let spans = highlighter.highlight_line("let x = 42;");

        // Should have a magenta span for the number
        assert!(spans
            .iter()
            .any(|span| span.style.fg == Some(Color::Magenta)));
    }

    #[test]
    fn test_hex_address_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let spans = highlighter.highlight_line("trace 0x1234abcd {");

        // Should have a magenta span for the hex address
        assert!(spans
            .iter()
            .any(|span| span.style.fg == Some(Color::Magenta)));
    }

    #[test]
    fn test_special_variable_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let spans = highlighter.highlight_line("print $pid;");

        // Should have a cyan span for the special variable
        assert!(spans.iter().any(|span| span.style.fg == Some(Color::Cyan)));
    }

    #[test]
    fn test_operator_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let spans = highlighter.highlight_line("if a == b {");

        // Should have a yellow span for the operator
        assert!(spans
            .iter()
            .any(|span| span.style.fg == Some(Color::Yellow)));
    }

    #[test]
    fn test_complex_line() {
        let highlighter = SyntaxHighlighter::new();
        let spans = highlighter
            .highlight_line(r#"print "Value: {} at 0x{:x}", value, 0x1000; // Debug output"#);

        // Should have multiple different colored spans
        let colors: std::collections::HashSet<_> =
            spans.iter().filter_map(|span| span.style.fg).collect();

        // Expect at least: blue (print), green (string), magenta (hex), dark gray (comment)
        assert!(colors.len() >= 3);
    }
}
