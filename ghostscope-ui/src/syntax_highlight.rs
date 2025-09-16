use ratatui::style::{Color, Style};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum TokenType {
    Keyword,
    String,
    Comment,
    Number,
    Function,
    Preprocessor,
    Normal,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub token_type: TokenType,
    pub start: usize,
    pub end: usize,
    pub text: String,
}

pub struct SyntaxHighlighter {
    c_keywords: HashMap<String, TokenType>,
    cpp_keywords: HashMap<String, TokenType>,
    rust_keywords: HashMap<String, TokenType>,
}

impl SyntaxHighlighter {
    pub fn new() -> Self {
        let mut highlighter = Self {
            c_keywords: HashMap::new(),
            cpp_keywords: HashMap::new(),
            rust_keywords: HashMap::new(),
        };

        highlighter.init_c_keywords();
        highlighter.init_cpp_keywords();
        highlighter.init_rust_keywords();

        highlighter
    }

    fn init_c_keywords(&mut self) {
        let keywords = vec![
            "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
            "else", "enum", "extern", "float", "for", "goto", "if", "int", "long", "register",
            "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
            "union", "unsigned", "void", "volatile", "while",
        ];

        for keyword in keywords {
            self.c_keywords
                .insert(keyword.to_string(), TokenType::Keyword);
        }
    }

    fn init_cpp_keywords(&mut self) {
        // C++ specific keywords (in addition to C keywords)
        let cpp_keywords = vec![
            "class",
            "namespace",
            "template",
            "typename",
            "public",
            "private",
            "protected",
            "virtual",
            "override",
            "final",
            "explicit",
            "friend",
            "inline",
            "mutable",
            "new",
            "delete",
            "this",
            "operator",
            "throw",
            "try",
            "catch",
            "const_cast",
            "dynamic_cast",
            "reinterpret_cast",
            "static_cast",
            "typeid",
            "using",
            "bool",
            "true",
            "false",
            "nullptr",
            "decltype",
            "auto",
            "constexpr",
            "noexcept",
            "override",
            "final",
            "alignas",
            "alignof",
            "char16_t",
            "char32_t",
            "concept",
            "consteval",
            "constinit",
            "co_await",
            "co_return",
            "co_yield",
            "requires",
            "std",
            "vector",
            "string",
            "map",
            "set",
            "unordered_map",
        ];

        for keyword in cpp_keywords {
            self.cpp_keywords
                .insert(keyword.to_string(), TokenType::Keyword);
        }
    }

    fn init_rust_keywords(&mut self) {
        let rust_keywords = vec![
            "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
            "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
            "return", "self", "Self", "static", "struct", "super", "trait", "true", "type",
            "unsafe", "use", "where", "while", "async", "await", "dyn", "abstract", "become",
            "box", "do", "final", "macro", "override", "priv", "try", "typeof", "unsized",
            "virtual", "yield",
        ];

        for keyword in rust_keywords {
            self.rust_keywords
                .insert(keyword.to_string(), TokenType::Keyword);
        }
    }

    pub fn highlight_line(&self, line: &str, language: &str) -> Vec<Token> {
        let mut tokens = Vec::new();
        let mut current_pos = 0;
        let mut in_string = false;
        let mut in_comment = false;
        let mut comment_start = 0;
        let mut string_start = 0;
        let mut string_char = '\0';

        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let ch = chars[i];

            // Handle comments
            if !in_string && !in_comment {
                if ch == '/' && i + 1 < chars.len() {
                    let next_ch = chars[i + 1];
                    if next_ch == '/' {
                        // Single line comment
                        comment_start = current_pos;
                        in_comment = true;
                        i += 2;
                        current_pos += 2;
                        continue;
                    } else if next_ch == '*' {
                        // Multi-line comment start
                        comment_start = current_pos;
                        in_comment = true;
                        i += 2;
                        current_pos += 2;
                        continue;
                    }
                }
            }

            // Handle multi-line comment end
            if in_comment && ch == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                tokens.push(Token {
                    token_type: TokenType::Comment,
                    start: comment_start,
                    end: current_pos + 2,
                    text: line[comment_start..current_pos + 2].to_string(),
                });
                in_comment = false;
                i += 2;
                current_pos += 2;
                continue;
            }

            // Handle strings
            if !in_comment && (ch == '"' || ch == '\'') {
                if !in_string {
                    string_start = current_pos;
                    string_char = ch;
                    in_string = true;
                } else if ch == string_char {
                    // End of string
                    tokens.push(Token {
                        token_type: TokenType::String,
                        start: string_start,
                        end: current_pos + 1,
                        text: line[string_start..current_pos + 1].to_string(),
                    });
                    in_string = false;
                }
            }

            // Handle keywords and identifiers
            if !in_string && !in_comment && (ch.is_alphabetic() || ch == '_') {
                let start = current_pos;
                let mut end = current_pos;
                let mut word = String::new();

                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    word.push(chars[i]);
                    end = current_pos + 1;
                    i += 1;
                    current_pos += 1;
                }

                let token_type = self.get_keyword_type(&word, language);
                tokens.push(Token {
                    token_type,
                    start,
                    end,
                    text: word,
                });
                continue;
            }

            // Handle numbers
            if !in_string && !in_comment && ch.is_numeric() {
                let start = current_pos;
                let mut end = current_pos;

                while i < chars.len()
                    && (chars[i].is_numeric()
                        || chars[i] == '.'
                        || chars[i] == 'x'
                        || chars[i] == 'X')
                {
                    end = current_pos + 1;
                    i += 1;
                    current_pos += 1;
                }

                tokens.push(Token {
                    token_type: TokenType::Number,
                    start,
                    end,
                    text: line[start..end].to_string(),
                });
                continue;
            }

            // Handle preprocessor directives
            if !in_string && !in_comment && ch == '#' && current_pos == 0 {
                let start = current_pos;
                let mut end = current_pos;

                while i < chars.len() && chars[i] != '\n' {
                    end = current_pos + 1;
                    i += 1;
                    current_pos += 1;
                }

                tokens.push(Token {
                    token_type: TokenType::Preprocessor,
                    start,
                    end,
                    text: line[start..end].to_string(),
                });
                continue;
            }

            i += 1;
            current_pos += 1;
        }

        // Handle remaining comment or string
        if in_comment {
            tokens.push(Token {
                token_type: TokenType::Comment,
                start: comment_start,
                end: current_pos,
                text: line[comment_start..].to_string(),
            });
        } else if in_string {
            tokens.push(Token {
                token_type: TokenType::String,
                start: string_start,
                end: current_pos,
                text: line[string_start..].to_string(),
            });
        }

        tokens
    }

    fn get_keyword_type(&self, word: &str, language: &str) -> TokenType {
        match language {
            "c" => {
                if self.c_keywords.contains_key(word) {
                    TokenType::Keyword
                } else {
                    TokenType::Normal
                }
            }
            "cpp" | "c++" => {
                if self.c_keywords.contains_key(word) || self.cpp_keywords.contains_key(word) {
                    TokenType::Keyword
                } else {
                    TokenType::Normal
                }
            }
            "rust" => {
                if self.rust_keywords.contains_key(word) {
                    TokenType::Keyword
                } else {
                    TokenType::Normal
                }
            }
            _ => TokenType::Normal,
        }
    }

    pub fn get_token_style(&self, token_type: &TokenType) -> Style {
        match token_type {
            TokenType::Keyword => Style::default().fg(Color::LightBlue),
            TokenType::String => Style::default().fg(Color::LightGreen),
            TokenType::Comment => Style::default().fg(Color::DarkGray),
            TokenType::Number => Style::default().fg(Color::LightYellow),
            TokenType::Function => Style::default().fg(Color::LightCyan),
            TokenType::Preprocessor => Style::default().fg(Color::LightRed),
            TokenType::Normal => Style::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_keyword_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let line = "int main() { return 0; }";
        let tokens = highlighter.highlight_line(line, "c");

        // Should have tokens for "int", "main", "(", ")", "{", "return", "0", ";", "}"
        assert!(!tokens.is_empty());

        // Check that "int" and "return" are keywords
        let keyword_tokens: Vec<_> = tokens
            .iter()
            .filter(|t| t.token_type == TokenType::Keyword)
            .collect();

        assert!(keyword_tokens.iter().any(|t| t.text == "int"));
        assert!(keyword_tokens.iter().any(|t| t.text == "return"));
    }

    #[test]
    fn test_string_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let line = r#"printf("Hello, World!");"#;
        let tokens = highlighter.highlight_line(line, "c");

        // Should have a string token
        let string_tokens: Vec<_> = tokens
            .iter()
            .filter(|t| t.token_type == TokenType::String)
            .collect();

        assert!(!string_tokens.is_empty());
        assert!(string_tokens.iter().any(|t| t.text == r#""Hello, World!""#));
    }

    #[test]
    fn test_comment_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let line = "int x = 5; // This is a comment";
        let tokens = highlighter.highlight_line(line, "c");

        // Should have a comment token
        let comment_tokens: Vec<_> = tokens
            .iter()
            .filter(|t| t.token_type == TokenType::Comment)
            .collect();

        assert!(!comment_tokens.is_empty());
        assert!(comment_tokens
            .iter()
            .any(|t| t.text.contains("// This is a comment")));
    }

    #[test]
    fn test_number_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let line = "int x = 42; double y = 3.14;";
        let tokens = highlighter.highlight_line(line, "c");

        // Should have number tokens
        let number_tokens: Vec<_> = tokens
            .iter()
            .filter(|t| t.token_type == TokenType::Number)
            .collect();

        assert!(!number_tokens.is_empty());
        assert!(number_tokens.iter().any(|t| t.text == "42"));
        assert!(number_tokens.iter().any(|t| t.text == "3.14"));
    }
}
