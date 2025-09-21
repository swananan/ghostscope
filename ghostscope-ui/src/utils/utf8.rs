use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// UTF-8 handling utilities
pub struct UTF8Utils;

impl UTF8Utils {
    /// Convert character position to byte position in a UTF-8 string
    pub fn char_pos_to_byte_pos(text: &str, char_pos: usize) -> usize {
        text.char_indices()
            .nth(char_pos)
            .map_or(text.len(), |(pos, _)| pos)
    }

    /// Convert byte position to character position in a UTF-8 string
    pub fn byte_pos_to_char_pos(text: &str, byte_pos: usize) -> usize {
        text[..byte_pos.min(text.len())].chars().count()
    }

    /// Get the display width of a string (handling wide characters)
    pub fn display_width(text: &str) -> usize {
        text.width()
    }

    /// Truncate string to fit within a given display width
    pub fn truncate_to_width(text: &str, max_width: usize) -> String {
        let mut width = 0;
        let mut result = String::new();

        for ch in text.chars() {
            let ch_width = ch.width().unwrap_or(0);
            if width + ch_width > max_width {
                break;
            }
            width += ch_width;
            result.push(ch);
        }

        result
    }

    /// Split text at character boundaries, not byte boundaries
    pub fn split_at_char_boundary(text: &str, char_index: usize) -> (&str, &str) {
        let byte_index = Self::char_pos_to_byte_pos(text, char_index);
        text.split_at(byte_index)
    }

    /// Check if a byte position is at a character boundary
    pub fn is_char_boundary(text: &str, byte_pos: usize) -> bool {
        text.is_char_boundary(byte_pos)
    }

    /// Find the next character boundary after a given byte position
    pub fn next_char_boundary(text: &str, byte_pos: usize) -> usize {
        let mut pos = byte_pos;
        while pos < text.len() && !text.is_char_boundary(pos) {
            pos += 1;
        }
        pos
    }

    /// Find the previous character boundary before a given byte position
    pub fn prev_char_boundary(text: &str, byte_pos: usize) -> usize {
        let mut pos = byte_pos;
        while pos > 0 && !text.is_char_boundary(pos) {
            pos -= 1;
        }
        pos
    }

    /// Count characters in a string (not bytes)
    pub fn char_count(text: &str) -> usize {
        text.chars().count()
    }

    /// Get the nth character from a string
    pub fn nth_char(text: &str, n: usize) -> Option<char> {
        text.chars().nth(n)
    }

    /// Pad string to a specific display width with spaces
    pub fn pad_to_width(text: &str, width: usize) -> String {
        let current_width = Self::display_width(text);
        if current_width >= width {
            text.to_string()
        } else {
            format!("{}{}", text, " ".repeat(width - current_width))
        }
    }

    /// Check if a character is a word boundary
    pub fn is_word_boundary(ch: char) -> bool {
        ch.is_whitespace() || ch.is_ascii_punctuation()
    }

    /// Find the start of the current word at cursor position
    pub fn find_word_start(text: &str, cursor_pos: usize) -> usize {
        if cursor_pos == 0 {
            return 0;
        }

        let chars: Vec<char> = text.chars().collect();
        let mut pos = cursor_pos.saturating_sub(1);

        // Skip current character if it's a word boundary
        while pos > 0 && Self::is_word_boundary(chars[pos]) {
            pos -= 1;
        }

        // Find the start of the word
        while pos > 0 && !Self::is_word_boundary(chars[pos - 1]) {
            pos -= 1;
        }

        pos
    }

    /// Find the end of the current word at cursor position
    pub fn find_word_end(text: &str, cursor_pos: usize) -> usize {
        let chars: Vec<char> = text.chars().collect();
        let mut pos = cursor_pos;

        if pos >= chars.len() {
            return chars.len();
        }

        // Skip current character if it's a word boundary
        while pos < chars.len() && Self::is_word_boundary(chars[pos]) {
            pos += 1;
        }

        // Find the end of the word
        while pos < chars.len() && !Self::is_word_boundary(chars[pos]) {
            pos += 1;
        }

        pos
    }
}
