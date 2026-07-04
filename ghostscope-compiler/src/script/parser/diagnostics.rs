// Best-effort heuristic: if a line contains a print statement with an opening quote
// but no closing quote before arguments, give a clearer error.
pub(super) fn detect_unclosed_print_string(input: &str) -> Option<String> {
    for (i, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim_start();
        if !line.contains("print ") && !line.starts_with("print") {
            continue;
        }
        // Toggle on '"' to detect unclosed string; ignore escaped quotes for simplicity
        let mut open = false;
        for ch in line.chars() {
            if ch == '"' {
                open = !open;
            }
        }
        if open {
            // Common case: missing closing quote before comma and arguments
            if line.contains(',') {
                return Some(format!(
                    "Unclosed string literal in print at line {}. Did you forget a closing \"\" before ',' and arguments?",
                    i + 1
                ));
            } else {
                return Some(format!(
                    "Unclosed string literal in print at line {}.",
                    i + 1
                ));
            }
        }
    }
    None
}

pub(super) fn detect_backtrace_depth_argument(input: &str) -> Option<String> {
    fn boundary_before(line: &str, idx: usize) -> bool {
        idx == 0
            || line[..idx]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_whitespace() || matches!(ch, '{' | ';' | '}'))
    }

    for (line_idx, raw_line) in input.lines().enumerate() {
        let line = raw_line.split("//").next().unwrap_or(raw_line);
        for command in ["bt", "backtrace"] {
            for (idx, _) in line.match_indices(command) {
                if !boundary_before(line, idx) {
                    continue;
                }
                let after = &line[idx + command.len()..];
                if !after.starts_with(char::is_whitespace) {
                    continue;
                }
                let arg = after.trim_start();
                if arg.starts_with("depth")
                    || arg.chars().next().is_some_and(|ch| ch.is_ascii_digit())
                {
                    return Some(format!(
                        "bt depth is no longer a script option at line {}. Set the global limit with --backtrace-depth <N> or [ebpf] backtrace_depth = N.",
                        line_idx + 1
                    ));
                }
            }
        }
    }
    None
}

// Try to detect lines that start with an unknown/misspelled keyword and suggest known ones.
pub(super) fn detect_unknown_keyword(input: &str) -> Option<String> {
    // Suggest only currently supported top-level keywords.
    const SUGGEST: &[&str] = &["trace", "print", "if", "else", "let"];
    // Valid statement starters that should not be flagged as unknown
    const SUPPORTED_HEADS: &[&str] = &["trace", "print", "if", "else", "let", "backtrace", "bt"];
    // Builtin call names allowed at expression head
    const BUILTIN_CALLS: &[&str] = &["memcmp", "strncmp", "starts_with", "hex", "cast"];

    // Helper: simple Levenshtein distance (small strings, few keywords)
    fn levenshtein(a: &str, b: &str) -> usize {
        let (n, m) = (a.len(), b.len());
        let mut dp = vec![0usize; (n + 1) * (m + 1)];
        let idx = |i: usize, j: usize| i * (m + 1) + j;
        for i in 0..=n {
            dp[idx(i, 0)] = i;
        }
        for j in 0..=m {
            dp[idx(0, j)] = j;
        }
        let ac: Vec<char> = a.chars().collect();
        let bc: Vec<char> = b.chars().collect();
        for i in 1..=n {
            for j in 1..=m {
                let cost = if ac[i - 1] == bc[j - 1] { 0 } else { 1 };
                let del = dp[idx(i - 1, j)] + 1;
                let ins = dp[idx(i, j - 1)] + 1;
                let sub = dp[idx(i - 1, j - 1)] + cost;
                dp[idx(i, j)] = del.min(ins).min(sub);
            }
        }
        dp[idx(n, m)]
    }

    // Helper: check a slice for a command-like unknown keyword
    fn check_slice(slice: &str, line_no_1based: usize) -> Option<String> {
        let mut s = slice.trim_start();
        if s.is_empty() || s.starts_with("//") {
            return None;
        }

        // If this slice begins with an if/else-if header, jump inside the condition
        if let Some(rest) = s.strip_prefix("if") {
            if rest.starts_with(char::is_whitespace) {
                s = rest.trim_start();
            }
        } else if let Some(rest) = s.strip_prefix("else") {
            let rest = rest.trim_start();
            if let Some(rest2) = rest.strip_prefix("if") {
                if rest2.starts_with(char::is_whitespace) {
                    s = rest2.trim_start();
                }
            } else {
                // 'else { ... }' — nothing to inspect here
            }
        }
        // Keywords must start with a letter or underscore; skip numeric heads
        let mut iter = s.chars();
        let first = iter.next()?;
        if !(first.is_ascii_alphabetic() || first == '_') {
            return None;
        }
        let mut token = String::new();
        token.push(first);
        for ch in iter {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                token.push(ch);
            } else {
                break;
            }
        }
        if token.is_empty() {
            return None;
        }
        if SUPPORTED_HEADS.iter().any(|k| *k == token) {
            return None;
        }
        let rest_untrimmed = &s[token.len()..];
        let rest = rest_untrimmed.trim_start();
        if rest.starts_with('=') || rest.starts_with('[') || rest.starts_with('.') {
            // likely an expression starting with identifier
            return None;
        }
        // Allow builtin calls as expression statements
        if BUILTIN_CALLS.iter().any(|k| *k == token) && rest.starts_with('(') {
            return None;
        }
        if rest.starts_with('(')
            || rest.starts_with('{')
            || rest.starts_with('"')
            || rest_untrimmed.starts_with(char::is_whitespace)
        {
            // If it looks like a call (token + '('), include builtin calls in suggestion candidates
            let candidates: Vec<&str> = if rest.starts_with('(') {
                let mut v = Vec::new();
                v.extend_from_slice(SUGGEST);
                v.extend_from_slice(BUILTIN_CALLS);
                v
            } else {
                SUGGEST.to_vec()
            };
            let mut suggestions: Vec<(&str, usize)> = candidates
                .iter()
                .map(|&k| (k, levenshtein(&token, k)))
                .collect();
            suggestions.sort_by_key(|&(_, d)| d);
            if let Some((cand, dist)) = suggestions.first().copied() {
                if dist <= 2 {
                    return Some(format!(
                        "Unknown keyword '{token}' at line {line_no_1based}. Did you mean '{cand}'?"
                    ));
                }
            }
            return Some(format!(
                "Unknown keyword '{token}' at line {}. Expected one of: {}",
                line_no_1based,
                SUGGEST.join(", ")
            ));
        }
        None
    }

    for (i, raw_line) in input.lines().enumerate() {
        let line = raw_line;
        // Scan potential statement starts: at line start, and right after '{', ';', '}', '(', ',' (outside strings)
        let mut quote_open = false;
        let mut positions: Vec<usize> = vec![0]; // include start-of-line
        for (idx, ch) in line.char_indices() {
            if ch == '"' {
                quote_open = !quote_open;
            }
            if !quote_open && (ch == '{' || ch == ';' || ch == '}' || ch == '(' || ch == ',') {
                let next = idx + ch.len_utf8();
                if next < line.len() {
                    positions.push(next);
                }
            }
        }
        for &pos in &positions {
            if let Some(msg) = check_slice(&line[pos..], i + 1) {
                return Some(msg);
            }
        }
    }
    None
}
