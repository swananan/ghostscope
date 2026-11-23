/// Split a target from optional command arguments, preserving quoted function names.
/// Quotes remain in the target so it can be passed directly to the script parser.
pub(crate) fn split_target_argument(input: &str) -> (&str, &str) {
    let input = input.trim();
    let mut quoted = false;
    for (index, ch) in input.char_indices() {
        if ch == '"' {
            quoted = !quoted;
        } else if ch.is_whitespace() && !quoted {
            return (&input[..index], input[index..].trim());
        }
    }
    (input, "")
}
