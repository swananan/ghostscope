pub const SCRIPT_HELP: &str = include_str!("scripting.md");

pub fn print_script_help() {
    print!("{SCRIPT_HELP}");
}
