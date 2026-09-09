pub const SCRIPT_HELP: &str = include_str!("scripting.md");
pub const VALUE_DIAGNOSTICS_HELP: &str = include_str!("value-diagnostics.md");

pub fn print_script_help() {
    print!("{SCRIPT_HELP}");
}

pub fn print_value_diagnostics_help() {
    print!("{VALUE_DIAGNOSTICS_HELP}");
}
