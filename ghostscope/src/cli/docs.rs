pub const SCRIPT_HELP: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/scripting.md"));

pub fn print_script_help() {
    print!("{SCRIPT_HELP}");
}
