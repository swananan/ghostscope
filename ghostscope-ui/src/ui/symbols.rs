/// Centralized UI symbols and icons with ASCII fallbacks
pub struct UISymbols;

impl UISymbols {
    // File type icons
    pub const FILE_FOLDER: &'static str = "📁";
    pub const FILE_FOLDER_ASCII: &'static str = "[DIR]";

    pub const FILE_PACKAGE: &'static str = "📦";
    pub const FILE_PACKAGE_ASCII: &'static str = "[PKG]";

    pub const FILE_HEADER: &'static str = "📑";
    pub const FILE_HEADER_ASCII: &'static str = "[H]";

    pub const FILE_SOURCE: &'static str = "📝";
    pub const FILE_SOURCE_ASCII: &'static str = "[C]";

    pub const FILE_RUST: &'static str = "🦀";
    pub const FILE_RUST_ASCII: &'static str = "[RS]";

    pub const FILE_ASM: &'static str = "🛠️";
    pub const FILE_ASM_ASCII: &'static str = "[ASM]";

    pub const FILE_GENERIC: &'static str = "📄";
    pub const FILE_GENERIC_ASCII: &'static str = "[FILE]";

    // Status icons
    pub const STATUS_ACTIVE: &'static str = "✅";
    pub const STATUS_ACTIVE_ASCII: &'static str = "[ON]";

    pub const STATUS_DISABLED: &'static str = "⏸️";
    pub const STATUS_DISABLED_ASCII: &'static str = "[OFF]";

    pub const STATUS_FAILED: &'static str = "❌";
    pub const STATUS_FAILED_ASCII: &'static str = "[FAIL]";

    pub const STATUS_YES: &'static str = "✅ Yes";
    pub const STATUS_YES_ASCII: &'static str = "[YES]";

    pub const STATUS_NO: &'static str = "❌ No ";
    pub const STATUS_NO_ASCII: &'static str = "[NO]";

    // Navigation symbols
    pub const NAV_TREE_BRANCH: &'static str = "├─";
    pub const NAV_TREE_BRANCH_ASCII: &'static str = "+-";

    pub const NAV_TREE_LAST: &'static str = "└─";
    pub const NAV_TREE_LAST_ASCII: &'static str = "\\-";

    pub const NAV_TREE_VERTICAL: &'static str = "│";
    pub const NAV_TREE_VERTICAL_ASCII: &'static str = "|";

    pub const NAV_TREE_SPACE: &'static str = "  ";

    // UI borders
    pub const BORDER_HORIZONTAL: &'static str = "─";
    pub const BORDER_HORIZONTAL_ASCII: &'static str = "-";

    // Progress and status
    pub const STATS_ICON: &'static str = "📊";
    pub const STATS_ICON_ASCII: &'static str = "[STATS]";

    pub const LIBRARY_ICON: &'static str = "📚";
    pub const LIBRARY_ICON_ASCII: &'static str = "[LIBS]";

    // Helper methods for getting symbols with fallback
    pub fn get_file_icon(extension: &str, use_ascii: bool) -> &'static str {
        if use_ascii {
            match extension {
                "h" | "hpp" | "hh" | "hxx" => Self::FILE_HEADER_ASCII,
                "c" | "cc" | "cpp" | "cxx" => Self::FILE_SOURCE_ASCII,
                "rs" => Self::FILE_RUST_ASCII,
                "s" | "asm" => Self::FILE_ASM_ASCII,
                _ => Self::FILE_GENERIC_ASCII,
            }
        } else {
            match extension {
                "h" | "hpp" | "hh" | "hxx" => Self::FILE_HEADER,
                "c" | "cc" | "cpp" | "cxx" => Self::FILE_SOURCE,
                "rs" => Self::FILE_RUST,
                "s" | "asm" => Self::FILE_ASM,
                _ => Self::FILE_GENERIC,
            }
        }
    }

    pub fn get_status_icon(active: bool, use_ascii: bool) -> &'static str {
        if use_ascii {
            if active {
                Self::STATUS_ACTIVE_ASCII
            } else {
                Self::STATUS_DISABLED_ASCII
            }
        } else {
            if active {
                Self::STATUS_ACTIVE
            } else {
                Self::STATUS_DISABLED
            }
        }
    }

    pub fn get_yes_no_icon(yes: bool, use_ascii: bool) -> &'static str {
        if use_ascii {
            if yes {
                Self::STATUS_YES_ASCII
            } else {
                Self::STATUS_NO_ASCII
            }
        } else {
            if yes {
                Self::STATUS_YES
            } else {
                Self::STATUS_NO
            }
        }
    }
}
