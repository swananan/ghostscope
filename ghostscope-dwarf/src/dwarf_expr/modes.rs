//! DWARF expression lowering modes and their error policies.

/// The consumer-specific context for DWARF expression parsing/lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DwarfExprMode {
    /// Normal DWARF location expressions used to recover variable values.
    Location,
    /// Caller-side call-site values used as an optional entry-value source.
    CallSiteValue,
    /// Lightweight scans that only answer a yes/no question.
    ScanOnly,
    /// CFI/CFA expressions used while recovering caller frames.
    Cfa,
    /// Constant-only expressions used for member offsets.
    ConstOffset,
    /// Optional global/static storage-address discovery while indexing.
    StorageAddress,
}

/// How parse/lowering errors should be surfaced for a mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorPolicy {
    /// Propagate the error to the caller.
    Hard,
    /// Treat errors as "not usable" so a caller-owned fallback can run.
    SoftWithFallback,
    /// Treat errors as `false` for best-effort presence scans.
    SilentFalse,
}

impl DwarfExprMode {
    pub(crate) const fn error_policy(self) -> ErrorPolicy {
        match self {
            Self::Location | Self::Cfa | Self::ConstOffset => ErrorPolicy::Hard,
            Self::CallSiteValue | Self::StorageAddress => ErrorPolicy::SoftWithFallback,
            Self::ScanOnly => ErrorPolicy::SilentFalse,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Location => "location",
            Self::CallSiteValue => "call-site value",
            Self::ScanOnly => "scan-only",
            Self::Cfa => "CFA",
            Self::ConstOffset => "const offset",
            Self::StorageAddress => "storage address",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DwarfExprMode, ErrorPolicy};

    #[test]
    fn mode_error_policies_are_explicit() {
        assert_eq!(DwarfExprMode::Location.error_policy(), ErrorPolicy::Hard);
        assert_eq!(DwarfExprMode::Cfa.error_policy(), ErrorPolicy::Hard);
        assert_eq!(DwarfExprMode::ConstOffset.error_policy(), ErrorPolicy::Hard);
        assert_eq!(
            DwarfExprMode::CallSiteValue.error_policy(),
            ErrorPolicy::SoftWithFallback
        );
        assert_eq!(
            DwarfExprMode::StorageAddress.error_policy(),
            ErrorPolicy::SoftWithFallback
        );
        assert_eq!(
            DwarfExprMode::ScanOnly.error_policy(),
            ErrorPolicy::SilentFalse
        );
    }
}
