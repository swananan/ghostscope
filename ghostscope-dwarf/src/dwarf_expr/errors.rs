//! DWARF expression error policy helpers.

use crate::{
    core::Result,
    dwarf_expr::modes::{DwarfExprMode, ErrorPolicy},
};
use tracing::debug;

pub(crate) fn hard<T>(mode: DwarfExprMode, result: Result<T>) -> Result<T> {
    debug_assert_eq!(mode.error_policy(), ErrorPolicy::Hard);
    result
}

pub(crate) fn soft_value<T>(mode: DwarfExprMode, result: Result<T>) -> Option<T> {
    debug_assert_eq!(mode.error_policy(), ErrorPolicy::SoftWithFallback);
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            debug!(
                mode = mode.label(),
                error = %error,
                "DWARF expression parse failed; trying fallback"
            );
            None
        }
    }
}

pub(crate) fn soft_optional<T>(mode: DwarfExprMode, result: Result<Option<T>>) -> Option<T> {
    debug_assert_eq!(mode.error_policy(), ErrorPolicy::SoftWithFallback);
    soft_value(mode, result).flatten()
}

pub(crate) fn silent_false(mode: DwarfExprMode, result: Result<bool>) -> bool {
    debug_assert_eq!(mode.error_policy(), ErrorPolicy::SilentFalse);
    match result {
        Ok(value) => value,
        Err(error) => {
            debug!(
                mode = mode.label(),
                error = %error,
                "DWARF expression scan failed; treating result as false"
            );
            false
        }
    }
}

pub(crate) fn downgrade_to_none<T>(
    mode: DwarfExprMode,
    result: Result<T>,
    reason: &'static str,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            debug!(
                mode = mode.label(),
                reason,
                error = %error,
                "DWARF expression error downgraded to None"
            );
            None
        }
    }
}

pub(crate) fn downgrade_optional_to_none<T>(
    mode: DwarfExprMode,
    result: Result<Option<T>>,
    reason: &'static str,
) -> Option<T> {
    downgrade_to_none(mode, result, reason).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_propagates_errors() {
        let result: Result<()> = Err(anyhow::anyhow!("boom"));
        assert!(hard(DwarfExprMode::Location, result).is_err());
    }

    #[test]
    fn soft_with_fallback_converts_errors_to_none() {
        let result: Result<u64> = Err(anyhow::anyhow!("boom"));
        assert_eq!(soft_value(DwarfExprMode::CallSiteValue, result), None);
    }

    #[test]
    fn silent_false_converts_errors_to_false() {
        let result: Result<bool> = Err(anyhow::anyhow!("boom"));
        assert!(!silent_false(DwarfExprMode::ScanOnly, result));
    }

    #[test]
    fn explicit_downgrade_converts_errors_to_none() {
        let result: Result<u64> = Err(anyhow::anyhow!("boom"));
        assert_eq!(
            downgrade_to_none(DwarfExprMode::ConstOffset, result, "test downgrade"),
            None
        );
    }
}
