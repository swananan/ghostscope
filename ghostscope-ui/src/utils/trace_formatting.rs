//! Trace event formatting utilities

use std::time::{SystemTime, UNIX_EPOCH};

/// Format eBPF timestamp (nanoseconds since boot) to human-readable format
pub fn format_timestamp_ns(ns_timestamp: u64) -> String {
    // Get current system time and boot time
    let now = SystemTime::now();
    let uptime = get_system_uptime_ns();

    if let (Ok(now_since_epoch), Some(boot_ns)) = (now.duration_since(UNIX_EPOCH), uptime) {
        // Calculate when the system booted
        let boot_time_ns = now_since_epoch.as_nanos() as u64 - boot_ns;

        // Add eBPF timestamp to boot time to get actual time
        let actual_time_ns = boot_time_ns + ns_timestamp;
        let actual_time_secs = actual_time_ns / 1_000_000_000;
        let actual_time_nanos = actual_time_ns % 1_000_000_000;

        // Convert to chrono DateTime with local timezone
        if let Some(utc_datetime) =
            chrono::DateTime::from_timestamp(actual_time_secs as i64, actual_time_nanos as u32)
        {
            let local_datetime: chrono::DateTime<chrono::Local> = utc_datetime.into();
            return format!(
                "{}.{:03}",
                local_datetime.format("%Y-%m-%d %H:%M:%S"),
                actual_time_nanos / 1_000_000
            );
        }
    }

    // Fallback to boot time offset if conversion fails
    let ms = ns_timestamp / 1_000_000;
    let seconds = ms / 1000;
    let ms_remainder = ms % 1000;
    format!("boot+{seconds}.{ms_remainder:03}s")
}

/// Get system uptime in nanoseconds
fn get_system_uptime_ns() -> Option<u64> {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|content| {
            let uptime_secs: f64 = content.split_whitespace().next()?.parse().ok()?;
            Some((uptime_secs * 1_000_000_000.0) as u64)
        })
}
