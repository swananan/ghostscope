//! CLI module - handles command line interface and non-TUI mode runtime

mod color;
mod docs;
mod loading_reporter;
pub mod script_output;
pub mod script_runtime;

use crate::config::BpffsPruneArgs;
use anyhow::Result;
use ghostscope_process::pinned_bpf_maps::{
    self, BpffsPruneMode, BpffsPruneOptions, BpffsPruneReport, BpffsPruneStatus,
};
use serde::Serialize;

#[derive(Serialize)]
struct JsonPruneReport {
    root: String,
    dry_run: bool,
    mode: &'static str,
    results: Vec<JsonPruneEntry>,
}

#[derive(Serialize)]
struct JsonPruneEntry {
    directory: String,
    status: &'static str,
    reason: String,
}

pub fn run_bpffs_prune(args: &BpffsPruneArgs) -> Result<()> {
    args.validate()?;
    crate::util::ensure_privileges();

    let report = pinned_bpf_maps::prune_pinned_maps_root(&BpffsPruneOptions {
        mode: prune_mode(args),
        dry_run: args.dry_run,
    })?;

    if args.json {
        print_json_report(args, &report)?;
    } else {
        print_human_report(args, &report);
    }

    Ok(())
}

fn prune_mode(args: &BpffsPruneArgs) -> BpffsPruneMode {
    if let Some(instance) = &args.instance {
        BpffsPruneMode::Instance(instance.clone())
    } else if args.all {
        BpffsPruneMode::All
    } else {
        BpffsPruneMode::Stale
    }
}

fn mode_label(args: &BpffsPruneArgs) -> &'static str {
    if args.instance.is_some() {
        "instance"
    } else if args.all {
        "all"
    } else {
        "stale"
    }
}

fn status_label(status: BpffsPruneStatus) -> &'static str {
    match status {
        BpffsPruneStatus::RemoveDir => "remove_dir",
        BpffsPruneStatus::CleanKnownPins => "clean_known_pins",
        BpffsPruneStatus::SkipLive => "skip_live",
        BpffsPruneStatus::Ignore => "ignore",
    }
}

fn print_json_report(args: &BpffsPruneArgs, report: &BpffsPruneReport) -> Result<()> {
    let json = JsonPruneReport {
        root: report.root.display().to_string(),
        dry_run: report.dry_run,
        mode: mode_label(args),
        results: report
            .entries
            .iter()
            .map(|entry| JsonPruneEntry {
                directory: entry.directory.clone(),
                status: status_label(entry.status),
                reason: entry.reason.clone(),
            })
            .collect(),
    };

    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn print_human_report(args: &BpffsPruneArgs, report: &BpffsPruneReport) {
    let remove_count = report
        .entries
        .iter()
        .filter(|entry| entry.status == BpffsPruneStatus::RemoveDir)
        .count();
    let clean_count = report
        .entries
        .iter()
        .filter(|entry| entry.status == BpffsPruneStatus::CleanKnownPins)
        .count();
    let skip_count = report
        .entries
        .iter()
        .filter(|entry| entry.status == BpffsPruneStatus::SkipLive)
        .count();
    let ignore_count = report
        .entries
        .iter()
        .filter(|entry| entry.status == BpffsPruneStatus::Ignore)
        .count();

    let action_prefix = if args.dry_run {
        "Would prune"
    } else {
        "Pruned"
    };
    let processed = remove_count + clean_count;
    if processed == 0 {
        println!(
            "No GhostScope bpffs pin directories matched prune mode '{}' under {}",
            mode_label(args),
            report.root.display()
        );
    } else {
        println!(
            "{action_prefix} {processed} GhostScope bpffs pin director{} under {}",
            if processed == 1 { "y" } else { "ies" },
            report.root.display()
        );
    }

    if remove_count > 0 {
        println!(
            "{} {} director{} fully removed",
            if args.dry_run {
                "  would remove"
            } else {
                "  removed"
            },
            remove_count,
            if remove_count == 1 { "y" } else { "ies" }
        );
    }
    if clean_count > 0 {
        println!(
            "{} {} director{} but retain non-GhostScope entries",
            if args.dry_run {
                "  would clean known pins in"
            } else {
                "  cleaned known pins in"
            },
            clean_count,
            if clean_count == 1 { "y" } else { "ies" }
        );
    }
    if skip_count > 0 {
        println!(
            "  skipped {} live director{}",
            skip_count,
            if skip_count == 1 { "y" } else { "ies" }
        );
    }
    if ignore_count > 0 {
        println!(
            "  ignored {} non-matching director{}",
            ignore_count,
            if ignore_count == 1 { "y" } else { "ies" }
        );
    }

    for entry in report
        .entries
        .iter()
        .filter(|entry| entry.status != BpffsPruneStatus::Ignore)
    {
        println!(
            "  {:<18} {} ({})",
            status_label(entry.status),
            entry.directory,
            entry.reason
        );
    }
}

// Re-export main functions for convenience
pub use docs::print_script_help;
pub use script_runtime::run_command_line_runtime_with_config;
