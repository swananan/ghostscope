//! Version 1 of the script event JSONL contract. Keep these DTOs independent
//! of UI/protocol serde representations so internal refactors do not change it.

use crate::trace::snapshot::TraceSnapshot;
use ghostscope_protocol::{
    trace_event::backtrace_error_label, trace_event::BacktraceStatus, ValueDiagnostic,
};
use ghostscope_ui::{BacktraceDisplayFrame, TraceDisplayItem, UiTraceEvent};
use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
struct Event<'a> {
    schema_version: u32,
    event: &'static str,
    timestamp_ns: u64,
    trace_id: u64,
    pid: u32,
    tid: u32,
    execution_status: Option<u8>,
    trace: Option<Trace<'a>>,
    value_diagnostics: Vec<Diagnostic<'a>>,
    items: Vec<Item<'a>>,
}

#[derive(Serialize)]
struct Trace<'a> {
    target: &'a str,
    target_display: &'a str,
    binary_path: &'a str,
}

#[derive(Serialize)]
struct Diagnostic<'a> {
    scope: &'static str,
    path: &'a str,
    type_name: &'a str,
    reason: &'static str,
    detail: &'a str,
}

impl<'a> From<&'a ValueDiagnostic> for Diagnostic<'a> {
    fn from(diagnostic: &'a ValueDiagnostic) -> Self {
        Self {
            scope: "static",
            path: &diagnostic.path,
            type_name: &diagnostic.type_name,
            reason: diagnostic.reason.code(),
            detail: &diagnostic.detail,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Item<'a> {
    Text {
        content: &'a str,
    },
    FormattedText {
        content: &'a str,
    },
    Variable {
        name: &'a str,
        type_name: &'a str,
        formatted_value: &'a str,
    },
    ComplexVariable {
        name: &'a str,
        access_path: &'a str,
        type_index: u16,
        formatted_value: &'a str,
    },
    ExprError {
        expr: &'a str,
        error_code: u8,
        flags: u8,
        failing_addr: u64,
    },
    Backtrace {
        requested_depth: u8,
        physical_frame_count: usize,
        status: &'static str,
        status_code: u8,
        error_code: u16,
        error_reason: Option<&'static str>,
        raw: bool,
        frames: Vec<Frame<'a>>,
    },
}

impl<'a> From<&'a TraceDisplayItem> for Item<'a> {
    fn from(item: &'a TraceDisplayItem) -> Self {
        match item {
            TraceDisplayItem::Text { content } => Self::Text { content },
            TraceDisplayItem::FormattedText { content } => Self::FormattedText { content },
            TraceDisplayItem::Variable(value) => Self::Variable {
                name: &value.name,
                type_name: &value.type_name,
                formatted_value: &value.formatted_value,
            },
            TraceDisplayItem::ComplexVariable(value) => Self::ComplexVariable {
                name: &value.name,
                access_path: &value.access_path,
                type_index: value.type_index,
                formatted_value: &value.formatted_value,
            },
            TraceDisplayItem::ExprError(error) => Self::ExprError {
                expr: &error.expr,
                error_code: error.error_code,
                flags: error.flags,
                failing_addr: error.failing_addr,
            },
            TraceDisplayItem::Backtrace(backtrace) => Self::Backtrace {
                requested_depth: backtrace.requested_depth,
                physical_frame_count: backtrace.physical_frame_count,
                status: status_name(backtrace.status),
                status_code: backtrace.status as u8,
                error_code: backtrace.error_code,
                error_reason: backtrace_error_label(backtrace.error_code),
                raw: backtrace.raw,
                frames: backtrace.frames.iter().map(Frame::from).collect(),
            },
        }
    }
}

fn status_name(status: BacktraceStatus) -> &'static str {
    match status {
        BacktraceStatus::Complete => "complete",
        BacktraceStatus::Truncated => "truncated",
        BacktraceStatus::DwarfUnavailable => "dwarf_unavailable",
        BacktraceStatus::UnsupportedCfi => "unsupported_cfi",
        BacktraceStatus::OffsetsUnavailable => "offsets_unavailable",
        BacktraceStatus::ReadError => "read_error",
        BacktraceStatus::InternalError => "internal_error",
        BacktraceStatus::InvalidFrame => "invalid_frame",
        BacktraceStatus::NoUnwindRowsForPc => "no_unwind_rows_for_pc",
    }
}

#[derive(Serialize)]
struct Frame<'a> {
    index: usize,
    inline: bool,
    function: Option<&'a str>,
    parameters: &'a [String],
    address: Option<&'a str>,
    location: Option<&'a str>,
    module: &'a str,
    raw_ip: Option<u64>,
    cookie: Option<u64>,
    flags: Option<u16>,
}

impl<'a> From<&'a BacktraceDisplayFrame> for Frame<'a> {
    fn from(frame: &'a BacktraceDisplayFrame) -> Self {
        Self {
            index: frame.index,
            inline: frame.inline,
            function: frame.function.as_deref(),
            parameters: &frame.parameters,
            address: frame.address.as_deref(),
            location: frame.location.as_deref(),
            module: &frame.module,
            raw_ip: frame.raw_ip,
            cookie: frame.cookie,
            flags: frame.flags,
        }
    }
}

pub(super) fn write_event<W: Write>(
    event: &UiTraceEvent,
    trace: Option<&TraceSnapshot>,
    writer: &mut W,
) -> io::Result<()> {
    let record = Event {
        schema_version: 1,
        event: "trace",
        timestamp_ns: event.timestamp,
        trace_id: event.trace_id,
        pid: event.pid,
        tid: event.tid,
        execution_status: event.execution_status,
        trace: trace.map(|trace| Trace {
            target: &trace.target,
            target_display: &trace.target_display,
            binary_path: &trace.binary_path,
        }),
        value_diagnostics: trace
            .into_iter()
            .flat_map(|trace| &trace.value_diagnostics)
            .map(Diagnostic::from)
            .collect(),
        items: event.items.iter().map(Item::from).collect(),
    };
    serde_json::to_writer(&mut *writer, &record).map_err(|error| match error.io_error_kind() {
        Some(kind) => io::Error::new(kind, error),
        None => io::Error::other(error),
    })?;
    writer.write_all(b"\n")
}
