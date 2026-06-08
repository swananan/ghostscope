use ghostscope_dwarf::{DwarfAnalyzer, FunctionParameter, ModuleAddress, PcContext};
use ghostscope_process::{PidOffsetsEntry, ProcessManager};
#[cfg(test)]
use ghostscope_protocol::trace_event::backtrace_error_label;
use ghostscope_protocol::trace_event::{
    BacktraceStatus, BACKTRACE_FLAG_INLINE, BACKTRACE_FLAG_RAW,
};
use ghostscope_protocol::{ParsedBacktraceFrame, ParsedInstruction, ParsedTraceEvent};
use ghostscope_ui::{BacktraceDisplay, BacktraceDisplayFrame, TraceDisplayItem, UiTraceEvent};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::hash::Hash;
use std::path::{Path, PathBuf};

const FRAME_RENDER_CACHE_MAX_ENTRIES: usize = 16_384;
const STATUS_CACHE_MAX_ENTRIES: usize = 4_096;

#[derive(Clone, Copy)]
struct ResolvedFrameModule<'a> {
    entry: &'a PidOffsetsEntry,
    pc: u64,
}

#[derive(Debug)]
pub struct BacktraceRenderer {
    #[cfg(test)]
    frame_cache: SimpleCache<FrameRenderCacheKey, Vec<String>>,
    frame_display_cache: SimpleCache<FrameRenderCacheKey, Vec<BacktraceDisplayFrame>>,
    status_cache: SimpleCache<StatusCacheKey, BacktraceStatus>,
}

impl Default for BacktraceRenderer {
    fn default() -> Self {
        Self {
            #[cfg(test)]
            frame_cache: SimpleCache::new(FRAME_RENDER_CACHE_MAX_ENTRIES),
            frame_display_cache: SimpleCache::new(FRAME_RENDER_CACHE_MAX_ENTRIES),
            status_cache: SimpleCache::new(STATUS_CACHE_MAX_ENTRIES),
        }
    }
}

#[derive(Debug)]
struct SimpleCache<K, V> {
    entries: HashMap<K, V>,
    insertion_order: VecDeque<K>,
    max_entries: usize,
}

impl<K, V> SimpleCache<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            max_entries,
        }
    }

    fn get(&self, key: &K) -> Option<V> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: K, value: V) {
        if self.max_entries == 0 {
            return;
        }
        if self.entries.insert(key.clone(), value).is_some() {
            return;
        }

        self.insertion_order.push_back(key);
        while self.entries.len() > self.max_entries {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PidCacheKey {
    first: u32,
    second: u32,
    len: u8,
}

impl PidCacheKey {
    fn from_pids(pids: &[u32]) -> Self {
        Self {
            first: pids.first().copied().unwrap_or_default(),
            second: pids.get(1).copied().unwrap_or_default(),
            len: pids.len().min(2) as u8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FrameRenderCacheKey {
    pids: PidCacheKey,
    analyzer_present: bool,
    index: u16,
    flags: u8,
    module_cookie: u64,
    pc: u64,
    raw_ip: u64,
    frame_flags: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StatusCacheKey {
    pids: PidCacheKey,
    analyzer_present: bool,
    module_cookie: u64,
    pc: u64,
    raw_ip: u64,
    frame_flags: u16,
    status: u8,
    error_code: u16,
}

impl BacktraceRenderer {
    pub fn render_event_for_tui(
        &mut self,
        event: &ParsedTraceEvent,
        analyzer: Option<&DwarfAnalyzer>,
        coordinator: &ProcessManager,
        proc_pid_hint: Option<u32>,
    ) -> UiTraceEvent {
        let mut items = Vec::new();
        let mut text_chunk = Vec::new();

        for instruction in &event.instructions {
            match instruction {
                ParsedInstruction::Backtrace { .. } => {
                    flush_text_chunk(event, &mut text_chunk, &mut items);
                    let backtrace = self.format_backtrace_display(
                        instruction,
                        event.pid,
                        analyzer,
                        coordinator,
                        proc_pid_hint,
                    );
                    items.push(TraceDisplayItem::Backtrace(backtrace));
                }
                other => text_chunk.push(other.clone()),
            }
        }
        flush_text_chunk(event, &mut text_chunk, &mut items);

        let execution_status = event.instructions.iter().rev().find_map(|instruction| {
            if let ParsedInstruction::EndInstruction {
                execution_status, ..
            } = instruction
            {
                Some(*execution_status)
            } else {
                None
            }
        });

        UiTraceEvent {
            trace_id: event.trace_id,
            timestamp: event.timestamp,
            pid: event.pid,
            tid: event.tid,
            items,
            execution_status,
        }
    }

    #[cfg(test)]
    pub fn render_event_backtraces(
        &mut self,
        event: &ParsedTraceEvent,
        analyzer: Option<&DwarfAnalyzer>,
        coordinator: &ProcessManager,
        proc_pid_hint: Option<u32>,
    ) -> ParsedTraceEvent {
        let mut changed = false;
        let mut instructions = Vec::with_capacity(event.instructions.len());

        for instruction in &event.instructions {
            match instruction {
                ParsedInstruction::Backtrace { .. } => {
                    changed = true;
                    for line in self.format_backtrace_instruction(
                        instruction,
                        event.pid,
                        analyzer,
                        coordinator,
                        proc_pid_hint,
                    ) {
                        instructions.push(ParsedInstruction::PrintString { content: line });
                    }
                }
                other => instructions.push(other.clone()),
            }
        }

        if !changed {
            return event.clone();
        }

        ParsedTraceEvent {
            trace_id: event.trace_id,
            timestamp: event.timestamp,
            pid: event.pid,
            tid: event.tid,
            instructions,
        }
    }

    #[cfg(test)]
    fn format_backtrace_instruction(
        &mut self,
        instruction: &ParsedInstruction,
        event_pid: u32,
        analyzer: Option<&DwarfAnalyzer>,
        coordinator: &ProcessManager,
        proc_pid_hint: Option<u32>,
    ) -> Vec<String> {
        let ParsedInstruction::Backtrace {
            requested_depth,
            flags,
            status,
            error_code,
            frames,
        } = instruction
        else {
            return Vec::new();
        };

        let pids = candidate_pids(event_pid, proc_pid_hint);
        let display_status = self.display_backtrace_status(
            *status,
            *error_code,
            frames,
            analyzer,
            coordinator,
            &pids,
        );
        let mut lines = vec![format_backtrace_header(
            display_status,
            frames.len(),
            *requested_depth,
        )];

        for (index, frame) in frames.iter().enumerate() {
            lines.extend(self.format_frame(index, frame, *flags, analyzer, coordinator, &pids));
        }

        if display_status != BacktraceStatus::Complete {
            let suffix = match backtrace_error_label(*error_code) {
                Some("unknown") => format!(" (code={error_code})"),
                Some(label) => format!(" ({label}, code={error_code})"),
                None => String::new(),
            };
            lines.push(format!("stopped: {}{}", display_status.label(), suffix));
        }

        lines
    }

    fn format_backtrace_display(
        &mut self,
        instruction: &ParsedInstruction,
        event_pid: u32,
        analyzer: Option<&DwarfAnalyzer>,
        coordinator: &ProcessManager,
        proc_pid_hint: Option<u32>,
    ) -> BacktraceDisplay {
        let ParsedInstruction::Backtrace {
            requested_depth,
            flags,
            status,
            error_code,
            frames,
        } = instruction
        else {
            return BacktraceDisplay {
                requested_depth: 0,
                physical_frame_count: 0,
                status: BacktraceStatus::InternalError,
                error_code: 0,
                raw: false,
                frames: Vec::new(),
            };
        };

        let pids = candidate_pids(event_pid, proc_pid_hint);
        let display_status = self.display_backtrace_status(
            *status,
            *error_code,
            frames,
            analyzer,
            coordinator,
            &pids,
        );

        let mut display_frames = Vec::new();
        for (index, frame) in frames.iter().enumerate() {
            display_frames.extend(self.display_frame(
                index,
                frame,
                *flags,
                analyzer,
                coordinator,
                &pids,
            ));
        }

        BacktraceDisplay {
            requested_depth: *requested_depth,
            physical_frame_count: frames.len(),
            status: display_status,
            error_code: *error_code,
            raw: (*flags & BACKTRACE_FLAG_RAW) != 0,
            frames: display_frames,
        }
    }

    fn display_backtrace_status(
        &mut self,
        status: BacktraceStatus,
        error_code: u16,
        frames: &[ParsedBacktraceFrame],
        analyzer: Option<&DwarfAnalyzer>,
        coordinator: &ProcessManager,
        pids: &[u32],
    ) -> BacktraceStatus {
        if !matches!(
            status,
            BacktraceStatus::UnsupportedCfi | BacktraceStatus::NoUnwindRowsForPc
        ) {
            return status;
        }

        let Some(analyzer) = analyzer else {
            return status;
        };
        let Some(last_frame) = frames.last() else {
            return status;
        };

        let cache_key = StatusCacheKey {
            pids: PidCacheKey::from_pids(pids),
            analyzer_present: true,
            module_cookie: last_frame.module_cookie,
            pc: last_frame.pc,
            raw_ip: last_frame.raw_ip,
            frame_flags: last_frame.flags,
            status: status as u8,
            error_code,
        };
        if let Some(cached) = self.status_cache.get(&cache_key) {
            return cached;
        }

        let Some(module) = resolve_frame_module(coordinator, pids, last_frame) else {
            self.status_cache.insert(cache_key, status);
            return status;
        };

        let display_status =
            if is_process_entry_frame(analyzer, module.entry.module_path.as_ref(), module.pc) {
                BacktraceStatus::Complete
            } else {
                status
            };
        self.status_cache.insert(cache_key, display_status);
        display_status
    }

    #[cfg(test)]
    fn format_frame(
        &mut self,
        index: usize,
        frame: &ParsedBacktraceFrame,
        flags: u8,
        analyzer: Option<&DwarfAnalyzer>,
        coordinator: &ProcessManager,
        pids: &[u32],
    ) -> Vec<String> {
        let cache_key = FrameRenderCacheKey {
            pids: PidCacheKey::from_pids(pids),
            analyzer_present: analyzer.is_some(),
            index: index.min(u16::MAX as usize) as u16,
            flags,
            module_cookie: frame.module_cookie,
            pc: frame.pc,
            raw_ip: frame.raw_ip,
            frame_flags: frame.flags,
        };
        if let Some(cached) = self.frame_cache.get(&cache_key) {
            return cached;
        }

        let raw = (flags & BACKTRACE_FLAG_RAW) != 0;
        let inline = (flags & BACKTRACE_FLAG_INLINE) != 0;
        let module = resolve_frame_module(coordinator, pids, frame);
        let frame_pc = module.map(|module| module.pc).unwrap_or(frame.pc);

        if raw {
            let lines = vec![format_raw_frame(index, frame, module, true)];
            self.frame_cache.insert(cache_key, lines.clone());
            return lines;
        }

        let resolved = analyzer
            .and_then(|analyzer| module.map(|module| (analyzer, module)))
            .and_then(|(analyzer, module)| {
                let lookup_pc = if index == 0 {
                    module.pc
                } else {
                    module.pc.saturating_sub(1)
                };
                let address =
                    ModuleAddress::new(PathBuf::from(&module.entry.module_path), lookup_pc);
                analyzer.resolve_pc(&address).ok()
            });

        let Some(ctx) = resolved else {
            let lines = vec![format_raw_frame(index, frame, module, false)];
            self.frame_cache.insert(cache_key, lines.clone());
            return lines;
        };

        let mut lines = Vec::new();
        if inline {
            for inline_frame in &ctx.inline_chain {
                if let Some(name) = &inline_frame.function_name {
                    let location = inline_frame
                        .call_site
                        .as_ref()
                        .map(format_line_info)
                        .unwrap_or_else(|| "??".to_string());
                    lines.push(format!("  #{index}.inline {name} at {location}"));
                }
            }
        }

        let function = ctx.function_name.as_deref().unwrap_or("<unknown function>");
        let function = analyzer
            .map(|analyzer| format_function_signature(function, analyzer, &ctx))
            .unwrap_or_else(|| function.to_string());
        let location = ctx
            .line
            .as_ref()
            .map(format_line_info)
            .unwrap_or_else(|| "??".to_string());
        let module_text = module
            .map(|module| format_module_offset(&module.entry.module_path, frame_pc))
            .unwrap_or_else(|| format!("0x{:x}", frame.pc));
        lines.push(format!(
            "  #{index} {function} at {location} [{module_text}]"
        ));
        self.frame_cache.insert(cache_key, lines.clone());
        lines
    }

    fn display_frame(
        &mut self,
        index: usize,
        frame: &ParsedBacktraceFrame,
        flags: u8,
        analyzer: Option<&DwarfAnalyzer>,
        coordinator: &ProcessManager,
        pids: &[u32],
    ) -> Vec<BacktraceDisplayFrame> {
        let cache_key = FrameRenderCacheKey {
            pids: PidCacheKey::from_pids(pids),
            analyzer_present: analyzer.is_some(),
            index: index.min(u16::MAX as usize) as u16,
            flags,
            module_cookie: frame.module_cookie,
            pc: frame.pc,
            raw_ip: frame.raw_ip,
            frame_flags: frame.flags,
        };
        if let Some(cached) = self.frame_display_cache.get(&cache_key) {
            return cached;
        }

        let raw = (flags & BACKTRACE_FLAG_RAW) != 0;
        let inline = (flags & BACKTRACE_FLAG_INLINE) != 0;
        let module = resolve_frame_module(coordinator, pids, frame);
        let frame_pc = module.map(|module| module.pc).unwrap_or(frame.pc);

        if raw {
            let frames = vec![raw_display_frame(index, frame, module, true)];
            self.frame_display_cache.insert(cache_key, frames.clone());
            return frames;
        }

        let resolved = analyzer
            .and_then(|analyzer| module.map(|module| (analyzer, module)))
            .and_then(|(analyzer, module)| {
                let lookup_pc = if index == 0 {
                    module.pc
                } else {
                    module.pc.saturating_sub(1)
                };
                let address =
                    ModuleAddress::new(PathBuf::from(&module.entry.module_path), lookup_pc);
                analyzer.resolve_pc(&address).ok()
            });

        let Some(ctx) = resolved else {
            let frames = vec![raw_display_frame(index, frame, module, false)];
            self.frame_display_cache.insert(cache_key, frames.clone());
            return frames;
        };

        let module_text = module
            .map(|module| format_module_offset(&module.entry.module_path, frame_pc))
            .unwrap_or_else(|| format!("0x{:x}", frame.pc));

        let mut display_frames = Vec::new();
        if inline {
            for inline_frame in &ctx.inline_chain {
                if let Some(name) = &inline_frame.function_name {
                    display_frames.push(BacktraceDisplayFrame {
                        index,
                        inline: true,
                        function: Some(name.clone()),
                        parameters: Vec::new(),
                        address: None,
                        location: inline_frame.call_site.as_ref().map(format_line_info),
                        module: module_text.clone(),
                        raw_ip: None,
                        cookie: None,
                        flags: None,
                    });
                }
            }
        }

        display_frames.push(BacktraceDisplayFrame {
            index,
            inline: false,
            function: Some(
                ctx.function_name
                    .clone()
                    .unwrap_or_else(|| "<unknown function>".to_string()),
            ),
            parameters: analyzer
                .map(|analyzer| format_function_parameters(analyzer, &ctx))
                .unwrap_or_default(),
            address: None,
            location: ctx.line.as_ref().map(format_line_info),
            module: module_text,
            raw_ip: None,
            cookie: None,
            flags: None,
        });

        self.frame_display_cache
            .insert(cache_key, display_frames.clone());
        display_frames
    }
}

fn flush_text_chunk(
    event: &ParsedTraceEvent,
    text_chunk: &mut Vec<ParsedInstruction>,
    items: &mut Vec<TraceDisplayItem>,
) {
    if text_chunk.is_empty() {
        return;
    }

    let chunk_event = ParsedTraceEvent {
        trace_id: event.trace_id,
        timestamp: event.timestamp,
        pid: event.pid,
        tid: event.tid,
        instructions: std::mem::take(text_chunk),
    };
    items.extend(UiTraceEvent::from_protocol_event(&chunk_event).items);
}

fn is_process_entry_frame(analyzer: &DwarfAnalyzer, module_path: &str, pc: u64) -> bool {
    let module_path = Path::new(module_path);
    if let Some(entry) = analyzer.module_entry_address(module_path) {
        if pc >= entry && pc < entry.saturating_add(0x100) {
            return true;
        }
    }

    analyzer
        .lookup_function_addresses("_start")
        .into_iter()
        .any(|start| {
            start.module_path.as_path() == module_path
                && pc >= start.address
                && pc < start.address.saturating_add(0x100)
        })
}

fn candidate_pids(event_pid: u32, proc_pid_hint: Option<u32>) -> Vec<u32> {
    let mut seen = BTreeSet::new();
    if let Some(pid) = proc_pid_hint {
        seen.insert(pid);
    }
    seen.insert(event_pid);
    seen.into_iter().collect()
}

#[cfg(test)]
fn format_backtrace_header(status: BacktraceStatus, frames: usize, requested_depth: u8) -> String {
    let frame_word = if frames == 1 { "frame" } else { "frames" };
    format!(
        "backtrace: {}, {} {} (max {})",
        status.label(),
        frames,
        frame_word,
        requested_depth
    )
}

fn resolve_frame_module<'a>(
    coordinator: &'a ProcessManager,
    pids: &[u32],
    frame: &ParsedBacktraceFrame,
) -> Option<ResolvedFrameModule<'a>> {
    for pid in pids {
        if let Some(entries) = coordinator.cached_offsets_with_paths_for_pid(*pid) {
            if let Some(entry) = entries.iter().find(|entry| {
                frame.raw_ip >= entry.base && frame.raw_ip < entry.base.saturating_add(entry.size)
            }) {
                return Some(ResolvedFrameModule {
                    entry,
                    pc: frame.raw_ip.saturating_sub(entry.offsets.text),
                });
            }
            if let Some(entry) = entries
                .iter()
                .find(|entry| entry.cookie == frame.module_cookie && frame.pc < entry.size)
            {
                return Some(ResolvedFrameModule {
                    entry,
                    pc: frame.pc,
                });
            }
        }
    }
    None
}

#[cfg(test)]
fn format_raw_frame(
    index: usize,
    frame: &ParsedBacktraceFrame,
    module: Option<ResolvedFrameModule<'_>>,
    include_metadata: bool,
) -> String {
    let pc = module.map(|module| module.pc).unwrap_or(frame.pc);
    let module_text = module
        .map(|module| format_module_offset(&module.entry.module_path, pc))
        .unwrap_or_else(|| format!("0x{:x}", frame.pc));
    let metadata_text = if include_metadata {
        let cookie = module
            .map(|module| module.entry.cookie)
            .unwrap_or(frame.module_cookie);
        format!(" raw=0x{:x} cookie=0x{:016x}", frame.raw_ip, cookie)
    } else {
        String::new()
    };
    let flags_text = if include_metadata && frame.flags != 0 {
        format!(" flags=0x{:x}", frame.flags)
    } else {
        String::new()
    };
    format!("  #{index} 0x{pc:x} [{module_text}]{metadata_text}{flags_text}")
}

fn raw_display_frame(
    index: usize,
    frame: &ParsedBacktraceFrame,
    module: Option<ResolvedFrameModule<'_>>,
    include_metadata: bool,
) -> BacktraceDisplayFrame {
    let pc = module.map(|module| module.pc).unwrap_or(frame.pc);
    let module_text = module
        .map(|module| format_module_offset(&module.entry.module_path, pc))
        .unwrap_or_else(|| format!("0x{:x}", frame.pc));
    let cookie = include_metadata.then(|| {
        module
            .map(|module| module.entry.cookie)
            .unwrap_or(frame.module_cookie)
    });

    BacktraceDisplayFrame {
        index,
        inline: false,
        function: None,
        parameters: Vec::new(),
        address: Some(format!("0x{pc:x}")),
        location: None,
        module: module_text,
        raw_ip: include_metadata.then_some(frame.raw_ip),
        cookie,
        flags: (include_metadata && frame.flags != 0).then_some(frame.flags),
    }
}

fn format_line_info(line: &ghostscope_dwarf::PcLineInfo) -> String {
    match line.column {
        Some(column) => format!("{}:{}:{}", line.file_path, line.line_number, column),
        None => format!("{}:{}", line.file_path, line.line_number),
    }
}

#[cfg(test)]
fn format_function_signature(function: &str, analyzer: &DwarfAnalyzer, ctx: &PcContext) -> String {
    let parameters = format_function_parameters(analyzer, ctx);
    if parameters.is_empty() {
        return function.to_string();
    }

    format!("{function}({})", parameters.join(", "))
}

fn format_function_parameters(analyzer: &DwarfAnalyzer, ctx: &PcContext) -> Vec<String> {
    let Ok(mut parameters) = analyzer.function_parameters(ctx) else {
        return Vec::new();
    };
    parameters.retain(|parameter| !parameter.is_artificial);
    parameters.dedup_by(|a, b| a.name == b.name && a.type_name == b.type_name);
    parameters.iter().map(format_parameter).collect::<Vec<_>>()
}

fn format_parameter(parameter: &FunctionParameter) -> String {
    let type_name = normalize_signature_type(&parameter.type_name);
    let name = parameter.name.trim();
    if type_name.is_empty() || type_name == "unknown" {
        return name.to_string();
    }
    if name.is_empty() {
        return type_name;
    }
    format!("{type_name} {name}")
}

fn normalize_signature_type(type_name: &str) -> String {
    type_name.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn format_module_offset(module_path: &str, pc: u64) -> String {
    let name = Path::new(module_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(module_path);
    format!("{name}+0x{pc:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghostscope_protocol::trace_event::BacktraceStatus;

    #[test]
    fn renders_raw_backtrace_without_dwarf_context() {
        let event = ParsedTraceEvent {
            trace_id: 1,
            timestamp: 0,
            pid: 10,
            tid: 11,
            instructions: vec![
                ParsedInstruction::PrintString {
                    content: "before".to_string(),
                },
                ParsedInstruction::Backtrace {
                    requested_depth: 3,
                    flags: BACKTRACE_FLAG_RAW,
                    status: BacktraceStatus::UnsupportedCfi,
                    error_code: 0,
                    frames: vec![ParsedBacktraceFrame {
                        module_cookie: 0x1234,
                        pc: 0x5678,
                        raw_ip: 0x7fff_0000_5678,
                        flags: 0,
                    }],
                },
                ParsedInstruction::PrintString {
                    content: "after".to_string(),
                },
            ],
        };
        let coordinator = ProcessManager::new();
        let rendered =
            BacktraceRenderer::default().render_event_backtraces(&event, None, &coordinator, None);
        let output = rendered.to_formatted_output();

        assert_eq!(output[0], "before");
        assert_eq!(output[1], "backtrace: unsupported CFI, 1 frame (max 3)");
        assert!(output.iter().any(|line| line.contains("#0 0x5678")));
        assert!(output
            .iter()
            .any(|line| line.contains("stopped: unsupported CFI")));
        assert_eq!(output.last().map(String::as_str), Some("after"));
    }

    #[test]
    fn formats_no_unwind_rows_for_pc_status() {
        assert_eq!(
            format_backtrace_header(BacktraceStatus::NoUnwindRowsForPc, 1, 3),
            "backtrace: no unwind rows for PC, 1 frame (max 3)"
        );
    }

    #[test]
    fn renders_backtrace_as_structured_tui_item() {
        let event = ParsedTraceEvent {
            trace_id: 1,
            timestamp: 0,
            pid: 10,
            tid: 11,
            instructions: vec![
                ParsedInstruction::PrintString {
                    content: "before".to_string(),
                },
                ParsedInstruction::Backtrace {
                    requested_depth: 3,
                    flags: BACKTRACE_FLAG_RAW,
                    status: BacktraceStatus::UnsupportedCfi,
                    error_code: 0,
                    frames: vec![ParsedBacktraceFrame {
                        module_cookie: 0x1234,
                        pc: 0x5678,
                        raw_ip: 0x7fff_0000_5678,
                        flags: 0,
                    }],
                },
                ParsedInstruction::PrintString {
                    content: "after".to_string(),
                },
            ],
        };
        let coordinator = ProcessManager::new();
        let rendered =
            BacktraceRenderer::default().render_event_for_tui(&event, None, &coordinator, None);

        assert_eq!(rendered.items.len(), 3);
        assert!(matches!(
            &rendered.items[0],
            TraceDisplayItem::Text { content } if content == "before"
        ));
        let TraceDisplayItem::Backtrace(backtrace) = &rendered.items[1] else {
            panic!("expected structured backtrace item");
        };
        assert_eq!(backtrace.status, BacktraceStatus::UnsupportedCfi);
        assert_eq!(backtrace.frames.len(), 1);
        assert_eq!(backtrace.frames[0].address.as_deref(), Some("0x5678"));
        assert!(matches!(
            &rendered.items[2],
            TraceDisplayItem::Text { content } if content == "after"
        ));
    }
}
