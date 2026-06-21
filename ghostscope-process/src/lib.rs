pub mod module_probe;
pub mod offsets;
pub mod pid;
pub mod pinned_bpf_maps;
pub mod proc_maps;
pub use offsets::{PidOffsetsEntry, ProcessManager, SectionOffsets};
pub use pid::{
    build_runtime_pid_plan, detect_runtime_environment, host_pid_for_proc_pid,
    resolve_event_pid_for_proc, resolve_input_pid, resolve_pid_session, resolve_proc_pid,
    resolve_proc_pid_for_event, runtime_pid_candidates_for_proc, PidAttachRequest, PidFilterSpec,
    PidModeFailFast, PidNamespaceId, PidResolveSource, PidViews, ResolvePidSessionError,
    ResolvedPidSession, RuntimeEnvironment, RuntimeEnvironmentInfo, RuntimePidPlan,
    RuntimePidPlanInput, INITIAL_PID_NAMESPACE_INO,
};
pub mod sysmon;
pub use sysmon::{ProcessSysmon, SysEvent, SysEventKind, SysmonConfig, SysmonEventMask};
pub mod util;
pub use util::is_shared_object;
