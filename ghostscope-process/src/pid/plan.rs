use super::{PidNamespaceId, PidViews};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidFilterSpec {
    /// Compare against host TGID from `bpf_get_current_pid_tgid() >> 32`.
    HostTgid { filter_pid: u32 },
    /// Compare against TGID in a specific PID namespace via `bpf_get_ns_current_pid_tgid`.
    NamespaceTgid {
        filter_pid: u32,
        pid_ns: PidNamespaceId,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimePidPlanInput<'a> {
    pub target_pid_views: Option<&'a PidViews>,
    pub self_pid_views: Option<&'a PidViews>,
    pub in_container: bool,
    pub helper_supported: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimePidPlan {
    pub pid_filter: Option<PidFilterSpec>,
    pub special_vars_pid_ns: Option<PidNamespaceId>,
    pub proc_offsets_pid_ns: Option<PidNamespaceId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidModeFailFast {
    pub proc_pid: u32,
}

pub fn build_runtime_pid_plan(
    input: RuntimePidPlanInput<'_>,
) -> Result<RuntimePidPlan, PidModeFailFast> {
    let mut plan = RuntimePidPlan::default();

    if let Some(pid_views) = input.target_pid_views {
        if should_fail_fast_pid_mode(pid_views, input.in_container, input.helper_supported) {
            return Err(PidModeFailFast {
                proc_pid: pid_views.proc_pid,
            });
        }

        let ns_context_needed =
            pid_ns_context_needed(pid_views, input.in_container, input.helper_supported);

        plan.pid_filter = if ns_context_needed && input.helper_supported {
            helper_pid_ns(pid_views)
                .map(|pid_ns| PidFilterSpec::NamespaceTgid {
                    filter_pid: pid_views.container_pid.unwrap_or(pid_views.proc_pid),
                    pid_ns,
                })
                .or(Some(PidFilterSpec::HostTgid {
                    filter_pid: pid_views.host_pid,
                }))
        } else {
            Some(PidFilterSpec::HostTgid {
                filter_pid: pid_views.host_pid,
            })
        };
    }

    if input.helper_supported {
        let self_pid_ns_for_target_mode = input
            .target_pid_views
            .is_none()
            .then_some(input.self_pid_views.and_then(helper_pid_ns))
            .flatten();
        let self_pid_ns_for_container_fallback = input
            .in_container
            .then_some(input.self_pid_views.and_then(helper_pid_ns))
            .flatten();

        plan.special_vars_pid_ns = input
            .target_pid_views
            .and_then(helper_pid_ns)
            .or_else(|| self_pid_ns_for_target_mode.or(self_pid_ns_for_container_fallback));

        plan.proc_offsets_pid_ns = input
            .target_pid_views
            .and_then(|pid_views| {
                should_use_target_proc_offsets_pid_ns(pid_views, plan.pid_filter.as_ref())
                    .then_some(helper_pid_ns(pid_views))
                    .flatten()
            })
            .or_else(|| self_pid_ns_for_target_mode.or(self_pid_ns_for_container_fallback));
    }

    Ok(plan)
}

fn pid_ns_context_needed(pid_views: &PidViews, in_container: bool, helper_supported: bool) -> bool {
    // We need namespace-aware filtering in two cases:
    // 1) `proc_pid` and `host_pid` differ (cross-namespace mapping is explicit),
    // 2) running in a container and the helper is available, even if NSpid only has one value.
    //    In private PID namespaces, single-value NSpid cannot prove host TGID equality.
    pid_views.host_pid != pid_views.proc_pid || (in_container && helper_supported)
}

fn helper_pid_ns(pid_views: &PidViews) -> Option<PidNamespaceId> {
    pid_views.pid_ns.filter(|pid_ns| pid_ns.dev.is_some())
}

fn should_use_target_proc_offsets_pid_ns(
    pid_views: &PidViews,
    pid_filter: Option<&PidFilterSpec>,
) -> bool {
    match pid_filter {
        Some(PidFilterSpec::NamespaceTgid { filter_pid, .. }) => {
            pid_views.container_pid == Some(*filter_pid) || pid_views.proc_pid == *filter_pid
        }
        _ => false,
    }
}

fn should_fail_fast_pid_mode(
    pid_views: &PidViews,
    in_container: bool,
    helper_supported: bool,
) -> bool {
    in_container
        && !helper_supported
        && !pid_views.has_explicit_host_mapping()
        && !pid_views.is_initial_pid_namespace()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PidResolveSource, INITIAL_PID_NAMESPACE_INO};

    fn make_pid_views(proc_pid: u32, host_pid: u32) -> PidViews {
        PidViews {
            proc_pid,
            host_pid,
            container_pid: None,
            pid_ns: None,
            nspid_chain: None,
            source: PidResolveSource::DirectProcStatus,
        }
    }

    #[test]
    fn host_filter_is_selected_when_pids_match_without_helper() {
        let pid_views = make_pid_views(321, 321);
        let plan = build_runtime_pid_plan(RuntimePidPlanInput {
            target_pid_views: Some(&pid_views),
            self_pid_views: None,
            in_container: false,
            helper_supported: false,
        })
        .unwrap();

        assert_eq!(
            plan.pid_filter,
            Some(PidFilterSpec::HostTgid { filter_pid: 321 })
        );
        assert_eq!(plan.special_vars_pid_ns, None);
        assert_eq!(plan.proc_offsets_pid_ns, None);
    }

    #[test]
    fn namespace_filter_is_selected_when_helper_is_available() {
        let pid_views = PidViews {
            proc_pid: 321,
            host_pid: 4321,
            container_pid: Some(17),
            pid_ns: Some(PidNamespaceId {
                dev: Some(1),
                inode: 2,
            }),
            nspid_chain: Some(vec![4321, 321, 17]),
            source: PidResolveSource::DirectProcStatus,
        };

        let plan = build_runtime_pid_plan(RuntimePidPlanInput {
            target_pid_views: Some(&pid_views),
            self_pid_views: None,
            in_container: true,
            helper_supported: true,
        })
        .unwrap();

        assert_eq!(
            plan.pid_filter,
            Some(PidFilterSpec::NamespaceTgid {
                filter_pid: 17,
                pid_ns: PidNamespaceId {
                    dev: Some(1),
                    inode: 2,
                },
            })
        );
        assert_eq!(
            plan.special_vars_pid_ns,
            Some(PidNamespaceId {
                dev: Some(1),
                inode: 2,
            })
        );
        assert_eq!(
            plan.proc_offsets_pid_ns,
            Some(PidNamespaceId {
                dev: Some(1),
                inode: 2,
            })
        );
    }

    #[test]
    fn target_mode_uses_self_namespace_for_special_vars_and_proc_offsets() {
        let self_pid_views = PidViews {
            proc_pid: 123,
            host_pid: 456,
            container_pid: Some(123),
            pid_ns: Some(PidNamespaceId {
                dev: Some(7),
                inode: 8,
            }),
            nspid_chain: Some(vec![456, 123]),
            source: PidResolveSource::DirectProcStatus,
        };

        let plan = build_runtime_pid_plan(RuntimePidPlanInput {
            target_pid_views: None,
            self_pid_views: Some(&self_pid_views),
            in_container: true,
            helper_supported: true,
        })
        .unwrap();

        assert_eq!(plan.pid_filter, None);
        assert_eq!(plan.special_vars_pid_ns, self_pid_views.pid_ns);
        assert_eq!(plan.proc_offsets_pid_ns, self_pid_views.pid_ns);
    }

    #[test]
    fn target_mode_uses_self_namespace_when_container_detection_misses() {
        let self_pid_views = PidViews {
            proc_pid: 123,
            host_pid: 456,
            container_pid: Some(123),
            pid_ns: Some(PidNamespaceId {
                dev: Some(7),
                inode: 8,
            }),
            nspid_chain: Some(vec![456, 123]),
            source: PidResolveSource::DirectProcStatus,
        };

        let plan = build_runtime_pid_plan(RuntimePidPlanInput {
            target_pid_views: None,
            self_pid_views: Some(&self_pid_views),
            in_container: false,
            helper_supported: true,
        })
        .unwrap();

        assert_eq!(plan.pid_filter, None);
        assert_eq!(plan.special_vars_pid_ns, self_pid_views.pid_ns);
        assert_eq!(plan.proc_offsets_pid_ns, self_pid_views.pid_ns);
    }

    #[test]
    fn fail_fast_in_container_without_helper_or_explicit_host_mapping() {
        let pid_views = make_pid_views(321, 321);
        assert_eq!(
            build_runtime_pid_plan(RuntimePidPlanInput {
                target_pid_views: Some(&pid_views),
                self_pid_views: None,
                in_container: true,
                helper_supported: false,
            }),
            Err(PidModeFailFast { proc_pid: 321 })
        );
    }

    #[test]
    fn initial_pid_namespace_disables_fail_fast_without_helper() {
        let pid_views = PidViews {
            proc_pid: 321,
            host_pid: 321,
            container_pid: None,
            pid_ns: Some(PidNamespaceId {
                dev: Some(1),
                inode: INITIAL_PID_NAMESPACE_INO,
            }),
            nspid_chain: None,
            source: PidResolveSource::DirectProcStatus,
        };

        let plan = build_runtime_pid_plan(RuntimePidPlanInput {
            target_pid_views: Some(&pid_views),
            self_pid_views: None,
            in_container: true,
            helper_supported: false,
        })
        .unwrap();

        assert_eq!(
            plan.pid_filter,
            Some(PidFilterSpec::HostTgid { filter_pid: 321 })
        );
    }

    #[test]
    fn explicit_host_mapping_disables_fail_fast_without_helper() {
        let pid_views = PidViews {
            proc_pid: 321,
            host_pid: 12345,
            container_pid: Some(321),
            pid_ns: None,
            nspid_chain: Some(vec![12345, 321]),
            source: PidResolveSource::DirectProcStatus,
        };

        let plan = build_runtime_pid_plan(RuntimePidPlanInput {
            target_pid_views: Some(&pid_views),
            self_pid_views: None,
            in_container: true,
            helper_supported: false,
        })
        .unwrap();

        assert_eq!(
            plan.pid_filter,
            Some(PidFilterSpec::HostTgid { filter_pid: 12345 })
        );
    }

    #[test]
    fn proc_offsets_stays_on_current_proc_view_for_host_filter() {
        let pid_views = PidViews {
            proc_pid: 321,
            host_pid: 4321,
            container_pid: Some(17),
            pid_ns: Some(PidNamespaceId {
                dev: Some(1),
                inode: 2,
            }),
            nspid_chain: Some(vec![4321, 321, 17]),
            source: PidResolveSource::DirectProcStatus,
        };

        let plan = build_runtime_pid_plan(RuntimePidPlanInput {
            target_pid_views: Some(&pid_views),
            self_pid_views: None,
            in_container: true,
            helper_supported: false,
        })
        .unwrap();

        assert_eq!(plan.proc_offsets_pid_ns, None);
    }
}
