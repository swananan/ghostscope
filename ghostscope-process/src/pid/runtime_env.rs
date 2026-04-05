use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeEnvironment {
    ContainerLikely,
    HostLikely,
    #[default]
    Unknown,
}

impl fmt::Display for RuntimeEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeEnvironment::ContainerLikely => write!(f, "container-likely"),
            RuntimeEnvironment::HostLikely => write!(f, "host-likely"),
            RuntimeEnvironment::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeEnvironmentInfo {
    pub environment: RuntimeEnvironment,
    pub evidence: Vec<String>,
}

impl RuntimeEnvironmentInfo {
    pub fn compact_display(&self) -> String {
        let reason = if self.evidence.is_empty() {
            "no-evidence".to_string()
        } else {
            self.evidence.join(", ")
        };
        format!("env={} evidence=[{}]", self.environment, reason)
    }

    pub fn is_container_likely(&self) -> bool {
        self.environment == RuntimeEnvironment::ContainerLikely
    }
}

pub fn detect_runtime_environment() -> RuntimeEnvironmentInfo {
    let mut evidence = Vec::new();

    if Path::new("/.dockerenv").is_file() {
        evidence.push("/.dockerenv exists".to_string());
    }
    if Path::new("/run/.containerenv").is_file() {
        evidence.push("/run/.containerenv exists".to_string());
    }

    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        let cgroup_lc = cgroup.to_lowercase();
        let markers = [
            "docker",
            "containerd",
            "kubepods",
            "cri-containerd",
            "libpod",
        ];
        for marker in markers {
            if cgroup_lc.contains(marker) {
                evidence.push(format!("/proc/1/cgroup contains '{marker}'"));
                break;
            }
        }
    }

    let environment = if !evidence.is_empty() {
        RuntimeEnvironment::ContainerLikely
    } else if Path::new("/proc/1").exists() {
        RuntimeEnvironment::HostLikely
    } else {
        RuntimeEnvironment::Unknown
    };

    RuntimeEnvironmentInfo {
        environment,
        evidence,
    }
}
