//! Platform resource policy and complete native observation evidence.
//! Windows caps job commit; Linux caps each process's address space. Neither
//! policy claims a kernel resident-memory quota or a sampling-gap deadline.
use super::ProcessError;
use serde::Serialize;
#[cfg(any(windows, target_os = "linux", test))]
use std::time::{Duration, Instant};

#[cfg(any(windows, target_os = "linux", test))]
pub const MEMORY_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
#[cfg(any(windows, target_os = "linux", test))]
pub const PROCESS_LIMIT: u32 = 32;
#[cfg(any(windows, target_os = "linux", test))]
pub const TARGET: Duration = Duration::from_millis(100);
#[cfg(any(windows, test))]
const WINDOWS_FLAGS: u32 = 0x2208;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ResourcePolicy {
    #[serde(rename = "managed-windows-job-resources/1")]
    WindowsJob,
    #[serde(rename = "managed-linux-process-resources/1")]
    LinuxAddressSpace,
    #[serde(rename = "managed-darwin-resources/1")]
    DarwinObserved,
    #[serde(rename = "unsupported")]
    Unsupported,
}

impl ResourcePolicy {
    pub const fn current() -> Self {
        #[cfg(windows)]
        {
            Self::WindowsJob
        }
        #[cfg(target_os = "linux")]
        {
            Self::LinuxAddressSpace
        }
        #[cfg(target_os = "macos")]
        {
            Self::DarwinObserved
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            Self::Unsupported
        }
    }

    pub fn validate_current(&self) -> Result<(), ProcessError> {
        if *self == Self::Unsupported || *self != Self::current() {
            return Err(ProcessError::new(
                "resource_configuration",
                format!("resource policy {self:?} is unavailable on this platform"),
            ));
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug)]
pub struct JobReadback {
    pub flags: u32,
    pub committed_bytes: u64,
    pub active_limit: u32,
    pub returned_bytes: u32,
    pub expected_bytes: u32,
}

#[cfg(any(windows, test))]
impl JobReadback {
    fn validate(self) -> Result<(), ProcessError> {
        if self.flags != WINDOWS_FLAGS
            || self.committed_bytes != MEMORY_LIMIT
            || self.active_limit != PROCESS_LIMIT
            || self.expected_bytes == 0
            || self.returned_bytes != self.expected_bytes
        {
            return Err(ProcessError::new(
                "resource_configuration",
                format!(
                    "owned Windows Job resource readback mismatch; flags={:#x}; committed_limit={}; active_limit={}; returned_bytes={}; expected_bytes={}",
                    self.flags,
                    self.committed_bytes,
                    self.active_limit,
                    self.returned_bytes,
                    self.expected_bytes,
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(any(windows, target_os = "linux", test))]
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "policy")]
pub enum Evidence {
    #[cfg(any(windows, test))]
    #[serde(rename = "managed-windows-job-resources/1")]
    WindowsJob {
        memory_semantics: &'static str,
        process_count_semantics: &'static str,
        configured_limit_flags: u32,
        readback_limit_flags: u32,
        configured_job_committed_limit_bytes: u64,
        readback_job_committed_limit_bytes: u64,
        configured_active_process_limit: u32,
        readback_active_process_limit: u32,
        readback_bytes: u32,
        expected_readback_bytes: u32,
        kernel_resident_quota: bool,
        sample_target_ms: u64,
        sample_count: u64,
        peak_observed_job_committed_bytes: u64,
        peak_observed_processes: u32,
        max_observed_sample_gap_ms: u64,
    },
    #[cfg(any(target_os = "linux", test))]
    #[serde(rename = "managed-linux-process-resources/1")]
    LinuxAddressSpace {
        memory_semantics: &'static str,
        process_count_semantics: &'static str,
        configured_rlimit_as_bytes: u64,
        rlimit_as_readback_soft_bytes: u64,
        rlimit_as_readback_hard_bytes: u64,
        observed_live_process_limit: u32,
        aggregate_memory_quota: bool,
        kernel_process_quota: bool,
        kernel_resident_quota: bool,
        sampling_may_overshoot: bool,
        sample_target_ms: u64,
        sample_count: u64,
        peak_observed_processes: usize,
        max_observed_sample_gap_ms: u64,
    },
}

#[cfg(any(windows, target_os = "linux", test))]
pub struct Tracker {
    evidence: Evidence,
    last_complete: Option<Instant>,
}

#[cfg(any(windows, target_os = "linux", test))]
impl Tracker {
    #[cfg(any(windows, test))]
    pub fn windows(readback: JobReadback) -> Result<Self, ProcessError> {
        readback.validate()?;
        Ok(Self {
            last_complete: None,
            evidence: Evidence::WindowsJob {
                memory_semantics: "aggregate_job_committed_memory",
                process_count_semantics: "active_owned_job_including_command_leader",
                configured_limit_flags: WINDOWS_FLAGS,
                readback_limit_flags: readback.flags,
                configured_job_committed_limit_bytes: MEMORY_LIMIT,
                readback_job_committed_limit_bytes: readback.committed_bytes,
                configured_active_process_limit: PROCESS_LIMIT,
                readback_active_process_limit: readback.active_limit,
                readback_bytes: readback.returned_bytes,
                expected_readback_bytes: readback.expected_bytes,
                kernel_resident_quota: false,
                sample_target_ms: TARGET.as_millis() as u64,
                sample_count: 0,
                peak_observed_job_committed_bytes: 0,
                peak_observed_processes: 0,
                max_observed_sample_gap_ms: 0,
            },
        })
    }

    #[cfg(any(target_os = "linux", test))]
    pub fn linux() -> Self {
        // The caller constructs this only after Command::spawn has confirmed
        // successful pre_exec setrlimit and exact soft/hard getrlimit readback.
        Self {
            last_complete: None,
            evidence: Evidence::LinuxAddressSpace {
                memory_semantics: "per_process_address_space",
                process_count_semantics: "live_owned_group_including_command_leader",
                configured_rlimit_as_bytes: MEMORY_LIMIT,
                rlimit_as_readback_soft_bytes: MEMORY_LIMIT,
                rlimit_as_readback_hard_bytes: MEMORY_LIMIT,
                observed_live_process_limit: PROCESS_LIMIT,
                aggregate_memory_quota: false,
                kernel_process_quota: false,
                kernel_resident_quota: false,
                sampling_may_overshoot: true,
                sample_target_ms: TARGET.as_millis() as u64,
                sample_count: 0,
                peak_observed_processes: 0,
                max_observed_sample_gap_ms: 0,
            },
        }
    }

    pub fn due(&self) -> bool {
        self.last_complete
            .is_none_or(|last| last.elapsed() >= TARGET)
    }

    #[cfg(any(windows, test))]
    pub fn record_windows(
        &mut self,
        readback: JobReadback,
        active: u32,
        peak_committed: u64,
    ) -> Result<(), ProcessError> {
        readback.validate()?;
        let (
            readback_limit_flags,
            readback_job_committed_limit_bytes,
            readback_active_process_limit,
            readback_bytes,
            expected_readback_bytes,
            peak_observed_job_committed_bytes,
            peak_observed_processes,
        ) = match &mut self.evidence {
            Evidence::WindowsJob {
                readback_limit_flags,
                readback_job_committed_limit_bytes,
                readback_active_process_limit,
                readback_bytes,
                expected_readback_bytes,
                peak_observed_job_committed_bytes,
                peak_observed_processes,
                ..
            } => (
                readback_limit_flags,
                readback_job_committed_limit_bytes,
                readback_active_process_limit,
                readback_bytes,
                expected_readback_bytes,
                peak_observed_job_committed_bytes,
                peak_observed_processes,
            ),
            #[cfg(test)]
            _ => return Err(wrong_tracker()),
        };
        *readback_limit_flags = readback.flags;
        *readback_job_committed_limit_bytes = readback.committed_bytes;
        *readback_active_process_limit = readback.active_limit;
        *readback_bytes = readback.returned_bytes;
        *expected_readback_bytes = readback.expected_bytes;
        *peak_observed_job_committed_bytes =
            (*peak_observed_job_committed_bytes).max(peak_committed);
        *peak_observed_processes = (*peak_observed_processes).max(active);
        self.record_complete()?;
        if active > PROCESS_LIMIT || peak_committed > MEMORY_LIMIT {
            return Err(ProcessError::new(
                "resource_budget",
                format!(
                    "Windows owned Job resource budget exceeded; active={active}; peak_committed={peak_committed}"
                ),
            ));
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", test))]
    pub fn record_linux(&mut self, live: usize) -> Result<(), ProcessError> {
        let peak_observed_processes = match &mut self.evidence {
            Evidence::LinuxAddressSpace {
                peak_observed_processes,
                ..
            } => peak_observed_processes,
            #[cfg(test)]
            _ => return Err(wrong_tracker()),
        };
        *peak_observed_processes = (*peak_observed_processes).max(live);
        self.record_complete()?;
        if live > PROCESS_LIMIT as usize {
            return Err(ProcessError::new(
                "resource_budget",
                format!("Linux owned live process budget exceeded; live={live}"),
            ));
        }
        Ok(())
    }

    fn record_complete(&mut self) -> Result<(), ProcessError> {
        let now = Instant::now();
        let gap_ms = self
            .last_complete
            .map(|last| u64::try_from(now.duration_since(last).as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let (sample_count, maximum_gap) = match &mut self.evidence {
            #[cfg(any(windows, test))]
            Evidence::WindowsJob {
                sample_count,
                max_observed_sample_gap_ms,
                ..
            } => (sample_count, max_observed_sample_gap_ms),
            #[cfg(any(target_os = "linux", test))]
            Evidence::LinuxAddressSpace {
                sample_count,
                max_observed_sample_gap_ms,
                ..
            } => (sample_count, max_observed_sample_gap_ms),
        };
        *maximum_gap = (*maximum_gap).max(gap_ms);
        *sample_count = sample_count.checked_add(1).ok_or_else(|| {
            ProcessError::new(
                "resource_observation",
                "native resource sample count overflow",
            )
        })?;
        self.last_complete = Some(now);
        Ok(())
    }

    pub fn evidence(&self) -> Evidence {
        self.evidence.clone()
    }
}

#[cfg(test)]
fn wrong_tracker() -> ProcessError {
    ProcessError::new(
        "resource_configuration",
        "resource tracker platform mismatch",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> JobReadback {
        JobReadback {
            flags: WINDOWS_FLAGS,
            committed_bytes: MEMORY_LIMIT,
            active_limit: PROCESS_LIMIT,
            returned_bytes: 144,
            expected_bytes: 144,
        }
    }

    fn json(tracker: &Tracker) -> serde_json::Value {
        serde_json::to_value(tracker.evidence()).unwrap()
    }

    #[test]
    fn selected_policy_accepts_only_the_current_supported_platform() {
        for policy in [
            ResourcePolicy::WindowsJob,
            ResourcePolicy::LinuxAddressSpace,
            ResourcePolicy::DarwinObserved,
            ResourcePolicy::Unsupported,
        ] {
            assert_eq!(
                policy.validate_current().is_ok(),
                policy == ResourcePolicy::current() && policy != ResourcePolicy::Unsupported,
            );
        }
    }

    #[test]
    fn policy_serialization_preserves_versioned_identifiers() {
        for (policy, identifier) in [
            (
                ResourcePolicy::WindowsJob,
                "managed-windows-job-resources/1",
            ),
            (
                ResourcePolicy::LinuxAddressSpace,
                "managed-linux-process-resources/1",
            ),
            (ResourcePolicy::DarwinObserved, "managed-darwin-resources/1"),
            (ResourcePolicy::Unsupported, "unsupported"),
        ] {
            assert_eq!(serde_json::to_value(policy).unwrap(), identifier);
        }
    }

    #[test]
    fn windows_readback_requires_exact_flags_limits_and_complete_bytes() {
        assert!(Tracker::windows(job()).is_ok());
        let mut rejected = Vec::new();
        for flag in [0x2000, 0x0200, 0x0008] {
            rejected.push(JobReadback {
                flags: WINDOWS_FLAGS & !flag,
                ..job()
            });
        }
        for flag in [0x0800, 0x1000, 0x0001] {
            rejected.push(JobReadback {
                flags: WINDOWS_FLAGS | flag,
                ..job()
            });
        }
        for committed_bytes in [MEMORY_LIMIT - 1, MEMORY_LIMIT + 1] {
            rejected.push(JobReadback {
                committed_bytes,
                ..job()
            });
        }
        for active_limit in [31, 33] {
            rejected.push(JobReadback {
                active_limit,
                ..job()
            });
        }
        for returned_bytes in [0, 143, 145] {
            rejected.push(JobReadback {
                returned_bytes,
                ..job()
            });
        }
        rejected.push(JobReadback {
            returned_bytes: 0,
            expected_bytes: 0,
            ..job()
        });
        for readback in rejected {
            let error = Tracker::windows(readback).err().expect("invalid readback");
            assert_eq!(error.kind, "resource_configuration");
        }
    }

    #[test]
    fn windows_complete_over_budget_sample_preserves_observed_peaks() {
        let mut tracker = Tracker::windows(job()).unwrap();
        assert!(tracker.due());
        tracker.record_windows(job(), 32, MEMORY_LIMIT).unwrap();
        let memory_error = tracker
            .record_windows(job(), 32, MEMORY_LIMIT + 1)
            .unwrap_err();
        assert_eq!(memory_error.kind, "resource_budget");
        let process_error = tracker.record_windows(job(), 33, MEMORY_LIMIT).unwrap_err();
        assert_eq!(process_error.kind, "resource_budget");
        let evidence = json(&tracker);
        assert_eq!(evidence["sample_count"], 3);
        assert_eq!(evidence["peak_observed_processes"], 33);
        assert_eq!(
            evidence["peak_observed_job_committed_bytes"],
            MEMORY_LIMIT + 1
        );
    }

    #[test]
    fn windows_incomplete_readback_never_advances_sample_evidence() {
        let mut tracker = Tracker::windows(job()).unwrap();
        let error = tracker
            .record_windows(
                JobReadback {
                    returned_bytes: 143,
                    ..job()
                },
                7,
                42,
            )
            .unwrap_err();
        assert_eq!(error.kind, "resource_configuration");
        assert!(tracker.last_complete.is_none());
        assert!(tracker.due());
        assert_eq!(json(&tracker)["sample_count"], 0);
        assert_eq!(json(&tracker)["peak_observed_job_committed_bytes"], 0);
    }

    #[test]
    fn windows_evidence_distinguishes_commit_from_resident_memory() {
        let evidence = json(&Tracker::windows(job()).unwrap());
        assert_eq!(evidence["policy"], "managed-windows-job-resources/1");
        assert_eq!(
            evidence["memory_semantics"],
            "aggregate_job_committed_memory"
        );
        assert_eq!(
            evidence["process_count_semantics"],
            "active_owned_job_including_command_leader"
        );
        assert_eq!(
            evidence["configured_job_committed_limit_bytes"],
            MEMORY_LIMIT
        );
        assert_eq!(evidence["readback_job_committed_limit_bytes"], MEMORY_LIMIT);
        assert_eq!(evidence["configured_active_process_limit"], PROCESS_LIMIT);
        assert_eq!(evidence["readback_active_process_limit"], PROCESS_LIMIT);
        assert_eq!(evidence["kernel_resident_quota"], false);
        assert_eq!(evidence["sample_target_ms"], 100);
    }

    #[test]
    fn linux_count_boundary_preserves_the_failed_actual_observation() {
        let mut tracker = Tracker::linux();
        tracker.record_linux(32).unwrap();
        let error = tracker.record_linux(33).unwrap_err();
        assert_eq!(error.kind, "resource_budget");
        assert_eq!(json(&tracker)["sample_count"], 2);
        assert_eq!(json(&tracker)["peak_observed_processes"], 33);
    }

    #[test]
    fn linux_evidence_has_per_process_as_without_aggregate_or_resident_quota() {
        let evidence = json(&Tracker::linux());
        assert_eq!(evidence["policy"], "managed-linux-process-resources/1");
        assert_eq!(evidence["memory_semantics"], "per_process_address_space");
        assert_eq!(
            evidence["process_count_semantics"],
            "live_owned_group_including_command_leader"
        );
        assert_eq!(evidence["configured_rlimit_as_bytes"], MEMORY_LIMIT);
        assert_eq!(evidence["rlimit_as_readback_soft_bytes"], MEMORY_LIMIT);
        assert_eq!(evidence["rlimit_as_readback_hard_bytes"], MEMORY_LIMIT);
        assert_eq!(evidence["kernel_resident_quota"], false);
        assert_eq!(evidence["aggregate_memory_quota"], false);
        assert_eq!(evidence["kernel_process_quota"], false);
        assert_eq!(evidence["sampling_may_overshoot"], true);
    }

    #[test]
    fn due_checks_never_replace_actual_samples_or_add_a_linux_gap_quota() {
        let mut tracker = Tracker::linux();
        tracker.record_linux(1).unwrap();
        tracker.last_complete = Some(Instant::now() - Duration::from_secs(2));
        assert!(tracker.due());
        assert!(tracker.due());
        assert_eq!(json(&tracker)["sample_count"], 1);
        tracker.record_linux(2).unwrap();
        let evidence = json(&tracker);
        assert_eq!(evidence["sample_count"], 2);
        assert!(evidence["max_observed_sample_gap_ms"].as_u64().unwrap() >= 2000);
    }

    #[test]
    fn a_different_platform_sample_never_changes_tracker_evidence() {
        let mut linux = Tracker::linux();
        let before = json(&linux);
        assert_eq!(
            linux.record_windows(job(), 1, 1).unwrap_err().kind,
            "resource_configuration"
        );
        assert_eq!(json(&linux), before);
        let mut windows = Tracker::windows(job()).unwrap();
        let before = json(&windows);
        assert_eq!(
            windows.record_linux(1).unwrap_err().kind,
            "resource_configuration"
        );
        assert_eq!(json(&windows), before);
    }
}
