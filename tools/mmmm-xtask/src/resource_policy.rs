//! Platform resource policy and complete native observation evidence.
//! Windows caps job commit; Linux caps each process's address space. JVM builds
//! on Linux additionally observe aggregate RSS. These policies do not claim a
//! kernel resident-memory quota. Only the narrowly classified Linux JVM
//! incomplete leader/member transition has a conditional complete-sample deadline.
use super::ProcessError;
#[cfg(test)]
use super::linux_resources::PendingObservation;
#[cfg(any(target_os = "linux", test))]
use super::linux_resources::{GroupObservation, PendingHistory, PendingObservations, PendingRole};
use serde::Serialize;
#[cfg(any(windows, target_os = "linux", test))]
use std::time::{Duration, Instant};

#[cfg(any(windows, target_os = "linux", test))]
pub const MEMORY_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
#[cfg(any(target_os = "linux", test))]
pub const JVM_VM_LIMIT: u64 = 512 * 1024 * 1024 * 1024;
#[cfg(any(windows, target_os = "linux", test))]
pub const PROCESS_LIMIT: u32 = 32;
#[cfg(any(windows, target_os = "linux", test))]
pub const TARGET: Duration = Duration::from_millis(100);
#[cfg(any(target_os = "linux", test))]
const LINUX_PENDING_GAP: Duration = Duration::from_millis(1000);
#[cfg(any(windows, test))]
const WINDOWS_FLAGS: u32 = 0x2208;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ResourcePolicy {
    #[serde(rename = "managed-windows-job-resources/1")]
    WindowsJob,
    #[serde(rename = "managed-linux-process-resources/1")]
    LinuxAddressSpace,
    #[serde(rename = "managed-linux-jvm-resources/1")]
    LinuxJvmObserved,
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

    /// Only the exact fixed JVM build purpose selects the Linux JVM policy.
    /// Other purposes and the Windows/Darwin policies retain their defaults.
    pub fn for_managed_purpose(purpose: &str) -> Self {
        if cfg!(target_os = "linux") && purpose == "jvm" {
            Self::LinuxJvmObserved
        } else {
            Self::current()
        }
    }

    /// The fixed definition observer launches the same pinned JVM directly,
    /// under its own purpose and original startup deadline. Reuse the JVM's
    /// finite VM/RSS semantics without relabeling it as a build or changing
    /// the general process policy.
    pub const fn for_definition_startup() -> Self {
        if cfg!(target_os = "linux") {
            Self::LinuxJvmObserved
        } else {
            Self::current()
        }
    }

    pub fn validate_current(&self) -> Result<(), ProcessError> {
        let available = *self == Self::current()
            || (cfg!(target_os = "linux") && *self == Self::LinuxJvmObserved);
        if *self == Self::Unsupported || !available {
            return Err(ProcessError::new(
                "resource_configuration",
                format!("resource policy {self:?} is unavailable on this platform"),
            ));
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", test))]
    pub fn linux_address_space_limit(self) -> Result<u64, ProcessError> {
        match self {
            Self::LinuxAddressSpace => Ok(MEMORY_LIMIT),
            Self::LinuxJvmObserved => Ok(JVM_VM_LIMIT),
            _ => Err(ProcessError::new(
                "resource_configuration",
                "non-Linux resource policy has no Linux address-space limit",
            )),
        }
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
    #[cfg(any(target_os = "linux", test))]
    #[serde(rename = "managed-linux-jvm-resources/1")]
    LinuxJvmObserved {
        memory_semantics: &'static str,
        process_count_semantics: &'static str,
        rss_api: &'static str,
        configured_rlimit_as_bytes: u64,
        rlimit_as_readback_soft_bytes: u64,
        rlimit_as_readback_hard_bytes: u64,
        observed_aggregate_rss_limit_bytes: u64,
        observed_live_process_limit: u32,
        aggregate_memory_quota: bool,
        kernel_process_quota: bool,
        kernel_resident_quota: bool,
        shared_pages_counted_per_process: bool,
        group_snapshot_atomic: bool,
        sampling_may_overshoot: bool,
        detached_sessions_contained: bool,
        sample_target_ms: u64,
        sample_count: u64,
        incomplete_memory_sample_count: u64,
        pending_leader_complete_gap_limit_ms: u64,
        pending_leader_observations: Option<Box<PendingHistory>>,
        pending_member_complete_gap_limit_ms: u64,
        pending_member_observations: Option<Box<PendingHistory>>,
        peak_observed_processes: usize,
        peak_observed_aggregate_rss_bytes: u64,
        peak_observed_per_process_vm_bytes: u64,
        max_observed_sample_gap_ms: u64,
    },
}

#[cfg(any(windows, target_os = "linux", test))]
pub struct Tracker {
    evidence: Evidence,
    last_complete: Option<Instant>,
    #[cfg(any(target_os = "linux", test))]
    last_attempt: Option<Instant>,
    #[cfg(any(target_os = "linux", test))]
    pending_active: bool,
    #[cfg(any(target_os = "linux", test))]
    last_pending_role: Option<PendingRole>,
}

#[cfg(any(windows, target_os = "linux", test))]
impl Tracker {
    #[cfg(any(windows, test))]
    pub fn windows(readback: JobReadback) -> Result<Self, ProcessError> {
        readback.validate()?;
        Ok(Self {
            last_complete: None,
            #[cfg(any(target_os = "linux", test))]
            last_attempt: None,
            #[cfg(any(target_os = "linux", test))]
            pending_active: false,
            #[cfg(any(target_os = "linux", test))]
            last_pending_role: None,
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
            last_attempt: None,
            pending_active: false,
            last_pending_role: None,
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

    #[cfg(any(target_os = "linux", test))]
    pub fn linux_jvm() -> Self {
        // Successful spawn confirms the matching pre_exec setrlimit and exact
        // soft/hard readback. This tracker never modifies or retries a quota.
        Self {
            last_complete: None,
            last_attempt: None,
            pending_active: false,
            last_pending_role: None,
            evidence: Evidence::LinuxJvmObserved {
                memory_semantics: "sequential_sum_of_owned_per_process_rss",
                process_count_semantics: "live_owned_group_including_command_leader",
                rss_api: "procfs_smaps_rollup_rss",
                configured_rlimit_as_bytes: JVM_VM_LIMIT,
                rlimit_as_readback_soft_bytes: JVM_VM_LIMIT,
                rlimit_as_readback_hard_bytes: JVM_VM_LIMIT,
                observed_aggregate_rss_limit_bytes: MEMORY_LIMIT,
                observed_live_process_limit: PROCESS_LIMIT,
                aggregate_memory_quota: false,
                kernel_process_quota: false,
                kernel_resident_quota: false,
                shared_pages_counted_per_process: true,
                group_snapshot_atomic: false,
                sampling_may_overshoot: true,
                detached_sessions_contained: false,
                sample_target_ms: TARGET.as_millis() as u64,
                sample_count: 0,
                incomplete_memory_sample_count: 0,
                pending_leader_complete_gap_limit_ms: LINUX_PENDING_GAP.as_millis() as u64,
                pending_leader_observations: None,
                pending_member_complete_gap_limit_ms: LINUX_PENDING_GAP.as_millis() as u64,
                pending_member_observations: None,
                peak_observed_processes: 0,
                peak_observed_aggregate_rss_bytes: 0,
                peak_observed_per_process_vm_bytes: 0,
                max_observed_sample_gap_ms: 0,
            },
        }
    }

    #[cfg(target_os = "linux")]
    pub fn linux_for_policy(policy: ResourcePolicy) -> Result<Self, ProcessError> {
        match policy {
            ResourcePolicy::LinuxAddressSpace => Ok(Self::linux()),
            ResourcePolicy::LinuxJvmObserved => Ok(Self::linux_jvm()),
            _ => Err(ProcessError::new(
                "resource_configuration",
                "Linux resource tracker policy mismatch",
            )),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub fn requires_linux_rss(&self) -> bool {
        matches!(self.evidence, Evidence::LinuxJvmObserved { .. })
    }

    #[cfg(any(windows, test))]
    pub fn due(&self) -> bool {
        self.due_at(Instant::now())
    }

    fn due_at(&self, now: Instant) -> bool {
        #[cfg(any(target_os = "linux", test))]
        if self.pending_active && self.requires_linux_rss() {
            return self
                .last_attempt
                .is_none_or(|last| now.duration_since(last) >= TARGET);
        }
        self.last_complete
            .is_none_or(|last| now.duration_since(last) >= TARGET)
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn begin_linux_sample(&mut self) -> Result<bool, ProcessError> {
        self.begin_linux_sample_at(Instant::now())
    }

    #[cfg(any(target_os = "linux", test))]
    fn begin_linux_sample_at(&mut self, now: Instant) -> Result<bool, ProcessError> {
        if self.pending_active {
            self.check_linux_pending_gap(now)?;
        }
        if !self.due_at(now) {
            return Ok(false);
        }
        self.last_attempt = Some(now);
        Ok(true)
    }

    #[cfg(test)]
    pub(super) fn record_linux_pending_fact(&mut self, observation: PendingObservation) {
        self.record_linux_pending_observations(observation.into());
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn record_linux_pending_observations(&mut self, observations: PendingObservations) {
        if let Evidence::LinuxJvmObserved {
            pending_leader_observations,
            pending_member_observations,
            ..
        } = &mut self.evidence
        {
            if let Some(history) = observations.leader {
                PendingHistory::merge(pending_leader_observations, history);
            }
            if let Some(history) = observations.member {
                PendingHistory::merge(pending_member_observations, history);
            }
            if let Some(role) = observations.last_role {
                self.last_pending_role = Some(role);
                self.pending_active = true;
            }
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn linux_pending(&self) -> bool {
        self.pending_active
    }

    #[cfg(any(target_os = "linux", test))]
    fn check_linux_pending_gap(&self, now: Instant) -> Result<(), ProcessError> {
        if self
            .last_complete
            .is_some_and(|last| now.duration_since(last) <= LINUX_PENDING_GAP)
        {
            return Ok(());
        }
        let Evidence::LinuxJvmObserved {
            pending_leader_observations,
            pending_member_observations,
            ..
        } = &self.evidence
        else {
            return Err(wrong_tracker());
        };
        let role = self.last_pending_role.ok_or_else(wrong_tracker)?;
        let history = match role {
            PendingRole::ReservedLeader => pending_leader_observations.as_deref(),
            PendingRole::OwnedMember => pending_member_observations.as_deref(),
        }
        .ok_or_else(wrong_tracker)?;
        let mut error = history.last.original_error();
        let reason = if self.last_complete.is_none() {
            "requires an earlier complete resource sample"
        } else {
            "exceeded the 1000ms complete resource sample gap"
        };
        error
            .message
            .push_str(&format!("; Linux JVM pending {} {reason}", role.label()));
        Err(error)
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn finish_linux_sample(
        &mut self,
        observation: GroupObservation,
    ) -> Result<(), ProcessError> {
        self.finish_linux_sample_at(observation, Instant::now())
    }

    #[cfg(any(target_os = "linux", test))]
    fn finish_linux_sample_at(
        &mut self,
        observation: GroupObservation,
        now: Instant,
    ) -> Result<(), ProcessError> {
        match observation {
            GroupObservation::Complete(sample) => {
                if self.requires_linux_rss() {
                    self.record_linux_jvm_at(
                        sample.live_processes,
                        sample.aggregate_rss_bytes,
                        sample.max_virtual_bytes,
                        now,
                    )
                } else {
                    self.record_linux(sample.live_processes)
                }
            }
            GroupObservation::Pending(sample) => {
                let Evidence::LinuxJvmObserved {
                    incomplete_memory_sample_count,
                    ..
                } = &mut self.evidence
                else {
                    return Err(wrong_tracker());
                };
                *incomplete_memory_sample_count = incomplete_memory_sample_count
                    .checked_add(1)
                    .ok_or_else(|| {
                        ProcessError::new(
                            "resource_observation",
                            "incomplete sample count overflow",
                        )
                    })?;
                // These are measured lower bounds, never completed-sample
                // peaks. A missing process RSS cannot hide another member's
                // actual count, VM or RSS budget failure.
                check_linux_jvm_budget(
                    sample.live_processes,
                    Some(sample.known_rss_bytes),
                    sample.max_virtual_bytes,
                )?;
                self.check_linux_pending_gap(now)
            }
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn with_linux_pending_diagnostics(&self, mut error: ProcessError) -> ProcessError {
        if let Evidence::LinuxJvmObserved {
            pending_leader_observations,
            pending_member_observations,
            ..
        } = &self.evidence
        {
            for (label, history) in [
                ("linux_pending_leader", pending_leader_observations),
                ("linux_pending_member", pending_member_observations),
            ] {
                if let Some(history) = history {
                    error.message.push_str(&format!(
                        "; {label}(count={}; first=[{}]; last=[{}])",
                        history.count,
                        history.first.original_error(),
                        history.last.original_error(),
                    ));
                }
            }
        }
        error
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
            _ => return Err(wrong_tracker()),
        };
        *peak_observed_processes = (*peak_observed_processes).max(live);
        self.record_complete()?;
        check_linux_process_budget(live)
    }

    #[cfg(test)]
    pub fn record_linux_jvm(
        &mut self,
        live: usize,
        rss: Option<u64>,
        virtual_bytes: u64,
    ) -> Result<(), ProcessError> {
        self.record_linux_jvm_at(live, rss, virtual_bytes, Instant::now())
    }

    #[cfg(any(target_os = "linux", test))]
    fn record_linux_jvm_at(
        &mut self,
        live: usize,
        rss: Option<u64>,
        virtual_bytes: u64,
        now: Instant,
    ) -> Result<(), ProcessError> {
        // Check a recovery before touching any complete sample or peak. A
        // late successful read must not erase an expired incomplete window.
        if self.pending_active {
            self.check_linux_pending_gap(now)?;
        }
        let Evidence::LinuxJvmObserved {
            peak_observed_processes,
            peak_observed_aggregate_rss_bytes,
            peak_observed_per_process_vm_bytes,
            incomplete_memory_sample_count,
            ..
        } = &mut self.evidence
        else {
            return Err(wrong_tracker());
        };
        *peak_observed_processes = (*peak_observed_processes).max(live);
        *peak_observed_per_process_vm_bytes =
            (*peak_observed_per_process_vm_bytes).max(virtual_bytes);
        if let Some(rss) = rss {
            *peak_observed_aggregate_rss_bytes = (*peak_observed_aggregate_rss_bytes).max(rss);
            self.record_complete_at(now)?;
            self.pending_active = false;
        } else {
            *incomplete_memory_sample_count = incomplete_memory_sample_count
                .checked_add(1)
                .ok_or_else(|| {
                    ProcessError::new("resource_observation", "incomplete sample count overflow")
                })?;
            if live <= PROCESS_LIMIT as usize {
                return Err(ProcessError::new(
                    "resource_observation",
                    "Linux JVM memory sample is incomplete",
                ));
            }
        }
        check_linux_jvm_budget(live, rss, virtual_bytes)
    }

    fn record_complete(&mut self) -> Result<(), ProcessError> {
        self.record_complete_at(Instant::now())
    }

    fn record_complete_at(&mut self, now: Instant) -> Result<(), ProcessError> {
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
            }
            | Evidence::LinuxJvmObserved {
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

#[cfg(any(target_os = "linux", test))]
pub(super) fn check_linux_process_budget(live: usize) -> Result<(), ProcessError> {
    if live > PROCESS_LIMIT as usize {
        return Err(ProcessError::new(
            "resource_budget",
            format!("Linux owned live process budget exceeded; live={live}"),
        ));
    }
    Ok(())
}

/// Check measured lower bounds without recording a complete sample or its peaks.
#[cfg(any(target_os = "linux", test))]
pub(super) fn check_linux_partial_budget(
    live: usize,
    known_rss: u64,
    virtual_bytes: u64,
    include_rss: bool,
) -> Result<(), ProcessError> {
    if include_rss {
        check_linux_jvm_budget(live, Some(known_rss), virtual_bytes)
    } else {
        check_linux_process_budget(live)
    }
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn check_linux_jvm_budget(
    live: usize,
    rss: Option<u64>,
    virtual_bytes: u64,
) -> Result<(), ProcessError> {
    if live > PROCESS_LIMIT as usize
        || rss.is_some_and(|rss| rss > MEMORY_LIMIT)
        || virtual_bytes > JVM_VM_LIMIT
    {
        return Err(ProcessError::new(
            "resource_budget",
            format!(
                "Linux JVM observed resource budget exceeded; live={live}; aggregate_rss={rss:?}; per_process_vm={virtual_bytes}"
            ),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn wrong_tracker() -> ProcessError {
    ProcessError::new(
        "resource_configuration",
        "resource tracker platform mismatch",
    )
}

#[cfg(test)]
mod tests {
    use super::super::linux_resources::{
        Sample,
        tests::{pending_observation, pending_observation_for_role},
    };
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
            ResourcePolicy::LinuxJvmObserved,
            ResourcePolicy::DarwinObserved,
            ResourcePolicy::Unsupported,
        ] {
            assert_eq!(
                policy.validate_current().is_ok(),
                policy != ResourcePolicy::Unsupported
                    && (policy == ResourcePolicy::current()
                        || (cfg!(target_os = "linux")
                            && policy == ResourcePolicy::LinuxJvmObserved)),
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
            (
                ResourcePolicy::LinuxJvmObserved,
                "managed-linux-jvm-resources/1",
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
    fn linux_partial_process_count_checks_both_policies_without_completing_a_sample() {
        for include_rss in [false, true] {
            check_linux_partial_budget(32, 4096, 8192, include_rss).unwrap();
            let error = check_linux_partial_budget(33, 4096, 8192, include_rss).unwrap_err();
            assert_eq!(error.kind, "resource_budget");
            assert!(error.message.contains("live=33"));
        }
        check_linux_partial_budget(32, u64::MAX, u64::MAX, false).unwrap();
        let error = check_linux_partial_budget(33, u64::MAX, u64::MAX, false).unwrap_err();
        assert_eq!(error.kind, "resource_budget");
        assert_eq!(
            error.message,
            "Linux owned live process budget exceeded; live=33"
        );
    }

    #[test]
    fn linux_partial_jvm_checks_exact_rss_and_vm_boundaries_and_each_overage() {
        check_linux_partial_budget(32, MEMORY_LIMIT, JVM_VM_LIMIT, true).unwrap();
        for (known_rss, virtual_bytes) in [
            (MEMORY_LIMIT + 1, JVM_VM_LIMIT),
            (MEMORY_LIMIT, JVM_VM_LIMIT + 1),
        ] {
            let error = check_linux_partial_budget(32, known_rss, virtual_bytes, true).unwrap_err();
            assert_eq!(error.kind, "resource_budget");
        }
    }

    #[test]
    fn only_the_exact_linux_jvm_purpose_changes_the_platform_default() {
        for purpose in ["checks", "bootstrap", "jvm-checks", "JVM", "jvm-", ""] {
            assert_eq!(
                ResourcePolicy::for_managed_purpose(purpose),
                ResourcePolicy::current()
            );
        }
        let expected = if cfg!(target_os = "linux") {
            ResourcePolicy::LinuxJvmObserved
        } else {
            ResourcePolicy::current()
        };
        assert_eq!(ResourcePolicy::for_managed_purpose("jvm"), expected);
        assert_eq!(
            ResourcePolicy::LinuxAddressSpace
                .linux_address_space_limit()
                .unwrap(),
            MEMORY_LIMIT
        );
        assert_eq!(
            ResourcePolicy::LinuxJvmObserved
                .linux_address_space_limit()
                .unwrap(),
            JVM_VM_LIMIT
        );
        assert!(
            ResourcePolicy::WindowsJob
                .linux_address_space_limit()
                .is_err()
        );
    }

    #[test]
    fn jvm_evidence_distinguishes_vm_readback_from_sequential_rss_observations() {
        let evidence = json(&Tracker::linux_jvm());
        assert_eq!(evidence["policy"], "managed-linux-jvm-resources/1");
        assert_eq!(evidence["configured_rlimit_as_bytes"], JVM_VM_LIMIT);
        assert_eq!(evidence["rlimit_as_readback_soft_bytes"], JVM_VM_LIMIT);
        assert_eq!(evidence["rlimit_as_readback_hard_bytes"], JVM_VM_LIMIT);
        assert_eq!(evidence["observed_aggregate_rss_limit_bytes"], MEMORY_LIMIT);
        assert_eq!(evidence["observed_live_process_limit"], PROCESS_LIMIT);
        assert_eq!(evidence["sample_target_ms"], 100);
        assert_eq!(evidence["rss_api"], "procfs_smaps_rollup_rss");
        for field in [
            "aggregate_memory_quota",
            "kernel_process_quota",
            "kernel_resident_quota",
            "group_snapshot_atomic",
            "detached_sessions_contained",
        ] {
            assert_eq!(evidence[field], false);
        }
        assert_eq!(evidence["shared_pages_counted_per_process"], true);
        assert_eq!(evidence["sampling_may_overshoot"], true);
    }

    #[test]
    fn jvm_failed_complete_observations_preserve_rss_process_and_vm_peaks() {
        let mut tracker = Tracker::linux_jvm();
        tracker
            .record_linux_jvm(32, Some(MEMORY_LIMIT), JVM_VM_LIMIT)
            .unwrap();
        assert_eq!(
            tracker
                .record_linux_jvm(32, Some(MEMORY_LIMIT + 1), JVM_VM_LIMIT)
                .unwrap_err()
                .kind,
            "resource_budget"
        );
        assert_eq!(
            tracker
                .record_linux_jvm(33, Some(1), JVM_VM_LIMIT + 1)
                .unwrap_err()
                .kind,
            "resource_budget"
        );
        let evidence = json(&tracker);
        assert_eq!(evidence["sample_count"], 3);
        assert_eq!(
            evidence["peak_observed_aggregate_rss_bytes"],
            MEMORY_LIMIT + 1
        );
        assert_eq!(evidence["peak_observed_processes"], 33);
        assert_eq!(
            evidence["peak_observed_per_process_vm_bytes"],
            JVM_VM_LIMIT + 1
        );
    }

    #[test]
    fn jvm_incomplete_rss_preserves_count_failure_without_advancing_complete_samples() {
        let mut tracker = Tracker::linux_jvm();
        tracker.record_linux_jvm(1, Some(4096), 8192).unwrap();
        assert_eq!(
            tracker.record_linux_jvm(33, None, 65536).unwrap_err().kind,
            "resource_budget"
        );
        assert_eq!(
            tracker.record_linux_jvm(2, None, 8192).unwrap_err().kind,
            "resource_observation"
        );
        let evidence = json(&tracker);
        assert_eq!(evidence["sample_count"], 1);
        assert_eq!(evidence["incomplete_memory_sample_count"], 2);
        assert_eq!(evidence["peak_observed_aggregate_rss_bytes"], 4096);
        assert_eq!(evidence["peak_observed_processes"], 33);
        assert_eq!(evidence["peak_observed_per_process_vm_bytes"], 65536);
    }

    #[test]
    fn jvm_sampling_keeps_actual_gap_without_adding_a_darwin_gap_quota() {
        let mut tracker = Tracker::linux_jvm();
        tracker.record_linux_jvm(1, Some(4096), 8192).unwrap();
        tracker.last_complete = Some(Instant::now() - Duration::from_secs(2));
        assert!(tracker.due());
        tracker.record_linux_jvm(1, Some(8192), 8192).unwrap();
        assert!(
            json(&tracker)["max_observed_sample_gap_ms"]
                .as_u64()
                .unwrap()
                >= 2000
        );
    }

    #[test]
    fn jvm_pending_keeps_complete_samples_peaks_and_cadence_separate() {
        let at = Instant::now();
        let partial = Sample {
            live_processes: 2,
            aggregate_rss_bytes: None,
            known_rss_bytes: 8192,
            max_virtual_bytes: 65536,
        };
        let mut tracker = Tracker::linux_jvm();
        tracker
            .record_linux_jvm_at(1, Some(4096), 8192, at)
            .unwrap();
        let before = json(&tracker);
        for (ms, role) in [
            (100, PendingRole::ReservedLeader),
            (200, PendingRole::OwnedMember),
            (900, PendingRole::ReservedLeader),
            (1000, PendingRole::OwnedMember),
        ] {
            let now = at + Duration::from_millis(ms);
            assert!(tracker.begin_linux_sample_at(now).unwrap());
            tracker.record_linux_pending_fact(pending_observation_for_role(role));
            tracker
                .finish_linux_sample_at(GroupObservation::Pending(partial), now)
                .unwrap();
            assert!(tracker.linux_pending());
            assert_eq!(tracker.last_complete, Some(at));
            assert!(!tracker.due_at(now + Duration::from_millis(99)));
            assert!(tracker.due_at(now + Duration::from_millis(100)));
            for field in [
                "sample_count",
                "peak_observed_processes",
                "peak_observed_aggregate_rss_bytes",
                "peak_observed_per_process_vm_bytes",
                "max_observed_sample_gap_ms",
            ] {
                assert_eq!(json(&tracker)[field], before[field], "{field}");
            }
        }
        let evidence = json(&tracker);
        assert_eq!(evidence["incomplete_memory_sample_count"], 4);
        assert_eq!(evidence["pending_leader_observations"]["count"], 2);
        assert_eq!(evidence["pending_member_observations"]["count"], 2);
        assert_eq!(evidence["pending_leader_complete_gap_limit_ms"], 1000);
        assert_eq!(evidence["pending_member_complete_gap_limit_ms"], 1000);
        let expired = at + Duration::from_millis(1001);
        let error = tracker.begin_linux_sample_at(expired).unwrap_err();
        assert_eq!(error.kind, "resource_observation");
        assert!(error.message.starts_with("native process metadata failed;"));
        assert!(error.to_string().contains("category=not_ready"));
        assert!(error.to_string().contains("process_role=owned_member"));
        assert!(error.message.contains("pending owned member exceeded"));
        assert!(
            error
                .message
                .contains("1000ms complete resource sample gap")
        );
        // A later complete result is checked before any peak/count/time
        // update; even an otherwise valid recovery cannot wash this failure.
        let before = json(&tracker);
        assert!(
            tracker
                .finish_linux_sample_at(
                    GroupObservation::Complete(Sample {
                        live_processes: 3,
                        aggregate_rss_bytes: Some(16384),
                        known_rss_bytes: 16384,
                        max_virtual_bytes: 131072,
                    }),
                    expired
                )
                .is_err()
        );
        assert_eq!(json(&tracker), before);
        assert_eq!(tracker.last_complete, Some(at));
        assert!(tracker.linux_pending());
    }

    #[test]
    fn jvm_pending_requires_a_prior_complete_and_retains_bounded_facts_on_every_failure() {
        let at = Instant::now();
        let partial = Sample {
            live_processes: 2,
            aggregate_rss_bytes: None,
            known_rss_bytes: 8192,
            max_virtual_bytes: 65536,
        };
        for role in [PendingRole::ReservedLeader, PendingRole::OwnedMember] {
            let mut first = Tracker::linux_jvm();
            first.record_linux_pending_fact(pending_observation_for_role(role));
            let error = first
                .finish_linux_sample_at(GroupObservation::Pending(partial), at)
                .unwrap_err();
            assert!(
                error
                    .message
                    .contains("requires an earlier complete resource sample")
            );
            assert_eq!(json(&first)["sample_count"], 0);
            assert_eq!(json(&first)["peak_observed_aggregate_rss_bytes"], 0);
        }
        for sample in [
            Sample {
                known_rss_bytes: MEMORY_LIMIT + 1,
                ..partial
            },
            Sample {
                max_virtual_bytes: JVM_VM_LIMIT + 1,
                ..partial
            },
            Sample {
                live_processes: PROCESS_LIMIT as usize + 1,
                ..partial
            },
        ] {
            let mut tracker = Tracker::linux_jvm();
            tracker
                .record_linux_jvm_at(1, Some(4096), 8192, at)
                .unwrap();
            tracker
                .record_linux_pending_fact(pending_observation_for_role(PendingRole::OwnedMember));
            assert_eq!(
                tracker
                    .finish_linux_sample_at(GroupObservation::Pending(sample), at)
                    .unwrap_err()
                    .kind,
                "resource_budget"
            );
            assert_eq!(json(&tracker)["sample_count"], 1);
            assert_eq!(json(&tracker)["peak_observed_processes"], 1);
            assert_eq!(json(&tracker)["peak_observed_aggregate_rss_bytes"], 4096);
        }
        let mut tracker = Tracker::linux_jvm();
        assert!(tracker.begin_linux_sample().unwrap());
        tracker
            .finish_linux_sample(GroupObservation::Complete(Sample {
                live_processes: 1,
                aggregate_rss_bytes: Some(4096),
                known_rss_bytes: 4096,
                max_virtual_bytes: 8192,
            }))
            .unwrap();
        tracker.record_linux_pending_fact(pending_observation());
        tracker.record_linux_pending_fact(pending_observation());
        let mut original =
            ProcessError::new("process_identity", "later original identity mismatch");
        original.drained = false;
        let error = tracker.with_linux_pending_diagnostics(original);
        assert_eq!(error.kind, "process_identity");
        assert!(!error.drained);
        assert!(
            error
                .message
                .starts_with("later original identity mismatch;")
        );
        assert!(error.message.contains("linux_pending_leader(count=2; first=[resource_observation: native process metadata failed;"));
        assert!(
            error
                .message
                .contains("last=[resource_observation: native process metadata failed;")
        );
        assert!(error.to_string().len() < 4096);
        assert_eq!(json(&tracker)["pending_leader_observations"]["count"], 2);
        // Match the process boundary: collect every provisional fact, then
        // merge that scan exactly once even when a later native check fails.
        let mut scan = PendingObservations::default();
        scan.record(pending_observation_for_role(PendingRole::OwnedMember));
        scan.record(pending_observation_for_role(PendingRole::OwnedMember));
        scan.record(pending_observation());
        tracker.record_linux_pending_observations(scan);
        let evidence = json(&tracker);
        assert_eq!(evidence["pending_leader_observations"]["count"], 3);
        assert_eq!(evidence["pending_member_observations"]["count"], 2);
        assert_eq!(tracker.last_pending_role, Some(PendingRole::ReservedLeader));
        let mut next_scan = PendingObservations::default();
        next_scan.record(pending_observation_for_role(PendingRole::OwnedMember));
        tracker.record_linux_pending_observations(next_scan);
        tracker.record_linux_pending_observations(PendingObservations::default());
        assert_eq!(tracker.last_pending_role, Some(PendingRole::OwnedMember));
        let evidence = json(&tracker);
        assert_eq!(evidence["pending_leader_observations"]["count"], 3);
        assert_eq!(evidence["pending_member_observations"]["count"], 3);
        for endpoint in ["first", "last"] {
            assert_eq!(
                evidence["pending_member_observations"][endpoint]["role"],
                "owned_member"
            );
            assert_eq!(
                evidence["pending_member_observations"][endpoint]["stat_observation"]["role"],
                "owned_member"
            );
        }
        let mut original =
            ProcessError::new("process_identity", "later original leader anchor lost");
        original.drained = false;
        let error = tracker.with_linux_pending_diagnostics(original);
        assert_eq!(error.kind, "process_identity");
        assert!(!error.drained);
        assert!(
            error
                .message
                .starts_with("later original leader anchor lost;")
        );
        assert!(error.message.contains("linux_pending_leader(count=3;"));
        assert!(error.message.contains("linux_pending_member(count=3;"));
        assert!(error.message.contains("process_role=owned_member"));
        assert!(error.to_string().len() < 8192);
    }

    #[test]
    fn jvm_pending_recovery_at_the_exact_gap_boundary_is_a_new_actual_complete() {
        for role in [PendingRole::ReservedLeader, PendingRole::OwnedMember] {
            let at = Instant::now();
            let mut tracker = Tracker::linux_jvm();
            tracker
                .record_linux_jvm_at(1, Some(4096), 8192, at)
                .unwrap();
            tracker.record_linux_pending_fact(pending_observation_for_role(role));
            tracker
                .finish_linux_sample_at(
                    GroupObservation::Pending(Sample {
                        live_processes: 1,
                        aggregate_rss_bytes: None,
                        known_rss_bytes: 0,
                        max_virtual_bytes: 8192,
                    }),
                    at + TARGET,
                )
                .unwrap();
            let now = at + LINUX_PENDING_GAP;
            tracker
                .finish_linux_sample_at(
                    GroupObservation::Complete(Sample {
                        live_processes: 0,
                        aggregate_rss_bytes: Some(0),
                        known_rss_bytes: 0,
                        max_virtual_bytes: 0,
                    }),
                    now,
                )
                .unwrap();
            assert!(!tracker.linux_pending());
            assert_eq!(tracker.last_complete, Some(now));
            let evidence = json(&tracker);
            assert_eq!(evidence["sample_count"], 2);
            assert_eq!(evidence["max_observed_sample_gap_ms"], 1000);
            assert_eq!(evidence["peak_observed_aggregate_rss_bytes"], 4096);
            let field = match role {
                PendingRole::ReservedLeader => "pending_leader_observations",
                PendingRole::OwnedMember => "pending_member_observations",
            };
            assert_eq!(evidence[field]["count"], 1);
            assert_eq!(evidence["incomplete_memory_sample_count"], 1);
            // Only the active transition has a deadline. Its retained history
            // does not impose a new quota on future ordinary Linux observations.
            tracker
                .record_linux_jvm_at(1, Some(8192), 8192, now + Duration::from_secs(2))
                .unwrap();
            assert_eq!(json(&tracker)["sample_count"], 3);
            assert_eq!(json(&tracker)["max_observed_sample_gap_ms"], 2000);
        }
        // Also cover pending facts and final Complete from the same native call.
        for role in [PendingRole::ReservedLeader, PendingRole::OwnedMember] {
            for (prior_complete, elapsed, recovers) in [
                (true, LINUX_PENDING_GAP, true),
                (true, LINUX_PENDING_GAP + Duration::from_millis(1), false),
                (false, LINUX_PENDING_GAP, false),
            ] {
                let at = Instant::now();
                let mut tracker = Tracker::linux_jvm();
                if prior_complete {
                    tracker
                        .record_linux_jvm_at(1, Some(4096), 8192, at)
                        .unwrap();
                }
                let attempted_at = at + TARGET;
                assert!(tracker.begin_linux_sample_at(attempted_at).unwrap());
                let observation = pending_observation_for_role(role);
                let original = observation.original_error();
                let mut first_pass = PendingObservations::default();
                first_pass.record(observation);
                // Production merges both passes once before finishing the one
                // final result; it never records the first pass as Complete.
                tracker.record_linux_pending_observations(first_pass);
                let before = json(&tracker);
                let original_complete = prior_complete.then_some(at);
                assert_eq!(tracker.last_complete, original_complete);
                assert_eq!(tracker.last_attempt, Some(attempted_at));
                let now = at + elapsed;
                let result = tracker.finish_linux_sample_at(
                    GroupObservation::Complete(Sample {
                        live_processes: 2,
                        aggregate_rss_bytes: Some(8192),
                        known_rss_bytes: 8192,
                        max_virtual_bytes: 16384,
                    }),
                    now,
                );
                if recovers {
                    result.unwrap();
                    assert!(!tracker.linux_pending());
                    assert_eq!(tracker.last_complete, Some(now));
                    let evidence = json(&tracker);
                    assert_eq!(
                        evidence["sample_count"],
                        before["sample_count"].as_u64().unwrap() + 1
                    );
                    assert_eq!(evidence["max_observed_sample_gap_ms"], 1000);
                    assert_eq!(evidence["incomplete_memory_sample_count"], 0);
                    assert_eq!(evidence["peak_observed_processes"], 2);
                    assert_eq!(evidence["peak_observed_aggregate_rss_bytes"], 8192);
                    assert_eq!(evidence["peak_observed_per_process_vm_bytes"], 16384);
                    let field = match role {
                        PendingRole::ReservedLeader => "pending_leader_observations",
                        PendingRole::OwnedMember => "pending_member_observations",
                    };
                    assert_eq!(evidence[field], before[field]);
                    assert_eq!(evidence[field]["count"], 1);
                } else {
                    let error = result.unwrap_err();
                    assert_eq!(error.kind, original.kind);
                    assert_eq!(error.drained, original.drained);
                    assert!(error.message.starts_with(&original.message));
                    let reason = if prior_complete {
                        "exceeded the 1000ms complete resource sample gap"
                    } else {
                        "requires an earlier complete resource sample"
                    };
                    assert!(error.message.contains(reason));
                    assert_eq!(json(&tracker), before);
                    assert_eq!(tracker.last_complete, original_complete);
                    assert!(tracker.linux_pending());
                }
                assert_eq!(tracker.last_attempt, Some(attempted_at));
                assert_eq!(tracker.last_pending_role, Some(role));
            }
        }
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
