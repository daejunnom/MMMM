//! Darwin cooperative resource observations, separate from native drain proof.
//! Adjusted VM, RSS and physical footprint are distinct measured quantities.
//! The shared native-process crate owns the public libproc memory ABI only.
use super::ProcessError;
use mmmm_native_process::darwin::{NativeResourceError, NativeResourceFailure};
use serde::Serialize;
use std::time::{Duration, Instant};

pub(super) const VM_LIMIT: u64 = 512 * 1024 * 1024 * 1024;
const MEMORY_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const WORKER_LIMIT: usize = 32;
const TARGET: Duration = Duration::from_millis(100);
const MAX_GAP: Duration = Duration::from_secs(1);
// Darwin errno.h; pure classification tests also run on non-Unix targets.
#[cfg(test)]
const DARWIN_ESRCH: i32 = 3;

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    policy: &'static str,
    configured_rlimit_as_bytes: u64,
    rlimit_as_readback_bytes: Option<u64>,
    adjusted_vm_per_pid_limit_bytes: u64,
    aggregate_rss_limit_bytes: u64,
    aggregate_footprint_limit_bytes: u64,
    worker_limit: usize,
    wrapper_limit: usize,
    wrapper_in_memory_sum: bool,
    sample_target_ms: u64,
    max_successful_sample_gap_ms: u64,
    taskinfo_flavor: i32,
    rusage_flavor: i32,
    sample_count: u64,
    peak_observed_adjusted_vm_bytes: u64,
    peak_observed_aggregate_rss_bytes: u64,
    peak_observed_aggregate_footprint_bytes: u64,
    peak_observed_workers: usize,
    max_observed_sample_gap_ms: u64,
    preflight_self_adjusted_vm_bytes: u64,
    preflight_self_rss_bytes: u64,
    preflight_self_footprint_bytes: u64,
    sampling_may_overshoot: bool,
    kernel_resident_quota: bool,
}

pub(super) struct Tracker {
    pub(super) evidence: Evidence,
    last_success: Instant,
}
impl Tracker {
    pub(super) fn new(preflight: Memory) -> Result<Self, ProcessError> {
        let mut sample = Sample::default();
        sample.push(preflight)?;
        sample.check()?;
        Ok(Self {
            last_success: Instant::now(),
            evidence: Evidence {
                policy: "managed-darwin-resources/1",
                configured_rlimit_as_bytes: VM_LIMIT,
                rlimit_as_readback_bytes: None,
                adjusted_vm_per_pid_limit_bytes: VM_LIMIT,
                aggregate_rss_limit_bytes: MEMORY_LIMIT,
                aggregate_footprint_limit_bytes: MEMORY_LIMIT,
                worker_limit: WORKER_LIMIT,
                wrapper_limit: 0,
                wrapper_in_memory_sum: false,
                sample_target_ms: 100,
                max_successful_sample_gap_ms: 1000,
                taskinfo_flavor: 4,
                rusage_flavor: 0,
                sample_count: 0,
                peak_observed_adjusted_vm_bytes: 0,
                peak_observed_aggregate_rss_bytes: 0,
                peak_observed_aggregate_footprint_bytes: 0,
                peak_observed_workers: 0,
                max_observed_sample_gap_ms: 0,
                preflight_self_adjusted_vm_bytes: preflight.adjusted_vm,
                preflight_self_rss_bytes: preflight.rss,
                preflight_self_footprint_bytes: preflight.footprint,
                sampling_may_overshoot: true,
                kernel_resident_quota: false,
            },
        })
    }
    pub(super) fn configured(&mut self) {
        // Command::spawn returns only after the child's pre_exec hook succeeded.
        // This proves the BSD readback, not map enforcement across later execs.
        self.evidence.rlimit_as_readback_bytes = Some(VM_LIMIT);
    }
    fn gap(&mut self, now: Instant) -> Result<(), ProcessError> {
        let gap = now.duration_since(self.last_success);
        self.evidence.max_observed_sample_gap_ms = self
            .evidence
            .max_observed_sample_gap_ms
            .max(u64::try_from(gap.as_millis()).unwrap_or(u64::MAX));
        if gap > MAX_GAP {
            return Err(ProcessError::new(
                "resource_observation",
                "Darwin successful resource sample gap exceeded 1000ms",
            ));
        }
        Ok(())
    }
    pub(super) fn begin(&mut self) -> Result<Option<Instant>, ProcessError> {
        let now = Instant::now();
        self.gap(now)?;
        Ok(
            (self.evidence.sample_count == 0 || now.duration_since(self.last_success) >= TARGET)
                .then_some(now),
        )
    }
    pub(super) fn finish(&mut self, sample: Sample) -> Result<(), ProcessError> {
        let finished = Instant::now();
        self.evidence.sample_count += 1;
        self.evidence.peak_observed_adjusted_vm_bytes = self
            .evidence
            .peak_observed_adjusted_vm_bytes
            .max(sample.adjusted_vm_peak);
        self.evidence.peak_observed_aggregate_rss_bytes = self
            .evidence
            .peak_observed_aggregate_rss_bytes
            .max(sample.rss);
        self.evidence.peak_observed_aggregate_footprint_bytes = self
            .evidence
            .peak_observed_aggregate_footprint_bytes
            .max(sample.footprint);
        self.evidence.peak_observed_workers =
            self.evidence.peak_observed_workers.max(sample.workers);
        // Preserve a complete observed sample even when its freshness fails.
        self.gap(finished)?;
        self.last_success = finished;
        sample.check()
    }
}

#[derive(Clone, Copy)]
pub(super) struct Memory {
    pub(super) adjusted_vm: u64,
    pub(super) rss: u64,
    pub(super) footprint: u64,
}
#[derive(Default)]
pub(super) struct Sample {
    adjusted_vm_peak: u64,
    rss: u64,
    footprint: u64,
    workers: usize,
}
impl Sample {
    pub(super) fn push(&mut self, memory: Memory) -> Result<(), ProcessError> {
        self.adjusted_vm_peak = self.adjusted_vm_peak.max(memory.adjusted_vm);
        self.rss = self.rss.checked_add(memory.rss).ok_or_else(sum_overflow)?;
        self.footprint = self
            .footprint
            .checked_add(memory.footprint)
            .ok_or_else(sum_overflow)?;
        self.workers = self.workers.checked_add(1).ok_or_else(sum_overflow)?;
        Ok(())
    }
    fn check(&self) -> Result<(), ProcessError> {
        if self.adjusted_vm_peak > VM_LIMIT
            || self.rss > MEMORY_LIMIT
            || self.footprint > MEMORY_LIMIT
            || self.workers > WORKER_LIMIT
        {
            return Err(ProcessError::new(
                "resource_budget",
                format!(
                    "Darwin resource budget exceeded; adjusted_vm={}; aggregate_rss={}; aggregate_footprint={}; workers={}",
                    self.adjusted_vm_peak, self.rss, self.footprint, self.workers,
                ),
            ));
        }
        Ok(())
    }
}
fn sum_overflow() -> ProcessError {
    ProcessError::new(
        "resource_observation",
        "Darwin native resource sum overflow",
    )
}

#[cfg(test)]
fn task_result(bytes: i32, number: i32) -> Result<(), ProcessError> {
    mmmm_native_process::darwin::classify_task_result(bytes, number).map_err(native_error)
}
#[cfg(test)]
fn rusage_result(result: i32, number: i32, start: u64, exit: u64) -> Result<(), ProcessError> {
    mmmm_native_process::darwin::classify_rusage_result(result, number, start, exit)
        .map_err(native_error)
}

fn native_error(error: NativeResourceError) -> ProcessError {
    // ESRCH and an observed exit timestamp remain exit-class failures. Only
    // process.rs may independently confirm the unchanged native zombie.
    let kind = if error.failure == NativeResourceFailure::Exited {
        "resource_process_exit"
    } else {
        "resource_observation"
    };
    ProcessError::new(kind, error.to_string())
}

#[cfg(target_os = "macos")]
pub(super) fn memory(pid: i32) -> Result<Memory, ProcessError> {
    let actual = mmmm_native_process::darwin::observe_memory(pid).map_err(native_error)?;
    // tools retains its existing before/after BSD birth/UID/group sandwich.
    // The shared observation additionally returns rusage start identity for
    // consumers that keep it fixed throughout a single worker lifecycle.
    Ok(Memory {
        adjusted_vm: actual.adjusted_vm,
        rss: actual.rss,
        footprint: actual.footprint,
    })
}

/// Only async-signal-safe libc calls; no libproc, formatting or allocation.
#[cfg(target_os = "macos")]
pub(super) fn configure_before_exec() -> std::io::Result<()> {
    let configured = libc::rlimit {
        rlim_cur: VM_LIMIT,
        rlim_max: VM_LIMIT,
    };
    let mut readback = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &configured) } == -1
        || unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut readback) } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    if readback.rlim_cur != VM_LIMIT || readback.rlim_max != VM_LIMIT {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn small() -> Memory {
        Memory {
            adjusted_vm: 400 * 1024 * 1024 * 1024,
            rss: 16,
            footprint: 8,
        }
    }
    #[test]
    fn aggregate_and_distinct_measures_are_bounded() {
        let mut sample = Sample::default();
        sample.push(small()).unwrap();
        sample
            .push(Memory {
                rss: MEMORY_LIMIT,
                ..small()
            })
            .unwrap();
        assert_eq!(sample.check().unwrap_err().kind, "resource_budget");
        let mut sample = Sample::default();
        sample
            .push(Memory {
                footprint: MEMORY_LIMIT + 1,
                ..small()
            })
            .unwrap();
        assert_eq!(sample.check().unwrap_err().kind, "resource_budget");
    }
    #[test]
    fn overflow_and_vm_are_not_silently_normalized() {
        let mut sample = Sample::default();
        sample
            .push(Memory {
                rss: u64::MAX,
                ..small()
            })
            .unwrap();
        assert_eq!(
            sample.push(small()).unwrap_err().kind,
            "resource_observation"
        );
        let mut sample = Sample::default();
        sample
            .push(Memory {
                adjusted_vm: VM_LIMIT + 1,
                ..small()
            })
            .unwrap();
        assert_eq!(sample.check().unwrap_err().kind, "resource_budget");
        let mut sample = Sample::default();
        sample
            .push(Memory {
                footprint: u64::MAX,
                ..small()
            })
            .unwrap();
        assert_eq!(
            sample.push(small()).unwrap_err().kind,
            "resource_observation"
        );
    }
    #[test]
    fn stalled_sampling_fails_and_keeps_the_gap_fact() {
        let mut tracker = Tracker::new(small()).unwrap();
        tracker.last_success = Instant::now() - Duration::from_millis(1001);
        assert_eq!(tracker.begin().unwrap_err().kind, "resource_observation");
        assert!(tracker.evidence.max_observed_sample_gap_ms >= 1001);
    }
    #[test]
    fn complete_sample_preserves_readback_and_observed_failure_peak() {
        let mut tracker = Tracker::new(small()).unwrap();
        tracker.configured();
        assert!(tracker.begin().unwrap().is_some());
        let mut sample = Sample::default();
        sample
            .push(Memory {
                rss: MEMORY_LIMIT + 1,
                ..small()
            })
            .unwrap();
        assert_eq!(tracker.finish(sample).unwrap_err().kind, "resource_budget");
        assert_eq!(tracker.evidence.rlimit_as_readback_bytes, Some(VM_LIMIT));
        assert_eq!(tracker.evidence.sample_count, 1);
        assert_eq!(
            tracker.evidence.peak_observed_aggregate_rss_bytes,
            MEMORY_LIMIT + 1
        );
        assert!(!tracker.evidence.kernel_resident_quota);
    }
    #[test]
    fn worker_limit_counts_the_command_and_all_live_children() {
        let mut sample = Sample::default();
        for _ in 0..WORKER_LIMIT {
            sample.push(small()).unwrap();
        }
        sample.check().unwrap();
        sample.push(small()).unwrap();
        assert_eq!(sample.check().unwrap_err().kind, "resource_budget");
    }
    #[test]
    fn native_resource_failures_require_full_results_and_live_identity() {
        let permission_denied = 1; // Darwin EPERM.
        task_result(96, 0).unwrap();
        for bytes in [-1, 0, 95, 97] {
            assert_eq!(
                task_result(bytes, permission_denied).unwrap_err().kind,
                "resource_observation"
            );
        }
        assert_eq!(
            task_result(0, DARWIN_ESRCH).unwrap_err().kind,
            "resource_process_exit"
        );
        assert_eq!(
            task_result(95, DARWIN_ESRCH).unwrap_err().kind,
            "resource_observation"
        );
        rusage_result(0, 0, 1, 0).unwrap();
        assert_eq!(
            rusage_result(-1, permission_denied, 0, 0).unwrap_err().kind,
            "resource_observation"
        );
        assert_eq!(
            rusage_result(-1, DARWIN_ESRCH, 0, 0).unwrap_err().kind,
            "resource_process_exit"
        );
        assert_eq!(
            rusage_result(0, 0, 0, 0).unwrap_err().kind,
            "resource_observation"
        );
        assert_eq!(
            rusage_result(0, 0, 1, 2).unwrap_err().kind,
            "resource_process_exit"
        );
    }
    #[test]
    fn late_complete_sample_retains_usage_without_refreshing_success() {
        let mut tracker = Tracker::new(small()).unwrap();
        tracker.last_success = Instant::now() - Duration::from_millis(1001);
        let prior_success = tracker.last_success;
        let mut sample = Sample::default();
        sample.push(small()).unwrap();
        assert_eq!(
            tracker.finish(sample).unwrap_err().kind,
            "resource_observation"
        );
        assert_eq!(tracker.last_success, prior_success);
        assert_eq!(
            tracker.evidence.peak_observed_adjusted_vm_bytes,
            small().adjusted_vm
        );
        assert_eq!(tracker.evidence.sample_count, 1);
    }
    #[test]
    fn vm_is_per_pid_and_resident_budgets_include_every_live_member() {
        let half = Memory {
            rss: MEMORY_LIMIT / 2,
            footprint: MEMORY_LIMIT / 2,
            ..small()
        };
        let mut sample = Sample::default();
        sample.push(half).unwrap();
        sample.push(half).unwrap();
        // Two normal Darwin reservations total >512GiB; only each PID's
        // adjusted VM is bounded, while physical measurements are summed.
        sample.check().unwrap();
        sample
            .push(Memory {
                rss: 1,
                footprint: 0,
                ..small()
            })
            .unwrap();
        assert_eq!(sample.check().unwrap_err().kind, "resource_budget");
    }
    #[test]
    fn exactly_one_second_is_fresh_and_any_excess_fails() {
        let mut tracker = Tracker::new(small()).unwrap();
        let origin = tracker.last_success;
        tracker.gap(origin + MAX_GAP).unwrap();
        assert_eq!(
            tracker
                .gap(origin + MAX_GAP + Duration::from_nanos(1))
                .unwrap_err()
                .kind,
            "resource_observation"
        );
        assert_eq!(tracker.last_success, origin);
    }
}
