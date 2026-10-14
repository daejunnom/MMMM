//! Darwin memory observations and all-platform native-result classification.
//!
//! The two C layouts and flavors below follow Apple's public XNU
//! `xnu-11417.140.69` headers, rather than a private or later rusage flavor:
//! - `bsd/sys/proc_info.h`: `proc_taskinfo`, `PROC_PIDTASKINFO = 4`.
//! - `bsd/sys/resource.h`: `rusage_info_v0`, `RUSAGE_INFO_V0 = 0`.
//! - `libsyscall/wrappers/libproc/libproc.h`: both function declarations.
//!
//! A successful result is two sequential observations, not an atomic process
//! snapshot. The caller must surround it with its own native identity checks
//! and compare the returned rusage start identity where its lifecycle requires
//! a fixed process. An exit-class error does not prove a zombie or drain.

use std::fmt;

pub const TASK_INFO_FLAVOR: i32 = 4;
pub const RUSAGE_INFO_FLAVOR: i32 = 0;
const TASK_INFO_BYTES: i32 = 96;
// Darwin errno.h, deliberately independent of the host running pure tests.
const DARWIN_ESRCH: i32 = 3;

/// Distinct native memory quantities. None is an installed resource quota.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryObservation {
    /// The task's reported virtual size in bytes.
    pub adjusted_vm: u64,
    /// Maximum of the task-info and rusage current resident sizes in bytes.
    pub rss: u64,
    /// The current rusage physical footprint in bytes; not its lifetime peak.
    pub footprint: u64,
    /// Actual `ri_proc_start_abstime`; opaque native identity, not wall time.
    pub start_abstime: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeResourceStage {
    ProcessIdentifier,
    TaskInfo,
    Rusage,
}
impl NativeResourceStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessIdentifier => "process_identifier",
            Self::TaskInfo => "task_info",
            Self::Rusage => "rusage",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeResourceFailure {
    InvalidProcessIdentifier,
    Unavailable,
    Malformed,
    /// Requires independent confirmation of the same owned native zombie.
    Exited,
}
impl NativeResourceFailure {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProcessIdentifier => "invalid_process_identifier",
            Self::Unavailable => "unavailable",
            Self::Malformed => "malformed",
            Self::Exited => "exit_requires_identity_confirmation",
        }
    }
}

/// Closed diagnostic fields; no process identifier, path or OS error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeResourceError {
    pub stage: NativeResourceStage,
    pub failure: NativeResourceFailure,
    pub native_result: i32,
    pub native_errno: i32,
}
impl fmt::Display for NativeResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Darwin resource observation; stage={}; failure={}; native_result={}; errno={}",
            self.stage.as_str(),
            self.failure.as_str(),
            self.native_result,
            self.native_errno,
        )
    }
}
impl std::error::Error for NativeResourceError {}

/// Only the fields obtained from a complete task-info result. This cannot
/// supply a rusage footprint or a process start identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskMemoryLowerBound {
    adjusted_vm: u64,
    rss: u64,
}
impl TaskMemoryLowerBound {
    pub const fn adjusted_vm(self) -> u64 {
        self.adjusted_vm
    }
    pub const fn rss(self) -> u64 {
        self.rss
    }
}

/// Presence of timestamps in an actual successful rusage return. These
/// booleans do not expose or establish the process's current start identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RusageTimestampObservation {
    start_observed: bool,
    exit_observed: bool,
}
impl RusageTimestampObservation {
    pub const fn start_observed(self) -> bool {
        self.start_observed
    }
    pub const fn exit_observed(self) -> bool {
        self.exit_observed
    }
}

/// A failed memory observation with only facts already obtained by the same
/// native query sequence. Construction stays inside this producer. Callers
/// must still independently establish identity and their own pending policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryObservationFailure {
    native: NativeResourceError,
    task_lower_bound: Option<TaskMemoryLowerBound>,
    rusage_timestamps: Option<RusageTimestampObservation>,
}
impl MemoryObservationFailure {
    pub const fn native_error(self) -> NativeResourceError {
        self.native
    }
    pub const fn task_lower_bound(self) -> Option<TaskMemoryLowerBound> {
        self.task_lower_bound
    }
    pub const fn rusage_timestamps(self) -> Option<RusageTimestampObservation> {
        self.rusage_timestamps
    }
    #[cfg(any(target_os = "macos", test))]
    fn without_partial(native: NativeResourceError) -> Self {
        Self {
            native,
            task_lower_bound: None,
            rusage_timestamps: None,
        }
    }
}

/// Validate the entire `proc_pidinfo(PROC_PIDTASKINFO)` return value.
/// A partial result is never an exit witness, even when errno is ESRCH.
pub fn classify_task_result(bytes: i32, number: i32) -> Result<(), NativeResourceError> {
    if bytes == TASK_INFO_BYTES {
        return Ok(());
    }
    let failure = if bytes == 0 && number == DARWIN_ESRCH {
        NativeResourceFailure::Exited
    } else if bytes <= 0 {
        NativeResourceFailure::Unavailable
    } else {
        NativeResourceFailure::Malformed
    };
    Err(NativeResourceError {
        stage: NativeResourceStage::TaskInfo,
        failure,
        native_result: bytes,
        native_errno: number,
    })
}

/// Validate `proc_pid_rusage(RUSAGE_INFO_V0)` before using any memory fields.
/// A successful call must identify a started process with no exit timestamp.
pub fn classify_rusage_result(
    result: i32,
    number: i32,
    start_abstime: u64,
    exit_abstime: u64,
) -> Result<(), NativeResourceError> {
    let failure = if result != 0 {
        if number == DARWIN_ESRCH {
            NativeResourceFailure::Exited
        } else {
            NativeResourceFailure::Unavailable
        }
    } else if start_abstime == 0 {
        NativeResourceFailure::Malformed
    } else if exit_abstime != 0 {
        NativeResourceFailure::Exited
    } else {
        return Ok(());
    };
    Err(NativeResourceError {
        stage: NativeResourceStage::Rusage,
        failure,
        native_result: result,
        native_errno: number,
    })
}

#[repr(C)]
#[cfg(any(target_os = "macos", test))]
struct TaskInfo {
    virtual_size: u64,
    resident_size: u64,
    times: [u64; 4],
    counters: [i32; 12],
}

#[repr(C)]
#[cfg(any(target_os = "macos", test))]
struct RusageInfoV0 {
    uuid: [u8; 16],
    times_and_counts: [u64; 6],
    resident_size: u64,
    phys_footprint: u64,
    start_abstime: u64,
    exit_abstime: u64,
}

#[cfg(any(target_os = "macos", test))]
const _: () = {
    assert!(std::mem::size_of::<TaskInfo>() == TASK_INFO_BYTES as usize);
    assert!(std::mem::offset_of!(TaskInfo, resident_size) == 8);
    assert!(std::mem::offset_of!(TaskInfo, times) == 16);
    assert!(std::mem::offset_of!(TaskInfo, counters) == 48);
    assert!(std::mem::size_of::<RusageInfoV0>() == 96);
    assert!(std::mem::offset_of!(RusageInfoV0, resident_size) == 64);
    assert!(std::mem::offset_of!(RusageInfoV0, phys_footprint) == 72);
    assert!(std::mem::offset_of!(RusageInfoV0, start_abstime) == 80);
    assert!(std::mem::offset_of!(RusageInfoV0, exit_abstime) == 88);
};

#[cfg(target_os = "macos")]
const _: () = {
    assert!(std::mem::size_of::<*mut std::ffi::c_void>() == 8);
    assert!(std::mem::align_of::<TaskInfo>() == 8);
    assert!(std::mem::align_of::<RusageInfoV0>() == 8);
};

#[cfg(any(target_os = "macos", test))]
fn complete_observation(task: TaskInfo, usage: RusageInfoV0) -> MemoryObservation {
    MemoryObservation {
        adjusted_vm: task.virtual_size,
        rss: task.resident_size.max(usage.resident_size),
        footprint: usage.phys_footprint,
        start_abstime: usage.start_abstime,
    }
}

#[cfg(any(target_os = "macos", test))]
fn finish_rusage_observation(
    task: TaskInfo,
    usage: RusageInfoV0,
    result: i32,
    number: i32,
) -> Result<MemoryObservation, MemoryObservationFailure> {
    classify_rusage_result(result, number, usage.start_abstime, usage.exit_abstime).map_err(
        |native| MemoryObservationFailure {
            native,
            task_lower_bound: Some(TaskMemoryLowerBound {
                adjusted_vm: task.virtual_size,
                rss: task.resident_size,
            }),
            // A failed call may have left arbitrary output in its buffer.
            rusage_timestamps: (result == 0).then_some(RusageTimestampObservation {
                start_observed: usage.start_abstime != 0,
                exit_observed: usage.exit_abstime != 0,
            }),
        },
    )?;
    Ok(complete_observation(task, usage))
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut std::ffi::c_void,
        bytes: i32,
    ) -> i32;
    // Public libproc declares rusage_info_t as void*, then takes its pointer.
    // The caller supplies storage for the selected rusage structure.
    fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut *mut std::ffi::c_void) -> i32;
}

/// Observe one positive PID with the public task-info and rusage V0 APIs.
///
/// This performs no allocation, retry, sleep, process signaling or policy
/// mutation. Native calls are synchronous and cannot enforce a caller's
/// deadline; the caller must check its original deadline before and after.
#[cfg(target_os = "macos")]
pub fn observe_memory(pid: i32) -> Result<MemoryObservation, NativeResourceError> {
    observe_memory_with_partial(pid).map_err(MemoryObservationFailure::native_error)
}

/// The same strict native observation, retaining task-info lower bounds when
/// rusage fails. A partial failure remains an error, never a complete sample.
/// No native query is repeated for either API.
#[cfg(target_os = "macos")]
pub fn observe_memory_with_partial(
    pid: i32,
) -> Result<MemoryObservation, MemoryObservationFailure> {
    if pid <= 0 {
        return Err(MemoryObservationFailure::without_partial(
            NativeResourceError {
                stage: NativeResourceStage::ProcessIdentifier,
                failure: NativeResourceFailure::InvalidProcessIdentifier,
                native_result: 0,
                native_errno: 0,
            },
        ));
    }
    let mut task: TaskInfo = unsafe { std::mem::zeroed() };
    let mut usage: RusageInfoV0 = unsafe { std::mem::zeroed() };
    // Capture each call's errno immediately, before any other native call.
    let (bytes, task_errno) = unsafe {
        *libc::__error() = 0;
        let bytes = proc_pidinfo(
            pid,
            TASK_INFO_FLAVOR,
            0,
            (&mut task as *mut TaskInfo).cast(),
            TASK_INFO_BYTES,
        );
        (bytes, *libc::__error())
    };
    classify_task_result(bytes, task_errno).map_err(MemoryObservationFailure::without_partial)?;
    let (result, usage_errno) = unsafe {
        *libc::__error() = 0;
        let result = proc_pid_rusage(
            pid,
            RUSAGE_INFO_FLAVOR,
            (&mut usage as *mut RusageInfoV0).cast(),
        );
        (result, *libc::__error())
    };
    finish_rusage_observation(task, usage, result, usage_errno)
}

#[cfg(test)]
#[path = "darwin_tests.rs"]
mod tests;
