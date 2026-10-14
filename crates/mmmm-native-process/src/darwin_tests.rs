use super::*;

#[test]
fn complete_task_bytes_are_required_even_when_errno_suggests_exit() {
    classify_task_result(96, 0).unwrap();
    classify_task_result(96, DARWIN_ESRCH).unwrap();
    for bytes in [-1, 0, 95, 97] {
        let error = classify_task_result(bytes, 1).unwrap_err();
        assert_eq!(error.stage, NativeResourceStage::TaskInfo);
        assert_ne!(error.failure, NativeResourceFailure::Exited);
        assert_eq!((error.native_result, error.native_errno), (bytes, 1));
    }
    let exited = classify_task_result(0, DARWIN_ESRCH).unwrap_err();
    assert_eq!(exited.failure, NativeResourceFailure::Exited);
    for bytes in [-1, 1, 95, 97] {
        assert_ne!(
            classify_task_result(bytes, DARWIN_ESRCH)
                .unwrap_err()
                .failure,
            NativeResourceFailure::Exited,
        );
    }
}

#[test]
fn only_a_successful_started_unexited_rusage_is_usable() {
    classify_rusage_result(0, 0, 1, 0).unwrap();
    let unavailable = classify_rusage_result(-1, 1, 1, 0).unwrap_err();
    assert_eq!(unavailable.failure, NativeResourceFailure::Unavailable);
    assert_eq!(
        (unavailable.native_result, unavailable.native_errno),
        (-1, 1)
    );
    assert_eq!(
        classify_rusage_result(-1, DARWIN_ESRCH, 0, 0)
            .unwrap_err()
            .failure,
        NativeResourceFailure::Exited,
    );
    for exit in [0, 1] {
        assert_eq!(
            classify_rusage_result(0, 0, 0, exit).unwrap_err().failure,
            NativeResourceFailure::Malformed,
        );
    }
    let exited = classify_rusage_result(0, 0, 1, 2).unwrap_err();
    assert_eq!(exited.stage, NativeResourceStage::Rusage);
    assert_eq!(exited.failure, NativeResourceFailure::Exited);
    assert_eq!((exited.native_result, exited.native_errno), (0, 0));

    for (result, number, start, exit) in [
        (-1, DARWIN_ESRCH, 11, 12),
        (-1, 1, 11, 12),
        (0, 0, 0, 12),
        (0, 0, 11, 12),
        (0, 1, 11, 12),
    ] {
        let task = TaskInfo {
            virtual_size: 17,
            resident_size: 23,
            times: [0; 4],
            counters: [0; 12],
        };
        let usage = RusageInfoV0 {
            uuid: [0; 16],
            times_and_counts: [0; 6],
            resident_size: u64::MAX,
            phys_footprint: u64::MAX,
            start_abstime: start,
            exit_abstime: exit,
        };
        let partial = finish_rusage_observation(task, usage, result, number).unwrap_err();
        // The strict API maps the same failure back to precisely the original
        // four fields, without a second observation or a weaker classification.
        assert_eq!(
            partial.native_error(),
            classify_rusage_result(result, number, start, exit).unwrap_err()
        );
        let lower = partial.task_lower_bound().unwrap();
        assert_eq!((lower.adjusted_vm(), lower.rss()), (17, 23));
        assert_eq!(
            partial.rusage_timestamps(),
            (result == 0).then_some(RusageTimestampObservation {
                start_observed: start != 0,
                exit_observed: exit != 0,
            })
        );
    }
    let task_failure = MemoryObservationFailure::without_partial(
        classify_task_result(0, DARWIN_ESRCH).unwrap_err(),
    );
    assert!(task_failure.task_lower_bound().is_none());
    assert!(task_failure.rusage_timestamps().is_none());
}

#[test]
fn observation_keeps_native_start_and_distinct_memory_quantities() {
    let task = TaskInfo {
        virtual_size: 400 * 1024 * 1024 * 1024,
        resident_size: 512,
        times: [0; 4],
        counters: [0; 12],
    };
    let usage = RusageInfoV0 {
        uuid: [7; 16],
        times_and_counts: [0; 6],
        resident_size: 1024,
        phys_footprint: 256,
        start_abstime: 42,
        exit_abstime: 0,
    };
    assert_eq!(
        finish_rusage_observation(task, usage, 0, 0).unwrap(),
        MemoryObservation {
            adjusted_vm: 400 * 1024 * 1024 * 1024,
            rss: 1024,
            footprint: 256,
            start_abstime: 42,
        },
    );
}

#[test]
fn resident_measure_never_drops_the_larger_task_value() {
    let task = TaskInfo {
        virtual_size: 1,
        resident_size: u64::MAX,
        times: [0; 4],
        counters: [0; 12],
    };
    let usage = RusageInfoV0 {
        uuid: [0; 16],
        times_and_counts: [0; 6],
        resident_size: 1,
        phys_footprint: 2,
        start_abstime: u64::MAX,
        exit_abstime: 0,
    };
    let actual = complete_observation(task, usage);
    assert_eq!(actual.rss, u64::MAX);
    assert_eq!(actual.start_abstime, u64::MAX);
    for value in [0, u64::MAX] {
        let task = TaskInfo {
            virtual_size: value,
            resident_size: value,
            times: [0; 4],
            counters: [0; 12],
        };
        let usage = RusageInfoV0 {
            uuid: [0; 16],
            times_and_counts: [0; 6],
            resident_size: u64::MAX,
            phys_footprint: u64::MAX,
            start_abstime: 1,
            exit_abstime: 2,
        };
        let partial = finish_rusage_observation(task, usage, 0, 0).unwrap_err();
        let lower = partial.task_lower_bound().unwrap();
        assert_eq!((lower.adjusted_vm(), lower.rss()), (value, value));
    }
}

#[test]
fn errors_have_closed_static_fields_and_numeric_native_results() {
    fn assert_error_bounds<T: std::error::Error + Send + Sync + 'static>() {}
    assert_error_bounds::<NativeResourceError>();
    let error = classify_task_result(95, 1).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Darwin resource observation; stage=task_info; failure=malformed; native_result=95; errno=1",
    );
    assert_eq!(
        NativeResourceStage::ProcessIdentifier.as_str(),
        "process_identifier"
    );
    assert_eq!(
        NativeResourceFailure::InvalidProcessIdentifier.as_str(),
        "invalid_process_identifier"
    );
}
