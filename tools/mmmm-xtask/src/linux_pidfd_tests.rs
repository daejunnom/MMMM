use super::super::{Sample, Stat, metadata, push, settle_member_with_terminal};
use super::*;

#[cfg(target_os = "linux")]
#[path = "linux_pidfd_lifecycle_tests.rs"]
mod native_lifecycle;

// Existing stat fixtures cannot exercise the private fdinfo / pidfd gate.
// These pure tests construct no kernel proof and claim no native validation.
fn stat() -> Stat {
    Stat {
        identity: Identity {
            pid: 123,
            start_ticks: 456,
            group: 123,
            session: 123,
        },
        state: b'R',
        threads: 2,
        virtual_bytes: 8192,
    }
}

#[test]
fn fdinfo_requires_one_positive_canonical_pid_within_the_byte_bound() {
    assert_eq!(
        fdinfo_pid(b"pos:\t0\nflags:\t02000002\nPid:\t123\nNSpid:\t123\n"),
        Some(123)
    );
    for invalid in [
        b"Pid:\t0\n".as_slice(),
        b"Pid:\t-1\n".as_slice(),
        b"Pid:\t0123\n".as_slice(),
        b"Pid:\t+123\n".as_slice(),
        b"Pid:\t2147483648\n".as_slice(),
        b"Pid:\t123 456\n".as_slice(),
        b"Pid:\t123\nPid:\t123\n".as_slice(),
        b"Pid:\t123\nPid:\t0\n".as_slice(),
        b"Pid:\t\n".as_slice(),
        b"NSpid:\t123\n".as_slice(),
    ] {
        assert_eq!(fdinfo_pid(invalid), None);
    }
    let mut oversized = b"Pid:\t123\n".to_vec();
    oversized.resize(FDINFO_BYTES + 1, b'x');
    assert_eq!(fdinfo_pid(&oversized), None);
    oversized.truncate(FDINFO_BYTES);
    assert_eq!(fdinfo_pid(&oversized), Some(123));
}

#[test]
fn self_link_mapping_rejects_noncanonical_or_truncated_identity() {
    assert_eq!(canonical_positive_pid(b"1"), Some(1));
    assert_eq!(canonical_positive_pid(b"2147483647"), Some(i32::MAX));
    for invalid in [
        b"".as_slice(),
        b"0",
        b"01",
        b"123\n",
        b"123/",
        b"-1",
        b"+1",
        b"2147483648",
        b"99999999999",
    ] {
        assert_eq!(canonical_positive_pid(invalid), None);
    }
}

#[test]
fn poll_accepts_only_one_ready_descriptor_with_known_process_terminal_bits() {
    for accepted in [
        POLL_IN,
        POLL_IN | POLL_RDNORM,
        POLL_IN | POLL_HUP,
        POLL_IN | POLL_RDNORM | POLL_HUP,
    ] {
        assert_eq!(classify_poll(1, accepted), PollObservation::Terminal);
    }
    assert_eq!(classify_poll(0, 0), PollObservation::NotReady);
    // Cover every possible returned bit pattern, including signed high bits.
    for raw in 0..=u16::MAX {
        let events = raw as i16;
        let terminal = [0x0001u16, 0x0011, 0x0041, 0x0051].contains(&raw);
        assert_eq!(
            classify_poll(1, events) == PollObservation::Terminal,
            terminal
        );
        assert_ne!(classify_poll(-1, events), PollObservation::Terminal);
        assert_ne!(classify_poll(2, events), PollObservation::Terminal);
        assert_ne!(classify_poll(0, events), PollObservation::Terminal);
    }
    assert_eq!(classify_poll(1, POLL_HUP), PollObservation::Unknown);
}

#[test]
fn terminal_witness_cannot_cross_any_full_identity_component() {
    let original = stat().identity;
    let witness = TerminalWitness { identity: original };
    assert!(witness.matches(original, original));
    for changed in [
        Identity {
            pid: original.pid + 1,
            ..original
        },
        Identity {
            start_ticks: original.start_ticks + 1,
            ..original
        },
        Identity {
            group: original.group + 1,
            ..original
        },
        Identity {
            session: original.session + 1,
            ..original
        },
    ] {
        assert!(!witness.matches(original, changed));
        assert!(!witness.matches(changed, original));
    }
}

#[test]
fn matching_terminal_witness_settles_only_the_identified_rss_failure() {
    let before = stat();
    let witness = TerminalWitness {
        identity: before.identity,
    };
    assert!(
        settle_member_with_terminal(
            before,
            Some(before),
            Some(Err(metadata("original RSS error"))),
            false,
            Some(&witness)
        )
        .unwrap()
        .is_none()
    );
    let other = TerminalWitness {
        identity: Identity {
            start_ticks: before.identity.start_ticks + 1,
            ..before.identity
        },
    };
    for witness in [None, Some(&other)] {
        let error = settle_member_with_terminal(
            before,
            Some(before),
            Some(Err(metadata("original RSS error"))),
            false,
            witness,
        )
        .unwrap_err();
        assert_eq!(error.kind, "resource_observation");
        assert_eq!(error.message, "original RSS error");
    }
}

#[test]
fn terminal_witness_never_repairs_a_lost_or_replaced_leader_reservation() {
    let before = stat();
    let witness = TerminalWitness {
        identity: before.identity,
    };
    for after in [
        None,
        Some(Stat {
            identity: Identity {
                start_ticks: before.identity.start_ticks + 1,
                ..before.identity
            },
            ..before
        }),
    ] {
        let error = settle_member_with_terminal(
            before,
            after,
            Some(Err(metadata("RSS missing"))),
            true,
            Some(&witness),
        )
        .unwrap_err();
        assert_eq!(error.kind, "process_identity");
    }
}

#[test]
fn measured_rss_and_vm_remain_in_peaks_when_kernel_terminal_is_known() {
    let before = stat();
    let after = Stat {
        virtual_bytes: before.virtual_bytes * 2,
        ..before
    };
    let witness = TerminalWitness {
        identity: before.identity,
    };
    let measured = 2 * 1024 * 1024 * 1024 + 1;
    let member = settle_member_with_terminal(
        before,
        Some(after),
        Some(Ok(measured)),
        false,
        Some(&witness),
    )
    .unwrap()
    .unwrap();
    assert!(!member.live);
    assert_eq!(member.rss, Some(measured));
    let mut sample = Sample {
        live_processes: 0,
        aggregate_rss_bytes: Some(0),
        max_virtual_bytes: 0,
    };
    push(&mut sample, member).unwrap();
    assert_eq!(sample.live_processes, 0);
    assert_eq!(sample.aggregate_rss_bytes, Some(measured));
    assert_eq!(sample.max_virtual_bytes, after.virtual_bytes);
}
