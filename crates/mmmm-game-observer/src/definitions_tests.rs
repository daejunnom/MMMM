// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors

use super::*;

const THREAD: u64 = 10;
const LOADER: u64 = 20;
const CLASS: u64 = 30;

fn ordinary(core: &mut RecordingCore, thread: u64, name: &[u8]) -> AttemptId {
    core.begin(
        thread,
        LOADER,
        Some(name.to_vec()),
        DefinitionKind::Ordinary,
        None,
        false,
    )
    .unwrap()
}

fn snapshot() -> ExecutableSnapshot {
    ExecutableSnapshot {
        constant_pool_count: 3,
        constant_pool: vec![1, 0, 1, b'A', 7, 0, 1],
        methods: vec![
            MethodSnapshot {
                name_mutf8: b"run".to_vec(),
                descriptor_mutf8: b"()V".to_vec(),
                modifiers: 1,
                code: MethodCode::Bytecodes(vec![0xb1]),
            },
            MethodSnapshot {
                name_mutf8: b"nativeCall".to_vec(),
                descriptor_mutf8: b"()V".to_vec(),
                modifiers: 0x100,
                code: MethodCode::Native,
            },
            MethodSnapshot {
                name_mutf8: b"abstractCall".to_vec(),
                descriptor_mutf8: b"()V".to_vec(),
                modifiers: 0x400,
                code: MethodCode::Abstract,
            },
        ],
    }
}

fn recipe() -> HiddenRecipe {
    HiddenRecipe {
        input: vec![0xca, 0xfe, 0xba, 0xbe],
        flags: 0x2,
        initialize: false,
        lookup_class_id: 40,
        defining_loader_id: LOADER,
        requested_name_mutf8: b"sample/Hidden".to_vec(),
    }
}

fn ready_ordinary(core: &mut RecordingCore, class: u64) {
    let token = ordinary(core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![0xca, 0xfe])
        .unwrap();
    core.class_load(THREAD, class, LOADER, b"sample.A".to_vec())
        .unwrap();
    core.finish(THREAD, token, Some(class), false).unwrap();
    core.class_prepare(99, class, LOADER, b"sample.A".to_vec(), None)
        .unwrap();
}

fn ready_ordinary_source(core: &mut RecordingCore, class: u64) {
    let token = ordinary(core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![0xca, 0xfe])
        .unwrap();
    core.class_load(THREAD, class, LOADER, b"sample.A".to_vec())
        .unwrap();
    core.finish(THREAD, token, Some(class), false).unwrap();
    core.class_prepare(99, class, LOADER, b"sample.A".to_vec(), Some(snapshot()))
        .unwrap();
}

#[test]
fn ordinary_source_borrows_exact_prepared_record_without_changing_evidence() {
    let mut core = RecordingCore::new(7);
    ready_ordinary_source(&mut core, CLASS);
    let before = core.encode_evidence(CLASS).unwrap();
    let bytes = core.retained_bytes();
    let source = core
        .with_ordinary_source(7, CLASS, 1, LOADER, |source| {
            assert_eq!(source.identity(), (7, CLASS, 1, LOADER));
            assert_eq!(source.name_utf8(), b"sample.A");
            assert_eq!(source.terminal_bytes(), &[0xca, 0xfe]);
            assert_eq!(source.snapshot(), &snapshot());
            (
                source.terminal_bytes().as_ptr() as usize,
                source.snapshot() as *const ExecutableSnapshot as usize,
            )
        })
        .unwrap();
    let record = &core.records[&CLASS];
    assert_eq!(source.0, record.terminal_bytes.as_ptr() as usize);
    assert_eq!(
        source.1,
        record.snapshot.as_ref().unwrap() as *const ExecutableSnapshot as usize
    );
    assert_eq!(core.retained_bytes(), bytes);
    assert_eq!(core.encode_evidence(CLASS).unwrap(), before);
}

#[test]
fn ordinary_source_rejects_wrong_stamp_and_unavailable_source_without_calling_matcher() {
    let mut core = RecordingCore::new(7);
    ready_ordinary_source(&mut core, CLASS);
    let before = core.encode_evidence(CLASS).unwrap();
    for (issuer, class, generation, loader) in [
        (0, CLASS, 1, LOADER),
        (8, CLASS, 1, LOADER),
        (7, CLASS + 1, 1, LOADER),
        (7, CLASS, 2, LOADER),
        (7, CLASS, 1, LOADER + 1),
    ] {
        assert!(
            core.with_ordinary_source::<()>(issuer, class, generation, loader, |_| {
                panic!("a mismatched source must not reach the matcher")
            })
            .is_none()
        );
    }
    assert_eq!(core.encode_evidence(CLASS).unwrap(), before);
    core.invalidate_class(CLASS);
    assert!(
        core.with_ordinary_source(7, CLASS, 1, LOADER, |_| ())
            .is_none()
    );

    let mut no_snapshot = RecordingCore::new(7);
    ready_ordinary(&mut no_snapshot, CLASS);
    assert!(
        no_snapshot
            .with_ordinary_source(7, CLASS, 1, LOADER, |_| ())
            .is_none()
    );
    let mut exhausted = RecordingCore::new(7);
    ready_ordinary_source(&mut exhausted, CLASS);
    exhausted.exhausted = true;
    assert!(
        exhausted
            .with_ordinary_source(7, CLASS, 1, LOADER, |_| ())
            .is_none()
    );
}

#[test]
fn ordinary_requires_exact_return_identity_and_prepare_even_after_native_return() {
    let mut core = RecordingCore::new(7);
    let token = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1, 2, 3])
        .unwrap();
    core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec())
        .unwrap();
    core.finish(THREAD, token, Some(CLASS), false).unwrap();
    assert!(core.contains_class(CLASS));
    assert!(core.needs_snapshot(CLASS));
    assert!(
        core.with_ordinary_source(7, CLASS, 1, LOADER, |_| ())
            .is_none()
    );
    assert_eq!(
        core.encode_evidence(CLASS),
        Err(RecordingError::NotPrepared)
    );
    assert!(matches!(
        core.encode_evidence_with_stamp(CLASS),
        Err(RecordingError::NotPrepared)
    ));
    core.class_prepare(99, CLASS, LOADER, b"sample.A".to_vec(), None)
        .unwrap();
    let encoded = core.encode_evidence(CLASS).unwrap();
    assert_eq!(&encoded[..8], b"MMMMDEF1");
    assert_eq!(encoded[8], 1);
    assert_eq!(encoded[9], 1);
    assert_eq!(
        u64::from_be_bytes(encoded[12..20].try_into().unwrap()),
        CLASS
    );
    assert_eq!(u64::from_be_bytes(encoded[20..28].try_into().unwrap()), 1);
    assert_eq!(
        u64::from_be_bytes(encoded[28..36].try_into().unwrap()),
        token.raw()
    );
    assert_eq!(u64::from_be_bytes(encoded[36..44].try_into().unwrap()), 7);
    let mut cursor = 44;
    assert_eq!(read_sized(&encoded, &mut cursor), b"sample.A");
    assert_eq!(read_sized(&encoded, &mut cursor), &[1, 2, 3]);
    assert!(read_sized(&encoded, &mut cursor).is_empty());
    assert_eq!(read_u32(&encoded, &mut cursor), 0);
    assert_eq!(&encoded[cursor..cursor + 4], &[0, 0, 0, 0]);
    cursor += 4;
    assert_eq!(read_u64(&encoded, &mut cursor), 0);
    assert_eq!(read_u64(&encoded, &mut cursor), LOADER);
    assert!(read_sized(&encoded, &mut cursor).is_empty());
    assert!(!core.needs_snapshot(CLASS));
}

#[test]
fn ordinary_same_name_definitions_preserve_distinct_and_bootstrap_loader_identities() {
    let mut core = RecordingCore::new(7);
    for (class, loader) in [
        (CLASS, LOADER),
        (CLASS + 1, LOADER + 1),
        (CLASS + 2, 0),
        (CLASS + 3, u64::MAX),
    ] {
        let token = core
            .begin(
                THREAD,
                loader,
                Some(b"sample/A".to_vec()),
                DefinitionKind::Ordinary,
                None,
                false,
            )
            .unwrap();
        core.terminal_hook(THREAD, loader, Some(b"sample/A"), vec![1])
            .unwrap();
        core.class_load(THREAD, class, loader, b"sample.A".to_vec())
            .unwrap();
        core.finish(THREAD, token, Some(class), false).unwrap();
        core.class_prepare(99, class, loader, b"sample.A".to_vec(), None)
            .unwrap();
        let encoded = core.encode_evidence(class).unwrap();
        assert_eq!(
            u64::from_be_bytes(encoded[12..20].try_into().unwrap()),
            class
        );
        assert_eq!(u64::from_be_bytes(encoded[20..28].try_into().unwrap()), 1);
        let mut cursor = 44;
        assert_eq!(read_sized(&encoded, &mut cursor), b"sample.A");
        assert_eq!(read_sized(&encoded, &mut cursor), &[1]);
        assert!(read_sized(&encoded, &mut cursor).is_empty());
        assert_eq!(read_u32(&encoded, &mut cursor), 0);
        cursor += 4;
        assert_eq!(read_u64(&encoded, &mut cursor), 0);
        assert_eq!(read_u64(&encoded, &mut cursor), loader);
        assert_eq!(core.ordinary_generation(class), Some(1));
    }
}

#[test]
fn issued_evidence_stamp_rejects_redefinition_after_encoding() {
    let mut core = RecordingCore::new(7);
    ready_ordinary(&mut core, CLASS);
    let (encoded, stamp) = core.encode_evidence_with_stamp(CLASS).unwrap();
    assert_eq!(encoded, core.encode_evidence(CLASS).unwrap());
    assert!(core.evidence_stamp_is_current(&stamp));
    core.invalidate_class(CLASS);
    assert!(!core.evidence_stamp_is_current(&stamp));
    assert_eq!(core.records[&CLASS].generation, 2);
    assert!(matches!(
        core.encode_evidence_with_stamp(CLASS),
        Err(RecordingError::Invalidated)
    ));
}

#[test]
fn issued_evidence_stamp_binds_issuer_class_attempt_and_loader() {
    fn recorded(epoch: u64, class: u64, loader: u64, earlier_attempt: bool) -> RecordingCore {
        let mut core = RecordingCore::new(epoch);
        if earlier_attempt {
            let token = core
                .begin(THREAD, loader, None, DefinitionKind::Ordinary, None, false)
                .unwrap();
            assert!(core.finish(THREAD, token, None, true).is_err());
        }
        let token = core
            .begin(
                THREAD,
                loader,
                Some(b"sample/A".to_vec()),
                DefinitionKind::Ordinary,
                None,
                false,
            )
            .unwrap();
        core.terminal_hook(THREAD, loader, Some(b"sample/A"), vec![1])
            .unwrap();
        core.class_load(THREAD, class, loader, b"sample.A".to_vec())
            .unwrap();
        core.finish(THREAD, token, Some(class), false).unwrap();
        core.class_prepare(99, class, loader, b"sample.A".to_vec(), None)
            .unwrap();
        core
    }

    let core = recorded(7, CLASS, LOADER, false);
    let (_, stamp) = core.encode_evidence_with_stamp(CLASS).unwrap();
    assert!(core.evidence_stamp_is_current(&stamp));
    for changed in [
        recorded(8, CLASS, LOADER, false),
        recorded(7, CLASS + 1, LOADER, false),
        recorded(7, CLASS, LOADER + 1, false),
        recorded(7, CLASS, LOADER, true),
    ] {
        assert!(!changed.evidence_stamp_is_current(&stamp));
    }
}

#[test]
fn hidden_prepare_before_load_keeps_recipe_and_vm_snapshot_separate() {
    let mut core = RecordingCore::new(9);
    let token = core
        .begin(
            THREAD,
            LOADER,
            None,
            DefinitionKind::Hidden,
            Some(recipe()),
            true,
        )
        .unwrap();
    core.class_prepare(
        THREAD,
        CLASS,
        LOADER,
        b"sample.Hidden/0x1234".to_vec(),
        Some(snapshot()),
    )
    .unwrap();
    core.class_load(THREAD, CLASS, LOADER, b"sample.Hidden/0x1234".to_vec())
        .unwrap();
    core.finish(THREAD, token, Some(CLASS), false).unwrap();
    let encoded = core.encode_evidence(CLASS).unwrap();
    assert_eq!(encoded[8], 2);
    assert_eq!(encoded[9], 3);
    let mut cursor = 44;
    assert_eq!(read_sized(&encoded, &mut cursor), b"sample.Hidden/0x1234");
    assert!(read_sized(&encoded, &mut cursor).is_empty());
    assert_eq!(read_sized(&encoded, &mut cursor), &[0xca, 0xfe, 0xba, 0xbe]);
    assert_eq!(read_u32(&encoded, &mut cursor), 2);
    assert_eq!(&encoded[cursor..cursor + 4], &[0, 0, 0, 0]);
    cursor += 4;
    assert_eq!(read_u64(&encoded, &mut cursor), 40);
    assert_eq!(read_u64(&encoded, &mut cursor), LOADER);
    assert_eq!(read_sized(&encoded, &mut cursor), b"sample/Hidden");
    assert_eq!(read_u32(&encoded, &mut cursor), 3);
    assert_eq!(read_sized(&encoded, &mut cursor), &[1, 0, 1, b'A', 7, 0, 1]);
    assert_eq!(read_u32(&encoded, &mut cursor), 3);
    for (name, modifiers, code_kind, bytes) in [
        (b"run".as_slice(), 1, 0, vec![0xb1]),
        (b"nativeCall".as_slice(), 0x100, 1, vec![]),
        (b"abstractCall".as_slice(), 0x400, 2, vec![]),
    ] {
        assert_eq!(read_sized(&encoded, &mut cursor), name);
        assert_eq!(read_sized(&encoded, &mut cursor), b"()V");
        assert_eq!(read_u32(&encoded, &mut cursor), modifiers);
        assert_eq!(encoded[cursor], code_kind);
        cursor += 1;
        assert_eq!(read_sized(&encoded, &mut cursor), bytes.as_slice());
    }
    assert_eq!(cursor, encoded.len());
    let (stamped, stamp) = core.encode_evidence_with_stamp(CLASS).unwrap();
    assert_eq!(stamped, encoded);
    assert!(core.evidence_stamp_is_current(&stamp));
    core.invalidate_class(CLASS);
    assert!(!core.evidence_stamp_is_current(&stamp));
}

#[test]
fn nested_failed_duplicate_does_not_replace_outer_terminal_buffer() {
    let mut core = RecordingCore::new(1);
    let outer = ordinary(&mut core, THREAD, b"sample/B");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/B"), vec![0xb0])
        .unwrap();
    let nested = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![0xa0])
        .unwrap();
    assert_eq!(
        core.finish(THREAD, nested, None, true),
        Err(RecordingError::NativeException { class_effect: None })
    );
    core.class_load(THREAD, CLASS, LOADER, b"sample.B".to_vec())
        .unwrap();
    core.class_prepare(THREAD, CLASS, LOADER, b"sample.B".to_vec(), None)
        .unwrap();
    core.finish(THREAD, outer, Some(CLASS), false).unwrap();
    let encoded = core.encode_evidence(CLASS).unwrap();
    let mut cursor = 44;
    read_sized(&encoded, &mut cursor);
    assert_eq!(read_sized(&encoded, &mut cursor), &[0xb0]);
}

#[test]
fn returned_class_must_be_observed_within_same_attempt() {
    let mut core = RecordingCore::new(1);
    let token = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1])
        .unwrap();
    core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec())
        .unwrap();
    assert_eq!(
        core.finish(THREAD, token, Some(CLASS + 1), false),
        Err(RecordingError::ClassMismatch)
    );
    assert_eq!(
        core.encode_evidence(CLASS),
        Err(RecordingError::Unavailable)
    );
    assert_eq!(
        core.encode_evidence(CLASS + 1),
        Err(RecordingError::Unavailable)
    );
}

#[test]
fn failed_definition_with_class_effect_keeps_tombstone() {
    let mut core = RecordingCore::new(1);
    let first = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1])
        .unwrap();
    core.class_prepare(THREAD, CLASS, LOADER, b"sample.A".to_vec(), None)
        .unwrap();
    assert_eq!(
        core.finish(THREAD, first, None, true),
        Err(RecordingError::NativeException {
            class_effect: Some(CLASS)
        })
    );
    let second = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![2])
        .unwrap();
    assert_eq!(
        core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec()),
        Err(RecordingError::ExistingClass)
    );
    assert_eq!(
        core.finish(THREAD, second, Some(CLASS), false),
        Err(RecordingError::ExistingClass)
    );
    assert_eq!(
        core.encode_evidence(CLASS),
        Err(RecordingError::Unavailable)
    );
}

#[test]
fn class_created_outside_boundaries_cannot_be_adopted() {
    let mut core = RecordingCore::new(1);
    core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec())
        .unwrap();
    let token = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1])
        .unwrap();
    assert_eq!(
        core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec()),
        Err(RecordingError::ExistingClass)
    );
    assert_eq!(
        core.finish(THREAD, token, Some(CLASS), false),
        Err(RecordingError::ExistingClass)
    );
}

#[test]
fn duplicate_hook_or_changed_loader_taints_only_current_attempt() {
    for (loader, name, expected) in [
        (
            LOADER,
            b"sample/A".as_slice(),
            RecordingError::DuplicateHook,
        ),
        (
            LOADER + 1,
            b"sample/A".as_slice(),
            RecordingError::HookMismatch,
        ),
        (LOADER, b"sample/B".as_slice(), RecordingError::HookMismatch),
    ] {
        let mut core = RecordingCore::new(1);
        let token = ordinary(&mut core, THREAD, b"sample/A");
        if expected == RecordingError::DuplicateHook {
            core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1])
                .unwrap();
        }
        assert_eq!(
            core.terminal_hook(THREAD, loader, Some(name), vec![2]),
            Err(expected.clone())
        );
        core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec())
            .unwrap();
        assert_eq!(
            core.finish(THREAD, token, Some(CLASS), false),
            Err(expected)
        );
        ready_ordinary(&mut core, CLASS + 1);
        assert!(core.encode_evidence(CLASS + 1).is_ok());
    }
}

#[test]
fn hidden_hook_and_missing_snapshot_never_claim_classfile_evidence() {
    let mut core = RecordingCore::new(1);
    let token = core
        .begin(
            THREAD,
            LOADER,
            None,
            DefinitionKind::Hidden,
            Some(recipe()),
            true,
        )
        .unwrap();
    assert_eq!(
        core.terminal_hook(THREAD, LOADER, None, vec![1]),
        Err(RecordingError::UnexpectedHiddenHook)
    );
    core.class_prepare(
        THREAD,
        CLASS,
        LOADER,
        b"sample.Hidden/0x1".to_vec(),
        Some(snapshot()),
    )
    .unwrap();
    assert_eq!(
        core.finish(THREAD, token, Some(CLASS), false),
        Err(RecordingError::UnexpectedHiddenHook)
    );
    let token = core
        .begin(
            THREAD,
            LOADER,
            None,
            DefinitionKind::Hidden,
            Some(recipe()),
            true,
        )
        .unwrap();
    core.class_load(THREAD, CLASS + 1, LOADER, b"sample.Hidden/0x2".to_vec())
        .unwrap();
    assert_eq!(
        core.finish(THREAD, token, Some(CLASS + 1), false),
        Err(RecordingError::MissingHiddenSnapshot)
    );
    assert_eq!(
        core.encode_evidence(CLASS + 1),
        Err(RecordingError::Unavailable)
    );
}

#[test]
fn uncontrolled_input_snapshot_is_not_accepted_as_exact_hidden_recipe() {
    let mut core = RecordingCore::new(1);
    assert_eq!(
        core.begin(
            THREAD,
            LOADER,
            None,
            DefinitionKind::Hidden,
            Some(recipe()),
            false
        ),
        Err(RecordingError::InputContract)
    );
}

#[test]
fn ordinary_controlled_clone_sets_provenance_flag_and_prepared_generation() {
    let mut core = RecordingCore::new(1);
    let token = core
        .begin(
            THREAD,
            LOADER,
            Some(b"sample/A".to_vec()),
            DefinitionKind::Ordinary,
            None,
            true,
        )
        .unwrap();
    assert!(core.retained_bytes() >= WIRE_FIXED_BYTES);
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1])
        .unwrap();
    core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec())
        .unwrap();
    core.finish(THREAD, token, Some(CLASS), false).unwrap();
    assert_eq!(core.ordinary_generation(CLASS), None);
    assert_eq!(core.class_generation(CLASS), None);
    assert!(core.needs_snapshot(CLASS));
    core.class_prepare(99, CLASS, LOADER, b"sample.A".to_vec(), Some(snapshot()))
        .unwrap();
    assert_eq!(core.encode_evidence(CLASS).unwrap()[9], 3);
    assert_eq!(core.ordinary_generation(CLASS), Some(1));
    assert_eq!(core.class_generation(CLASS), Some(1));
    assert_eq!(core.hidden_context(CLASS), None);
    core.invalidate_class(CLASS);
    assert_eq!(core.ordinary_generation(CLASS), None);
    assert_eq!(core.class_generation(CLASS), None);
}

#[test]
fn hidden_context_requires_current_prepared_actual_identity() {
    let mut core = RecordingCore::new(1);
    let token = core
        .begin(
            THREAD,
            LOADER,
            None,
            DefinitionKind::Hidden,
            Some(recipe()),
            true,
        )
        .unwrap();
    assert_eq!(core.hidden_context(CLASS), None);
    core.class_prepare(
        THREAD,
        CLASS,
        LOADER,
        b"sample.Hidden/0x1".to_vec(),
        Some(snapshot()),
    )
    .unwrap();
    assert_eq!(core.hidden_context(CLASS), None);
    core.finish(THREAD, token, Some(CLASS), false).unwrap();
    assert_eq!(core.hidden_context(CLASS), Some((1, 40, LOADER)));
    assert_eq!(core.class_generation(CLASS), Some(1));
    assert_eq!(core.ordinary_generation(CLASS), None);
    assert!(
        core.with_ordinary_source(1, CLASS, 1, LOADER, |_| ())
            .is_none()
    );
    core.invalidate_class(CLASS);
    assert_eq!(core.hidden_context(CLASS), None);
    assert_eq!(core.class_generation(CLASS), None);
}

#[test]
fn resource_exhaustion_revokes_generation_and_context_queries() {
    let mut core = RecordingCore::new(1);
    ready_ordinary(&mut core, CLASS);
    let (_, stamp) = core.encode_evidence_with_stamp(CLASS).unwrap();
    assert!(core.evidence_stamp_is_current(&stamp));
    assert_eq!(core.ordinary_generation(CLASS), Some(1));
    core.exhausted = true;
    assert!(!core.evidence_stamp_is_current(&stamp));
    assert_eq!(core.ordinary_generation(CLASS), None);
    assert_eq!(core.class_generation(CLASS), None);
    assert_eq!(core.hidden_context(CLASS), None);
}

#[test]
fn out_of_order_finish_discards_thread_stack_and_preserves_other_thread() {
    let mut core = RecordingCore::new(1);
    let outer = ordinary(&mut core, THREAD, b"sample/A");
    let inner = ordinary(&mut core, THREAD, b"sample/B");
    let other = ordinary(&mut core, THREAD + 1, b"sample/C");
    assert_eq!(
        core.finish(THREAD, outer, None, false),
        Err(RecordingError::InvalidToken)
    );
    assert_eq!(
        core.finish(THREAD, inner, None, false),
        Err(RecordingError::NoActiveAttempt)
    );
    core.terminal_hook(THREAD + 1, LOADER, Some(b"sample/C"), vec![1])
        .unwrap();
    core.class_load(THREAD + 1, CLASS, LOADER, b"sample.C".to_vec())
        .unwrap();
    core.class_prepare(THREAD + 1, CLASS, LOADER, b"sample.C".to_vec(), None)
        .unwrap();
    core.finish(THREAD + 1, other, Some(CLASS), false).unwrap();
    assert!(core.encode_evidence(CLASS).is_ok());
    assert_eq!(core.active_attempts, 0);
}

#[test]
fn redefine_invalidates_prepared_and_pending_class_generations() {
    let mut core = RecordingCore::new(1);
    ready_ordinary(&mut core, CLASS);
    core.invalidate_class(CLASS);
    assert_eq!(core.records[&CLASS].generation, 2);
    assert_eq!(
        core.encode_evidence(CLASS),
        Err(RecordingError::Invalidated)
    );
    assert!(!core.needs_snapshot(CLASS));
    let pending = ordinary(&mut core, THREAD, b"sample/B");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/B"), vec![1])
        .unwrap();
    core.class_load(THREAD, CLASS + 1, LOADER, b"sample.B".to_vec())
        .unwrap();
    core.invalidate_class(CLASS + 1);
    assert_eq!(
        core.finish(THREAD, pending, Some(CLASS + 1), false),
        Err(RecordingError::Invalidated)
    );
}

#[test]
fn delayed_prepare_metadata_mismatch_invalidates_record() {
    let mut core = RecordingCore::new(1);
    let token = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1])
        .unwrap();
    core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec())
        .unwrap();
    core.finish(THREAD, token, Some(CLASS), false).unwrap();
    assert_eq!(
        core.class_prepare(99, CLASS, LOADER + 1, b"sample.A".to_vec(), None),
        Err(RecordingError::MetadataMismatch)
    );
    assert_eq!(
        core.encode_evidence(CLASS),
        Err(RecordingError::Invalidated)
    );
}

#[test]
fn redefine_before_initial_class_observation_cannot_publish_generation_one() {
    let mut core = RecordingCore::new(1);
    let token = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1])
        .unwrap();
    core.invalidate_class(CLASS);
    assert_eq!(
        core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec()),
        Err(RecordingError::Invalidated)
    );
    assert_eq!(
        core.finish(THREAD, token, Some(CLASS), false),
        Err(RecordingError::Invalidated)
    );
    assert_eq!(
        core.encode_evidence(CLASS),
        Err(RecordingError::Unavailable)
    );
}

#[test]
fn failed_calls_release_buffers_without_reusing_tokens() {
    let mut core = RecordingCore::new(1);
    let first = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1; 1024])
        .unwrap();
    assert!(core.retained_bytes >= 1024);
    assert!(core.finish(THREAD, first, None, true).is_err());
    assert_eq!(core.retained_bytes, 0);
    let next = ordinary(&mut core, THREAD, b"sample/A");
    assert_ne!(first, next);
}

#[test]
fn abort_after_class_observation_preserves_effect_tombstone_and_releases_buffers() {
    let mut core = RecordingCore::new(1);
    let token = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1; 1024])
        .unwrap();
    core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec())
        .unwrap();
    assert!(core.retained_bytes() > 1024);
    core.abort_observation(THREAD, token).unwrap();
    assert_eq!(core.retained_bytes(), 0);
    assert_eq!(core.active_attempts, 0);
    assert!(!core.stacks.contains_key(&THREAD));
    assert!(core.seen_classes.contains(&CLASS));
    assert_eq!(
        core.encode_evidence(CLASS),
        Err(RecordingError::Unavailable)
    );
    let retry = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![2])
        .unwrap();
    assert_eq!(
        core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec()),
        Err(RecordingError::ExistingClass)
    );
    assert_eq!(
        core.finish(THREAD, retry, Some(CLASS), false),
        Err(RecordingError::ExistingClass)
    );
}

#[test]
fn abort_releases_owned_attempt_after_global_exhaustion_without_restoring_availability() {
    let mut core = RecordingCore::new(1);
    let token = ordinary(&mut core, THREAD, b"sample/A");
    core.exhausted = true;
    core.abort_observation(THREAD, token).unwrap();
    assert_eq!(core.retained_bytes(), 0);
    assert_eq!(core.active_attempts, 0);
    assert!(core.is_resource_exhausted());
    assert_eq!(
        core.begin(THREAD, LOADER, None, DefinitionKind::Ordinary, None, false),
        Err(RecordingError::ResourceLimit)
    );
}

#[test]
fn finish_releases_current_token_after_global_resource_failure() {
    let mut core = RecordingCore::new(1);
    let token = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1])
        .unwrap();
    core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec())
        .unwrap();
    core.exhausted = true;
    assert_eq!(
        core.finish(THREAD, token, Some(CLASS), false),
        Err(RecordingError::ResourceLimit)
    );
    assert_eq!(core.retained_bytes(), 0);
    assert_eq!(core.active_attempts, 0);
    assert!(!core.stacks.contains_key(&THREAD));
    assert!(core.seen_classes.contains(&CLASS));
    assert!(core.is_resource_exhausted());
}

#[test]
fn record_reservation_failure_releases_popped_attempt_budget() {
    let mut core = RecordingCore::new(1);
    let token = ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1])
        .unwrap();
    core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec())
        .unwrap();
    core.force_record_reservation_failure = true;
    assert_eq!(
        core.finish(THREAD, token, Some(CLASS), false),
        Err(RecordingError::ResourceLimit)
    );
    assert_eq!(core.retained_bytes(), 0);
    assert_eq!(core.active_attempts, 0);
    assert!(!core.stacks.contains_key(&THREAD));
    assert!(!core.contains_class(CLASS));
    assert!(core.seen_classes.contains(&CLASS));
    assert!(core.is_resource_exhausted());
}

#[test]
fn resource_limits_fail_closed_for_depth_class_count_and_bytes() {
    let mut core = RecordingCore::new(1);
    ready_ordinary(&mut core, CLASS);
    for _ in 0..MAX_ATTEMPT_DEPTH {
        ordinary(&mut core, THREAD, b"sample/A");
    }
    assert_eq!(
        core.begin(THREAD, LOADER, None, DefinitionKind::Ordinary, None, false),
        Err(RecordingError::ResourceLimit)
    );
    assert_eq!(
        core.encode_evidence(CLASS),
        Err(RecordingError::ResourceLimit)
    );

    let mut core = RecordingCore::new(1);
    for id in 1..=MAX_CLASSES as u64 {
        core.class_load(THREAD, id, LOADER, b"A".to_vec()).unwrap();
    }
    assert_eq!(
        core.class_load(THREAD, MAX_CLASSES as u64 + 1, LOADER, b"A".to_vec()),
        Err(RecordingError::ResourceLimit)
    );

    let mut core = RecordingCore::new(1);
    ordinary(&mut core, THREAD, b"sample/A");
    assert_eq!(
        core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1; MAX_CLASS_BYTES]),
        Err(RecordingError::ResourceLimit)
    );
    assert_eq!(
        core.begin(
            THREAD + 1,
            LOADER,
            None,
            DefinitionKind::Ordinary,
            None,
            false
        ),
        Err(RecordingError::ResourceLimit)
    );
}

#[test]
fn total_retained_budget_is_separate_from_single_class_budget() {
    let mut core = RecordingCore::new(1);
    core.retained_bytes = MAX_TOTAL_BYTES - 2;
    assert_eq!(
        core.begin(
            THREAD,
            LOADER,
            Some(vec![1, 2, 3]),
            DefinitionKind::Ordinary,
            None,
            false
        ),
        Err(RecordingError::ResourceLimit)
    );
}

#[test]
fn class_budget_includes_wire_overhead_before_evidence_is_published() {
    let mut core = RecordingCore::new(1);
    let token = ordinary(&mut core, THREAD, b"sample/A");
    let payload = MAX_CLASS_BYTES - WIRE_FIXED_BYTES - b"sample/A".len() - b"sample.A".len();
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1; payload])
        .unwrap();
    core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec())
        .unwrap();
    core.class_prepare(THREAD, CLASS, LOADER, b"sample.A".to_vec(), None)
        .unwrap();
    core.finish(THREAD, token, Some(CLASS), false).unwrap();
    assert!(core.encode_evidence(CLASS).unwrap().len() <= MAX_CLASS_BYTES);

    let mut core = RecordingCore::new(1);
    ordinary(&mut core, THREAD, b"sample/A");
    core.terminal_hook(THREAD, LOADER, Some(b"sample/A"), vec![1; payload + 1])
        .unwrap();
    assert_eq!(
        core.class_load(THREAD, CLASS, LOADER, b"sample.A".to_vec()),
        Err(RecordingError::ResourceLimit)
    );
    assert_eq!(
        core.encode_evidence(CLASS),
        Err(RecordingError::ResourceLimit)
    );
}

#[test]
fn malformed_or_excessive_vm_snapshot_is_not_prepared() {
    let mut core = RecordingCore::new(1);
    let token = core
        .begin(
            THREAD,
            LOADER,
            None,
            DefinitionKind::Hidden,
            Some(recipe()),
            true,
        )
        .unwrap();
    let malformed = ExecutableSnapshot {
        constant_pool_count: 0,
        constant_pool: vec![],
        methods: vec![],
    };
    assert_eq!(
        core.class_prepare(
            THREAD,
            CLASS,
            LOADER,
            b"sample.Hidden/0x1".to_vec(),
            Some(malformed)
        ),
        Err(RecordingError::InputContract)
    );
    assert_eq!(
        core.finish(THREAD, token, Some(CLASS), false),
        Err(RecordingError::InputContract)
    );

    let mut core = RecordingCore::new(1);
    core.begin(
        THREAD,
        LOADER,
        None,
        DefinitionKind::Hidden,
        Some(recipe()),
        true,
    )
    .unwrap();
    let mut excessive = snapshot();
    excessive.methods = vec![excessive.methods[0].clone(); MAX_METHODS + 1];
    assert_eq!(
        core.class_prepare(
            THREAD,
            CLASS,
            LOADER,
            b"sample.Hidden/0x2".to_vec(),
            Some(excessive)
        ),
        Err(RecordingError::ResourceLimit)
    );
    assert_eq!(
        core.encode_evidence(CLASS),
        Err(RecordingError::ResourceLimit)
    );
}

#[test]
fn method_code_kind_must_match_vm_method_modifiers() {
    for (modifiers, code) in [
        (0, MethodCode::Native),
        (0x100, MethodCode::Bytecodes(vec![0xb1])),
        (0, MethodCode::Abstract),
        (0x400, MethodCode::Bytecodes(vec![0xb1])),
        (0, MethodCode::Bytecodes(vec![])),
    ] {
        let mut actual = snapshot();
        actual.methods[0].modifiers = modifiers;
        actual.methods[0].code = code;
        assert_eq!(
            validate_snapshot(&actual),
            Err(RecordingError::InputContract)
        );
    }
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> u32 {
    let value = u32::from_be_bytes(bytes[*cursor..*cursor + 4].try_into().unwrap());
    *cursor += 4;
    value
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> u64 {
    let value = u64::from_be_bytes(bytes[*cursor..*cursor + 8].try_into().unwrap());
    *cursor += 8;
    value
}

fn read_sized<'a>(bytes: &'a [u8], cursor: &mut usize) -> &'a [u8] {
    let len = read_u32(bytes, cursor) as usize;
    let value = &bytes[*cursor..*cursor + len];
    *cursor += len;
    value
}
