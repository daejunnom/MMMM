// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors

use super::*;

const TEST_PROBE_DOT: &str = "io.github.daejunnom.mmmm.observer.DefinitionStartupProbe";
const TEST_PROBE_INTERNAL: &str = "io/github/daejunnom/mmmm/observer/DefinitionStartupProbe";
const TEST_LAMBDA_INTERNAL: &str =
    "io/github/daejunnom/mmmm/observer/DefinitionStartupProbe$$Lambda";
const TEST_ORDINARY_INPUT: &[u8] = b"owned ordinary fixture";
const TEST_POSITIVE_INPUT: &[u8] = b"owned forwarder fixture";

// These small descriptive payloads exercise the wire decoder. They are not
// executable classfiles, observations of a JVM, or an executable-closure proof.
#[derive(Clone)]
struct TestDefinition {
    kind: u8,
    flags: u8,
    reserved: u16,
    identity: u64,
    generation: u64,
    attempt: u64,
    epoch: u64,
    name: Vec<u8>,
    ordinary: Vec<u8>,
    hidden: Vec<u8>,
    hidden_flags: i32,
    initialize: u8,
    initialize_reserved: [u8; 3],
    lookup: u64,
    loader: u64,
    requested: Vec<u8>,
    pool_count: u32,
    pool: Vec<u8>,
    method_count: u32,
    method_name: Vec<u8>,
    method_descriptor: Vec<u8>,
    method_modifiers: i32,
    code_kind: u8,
    code: Vec<u8>,
}

#[derive(Clone)]
struct TestForwarder {
    version: u16,
    reserved: u16,
    epoch: u64,
    source: u64,
    source_generation: u64,
    target: u64,
    target_generation: u64,
    target_status: i32,
    symbols: [Vec<u8>; 7],
    interface: u8,
    interface_reserved: [u8; 3],
    references: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct TestFrame {
    outer_version: u16,
    outer_reserved: u16,
    legacy_version: u16,
    legacy_reserved: u16,
    status: i32,
    epoch: u64,
    direct: u8,
    direct_reserved: [u8; 3],
    ordinary: TestDefinition,
    samless: TestDefinition,
    positive: TestDefinition,
    forwarder: TestForwarder,
}

fn test_definition(identity: u64, kind: u8, name: String, requested: &[u8]) -> TestDefinition {
    let hidden = kind == 2;
    TestDefinition {
        kind,
        flags: 3,
        reserved: 0,
        identity,
        generation: 1,
        attempt: identity,
        epoch: 1,
        name: name.into_bytes(),
        ordinary: if hidden {
            Vec::new()
        } else {
            TEST_ORDINARY_INPUT.to_vec()
        },
        hidden: if hidden {
            TEST_ORDINARY_INPUT.to_vec()
        } else {
            Vec::new()
        },
        hidden_flags: if hidden { 10 } else { 0 },
        initialize: 0,
        initialize_reserved: [0; 3],
        lookup: if hidden { 4 } else { 0 },
        loader: 0,
        requested: requested.to_vec(),
        pool_count: 1,
        pool: b"cp".to_vec(),
        method_count: 1,
        method_name: b"identity".to_vec(),
        method_descriptor: b"()V".to_vec(),
        method_modifiers: 8,
        code_kind: 0,
        code: vec![0xb1],
    }
}

fn test_frame() -> TestFrame {
    let mut ordinary = test_definition(1, 1, TEST_PROBE_DOT.to_owned(), &[]);
    ordinary.method_name = b"lambda$ownedRunnable$0".to_vec();
    let samless = test_definition(
        2,
        2,
        format!("{TEST_PROBE_DOT}/opaque"),
        TEST_PROBE_DOT.as_bytes(),
    );
    let mut positive = test_definition(
        3,
        2,
        format!("{TEST_PROBE_DOT}$$Lambda/opaque"),
        TEST_LAMBDA_INTERNAL.as_bytes(),
    );
    positive.hidden = TEST_POSITIVE_INPUT.to_vec();
    positive.hidden_flags = 7;
    positive.initialize = 1;
    positive.lookup = ordinary.identity;
    positive.loader = 5;
    positive.method_name = b"run".to_vec();
    positive.method_modifiers = 1;
    TestFrame {
        outer_version: 1,
        outer_reserved: 0,
        legacy_version: 1,
        legacy_reserved: 0,
        status: 255,
        epoch: 1,
        direct: 1,
        direct_reserved: [0; 3],
        ordinary,
        samless,
        positive,
        forwarder: TestForwarder {
            version: 1,
            reserved: 0,
            epoch: 1,
            source: 3,
            source_generation: 1,
            target: 1,
            target_generation: 1,
            target_status: 6,
            symbols: [
                TEST_LAMBDA_INTERNAL.as_bytes().to_vec(),
                b"java/lang/Runnable".to_vec(),
                b"run".to_vec(),
                b"()V".to_vec(),
                TEST_PROBE_INTERNAL.as_bytes().to_vec(),
                b"lambda$ownedRunnable$0".to_vec(),
                b"()V".to_vec(),
            ],
            interface: 0,
            interface_reserved: [0; 3],
            references: vec![
                TEST_PROBE_INTERNAL.as_bytes().to_vec(),
                b"java/lang/Object".to_vec(),
                b"java/lang/Runnable".to_vec(),
            ],
        },
    }
}

fn test_sized(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("small test payload fits u32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn test_definition_bytes(value: &TestDefinition) -> Vec<u8> {
    let mut output = b"MMMMDEF1".to_vec();
    output.extend_from_slice(&[value.kind, value.flags]);
    output.extend_from_slice(&value.reserved.to_be_bytes());
    for token in [value.identity, value.generation, value.attempt, value.epoch] {
        output.extend_from_slice(&token.to_be_bytes());
    }
    for bytes in [&value.name, &value.ordinary, &value.hidden] {
        test_sized(&mut output, bytes);
    }
    output.extend_from_slice(&value.hidden_flags.to_be_bytes());
    output.push(value.initialize);
    output.extend_from_slice(&value.initialize_reserved);
    output.extend_from_slice(&value.lookup.to_be_bytes());
    output.extend_from_slice(&value.loader.to_be_bytes());
    test_sized(&mut output, &value.requested);
    output.extend_from_slice(&value.pool_count.to_be_bytes());
    test_sized(&mut output, &value.pool);
    output.extend_from_slice(&value.method_count.to_be_bytes());
    test_sized(&mut output, &value.method_name);
    test_sized(&mut output, &value.method_descriptor);
    output.extend_from_slice(&value.method_modifiers.to_be_bytes());
    output.push(value.code_kind);
    test_sized(&mut output, &value.code);
    output
}

fn test_forwarder_bytes(value: &TestForwarder) -> Vec<u8> {
    let mut output = b"MMMMSAM1".to_vec();
    output.extend_from_slice(&value.version.to_be_bytes());
    output.extend_from_slice(&value.reserved.to_be_bytes());
    for token in [
        value.epoch,
        value.source,
        value.source_generation,
        value.target,
        value.target_generation,
    ] {
        output.extend_from_slice(&token.to_be_bytes());
    }
    output.extend_from_slice(&value.target_status.to_be_bytes());
    for text in &value.symbols {
        test_sized(&mut output, text);
    }
    output.push(value.interface);
    output.extend_from_slice(&value.interface_reserved);
    output.extend_from_slice(
        &u32::try_from(value.references.len())
            .expect("small reference list fits u32")
            .to_be_bytes(),
    );
    for reference in &value.references {
        test_sized(&mut output, reference);
    }
    output
}

fn test_legacy_bytes(value: &TestFrame, ordinary: &[u8], samless: &[u8]) -> Vec<u8> {
    let mut output = b"MMMMABI1".to_vec();
    output.extend_from_slice(&value.legacy_version.to_be_bytes());
    output.extend_from_slice(&value.legacy_reserved.to_be_bytes());
    output.extend_from_slice(&value.status.to_be_bytes());
    output.extend_from_slice(&value.epoch.to_be_bytes());
    output.push(value.direct);
    output.extend_from_slice(&value.direct_reserved);
    test_sized(&mut output, ordinary);
    test_sized(&mut output, samless);
    output
}

fn test_outer_bytes(
    value: &TestFrame,
    legacy: &[u8],
    positive: &[u8],
    forwarder: &[u8],
) -> Vec<u8> {
    let mut output = b"MMMMABI2".to_vec();
    output.extend_from_slice(&value.outer_version.to_be_bytes());
    output.extend_from_slice(&value.outer_reserved.to_be_bytes());
    test_sized(&mut output, legacy);
    test_sized(&mut output, positive);
    test_sized(&mut output, forwarder);
    output
}

fn test_bytes(value: &TestFrame) -> Vec<u8> {
    let ordinary = test_definition_bytes(&value.ordinary);
    let samless = test_definition_bytes(&value.samless);
    let legacy = test_legacy_bytes(value, &ordinary, &samless);
    test_outer_bytes(
        value,
        &legacy,
        &test_definition_bytes(&value.positive),
        &test_forwarder_bytes(&value.forwarder),
    )
}

fn test_decode(value: &TestFrame) -> DefinitionFixtureSummary {
    match decode_abi2(&test_bytes(value)) {
        Ok(summary) => summary,
        Err(_) => panic!("valid descriptive ABI2 fixture must decode"),
    }
}

fn test_rejected(value: &TestFrame) {
    assert!(decode_abi2(&test_bytes(value)).is_err());
}

#[test]
fn abi2_decodes_fixed_nested_fixture_summary() {
    let summary = test_decode(&test_frame());
    assert_eq!(summary.observed_status, 255);
    assert_eq!(summary.issuer_epoch, "1");
    assert_eq!(summary.ordinary.class_identity, "1");
    assert_eq!(summary.ordinary.generation, "1");
    assert_eq!(summary.ordinary.attempt, "1");
    assert_eq!(summary.ordinary.observed_name, TEST_PROBE_DOT);
    assert_eq!(summary.ordinary.methods, 1);
    assert_eq!(summary.ordinary.constant_pool_count, 1);
    assert_eq!(summary.samless_hidden.class_identity, "2");
    assert_eq!(
        summary.samless_hidden.observed_name,
        format!("{TEST_PROBE_DOT}/opaque")
    );
    assert_eq!(summary.positive_hidden.class_identity, "3");
    assert_eq!(
        summary.positive_hidden.observed_name,
        format!("{TEST_PROBE_DOT}$$Lambda/opaque")
    );
    assert_eq!(summary.target_class_status, 6);
}

#[test]
fn abi2_preserves_unsigned_token_bit_patterns_as_decimal_strings() {
    let mut value = test_frame();
    value.epoch = u64::MAX;
    value.ordinary.identity = u64::MAX;
    value.samless.identity = u64::MAX - 1;
    value.positive.identity = u64::MAX - 2;
    value.ordinary.generation = u64::MAX;
    value.positive.generation = u64::MAX - 1;
    for definition in [&mut value.ordinary, &mut value.samless, &mut value.positive] {
        definition.epoch = u64::MAX;
        definition.attempt = u64::MAX;
    }
    value.positive.lookup = value.ordinary.identity;
    value.forwarder.epoch = u64::MAX;
    value.forwarder.source = value.positive.identity;
    value.forwarder.source_generation = value.positive.generation;
    value.forwarder.target = value.ordinary.identity;
    value.forwarder.target_generation = value.ordinary.generation;
    let summary = test_decode(&value);
    assert_eq!(summary.issuer_epoch, u64::MAX.to_string());
    assert_eq!(summary.ordinary.class_identity, u64::MAX.to_string());
    assert_eq!(summary.ordinary.generation, u64::MAX.to_string());
    assert_eq!(
        summary.positive_hidden.generation,
        (u64::MAX - 1).to_string()
    );
    assert_eq!(summary.positive_hidden.attempt, u64::MAX.to_string());
}

#[test]
fn abi2_rejects_every_truncated_prefix() {
    let frame = test_bytes(&test_frame());
    for length in 0..frame.len() {
        assert!(decode_abi2(&frame[..length]).is_err(), "prefix {length}");
    }
}

#[test]
fn abi2_rejects_trailing_stdout_bytes() {
    let mut frame = test_bytes(&test_frame());
    frame.extend_from_slice(b"extra output");
    assert!(decode_abi2(&frame).is_err());
}

#[test]
fn abi2_rejects_magic_mismatches_at_each_section() {
    let value = test_frame();
    let ordinary = test_definition_bytes(&value.ordinary);
    let samless = test_definition_bytes(&value.samless);
    let positive = test_definition_bytes(&value.positive);
    let forwarder = test_forwarder_bytes(&value.forwarder);
    for section in 0..6 {
        let mut ordinary = ordinary.clone();
        let mut samless = samless.clone();
        let mut positive = positive.clone();
        let mut forwarder = forwarder.clone();
        match section {
            2 => ordinary[0] ^= 1,
            3 => samless[0] ^= 1,
            4 => positive[0] ^= 1,
            5 => forwarder[0] ^= 1,
            _ => {}
        }
        let mut legacy = test_legacy_bytes(&value, &ordinary, &samless);
        if section == 1 {
            legacy[0] ^= 1;
        }
        let mut frame = test_outer_bytes(&value, &legacy, &positive, &forwarder);
        if section == 0 {
            frame[0] ^= 1;
        }
        assert!(decode_abi2(&frame).is_err(), "section {section}");
    }
}

#[test]
fn abi2_rejects_unknown_versions() {
    let mut value = test_frame();
    value.outer_version = 2;
    test_rejected(&value);
    value = test_frame();
    value.legacy_version = 2;
    test_rejected(&value);
    value = test_frame();
    value.forwarder.version = 2;
    test_rejected(&value);
}

#[test]
fn abi2_rejects_nonzero_reserved_fields() {
    for reserved in 0..8 {
        let mut value = test_frame();
        match reserved {
            0 => value.outer_reserved = 1,
            1 => value.legacy_reserved = 1,
            2 => value.direct_reserved[0] = 1,
            3 => value.ordinary.reserved = 1,
            4 => value.samless.initialize_reserved[1] = 1,
            5 => value.positive.reserved = 1,
            6 => value.forwarder.reserved = 1,
            _ => value.forwarder.interface_reserved[2] = 1,
        }
        test_rejected(&value);
    }
}

#[test]
fn abi2_rejects_declared_outer_lengths_beyond_section_bounds() {
    let value = test_frame();
    let legacy = test_legacy_bytes(
        &value,
        &test_definition_bytes(&value.ordinary),
        &test_definition_bytes(&value.samless),
    );
    let positive = test_definition_bytes(&value.positive);
    let original = test_outer_bytes(
        &value,
        &legacy,
        &positive,
        &test_forwarder_bytes(&value.forwarder),
    );
    for offset in [12, 16 + legacy.len(), 20 + legacy.len() + positive.len()] {
        let mut frame = original.clone();
        frame[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_abi2(&frame).is_err(), "length at {offset}");
    }
}

#[test]
fn abi2_rejects_aggregate_stdout_above_18_mib() {
    let mut frame = test_bytes(&test_frame());
    frame.resize(18 * 1024 * 1024 + 1, 0);
    assert!(decode_abi2(&frame).is_err());
}

#[test]
fn abi2_rejects_declared_sections_above_native_envelope_caps() {
    let value = test_frame();
    let ordinary = test_definition_bytes(&value.ordinary);
    let samless = test_definition_bytes(&value.samless);
    let original_legacy = test_legacy_bytes(&value, &ordinary, &samless);
    let positive = test_definition_bytes(&value.positive);
    let forwarder = test_forwarder_bytes(&value.forwarder);
    for offset in [28, 32 + ordinary.len()] {
        let mut legacy = original_legacy.clone();
        legacy[offset..offset + 4].copy_from_slice(&(8_u32 * 1024 * 1024 + 1).to_be_bytes());
        let frame = test_outer_bytes(&value, &legacy, &positive, &forwarder);
        assert!(decode_abi2(&frame).is_err(), "DEF1 section at {offset}");
    }
    let original = test_outer_bytes(&value, &original_legacy, &positive, &forwarder);
    for (offset, cap) in [
        (16 + original_legacy.len(), 8_u32 * 1024 * 1024),
        (20 + original_legacy.len() + positive.len(), 1024_u32 * 1024),
    ] {
        let mut frame = original.clone();
        frame[offset..offset + 4].copy_from_slice(&(cap + 1).to_be_bytes());
        assert!(decode_abi2(&frame).is_err(), "outer section at {offset}");
    }
}

#[test]
fn abi2_rejects_declared_definition_text_above_16_kib() {
    let value = test_frame();
    let mut ordinary = test_definition_bytes(&value.ordinary);
    ordinary[44..48].copy_from_slice(&(16_u32 * 1024 + 1).to_be_bytes());
    let legacy = test_legacy_bytes(&value, &ordinary, &test_definition_bytes(&value.samless));
    let frame = test_outer_bytes(
        &value,
        &legacy,
        &test_definition_bytes(&value.positive),
        &test_forwarder_bytes(&value.forwarder),
    );
    assert!(decode_abi2(&frame).is_err());
}

#[test]
fn abi2_rejects_incomplete_or_negative_native_status() {
    for status in [0, 127, 254, 256, -1, -4] {
        let mut value = test_frame();
        value.status = status;
        test_rejected(&value);
    }
}

#[test]
fn abi2_requires_direct_buffer_evidence_absence_flag_one() {
    for direct in [0, 2, 255] {
        let mut value = test_frame();
        value.direct = direct;
        test_rejected(&value);
    }
}

#[test]
fn abi2_rejects_zero_or_mismatched_epochs() {
    for epoch_field in 0..5 {
        let mut value = test_frame();
        match epoch_field {
            0 => value.epoch = 0,
            1 => value.ordinary.epoch = 2,
            2 => value.samless.epoch = 2,
            3 => value.positive.epoch = 2,
            _ => value.forwarder.epoch = 2,
        }
        test_rejected(&value);
    }
}

#[test]
fn abi2_rejects_zero_definition_tokens() {
    for definition in 0..3 {
        for token in 0..4 {
            let mut value = test_frame();
            let definition = match definition {
                0 => &mut value.ordinary,
                1 => &mut value.samless,
                _ => &mut value.positive,
            };
            match token {
                0 => definition.identity = 0,
                1 => definition.generation = 0,
                2 => definition.attempt = 0,
                _ => definition.epoch = 0,
            }
            test_rejected(&value);
        }
    }
}

#[test]
fn abi2_requires_three_distinct_class_identities() {
    let mut value = test_frame();
    value.samless.identity = value.ordinary.identity;
    test_rejected(&value);
    value = test_frame();
    value.positive.identity = value.ordinary.identity;
    value.forwarder.source = value.positive.identity;
    test_rejected(&value);
    value = test_frame();
    value.positive.identity = value.samless.identity;
    value.forwarder.source = value.positive.identity;
    test_rejected(&value);
}

#[test]
fn abi2_rejects_forwarder_identity_or_generation_mismatches() {
    for field in 0..4 {
        let mut value = test_frame();
        match field {
            0 => value.forwarder.source = 4,
            1 => value.forwarder.source_generation = 2,
            2 => value.forwarder.target = 4,
            _ => value.forwarder.target_generation = 2,
        }
        test_rejected(&value);
    }
}

#[test]
fn abi2_requires_initialized_prepared_nonerror_target_status() {
    for status in [0, 2, 4, 8, 14, 0x46, -1] {
        let mut value = test_frame();
        value.forwarder.target_status = status;
        test_rejected(&value);
    }
}

#[test]
fn abi2_rejects_each_fixed_forwarder_symbol_mismatch() {
    for index in 0..7 {
        let mut value = test_frame();
        value.forwarder.symbols[index].push(b'x');
        test_rejected(&value);
    }
}

#[test]
fn abi2_requires_class_method_reference_kind() {
    for kind in [1, 2, 255] {
        let mut value = test_frame();
        value.forwarder.interface = kind;
        test_rejected(&value);
    }
}

#[test]
fn abi2_rejects_duplicate_missing_or_extra_references() {
    let mut value = test_frame();
    value.forwarder.references[2] = value.forwarder.references[1].clone();
    test_rejected(&value);
    value = test_frame();
    value.forwarder.references.remove(1);
    test_rejected(&value);
    value = test_frame();
    value
        .forwarder
        .references
        .push(b"java/lang/String".to_vec());
    test_rejected(&value);
    value = test_frame();
    value.forwarder.references.clear();
    test_rejected(&value);
}

#[test]
fn abi2_rejects_noncanonical_reference_order() {
    let mut value = test_frame();
    value.forwarder.references.swap(0, 1);
    test_rejected(&value);
}

#[test]
fn abi2_rejects_invalid_nonascii_nul_or_oversized_forwarder_text() {
    for text in [
        vec![0xff],
        vec![0xc3, 0xa9],
        b"run\0".to_vec(),
        vec![b'x'; 4097],
        Vec::new(),
    ] {
        let mut value = test_frame();
        value.forwarder.symbols[2] = text;
        test_rejected(&value);
    }
    let mut value = test_frame();
    value.forwarder.references = vec![b"java/lang/Object".to_vec(); 257];
    test_rejected(&value);
}

#[test]
fn abi2_rejects_definition_kind_or_flags_outside_current_fixture() {
    for kind in [0, 2, 3] {
        let mut value = test_frame();
        value.ordinary.kind = kind;
        test_rejected(&value);
    }
    for flags in [0, 1, 2, 4, 255] {
        let mut value = test_frame();
        value.ordinary.flags = flags;
        test_rejected(&value);
    }
    let mut value = test_frame();
    value.positive.kind = 1;
    test_rejected(&value);
}

#[test]
fn abi2_rejects_wrong_definition_names_or_requested_recipe_names() {
    let mut value = test_frame();
    value.ordinary.name.push(b'x');
    test_rejected(&value);
    value = test_frame();
    value.samless.name = b"other.Probe/opaque".to_vec();
    test_rejected(&value);
    value = test_frame();
    value.positive.name = format!("{TEST_PROBE_DOT}$$Other/opaque").into_bytes();
    test_rejected(&value);
    value = test_frame();
    value.samless.requested = b"other.Probe".to_vec();
    test_rejected(&value);
    value = test_frame();
    value.positive.requested = TEST_PROBE_INTERNAL.as_bytes().to_vec();
    test_rejected(&value);
}

#[test]
fn abi2_requires_same_samless_input_and_distinct_positive_recipe_input() {
    let mut value = test_frame();
    value.samless.hidden.push(b'x');
    test_rejected(&value);
    value = test_frame();
    value.positive.hidden = value.ordinary.ordinary.clone();
    test_rejected(&value);
}

#[test]
fn abi2_rejects_inconsistent_ordinary_and_hidden_fields() {
    let mut value = test_frame();
    value.ordinary.hidden = b"unexpected hidden recipe".to_vec();
    test_rejected(&value);
    value = test_frame();
    value.ordinary.loader = 1;
    test_rejected(&value);
    value = test_frame();
    value.ordinary.lookup = 1;
    test_rejected(&value);
    value = test_frame();
    value.samless.ordinary = b"unexpected terminal bytes".to_vec();
    test_rejected(&value);
    value = test_frame();
    value.positive.lookup = 0;
    test_rejected(&value);
    value = test_frame();
    value.positive.hidden_flags = 0;
    test_rejected(&value);
    value = test_frame();
    value.positive.initialize = 2;
    test_rejected(&value);
}

#[test]
fn abi2_rejects_uninitialized_positive_hidden_recipe() {
    let mut value = test_frame();
    value.positive.initialize = 0;
    test_rejected(&value);
}

#[test]
fn abi2_requires_pinned_samless_flags_initialization_and_bootstrap_loader() {
    for flags in [0, 2, 7, 8, 11, 15, -1] {
        let mut value = test_frame();
        value.samless.hidden_flags = flags;
        test_rejected(&value);
    }
    for initialize in [1, 2] {
        let mut value = test_frame();
        value.samless.initialize = initialize;
        test_rejected(&value);
    }
    for loader in [1, u64::MAX] {
        let mut value = test_frame();
        value.samless.loader = loader;
        test_rejected(&value);
    }
    let mut value = test_frame();
    value.samless.lookup = 0;
    test_rejected(&value);
}

#[test]
fn abi2_requires_pinned_positive_hidden_flags() {
    for flags in [0, 2, 3, 6, 10, 15, -1] {
        let mut value = test_frame();
        value.positive.hidden_flags = flags;
        test_rejected(&value);
    }
}

#[test]
fn abi2_requires_positive_lookup_identity_and_nonbootstrap_loader() {
    for lookup in [0, 2, u64::MAX] {
        let mut value = test_frame();
        value.positive.lookup = lookup;
        test_rejected(&value);
    }
    let mut value = test_frame();
    value.positive.loader = 0;
    test_rejected(&value);
    value = test_frame();
    value.positive.loader = u64::MAX;
    let summary = test_decode(&value);
    assert_eq!(summary.positive_hidden.class_identity, "3");
}

#[test]
fn abi2_rejects_invalid_pool_or_method_bounds() {
    for count in [0, 65536] {
        let mut value = test_frame();
        value.ordinary.pool_count = count;
        test_rejected(&value);
    }
    let mut value = test_frame();
    value.ordinary.pool.clear();
    test_rejected(&value);
    for count in [0, 4097] {
        value = test_frame();
        value.ordinary.method_count = count;
        test_rejected(&value);
    }
}

#[test]
fn abi2_requires_actual_snapshot_method_for_fixed_static_target_and_run() {
    let mut value = test_frame();
    value.ordinary.method_name = b"unrelated".to_vec();
    test_rejected(&value);
    value = test_frame();
    value.ordinary.method_modifiers = 1;
    test_rejected(&value);
    value = test_frame();
    value.positive.method_name = b"unrelated".to_vec();
    test_rejected(&value);
    value = test_frame();
    value.positive.method_modifiers = 8;
    test_rejected(&value);
}

#[test]
fn abi2_rejects_inconsistent_method_code_kinds() {
    let mut value = test_frame();
    value.ordinary.code.clear();
    test_rejected(&value);
    value = test_frame();
    value.ordinary.code_kind = 1;
    test_rejected(&value);
    value = test_frame();
    value.ordinary.method_modifiers |= 0x0100;
    test_rejected(&value);
    value = test_frame();
    value.ordinary.code_kind = 3;
    test_rejected(&value);
}

#[test]
fn abi2_rejects_trailing_bytes_inside_nested_sections() {
    let value = test_frame();
    for section in 0..4 {
        let mut ordinary = test_definition_bytes(&value.ordinary);
        let mut positive = test_definition_bytes(&value.positive);
        let mut forwarder = test_forwarder_bytes(&value.forwarder);
        if section == 0 {
            ordinary.push(0);
        }
        if section == 2 {
            positive.push(0);
        }
        if section == 3 {
            forwarder.push(0);
        }
        let mut legacy =
            test_legacy_bytes(&value, &ordinary, &test_definition_bytes(&value.samless));
        if section == 1 {
            legacy.push(0);
        }
        let frame = test_outer_bytes(&value, &legacy, &positive, &forwarder);
        assert!(decode_abi2(&frame).is_err(), "nested section {section}");
    }
}

// Selection tests pass only lexical owned paths. They never query filesystem
// state, open selected files, read global environment values or start a child.
fn test_rooted(relative: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    let root = std::path::PathBuf::from(r"C:\owned");
    #[cfg(not(windows))]
    let root = std::path::PathBuf::from("/owned");
    if relative.is_empty() {
        root
    } else {
        root.join(relative)
    }
}

#[derive(Clone)]
struct TestSelection {
    java: std::path::PathBuf,
    dll: std::path::PathBuf,
    jar: std::path::PathBuf,
    sources: Vec<DefinitionSourceInput>,
}

fn test_source(role: DefinitionSourceRole, relative: &str) -> DefinitionSourceInput {
    DefinitionSourceInput::new(role, test_rooted(relative))
}

fn test_selection() -> TestSelection {
    TestSelection {
        java: test_rooted("jdk/bin/java.exe"),
        dll: test_rooted("observer.dll"),
        jar: test_rooted("observer.jar"),
        sources: vec![
            test_source(DefinitionSourceRole::JdkArchive, "jdk/source.zip"),
            test_source(DefinitionSourceRole::JdkModules, "jdk/lib/modules"),
            test_source(
                DefinitionSourceRole::BuildSourceManifest,
                "build/source.json",
            ),
            test_source(DefinitionSourceRole::JdkLibrary, "jdk/bin/java.dll"),
        ],
    }
}

fn test_selected(
    value: &TestSelection,
) -> Result<DefinitionStartupSelection, DefinitionStartupError> {
    // Keep the established Windows role grammar explicit on every test OS.
    // Unix role selection has its own independent fixtures below.
    let selection = DefinitionStartupSelection {
        java_exe: value.java.clone(),
        observer_dll: value.dll.clone(),
        observer_jar: value.jar.clone(),
        source_inputs: value.sources.clone(),
    };
    selected_inputs_for_platform(&selection, StartupPlatform::Windows)?;
    Ok(selection)
}

#[test]
fn startup_java_argv_is_fixed_and_retains_spaced_paths_as_single_arguments() {
    use std::ffi::OsString;
    let dll = test_rooted("owned files/observer.dll");
    let jar = test_rooted("owned files/observer.jar");
    let args = fixed_java_args(&dll, &jar, StartupPlatform::Windows);
    let mut native = OsString::from("-agentpath:");
    native.push(&dll);
    native.push("=jdk25-windows-x64-msvc-controlled-startup-v1");
    let mut agent = OsString::from("-javaagent:");
    agent.push(&jar);
    agent.push("=protocol=mmmm.definition-observer/1");
    let expected = [
        OsString::from("--disable-@files"),
        OsString::from("-Xshare:off"),
        OsString::from("-Xlog:disable"),
        OsString::from("-Xlog:all=warning:stderr"),
        OsString::from("-XX:+DisableAttachMechanism"),
        OsString::from("-XX:-EnableDynamicAgentLoading"),
        OsString::from("--enable-native-access=ALL-UNNAMED"),
        OsString::from("--illegal-native-access=deny"),
        OsString::from("-Xms32m"),
        OsString::from("-Xmx256m"),
        OsString::from("-XX:MaxMetaspaceSize=256m"),
        OsString::from("-XX:ReservedCodeCacheSize=64m"),
        native,
        agent,
        OsString::from("-cp"),
        jar.into_os_string(),
        OsString::from("io.github.daejunnom.mmmm.observer.DefinitionStartupEvidenceMain"),
    ];
    assert_eq!(args.len(), 17);
    assert_eq!(args.as_slice(), expected.as_slice());
    assert!(args.iter().all(|arg| !arg.to_string_lossy().contains('"')));
}

#[test]
fn startup_environment_overrides_all_four_injection_keys_without_global_reads() {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    let injection_keys = [
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_AOT_VM_OPTIONS",
    ];
    let mut base = BTreeMap::new();
    for key in injection_keys {
        base.insert(key.to_owned(), "caller supplied injection".to_owned());
    }
    base.insert("OWNED_TEST_MARKER".to_owned(), "retained marker".to_owned());
    let environment = fixed_environment(base);
    for key in injection_keys {
        assert_eq!(
            environment.get(&OsString::from(key)),
            Some(&OsString::new())
        );
    }
    assert_eq!(
        environment.get(&OsString::from("OWNED_TEST_MARKER")),
        Some(&OsString::from("retained marker"))
    );
    assert_eq!(environment.len(), 5);
}

#[test]
fn startup_environment_adds_empty_overrides_to_an_empty_caller_map() {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    let environment = fixed_environment(BTreeMap::new());
    assert_eq!(environment.len(), 4);
    for key in [
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_AOT_VM_OPTIONS",
    ] {
        assert_eq!(
            environment.get(&OsString::from(key)),
            Some(&OsString::new())
        );
    }
}

#[test]
fn startup_selection_accepts_required_roles_without_filesystem_access() {
    let selection = test_selected(&test_selection()).expect("lexical owned selection is valid");
    let inputs = selected_inputs_for_platform(&selection, StartupPlatform::Windows)
        .expect("validated input roles remain available");
    assert_eq!(inputs.len(), 7);
    assert_eq!(inputs[0].0, DefinitionSourceRole::JavaExecutable);
    assert_eq!(inputs[1].0, DefinitionSourceRole::ObserverLibrary);
    assert_eq!(inputs[2].0, DefinitionSourceRole::ObserverJar);
}

#[test]
fn startup_selection_requires_each_singleton_and_at_least_one_jdk_library() {
    for index in 0..4 {
        let mut value = test_selection();
        value.sources.remove(index);
        assert!(
            test_selected(&value).is_err(),
            "missing source index {index}"
        );
    }
    for index in 0..3 {
        let mut value = test_selection();
        let mut duplicate = value.sources[index].clone();
        duplicate.path = test_rooted(&format!(
            "duplicate/{index}/{}",
            match duplicate.role {
                DefinitionSourceRole::JdkArchive => "source.zip",
                DefinitionSourceRole::JdkModules => "modules",
                DefinitionSourceRole::BuildSourceManifest => "source.json",
                _ => unreachable!("only singleton source roles are selected"),
            }
        ));
        value.sources.push(duplicate);
        assert!(
            test_selected(&value).is_err(),
            "duplicate singleton index {index}"
        );
    }
}

#[test]
fn startup_selection_rejects_primary_roles_in_the_additional_source_list() {
    for (role, name) in [
        (DefinitionSourceRole::JavaExecutable, "other/java.exe"),
        (DefinitionSourceRole::ObserverLibrary, "other/observer.dll"),
        (DefinitionSourceRole::ObserverJar, "other/observer.jar"),
    ] {
        let mut value = test_selection();
        value.sources.push(test_source(role, name));
        assert!(test_selected(&value).is_err());
    }
}

#[test]
fn startup_selection_rejects_case_insensitive_path_collisions() {
    let mut value = test_selection();
    value.sources[3].path = test_rooted("OBSERVER.DLL");
    assert!(test_selected(&value).is_err());
    value = test_selection();
    value.sources.push(value.sources[3].clone());
    assert!(test_selected(&value).is_err());
}

#[test]
fn startup_selection_counts_primary_inputs_in_the_32_input_limit() {
    let mut value = test_selection();
    for index in 0..25 {
        value.sources.push(test_source(
            DefinitionSourceRole::JdkLibrary,
            &format!("jdk/extra-{index}.dll"),
        ));
    }
    assert_eq!(value.sources.len() + 3, 32);
    assert!(test_selected(&value).is_ok());
    value.sources.push(test_source(
        DefinitionSourceRole::JdkLibrary,
        "jdk/one-too-many.dll",
    ));
    assert!(test_selected(&value).is_err());
}

#[test]
fn startup_source_roles_have_explicit_byte_budgets() {
    for (role, mebibytes) in [
        (DefinitionSourceRole::JavaExecutable, 64),
        (DefinitionSourceRole::ObserverLibrary, 64),
        (DefinitionSourceRole::ObserverJar, 16),
        (DefinitionSourceRole::JdkArchive, 192),
        (DefinitionSourceRole::JdkModules, 256),
        (DefinitionSourceRole::JdkLibrary, 64),
        (DefinitionSourceRole::BuildSourceManifest, 1),
    ] {
        assert_eq!(role.max_bytes(), mebibytes * 1024 * 1024);
    }
    assert_eq!(MAX_INPUT_BYTES, 512 * 1024 * 1024);
}

#[test]
fn startup_selection_rejects_role_filename_mismatches() {
    for primary in 0..3 {
        let mut value = test_selection();
        match primary {
            0 => value.java = test_rooted("jdk/bin/java.bin"),
            1 => value.dll = test_rooted("observer.so"),
            _ => value.jar = test_rooted("observer.zip"),
        }
        assert!(test_selected(&value).is_err());
    }
    for (index, name) in [
        (0, "jdk/source.tar"),
        (1, "jdk/lib/modulez"),
        (2, "build/source.txt"),
        (3, "jdk/bin/java.jar"),
    ] {
        let mut value = test_selection();
        value.sources[index].path = test_rooted(name);
        assert!(test_selected(&value).is_err());
    }
}

#[test]
fn startup_selection_requires_normal_absolute_paths_without_control_characters() {
    for java in [
        std::path::PathBuf::from("relative/java.exe"),
        test_rooted("jdk/../bin/java.exe"),
        test_rooted("jdk/./bin/java.exe"),
        test_rooted("jdk/control\0/bin/java.exe"),
        test_rooted("jdk/control\r/bin/java.exe"),
        test_rooted("jdk/control\n/bin/java.exe"),
    ] {
        let mut value = test_selection();
        value.java = java;
        assert!(test_selected(&value).is_err());
    }
}

#[test]
fn startup_selection_bounds_path_depth_at_64_components() {
    let mut java = test_rooted("");
    while java.components().count() + 1 < 64 {
        java.push("nested");
    }
    java.push("java.exe");
    assert_eq!(java.components().count(), 64);
    let mut value = test_selection();
    value.java = java;
    assert!(test_selected(&value).is_ok());
    value.java = value
        .java
        .parent()
        .expect("owned nested path has parent")
        .join("extra")
        .join("java.exe");
    assert_eq!(value.java.components().count(), 65);
    assert!(test_selected(&value).is_err());
}

#[test]
fn startup_selection_bounds_path_text_at_32760_bytes() {
    let root = test_rooted("");
    let fixed_length = root.to_str().expect("owned ASCII root").len() + 2 + "java.exe".len();
    let mut value = test_selection();
    value.java = root.join("x".repeat(32760 - fixed_length)).join("java.exe");
    assert_eq!(value.java.to_str().expect("owned ASCII path").len(), 32760);
    assert!(test_selected(&value).is_ok());
    value.java = root.join("x".repeat(32761 - fixed_length)).join("java.exe");
    assert_eq!(value.java.to_str().expect("owned ASCII path").len(), 32761);
    assert!(test_selected(&value).is_err());
}

#[test]
fn startup_selection_rejects_secret_named_components_without_opening_them() {
    for component in [
        ".env",
        ".env.production",
        ".ssh",
        "credentials",
        "api_key",
        "api-key",
        "apikey",
        "service-account",
        "service_account",
        "serviceaccount",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "private.pem",
        "private.key",
        "private.p12",
        "private.pfx",
        "private.keystore",
    ] {
        let mut value = test_selection();
        value.java = test_rooted(component).join("java.exe");
        assert!(
            test_selected(&value).is_err(),
            "secret-named component rejected lexically"
        );
    }
}

#[test]
fn startup_selection_rejects_delimiters_anywhere_in_native_and_java_agent_paths() {
    let mut value = test_selection();
    value.dll = test_rooted("owned=other/observer.dll");
    assert!(test_selected(&value).is_err());
    for jar in [
        "owned=other/observer.jar",
        "owned;other/observer.jar",
        "owned*other/observer.jar",
    ] {
        value = test_selection();
        value.jar = test_rooted(jar);
        assert!(test_selected(&value).is_err());
    }
}

#[test]
fn original_remaining_process_budget_never_rounds_up_a_fractional_second() {
    for nanos in [0, 1, 999_999_999, 60_000_000_001] {
        assert_eq!(
            remaining_process_budget(std::time::Duration::from_nanos(nanos))
                .unwrap_err()
                .kind(),
            "DEADLINE"
        );
    }
    for nanos in [1_000_000_000, 1_500_000_123, 60_000_000_000] {
        let remaining = std::time::Duration::from_nanos(nanos);
        assert_eq!(remaining_process_budget(remaining).unwrap(), remaining);
    }
}

#[test]
fn startup_selection_rejects_named_streams_and_win32_normalization_aliases_lexically() {
    // These are only in-memory path strings. No files, including secret files,
    // are created, opened, hashed or inspected by this regression.
    for component in [
        ".env:manifest.json",
        "source:stream.json",
        ".env ",
        "owned.",
    ] {
        let mut value = test_selection();
        value.sources = vec![
            test_source(DefinitionSourceRole::JdkArchive, "jdk/source.zip"),
            test_source(DefinitionSourceRole::JdkModules, "jdk/modules"),
            test_source(DefinitionSourceRole::JdkLibrary, "jdk/library.dll"),
            DefinitionSourceInput::new(
                DefinitionSourceRole::BuildSourceManifest,
                test_rooted(component).join("source.json"),
            ),
        ];
        assert!(test_selected(&value).is_err());
    }
}

#[test]
fn startup_role_grammar_and_marker_match_each_supported_platform() {
    for (platform, java, library, archive, marker) in [
        (
            StartupPlatform::Windows,
            "java.exe",
            "observer.dll",
            "jdk.zip",
            "jdk25-windows-x64-msvc-controlled-startup-v1",
        ),
        (
            StartupPlatform::Linux,
            "java",
            "observer.so",
            "jdk.tar.gz",
            "jdk25-linux-x64-gnu-controlled-startup-v1",
        ),
        (
            StartupPlatform::Macos,
            "java",
            "observer.dylib",
            "jdk.tar.gz",
            "jdk25-macos-arm64-darwin-controlled-startup-v1",
        ),
    ] {
        let selection = DefinitionStartupSelection {
            java_exe: test_rooted(&format!("jdk/bin/{java}")),
            observer_dll: test_rooted(library),
            observer_jar: test_rooted("observer.jar"),
            source_inputs: vec![
                test_source(DefinitionSourceRole::JdkArchive, archive),
                test_source(DefinitionSourceRole::JdkModules, "jdk/lib/modules"),
                test_source(
                    DefinitionSourceRole::JdkLibrary,
                    &format!("jdk/lib/{library}"),
                ),
                test_source(DefinitionSourceRole::BuildSourceManifest, "source.json"),
            ],
        };
        assert_eq!(
            selected_inputs_for_platform(&selection, platform)
                .unwrap()
                .len(),
            7
        );
        let args = fixed_java_args(&selection.observer_dll, &selection.observer_jar, platform);
        let mut expected = std::ffi::OsString::from("-agentpath:");
        expected.push(&selection.observer_dll);
        expected.push("=");
        expected.push(marker);
        if platform == StartupPlatform::Windows {
            assert_eq!(args.len(), 17);
            assert_eq!(args[12], expected);
        } else {
            assert_eq!(args.len(), 19);
            assert_eq!(args[12], std::ffi::OsString::from("-XX:-UsePerfData"));
            assert_eq!(args[13], std::ffi::OsString::from("-Djava.io.tmpdir=."));
            assert_eq!(args[14], expected);
        }
        for other in [
            StartupPlatform::Windows,
            StartupPlatform::Linux,
            StartupPlatform::Macos,
        ] {
            if other != platform {
                assert!(selected_inputs_for_platform(&selection, other).is_err());
            }
        }
    }
}

#[test]
fn unix_role_names_are_exact_and_do_not_reinterpret_windows_or_versioned_libraries() {
    for platform in [StartupPlatform::Linux, StartupPlatform::Macos] {
        assert!(!platform.role_name(DefinitionSourceRole::JavaExecutable, "JAVA"));
        assert!(!platform.role_name(DefinitionSourceRole::JavaExecutable, "java.exe"));
        assert!(!platform.role_name(DefinitionSourceRole::JdkArchive, "jdk.zip"));
        assert!(!platform.role_name(DefinitionSourceRole::JdkArchive, "jdk.tar"));
        assert!(!platform.role_name(DefinitionSourceRole::ObserverLibrary, "observer.dll"));
        assert!(!platform.role_name(DefinitionSourceRole::ObserverLibrary, "observer.so.1"));
    }
}
