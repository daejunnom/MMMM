// Existing examples are JSON documents, not ZIP byte/header boundaries. These
// small in-memory containers exercise the real decoder and never touch a file.
use super::*;
use mmmm_contracts::raw_digest;
use std::{io::Write, sync::atomic::AtomicBool, time::Duration};
use zip::{CompressionMethod, write::SimpleFileOptions};

fn zip(data: &[(&str, &[u8])], deflated: bool) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in data {
        if name.ends_with('/') {
            writer
                .add_directory(
                    *name,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .unwrap();
        } else {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(if deflated {
                        CompressionMethod::Deflated
                    } else {
                        CompressionMethod::Stored
                    }),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
    }
    writer.finish().unwrap().into_inner()
}
fn run(bytes: &[u8], limits: InputArchiveLimits) -> Result<InputArchiveInventory> {
    let cancellation = AtomicBool::new(false);
    inventory_input_archive(
        bytes,
        limits,
        &CaptureControl {
            cancellation: &cancellation,
            deadline: Instant::now() + Duration::from_secs(5),
        },
    )
}
fn rejected(bytes: &[u8], code: &str) {
    let error = run(bytes, InputArchiveLimits::default()).unwrap_err();
    assert_eq!(error.code(), code);
}
fn set16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn set32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn directory(bytes: &[u8]) -> usize {
    u32_at(bytes, bytes.len() - 22 + 16).unwrap() as usize
}
fn headers(bytes: &[u8]) -> Vec<Header> {
    preflight(bytes, InputArchiveLimits::default(), &mut || Ok(())).unwrap()
}
fn deflated_directory(body: &[u8]) -> Vec<u8> {
    // Reuse the real file compressor; change only same-length local/central
    // names and directory metadata so even forged zero lengths reach decoding.
    let mut bytes = zip(&[("dir_", body)], true);
    let h = &headers(&bytes)[0];
    let at = directory(&bytes);
    bytes[h.local + 30 + h.name.len() - 1] = b'/';
    bytes[at + 46 + h.name.len() - 1] = b'/';
    set32(&mut bytes, h.local + 14, 0);
    set32(&mut bytes, h.local + 22, 0);
    set32(&mut bytes, at + 16, 0);
    set32(&mut bytes, at + 24, 0);
    set32(&mut bytes, at + 38, (0o040755 << 16) | 0x10);
    bytes
}

#[test]
fn whole_actual_container_and_each_literal_member_have_observed_digests() {
    let bytes = zip(
        &[
            ("META-INF/", b""),
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            ("pkg/Probe.class", b"fixture-class-bytes"),
        ],
        false,
    );
    let observed = run(&bytes, InputArchiveLimits::default()).unwrap();
    assert!(observed.complete());
    assert_eq!(observed.input_byte_length(), bytes.len() as u64);
    assert_eq!(observed.input_sha256(), &raw_digest(&bytes));
    assert_eq!(observed.members().len(), 3);
    assert_eq!(observed.members()[0].name(), "META-INF/");
    assert_eq!(
        observed.members()[0].kind(),
        InputArchiveMemberKind::Directory
    );
    assert_eq!(observed.members()[0].byte_length(), 0);
    assert_eq!(observed.members()[0].sha256(), &raw_digest(b""));
    assert_eq!(observed.members()[2].name(), "pkg/Probe.class");
    assert_eq!(observed.members()[2].kind(), InputArchiveMemberKind::File);
    assert_eq!(
        observed.members()[2].sha256(),
        &raw_digest(b"fixture-class-bytes")
    );
    assert_eq!(
        observed.decoded_bytes(),
        b"Manifest-Version: 1.0\n".len() as u64 + b"fixture-class-bytes".len() as u64
    );
}

#[test]
fn no_exchange_manifest_is_required_and_empty_zip_is_a_complete_empty_input_fact() {
    for deflated in [false, true] {
        let body = vec![9; 20_000];
        let bytes = zip(&[("assets/example/data.bin", &body)], deflated);
        let observed = run(&bytes, InputArchiveLimits::default()).unwrap();
        assert_eq!(observed.members()[0].byte_length(), body.len() as u64);
        assert_eq!(observed.members()[0].sha256(), &raw_digest(&body));
    }
    let observed = run(&zip(&[], false), InputArchiveLimits::default()).unwrap();
    assert!(observed.complete());
    assert!(observed.members().is_empty());
    assert_eq!(observed.decoded_bytes(), 0);
}

#[test]
fn unsafe_names_and_secret_selectors_are_rejected_before_any_payload_hash() {
    for name in [
        "../x",
        "/absolute",
        "C:/drive",
        "\\\\host\\share",
        "a\\b",
        "a//b",
        "a/./b",
        "a/../b",
        "a/NUL.txt",
        "a/trailing.",
    ] {
        assert!(run(&zip(&[(name, b"")], false), InputArchiveLimits::default()).is_err());
    }
    for name in [
        ".env",
        "a/.ENV.local",
        "a/private.key",
        "a/id_ed25519",
        "a/credentials.json",
        "a/service_account.json",
        "a/api-key.txt",
        "a/credentıals.json",
        "a/apı_key.txt",
        "a/ıd_rsa",
        "a/id_rſa",
        "a/ſervice-account.json",
        "a/service-account.jſon",
        "a/.ſſh/config",
    ] {
        // A harmless earlier member must not be decoded/hashed before a later
        // secret portable alias is found by the complete name preflight.
        let bytes = zip(&[("public.bin", b"ordinary fixture"), (name, b"")], false);
        let mut checks = 0;
        let error = inventory(&bytes, InputArchiveLimits::default(), &mut || {
            checks += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.code(), "INPUT_ARCHIVE_SECRET_MEMBER");
        // Direct preflight rejects the same name: no ZipArchive or hashing is reached.
        let mut before = 0;
        let error = preflight(&bytes, InputArchiveLimits::default(), &mut || {
            before += 1;
            Ok(())
        })
        .err()
        .unwrap();
        assert_eq!(error.code(), "INPUT_ARCHIVE_SECRET_MEMBER");
        assert_eq!(checks, before);
        assert!(!error.to_string().contains(name));
        assert!(!format!("{error:?}").contains(name));
    }
}

#[test]
fn duplicate_case_unicode_and_ancestor_aliases_never_collapse() {
    for pair in [
        ("A/x", "a/y"),
        ("a", "a/b"),
        ("a/b", "a"),
        ("a/", "A/"),
        ("x/é", "x/e\u{301}"),
    ] {
        rejected(
            &zip(&[(pair.0, b""), (pair.1, b"")], false),
            "INPUT_ARCHIVE_NAME_ALIAS",
        );
    }
    let mut bytes = zip(&[("a.bin", b"a"), ("b.bin", b"b")], false);
    let index = headers(&bytes);
    let at = directory(&bytes);
    let second = at + 46 + index[0].name.len();
    bytes[index[1].local + 30..index[1].local + 35].copy_from_slice(b"a.bin");
    bytes[second + 46..second + 51].copy_from_slice(b"a.bin");
    rejected(&bytes, "INPUT_ARCHIVE_NAME_ALIAS");
    // A later explicit directory can confirm an already implicit ancestor.
    assert!(
        run(
            &zip(&[("a/b", b"x"), ("a/", b"")], false),
            InputArchiveLimits::default()
        )
        .is_ok()
    );
}

#[test]
fn long_shared_components_fit_a_lower_caller_metadata_budget() {
    // The small alias/header fixtures do not represent many members sharing a
    // long directory path. Repeating eight 32-byte components exposes retained
    // full-prefix copies while this real inventory still has tiny payloads.
    let prefix = ["shared_component0123456789abcdef"; 8].join("/");
    let names: Vec<_> = (0..64)
        .map(|index| format!("{prefix}/entry{index:03}.bin"))
        .collect();
    let data: Vec<(&str, &[u8])> = names
        .iter()
        .map(|name| (name.as_str(), &b"x"[..]))
        .collect();
    let bytes = zip(&data, false);
    let observed = run(
        &bytes,
        InputArchiveLimits {
            metadata_bytes: 64 * 1024,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(observed.complete());
    assert_eq!(observed.members().len(), names.len());
    assert_eq!(observed.decoded_bytes(), names.len() as u64);
    assert_eq!(observed.input_sha256(), &raw_digest(&bytes));
    assert_eq!(observed.members()[63].name(), names[63]);
    assert_eq!(
        run(
            &bytes,
            InputArchiveLimits {
                metadata_bytes: 40 * 1024,
                ..Default::default()
            }
        )
        .unwrap_err()
        .code(),
        "INPUT_ARCHIVE_METADATA_LIMIT"
    );
}

#[test]
fn declarations_are_bounded_before_library_directory_allocation() {
    let original = zip(&[("a", b"x")], false);
    let mut count = original.clone();
    let end = count.len() - 22;
    set16(&mut count, end + 8, u16::MAX);
    set16(&mut count, end + 10, u16::MAX);
    rejected(&count, "INPUT_ARCHIVE_DIRECTORY_INVALID");
    let mut size = original.clone();
    let end = size.len() - 22;
    set32(&mut size, end + 12, u32::MAX);
    rejected(&size, "INPUT_ARCHIVE_ZIP64_UNSUPPORTED");
    let mut locator = original.clone();
    let end = locator.len() - 22;
    let mut record = vec![0; 20];
    set32(&mut record, 0, ZIP64_LOCATOR);
    locator.splice(end..end, record);
    rejected(&locator, "INPUT_ARCHIVE_ZIP64_UNSUPPORTED");
    let mut multidisk = original;
    let end = multidisk.len() - 22;
    set16(&mut multidisk, end + 4, 1);
    rejected(&multidisk, "INPUT_ARCHIVE_MULTIDISK_UNSUPPORTED");
}

#[test]
fn encryption_compression_links_and_special_members_are_closed_failures() {
    let original = zip(&[("a.bin", b"abc")], false);
    let at = directory(&original);
    let mut encrypted = original.clone();
    set16(&mut encrypted, at + 8, UTF8 | 1);
    rejected(&encrypted, "INPUT_ARCHIVE_ENCRYPTED");
    let mut method = original.clone();
    set16(&mut method, at + 10, 99);
    rejected(&method, "INPUT_ARCHIVE_COMPRESSION_UNSUPPORTED");
    for mode in [0o120777u32, 0o020600, 0o010600, 0o140600] {
        let mut linked = original.clone();
        set32(&mut linked, at + 38, mode << 16);
        rejected(&linked, "INPUT_ARCHIVE_MEMBER_TYPE_UNSUPPORTED");
    }
    for tag in [0x0001, 0x7075, 0x6375, 0x9901] {
        let mut bytes = [0; 4];
        set16(&mut bytes, 0, tag);
        assert_eq!(
            extra(&bytes).unwrap_err().code(),
            "INPUT_ARCHIVE_EXTRA_UNSUPPORTED"
        );
    }
}

#[test]
fn actual_crc_local_names_sizes_and_coverage_are_not_trusted_from_directory() {
    let original = zip(&[("a.bin", b"abc")], false);
    let h = &headers(&original)[0];
    let mut crc = original.clone();
    crc[h.data] ^= 1;
    rejected(&crc, "INPUT_ARCHIVE_CRC_MISMATCH");
    let mut local = original.clone();
    local[h.local + 30] = b'b';
    rejected(&local, "INPUT_ARCHIVE_LOCAL_MISMATCH");
    let mut size = original.clone();
    let at = directory(&size);
    set32(&mut size, at + 24, 1);
    rejected(&size, "INPUT_ARCHIVE_SIZE_MISMATCH");
    let mut gap = original.clone();
    gap.insert(0, 0);
    let end = gap.len() - 22;
    let at = directory(&original) + 1;
    set32(&mut gap, end + 16, at as u32);
    set32(&mut gap, at + 42, 1);
    rejected(&gap, "INPUT_ARCHIVE_COVERAGE_INVALID");
    assert!(
        run(
            &original[..original.len() - 1],
            InputArchiveLimits::default()
        )
        .is_err()
    );
}

#[test]
fn every_caller_limit_can_only_lower_the_initial_finite_profile() {
    let bytes = zip(&[("a.bin", b"0123456789"), ("b.bin", b"0123456789")], false);
    let cases = [
        (
            InputArchiveLimits {
                input_bytes: bytes.len() as u64 - 1,
                ..Default::default()
            },
            "INPUT_ARCHIVE_INPUT_LIMIT",
        ),
        (
            InputArchiveLimits {
                member_bytes: 9,
                ..Default::default()
            },
            "INPUT_ARCHIVE_DECODE_LIMIT",
        ),
        (
            InputArchiveLimits {
                member_bytes: 15,
                total_bytes: 15,
                ..Default::default()
            },
            "INPUT_ARCHIVE_DECODE_LIMIT",
        ),
        (
            InputArchiveLimits {
                entries: 1,
                ..Default::default()
            },
            "INPUT_ARCHIVE_ENTRY_LIMIT",
        ),
        (
            InputArchiveLimits {
                metadata_bytes: 8,
                ..Default::default()
            },
            "INPUT_ARCHIVE_METADATA_LIMIT",
        ),
        (
            InputArchiveLimits {
                name_bytes: 2,
                ..Default::default()
            },
            "INPUT_ARCHIVE_METADATA_LIMIT",
        ),
        (
            InputArchiveLimits {
                input_bytes: 64 * 1024 * 1024 + 1,
                ..Default::default()
            },
            "INPUT_ARCHIVE_LIMITS",
        ),
    ];
    for (limits, code) in cases {
        assert_eq!(run(&bytes, limits).unwrap_err().code(), code);
    }
    let deflated = zip(&[("a.bin", &[0; 20_000])], true);
    assert_eq!(
        run(
            &deflated,
            InputArchiveLimits {
                ratio: 1,
                ..Default::default()
            }
        )
        .unwrap_err()
        .code(),
        "INPUT_ARCHIVE_DECODE_LIMIT"
    );
}

#[test]
fn signed_and_signatureless_descriptors_are_checked_against_both_headers() {
    // This four-byte payload has actual CRC32 == the optional signature.
    let collision = [0xac, 0x0a, 0x7a, 0xd5];
    assert_eq!(crc32fast::hash(&collision), DESCRIPTOR);
    for payload in [b"abc".as_slice(), collision.as_slice()] {
        for signed in [false, true] {
            for following_member in [false, true] {
                for reverse_central in [false, true] {
                    if reverse_central && !following_member {
                        continue;
                    }
                    let original = if following_member {
                        zip(&[("a.bin", payload), ("b.bin", b"next")], false)
                    } else {
                        zip(&[("a.bin", payload)], false)
                    };
                    let index = headers(&original);
                    let h = &index[0];
                    let mut record = Vec::new();
                    if signed {
                        record.extend_from_slice(&DESCRIPTOR.to_le_bytes());
                    }
                    for value in [h.crc, h.compressed, h.decoded] {
                        record.extend_from_slice(&value.to_le_bytes());
                    }
                    let mut bytes = original.clone();
                    bytes.splice(h.end..h.end, record.iter().copied());
                    set16(&mut bytes, h.local + 6, UTF8 | DESCRIBED);
                    for offset in [14, 18, 22] {
                        set32(&mut bytes, h.local + offset, 0);
                    }
                    let at = directory(&original) + record.len();
                    let end = bytes.len() - 22;
                    set16(&mut bytes, at + 8, UTF8 | DESCRIBED);
                    set32(&mut bytes, end + 16, at as u32);
                    let first_length = 46
                        + usize::from(u16_at(&bytes, at + 28).unwrap())
                        + usize::from(u16_at(&bytes, at + 30).unwrap())
                        + usize::from(u16_at(&bytes, at + 32).unwrap());
                    let second = at + first_length;
                    if following_member {
                        set32(
                            &mut bytes,
                            second + 42,
                            (index[1].local + record.len()) as u32,
                        );
                    }
                    if reverse_central {
                        let first = bytes[at..second].to_vec();
                        let later = bytes[second..end].to_vec();
                        bytes[at..at + later.len()].copy_from_slice(&later);
                        bytes[at + later.len()..end].copy_from_slice(&first);
                    }
                    let inventory = run(&bytes, InputArchiveLimits::default()).unwrap();
                    assert_eq!(
                        inventory
                            .members()
                            .iter()
                            .find(|member| member.name() == "a.bin")
                            .unwrap()
                            .sha256(),
                        &raw_digest(payload)
                    );
                    bytes[h.end + if signed { 4 } else { 0 }] ^= 1;
                    rejected(&bytes, "INPUT_ARCHIVE_DESCRIPTOR_MISMATCH");
                }
            }
        }
    }
}

#[test]
fn real_deflate_must_end_at_exact_consumed_input_and_actual_size() {
    let original = zip(&[("a.bin", &[9; 20_000])], true);
    let h = &headers(&original)[0];
    let mut trailing = original.clone();
    trailing.insert(h.end, 0);
    let at = directory(&original) + 1;
    let end = trailing.len() - 22;
    set32(&mut trailing, h.local + 18, h.compressed + 1);
    set32(&mut trailing, at + 20, h.compressed + 1);
    set32(&mut trailing, end + 16, at as u32);
    rejected(&trailing, "INPUT_ARCHIVE_DEFLATE_TRAILING");
    let mut short = original.clone();
    short.remove(h.end - 1);
    let at = directory(&original) - 1;
    let end = short.len() - 22;
    set32(&mut short, h.local + 18, h.compressed - 1);
    set32(&mut short, at + 20, h.compressed - 1);
    set32(&mut short, end + 16, at as u32);
    let error = run(&short, InputArchiveLimits::default()).unwrap_err();
    assert!(matches!(
        error.code(),
        "INPUT_ARCHIVE_DEFLATE" | "INPUT_ARCHIVE_DEFLATE_TRUNCATED"
    ));
    if error.code() == "INPUT_ARCHIVE_DEFLATE" {
        assert!(error.source().is_some());
    }
    let mut forged = original;
    let at = directory(&forged);
    set32(&mut forged, h.local + 22, 1);
    set32(&mut forged, at + 24, 1);
    rejected(&forged, "INPUT_ARCHIVE_SIZE_MISMATCH");
}

#[test]
fn deflated_empty_directories_require_the_complete_actual_decoder_checks() {
    let original = deflated_directory(b"");
    let h = &headers(&original)[0];
    assert_eq!(h.method, 8);
    assert!(h.compressed > 0);
    let observed = run(&original, InputArchiveLimits::default()).unwrap();
    assert!(observed.complete());
    assert_eq!(observed.input_sha256(), &raw_digest(&original));
    assert_eq!(observed.decoded_bytes(), 0);
    assert_eq!(observed.members().len(), 1);
    assert_eq!(observed.members()[0].name(), "dir/");
    assert_eq!(
        observed.members()[0].kind(),
        InputArchiveMemberKind::Directory
    );
    assert_eq!(observed.members()[0].byte_length(), 0);
    assert_eq!(observed.members()[0].sha256(), &raw_digest(b""));

    // A declared empty directory must not skip its nonempty actual stream.
    rejected(
        &deflated_directory(b"nonempty"),
        "INPUT_ARCHIVE_SIZE_MISMATCH",
    );
    let mut trailing = original.clone();
    trailing.insert(h.end, 0);
    let at = directory(&original) + 1;
    let end = trailing.len() - 22;
    set32(&mut trailing, h.local + 18, h.compressed + 1);
    set32(&mut trailing, at + 20, h.compressed + 1);
    set32(&mut trailing, end + 16, at as u32);
    rejected(&trailing, "INPUT_ARCHIVE_DEFLATE_TRAILING");
    for removed in [1, h.compressed as usize] {
        let mut short = original.clone();
        drop(short.drain(h.end - removed..h.end));
        let at = directory(&original) - removed;
        let end = short.len() - 22;
        let compressed = h.compressed - removed as u32;
        set32(&mut short, h.local + 18, compressed);
        set32(&mut short, at + 20, compressed);
        set32(&mut short, end + 16, at as u32);
        let error = run(&short, InputArchiveLimits::default()).unwrap_err();
        assert!(matches!(
            error.code(),
            "INPUT_ARCHIVE_DEFLATE" | "INPUT_ARCHIVE_DEFLATE_TRUNCATED"
        ));
        if error.code() == "INPUT_ARCHIVE_DEFLATE" {
            assert!(error.source().is_some());
        }
    }
    // Zero decoded length and CRC remain mandatory before opening a member.
    let mut crc = original.clone();
    let at = directory(&crc);
    set32(&mut crc, h.local + 14, 1);
    set32(&mut crc, at + 16, 1);
    rejected(&crc, "INPUT_ARCHIVE_DIRECTORY_PAYLOAD");
    let mut size = original;
    let at = directory(&size);
    set32(&mut size, h.local + 22, 1);
    set32(&mut size, at + 24, 1);
    rejected(&size, "INPUT_ARCHIVE_DIRECTORY_PAYLOAD");
}

#[test]
fn original_control_stops_before_and_during_work_without_returning_a_partial_inventory() {
    let bytes = zip(&[("a.bin", &[7; 100_000])], false);
    let cancellation = AtomicBool::new(true);
    assert_eq!(
        inventory_input_archive(
            &bytes,
            InputArchiveLimits::default(),
            &CaptureControl {
                cancellation: &cancellation,
                deadline: Instant::now() + Duration::from_secs(5)
            }
        )
        .unwrap_err()
        .code(),
        "CANCELLED"
    );
    cancellation.store(false, Ordering::Release);
    assert_eq!(
        inventory_input_archive(
            &bytes,
            InputArchiveLimits::default(),
            &CaptureControl {
                cancellation: &cancellation,
                deadline: Instant::now() - Duration::from_secs(1)
            }
        )
        .unwrap_err()
        .code(),
        "TIME_BUDGET_EXCEEDED"
    );
    let mut metadata_checks = 0;
    preflight(&bytes, InputArchiveLimits::default(), &mut || {
        metadata_checks += 1;
        Ok(())
    })
    .unwrap();
    for stop in [
        metadata_checks + 4,
        metadata_checks + 2 + 2 * bytes.len().div_ceil(CHUNK) + 4,
    ] {
        let mut checks = 0;
        let error = inventory(&bytes, InputArchiveLimits::default(), &mut || {
            checks += 1;
            if checks == stop {
                Err(InputArchiveError::caused(
                    "CANCELLED",
                    std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "local original control cause",
                    ),
                ))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(error.code(), "CANCELLED");
        assert!(error.source().is_some());
        assert_eq!(checks, stop);
        assert!(!error.to_string().contains("local original control cause"));
    }
}
