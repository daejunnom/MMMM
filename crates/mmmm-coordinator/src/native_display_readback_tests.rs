//! Tiny byte fixtures are pure NBT interpretation inputs, not NativeRead or
//! native game evidence. Existing target fixtures contain only opaque empty
//! compounds and cannot represent persisted display meanings. The one real
//! Store case checks rejection without an entered request; it forges no read.
use super::*;
use crate::{
    authority::LocalAuthority, host::HostBridge, native_targets::NativeTargetReader,
    service::RequestContextSlot,
};
use mmmm_contracts::raw_digest;
use mmmm_runtime::storage::{DurableStore, StoreConfig};
use serde_json::json;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

type Field = (u8, &'static str, Vec<u8>);
type Fields = Vec<Field>;
const OWNER_TAG: &str = "mmmm.instance.owned";
fn selector() -> NativeSelector {
    NativeSelector::from_value(&json!({"kind":"entity","dimension":"minecraft:overworld",
        "uuid":"80000000-ffff-0001-7fff-ffff00000001","expectedType":"minecraft:block_display"}))
    .unwrap()
}
fn text(value: &str) -> Vec<u8> {
    assert!(value.is_ascii());
    let mut bytes = (value.len() as u16).to_be_bytes().to_vec();
    bytes.extend_from_slice(value.as_bytes());
    bytes
}
fn list(kind: u8, values: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![kind];
    bytes.extend_from_slice(&(values.len() as i32).to_be_bytes());
    for value in values {
        bytes.extend_from_slice(value);
    }
    bytes
}
fn floats(values: &[f32]) -> Vec<u8> {
    list(
        5,
        &values
            .iter()
            .map(|value| value.to_bits().to_be_bytes().to_vec())
            .collect::<Vec<_>>(),
    )
}
fn compound(fields: &[Field]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (kind, name, payload) in fields {
        bytes.push(*kind);
        bytes.extend_from_slice(&text(name));
        bytes.extend_from_slice(payload);
    }
    bytes.push(0);
    bytes
}
fn fields() -> Fields {
    let mut uuid = 4i32.to_be_bytes().to_vec();
    for word in [i32::MIN, -65535, i32::MAX, 1] {
        uuid.extend_from_slice(&word.to_be_bytes());
    }
    vec![
        (11, "UUID", uuid),
        (8, "id", text("minecraft:block_display")),
        (
            9,
            "Pos",
            list(
                6,
                &[-0.0f64, 64.5, -0.25]
                    .iter()
                    .map(|v| v.to_bits().to_be_bytes().to_vec())
                    .collect::<Vec<_>>(),
            ),
        ),
        (9, "Tags", list(8, &[text("other"), text(OWNER_TAG)])),
        (
            9,
            "transformation",
            floats(&[
                1.0, -0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0,
            ]),
        ),
        (8, "billboard", text("fixed")),
        (3, "start_interpolation", (-2i32).to_be_bytes().to_vec()),
        (3, "interpolation_duration", 0i32.to_be_bytes().to_vec()),
        (3, "teleport_duration", 3i32.to_be_bytes().to_vec()),
        // An unrelated opaque StringTag contains a real unpaired Java UTF-16
        // surrogate. The shared decoder preserves its units without loss.
        (8, "opaque", vec![0, 3, 0xed, 0xa0, 0x80]),
    ]
}
fn raw(fields: &[Field]) -> Value {
    let selector = selector();
    let mut bytes = vec![10, 0, 0];
    bytes.extend_from_slice(&compound(fields));
    json!({"format":"mmmm.native.target/1","selector":selector.value(),"status":"known",
        "presence":"present","membershipScope":"loaded_entity_identity","captureScope":"native_persisted_entity",
        "coverage":"full_target","reason":null,"payload":{"entityType":"minecraft:block_display",
            "position":[-0.0,64.5,-0.25],"tags":[OWNER_TAG,"other"],
            "nativeNbt":{"format":"minecraft.nbt.named-compound/uncompressed",
                "bytesHex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),"sha256":raw_digest(&bytes)}}})
}

#[test]
fn persisted_display_types_signed_uuid_words_and_missing_fields_remain_factual() {
    let value = raw(&fields());
    let parsed = parse_display(&value, &selector(), OWNER_TAG, &|| Ok(())).unwrap();
    assert_eq!(
        parsed.uuid(),
        &[
            0x80, 0, 0, 0, 0xff, 0xff, 0, 1, 0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 1
        ]
    );
    assert_eq!(parsed.kind(), NativeDisplayKind::Block);
    assert_eq!(
        parsed.position_bits(),
        &[(-0.0f64).to_bits(), 64.5f64.to_bits(), (-0.25f64).to_bits()]
    );
    assert_eq!(parsed.owner_tag(), OWNER_TAG);
    assert_eq!(
        parsed.persisted_entity_type(),
        Some("minecraft:block_display")
    );
    assert_eq!(parsed.billboard(), Some(NativeDisplayBillboard::Fixed));
    assert_eq!(parsed.interpolation().start(), Some(-2));
    assert_eq!(parsed.interpolation().duration(), Some(0));
    assert_eq!(parsed.interpolation().teleport_duration(), Some(3));
    let Some(NativeDisplayTransformation::Matrix(matrix)) = parsed.transformation() else {
        panic!("actual matrix encoding was not preserved");
    };
    assert_eq!(matrix[1], NativeDisplayFloat::Float32((-0.0f32).to_bits()));
    let mut canonical_metadata = value.clone();
    canonical_metadata["payload"]["position"][0] = json!(0.0);
    let parsed = parse_display(&canonical_metadata, &selector(), OWNER_TAG, &|| Ok(())).unwrap();
    assert_eq!(parsed.position_bits()[0], (-0.0f64).to_bits());
    let mut minimal = fields();
    minimal.retain(|(_, name, _)| matches!(*name, "UUID" | "Pos" | "Tags" | "opaque"));
    let parsed = parse_display(&raw(&minimal), &selector(), OWNER_TAG, &|| Ok(())).unwrap();
    assert_eq!(parsed.persisted_entity_type(), None);
    assert_eq!(parsed.transformation(), None);
    assert_eq!(parsed.billboard(), None);
    assert_eq!(parsed.interpolation().start(), None);
    assert_eq!(parsed.interpolation().duration(), None);
    assert_eq!(parsed.interpolation().teleport_duration(), None);
    let mut decomposed = fields();
    let replacement = compound(&[
        (9, "translation", floats(&[0.0, 1.0, 2.0])),
        (9, "left_rotation", floats(&[0.0, 0.0, 0.0, 1.0])),
        (
            9,
            "scale",
            list(
                6,
                &[1.0f64, 1.0, 1.0]
                    .iter()
                    .map(|v| v.to_bits().to_be_bytes().to_vec())
                    .collect::<Vec<_>>(),
            ),
        ),
        (9, "right_rotation", floats(&[0.0, 0.0, 0.0, 1.0])),
    ]);
    *decomposed
        .iter_mut()
        .find(|(_, name, _)| *name == "transformation")
        .unwrap() = (10, "transformation", replacement);
    let parsed = parse_display(&raw(&decomposed), &selector(), OWNER_TAG, &|| Ok(())).unwrap();
    let Some(NativeDisplayTransformation::Decomposed { scale, .. }) = parsed.transformation()
    else {
        panic!("actual decomposed encoding was not preserved");
    };
    assert_eq!(scale[0], NativeDisplayFloat::Float64(1.0f64.to_bits()));
}

#[test]
fn persisted_display_rejects_hash_only_identity_mismatch_nonfinite_and_wrong_native_types() {
    for (name, kind, replacement) in [
        (
            "UUID",
            11,
            [4i32.to_be_bytes().as_slice(), &[0; 16]].concat(),
        ),
        (
            "UUID",
            9,
            list(
                3,
                &[0i32, 0, 0, 0]
                    .iter()
                    .map(|v| v.to_be_bytes().to_vec())
                    .collect::<Vec<_>>(),
            ),
        ),
        ("Pos", 9, floats(&[0.0, 64.5, -0.25])),
        ("id", 8, text("minecraft:pig")),
        ("Tags", 9, list(8, &[text("other")])),
        ("transformation", 9, floats(&[0.0; 15])),
        ("transformation", 9, floats(&[f32::INFINITY; 16])),
        ("transformation", 9, floats(&[f32::NAN; 16])),
        ("billboard", 8, text("unrecognized")),
        (
            "teleport_duration",
            5,
            3.0f32.to_bits().to_be_bytes().to_vec(),
        ),
    ] {
        let mut changed = fields();
        *changed
            .iter_mut()
            .find(|(_, field, _)| *field == name)
            .unwrap() = (kind, name, replacement);
        assert!(parse_display(&raw(&changed), &selector(), OWNER_TAG, &|| Ok(())).is_err());
    }
    for mutate in [
        ("position", json!([0.5, 64.5, -0.25])),
        ("tags", json!([OWNER_TAG])),
        ("entityType", json!("minecraft:pig")),
    ] {
        let mut changed = raw(&fields());
        changed["payload"][mutate.0] = mutate.1;
        assert!(parse_display(&changed, &selector(), OWNER_TAG, &|| Ok(())).is_err());
    }
    assert!(parse_display(&raw(&fields()), &selector(), "unobserved_owner", &|| Ok(())).is_err());
    assert!(parse_display(&raw(&[]), &selector(), OWNER_TAG, &|| Ok(())).is_err());
    let mut changed = raw(&fields());
    changed["payload"]["nativeNbt"]["sha256"] = json!(raw_digest(b"hash only"));
    assert!(parse_display(&changed, &selector(), OWNER_TAG, &|| Ok(())).is_err());
    let mut changed = raw(&fields());
    changed["status"] = json!("unknown");
    changed["presence"] = json!("unknown");
    changed["membershipScope"] = json!("unknown");
    changed["coverage"] = json!("best_effort");
    changed["reason"] = json!("loaded_uuid_not_observed");
    changed["payload"] = Value::Null;
    assert!(parse_display(&changed, &selector(), OWNER_TAG, &|| Ok(())).is_err());
}

#[test]
fn persisted_display_keeps_original_control_and_late_authority_failures() {
    let error = parse_display(&raw(&fields()), &selector(), OWNER_TAG, &|| {
        Err(AppError::new("CANCELLED", "Original request cancelled"))
    })
    .unwrap_err();
    assert_eq!(error.code, "CANCELLED");
    let mut deep = vec![];
    for _ in 0..65 {
        deep = vec![(10, "nested", compound(&deep))];
    }
    let mut changed = fields();
    changed.push((10, "deep", compound(&deep)));
    assert!(parse_display(&raw(&changed), &selector(), OWNER_TAG, &|| Ok(())).is_err());
    let error = finish::<NativeDisplaySnapshot>(
        Err(NativeDisplayReadError::Decode(AppError::new(
            "NATIVE_DISPLAY_INVALID",
            "Original NBT failure",
        ))),
        Err(NativeTargetError::Authority(AppError::new(
            "PERMISSION_REQUIRED",
            "Current read scope ended",
        ))),
    )
    .unwrap_err();
    let NativeDisplayReadError::Checkpoint {
        original,
        checkpoint,
    } = &error
    else {
        panic!("original and subsequent failures were not both preserved");
    };
    assert_eq!(
        original
            .source()
            .unwrap()
            .downcast_ref::<AppError>()
            .unwrap()
            .code,
        "NATIVE_DISPLAY_INVALID"
    );
    let NativeTargetError::Authority(checkpoint) = checkpoint else {
        panic!("typed current-authority failure was lost");
    };
    assert_eq!(checkpoint.code, "PERMISSION_REQUIRED");
}

// The existing reader's fixtures are pure DTOs. This external owned root is
// needed only to invoke its real public Store/request gate without forging an
// acquired NativeRead, host witness, session, ADMIN or a positive snapshot.
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const MARKER: &[u8] = b"mmmm-native-display-readback-fixture-v1\n";
struct TestRoot(PathBuf);
impl TestRoot {
    fn new() -> Self {
        let parent = fs::canonicalize(
            std::env::var_os("MMMM_TEST_DATA_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir),
        )
        .unwrap();
        let path = parent.join(format!(
            "mmmm-native-display-readback-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        let checkout =
            fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
        assert!(path.is_absolute() && !path.exists() && !path.starts_with(checkout));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(path.join("fixture-owner.txt"), MARKER).unwrap();
        Self(path)
    }
}
fn plain_tree(root: &Path) -> bool {
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut count = 0;
    while let Some((path, depth)) = pending.pop() {
        count += 1;
        if count > 4096 || depth > 32 || !path.is_absolute() || !path.starts_with(root) {
            return false;
        }
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            return false;
        };
        if metadata.file_type().is_symlink() {
            return false;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return false;
            }
        }
        if metadata.is_dir() {
            let Ok(entries) = fs::read_dir(&path) else {
                return false;
            };
            for entry in entries {
                let Ok(entry) = entry else { return false };
                pending.push((entry.path(), depth + 1));
            }
        } else if !metadata.is_file() {
            return false;
        }
    }
    true
}
impl Drop for TestRoot {
    fn drop(&mut self) {
        if fs::canonicalize(&self.0).ok().as_ref() == Some(&self.0)
            && plain_tree(&self.0)
            && fs::read(self.0.join("fixture-owner.txt")).ok().as_deref() == Some(MARKER)
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
#[test]
fn pure_display_parse_does_not_supply_an_actual_entered_native_read() {
    assert!(parse_display(&raw(&fields()), &selector(), OWNER_TAG, &|| Ok(())).is_ok());
    let root = TestRoot::new();
    let mut store = DurableStore::open(StoreConfig::new(root.0.clone())).unwrap();
    let hosts = HostBridge::default();
    let reader = NativeTargetReader::new(
        hosts.clone(),
        LocalAuthority::new(hosts),
        RequestContextSlot::default(),
    );
    let context =
        mmmm_contracts::parse_json(include_bytes!("../../../examples/execution-context.json"))
            .unwrap();
    let error = reader
        .observe_display_retained(&mut store, &context, &selector(), "1", OWNER_TAG)
        .unwrap_err();
    assert!(matches!(
        error,
        NativeDisplayReadError::Native(NativeTargetError::Authority(_))
    ));
}
