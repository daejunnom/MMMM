//! Nominal identifiers with the exact lexical forms of the canonical wire schema.
//!
//! Deserialization validates the original text. It never lowercases, trims, or
//! removes a namespace, because those changes alter identity.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    InvalidStableId { type_name: &'static str },
    InvalidNamespacedId { type_name: &'static str },
    InvalidNonEmptyId { type_name: &'static str },
    InvalidSha256Digest,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStableId { type_name } => write!(
                formatter,
                "{type_name} must match ^[a-z0-9][a-z0-9._:-]{{0,127}}$"
            ),
            Self::InvalidNamespacedId { type_name } => write!(
                formatter,
                "{type_name} must match ^[a-z0-9_.-]+:[a-z0-9_./-]+$"
            ),
            Self::InvalidNonEmptyId { type_name } => {
                write!(formatter, "{type_name} must contain at least one character")
            }
            Self::InvalidSha256Digest => formatter
                .write_str("SHA-256 digest must contain exactly 64 lowercase hexadecimal digits"),
        }
    }
}

impl std::error::Error for IdentityError {}

fn is_stable_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && is_lowercase_or_digit(bytes[0])
        && bytes
            .iter()
            .all(|byte| is_lowercase_or_digit(*byte) || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn is_lowercase_or_digit(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn is_nonempty_id(value: &str) -> bool {
    !value.is_empty()
}

fn is_namespaced_id(value: &str) -> bool {
    let Some((namespace, path)) = value.split_once(':') else {
        return false;
    };
    !namespace.is_empty()
        && !path.is_empty()
        && namespace
            .bytes()
            .all(|byte| is_lowercase_or_digit(byte) || matches!(byte, b'_' | b'.' | b'-'))
        && path
            .bytes()
            .all(|byte| is_lowercase_or_digit(byte) || matches!(byte, b'_' | b'.' | b'/' | b'-'))
}

macro_rules! identifier {
    ($name:ident, $validator:ident, $variant:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
                let value = value.into();
                if $validator(&value) {
                    Ok(Self(value))
                } else {
                    Err(IdentityError::$variant {
                        type_name: stringify!($name),
                    })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = IdentityError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdentityError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdentityError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! stable_identifiers {
    ($($name:ident),+ $(,)?) => {
        $(identifier!($name, is_stable_id, InvalidStableId);)+
    };
}

stable_identifiers!(
    ProjectId,
    PrefabId,
    InstanceId,
    NodeId,
    PortId,
    StateId,
    BodyId,
    ColliderId,
    JointId,
    BindingId,
    ContextId,
    PlanId,
    OperationId,
    InvocationId,
    ResourceId,
    ClipId,
    ModuleId,
    WorkspaceId,
    GameInstanceId,
    SessionEpoch,
    WorldId,
    ToolHostId,
    ObjectId,
    SourceId,
    SnapshotId,
    TargetProfileId,
    VersionProfileId,
    BakeId,
    PackId,
    SessionId,
    ClientId,
    StepId,
    CommandId,
    SymbolId,
    RecordId,
    SelectionId,
    MaterialId,
    PhysicsId,
    BundleId,
    RequestId,
    ArtifactId,
    PatchId,
    ManifestId,
    ComponentId,
    CodecId,
    ChangeSetId,
    ExprId,
    AssetId,
    PrincipalId,
    TargetId,
);

// ReleaseEvidence test identifiers have minLength: 1 and no lexical pattern.
identifier!(TestId, is_nonempty_id, InvalidNonEmptyId);
identifier!(ActionId, is_namespaced_id, InvalidNamespacedId);
identifier!(ResourceLocation, is_namespaced_id, InvalidNamespacedId);
identifier!(ProviderId, is_namespaced_id, InvalidNamespacedId);
identifier!(
    CompatibilityProfileId,
    is_namespaced_id,
    InvalidNamespacedId
);
identifier!(CapabilityId, is_namespaced_id, InvalidNamespacedId);
identifier!(ExtensionKey, is_namespaced_id, InvalidNamespacedId);

/// A SHA-256 digest in the schema's lowercase hexadecimal wire representation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(IdentityError::InvalidSha256Digest)
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(64);
        for byte in bytes {
            value.push(HEX[usize::from(byte >> 4)] as char);
            value.push(HEX[usize::from(byte & 15)] as char);
        }
        Self(value)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        fn digit(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!("digest construction guarantees lowercase hexadecimal"),
            }
        }

        let mut bytes = [0; 32];
        for (output, pair) in bytes.iter_mut().zip(self.0.as_bytes().chunks_exact(2)) {
            *output = (digit(pair[0]) << 4) | digit(pair[1]);
        }
        bytes
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Sha256Digest {
    type Err = IdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = IdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Sha256Digest {
    type Error = IdentityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl AsRef<str> for Sha256Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for Sha256Digest {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifiers_follow_only_the_canonical_nonempty_requirement() {
        assert_eq!(TestId::new("CT01").unwrap().as_str(), "CT01");
        assert_eq!(TestId::new("OB01").unwrap().as_str(), "OB01");
        assert_eq!(TestId::new("V101").unwrap().as_str(), "V101");
        assert!(TestId::new("검사 1").is_ok());
        assert!(TestId::new(" ").is_ok());
        assert!(TestId::new("").is_err());
        assert_eq!(
            serde_json::from_str::<TestId>("\"CT01\"").unwrap().as_str(),
            "CT01"
        );
        assert!(serde_json::from_str::<TestId>("\"\"").is_err());
    }

    #[test]
    fn stable_identifiers_preserve_allowed_text_and_enforce_boundaries() {
        let value = "project.01_node:root-2";
        assert_eq!(ProjectId::new(value).unwrap().as_str(), value);
        assert!(ProjectId::new("a".repeat(128)).is_ok());
        assert!(ProjectId::new("a".repeat(129)).is_err());
        for invalid in [
            "",
            "_root",
            "Root",
            " root",
            "root ",
            "root/path",
            "루트",
            "root\n",
        ] {
            assert!(ProjectId::new(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn namespace_is_preserved_and_schema_allows_dots_and_path_slashes() {
        let action = ActionId::new("example.mod:build/root").unwrap();
        assert_eq!(action.to_string(), "example.mod:build/root");
        assert!(ResourceLocation::new(".:.").is_ok());
        for invalid in [
            "block",
            "minecraft:",
            ":block",
            "Minecraft:block",
            "a:b:c",
            "a/b:c",
        ] {
            assert!(
                ResourceLocation::new(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(ProviderId::new("mmmm:host").is_ok());
        assert!(ProviderId::new("host").is_err());
    }

    #[test]
    fn identifier_deserialization_does_not_normalize_or_accept_numbers() {
        assert_eq!(
            serde_json::to_string(&NodeId::new("n:1").unwrap()).unwrap(),
            "\"n:1\""
        );
        for invalid in ["\"N:1\"", "\" n:1\"", "1", "null", "{}"] {
            assert!(serde_json::from_str::<NodeId>(invalid).is_err());
        }
    }

    #[test]
    fn digest_bytes_round_trip_and_wire_requires_lowercase() {
        let bytes = std::array::from_fn(|index| index as u8 * 7);
        let digest = Sha256Digest::from_bytes(bytes);
        assert_eq!(digest.to_bytes(), bytes);
        assert_eq!(
            serde_json::from_str::<Sha256Digest>(&serde_json::to_string(&digest).unwrap()).unwrap(),
            digest
        );
        assert!(Sha256Digest::new(digest.as_str().to_uppercase()).is_err());
        assert!(Sha256Digest::new("0".repeat(63)).is_err());
        assert!(Sha256Digest::new("g".repeat(64)).is_err());
    }
}
