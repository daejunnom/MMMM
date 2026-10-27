//! Search ordering and authenticated continuation. A cursor does not confer
//! access: its principal and currently visible record set are checked each time.

use crate::{
    catalog::{CatalogError, ReadPrincipal},
    snapshot::{IndexedRecord, Snapshot, text},
};
use hmac::{Hmac, Mac};
use mmmm_contracts::{
    ContextId, Int32, ResourceLocation, Sha256Digest, SnapshotId, canonical_bytes,
    canonical_digest, parse_json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CatalogQuery {
    pub snapshot_id: SnapshotId,
    pub query: String,
    pub kinds: Vec<ResourceLocation>,
    pub locale: String,
    pub cursor: Option<String>,
    pub limit: Int32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RecordQuery {
    pub snapshot_id: SnapshotId,
    pub kind: ResourceLocation,
    pub resource_id: ResourceLocation,
    pub context_id: ContextId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Cursor {
    version: u8,
    snapshot_id: SnapshotId,
    snapshot_revision: Sha256Digest,
    environment_fingerprint: Sha256Digest,
    query_digest: Sha256Digest,
    principal_id: String,
    permission_scope_digest: Sha256Digest,
    visibility_digest: Sha256Digest,
    next_offset: usize,
}

pub(crate) fn query_digest(query: &CatalogQuery) -> Result<Sha256Digest, CatalogError> {
    // Cursor and principal are deliberately outside the public query identity.
    // The opaque token binds those fields independently. Kind order is a filter
    // set, so equivalent orderings receive the same query identity.
    let mut kinds = query.kinds.clone();
    kinds.sort();
    canonical_digest(&json!({"snapshotId":query.snapshot_id,"query":query.query,
        "kinds":kinds,"locale":query.locale,"limit":query.limit}))
    .map_err(CatalogError::digest)
}

fn fold(text: &str) -> String {
    text.to_lowercase()
}

pub(crate) fn rank(query: &CatalogQuery, entry: &IndexedRecord) -> Option<u8> {
    let resource = text(&entry.record, "resourceId");
    let kind = text(&entry.record, "kind");
    if !query.kinds.is_empty() && !query.kinds.iter().any(|filter| filter.as_str() == kind) {
        return None;
    }
    let needle = fold(query.query.trim());
    if needle.is_empty() {
        return Some(7);
    }
    if needle == resource {
        return Some(0);
    }
    if resource.starts_with(&needle) {
        return Some(1);
    }
    let tag_needle = needle.strip_prefix('#').unwrap_or(&needle);
    if entry
        .terms
        .tags
        .iter()
        .any(|tag| tag.as_str() == tag_needle)
    {
        return Some(2);
    }
    if needle == kind
        || needle == fold(text(&entry.record, "valueType"))
        || entry
            .terms
            .type_terms
            .iter()
            .any(|term| fold(term) == needle)
    {
        return Some(3);
    }
    let aliases: Vec<String> = entry
        .terms
        .aliases
        .iter()
        .filter(|(locale, _)| {
            locale.as_str() == query.locale
                || locale.as_str() == "ko_kr"
                || locale.as_str() == "en_us"
        })
        .flat_map(|(_, aliases)| aliases)
        .map(|alias| fold(alias))
        .collect();
    if aliases.iter().any(|alias| alias == &needle) {
        return Some(4);
    }
    if aliases.iter().any(|alias| alias.starts_with(&needle)) {
        return Some(5);
    }
    let terms = needle.split_whitespace().collect::<Vec<_>>();
    let matches_all = terms.iter().all(|term| {
        resource.contains(term)
            || kind.contains(term)
            || fold(text(&entry.record, "valueType")).contains(term)
            || entry
                .terms
                .tags
                .iter()
                .any(|tag| tag.as_str().contains(term))
            || entry
                .terms
                .type_terms
                .iter()
                .any(|value| fold(value).contains(term))
            || aliases.iter().any(|alias| alias.contains(term))
    });
    matches_all.then_some(6)
}

pub(crate) fn visibility_digest(records: &[&IndexedRecord]) -> Result<Sha256Digest, CatalogError> {
    let ids = records
        .iter()
        .map(|record| text(&record.record, "recordId"))
        .collect::<Vec<_>>();
    canonical_digest(&json!(ids)).map_err(CatalogError::digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn decode_hex(text: &str) -> Result<Vec<u8>, CatalogError> {
    if !text.len().is_multiple_of(2) {
        return Err(CatalogError::StaleCursor);
    }
    fn digit(byte: u8) -> Result<u8, CatalogError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(CatalogError::StaleCursor),
        }
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

fn mac(key: &[u8; 32], bytes: &[u8]) -> Hmac<Sha256> {
    let mut result = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    result.update(b"MMMM catalog cursor v1\0");
    result.update(bytes);
    result
}

pub(crate) fn create_cursor(
    key: &[u8; 32],
    snapshot: &Snapshot,
    query_digest: &Sha256Digest,
    principal: &ReadPrincipal,
    visibility_digest: &Sha256Digest,
    next_offset: usize,
    max_bytes: usize,
) -> Result<String, CatalogError> {
    let claims = Cursor {
        version: 1,
        snapshot_id: snapshot.id.clone(),
        snapshot_revision: snapshot.revision.clone(),
        environment_fingerprint: snapshot.fingerprint.clone(),
        query_digest: query_digest.clone(),
        principal_id: principal.principal_id.as_str().to_owned(),
        permission_scope_digest: principal.permission_scope_digest.clone(),
        visibility_digest: visibility_digest.clone(),
        next_offset,
    };
    let bytes = canonical_bytes(&serde_json::to_value(claims).map_err(CatalogError::codec)?)
        .map_err(CatalogError::digest)?;
    let tag = mac(key, &bytes).finalize().into_bytes();
    let token = format!("{}.{}", encode_hex(&bytes), encode_hex(&tag));
    if token.len() > max_bytes {
        return Err(CatalogError::InputLimit);
    }
    Ok(token)
}

pub(crate) fn cursor_offset(
    token: &str,
    key: &[u8; 32],
    snapshot: &Snapshot,
    query_digest: &Sha256Digest,
    principal: &ReadPrincipal,
    visibility_digest: &Sha256Digest,
    max_bytes: usize,
) -> Result<usize, CatalogError> {
    if token.len() > max_bytes {
        return Err(CatalogError::StaleCursor);
    }
    let (body, tag) = token.split_once('.').ok_or(CatalogError::StaleCursor)?;
    if tag.len() != 64 {
        return Err(CatalogError::StaleCursor);
    }
    let bytes = decode_hex(body)?;
    let tag = decode_hex(tag)?;
    mac(key, &bytes)
        .verify_slice(&tag)
        .map_err(|_| CatalogError::StaleCursor)?;
    let value: Value = parse_json(&bytes).map_err(|_| CatalogError::StaleCursor)?;
    let claims: Cursor = serde_json::from_value(value).map_err(|_| CatalogError::StaleCursor)?;
    if claims.version != 1
        || claims.snapshot_id != snapshot.id
        || claims.snapshot_revision != snapshot.revision
        || claims.environment_fingerprint != snapshot.fingerprint
        || &claims.query_digest != query_digest
        || claims.principal_id != principal.principal_id.as_str()
        || claims.permission_scope_digest != principal.permission_scope_digest
        || &claims.visibility_digest != visibility_digest
    {
        return Err(CatalogError::StaleCursor);
    }
    Ok(claims.next_offset)
}
