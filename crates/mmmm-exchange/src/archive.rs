//! A bounded, file-only ZIP profile for neutral scene exchange.
//!
//! Header preflight happens before `ZipArchive` allocates its directory index.
//! Names remain literal UTF-8 resource keys: this module never extracts a file,
//! resolves a URI, or opens a path. Directory entries, self-extracting prefixes,
//! ZIP64 and encryption are outside this profile. A stored deterministic writer
//! computes its complete size before allocating the output buffer.

use crate::{ExchangeError, ExchangeResult};
use std::collections::BTreeMap;
use std::io::Cursor;
use unicode_normalization::UnicodeNormalization;
use zip::ZipArchive;

const MANIFEST: &str = "mmmm-exchange.json";
const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const END: u32 = 0x0605_4b50;
const DESCRIPTOR: u32 = 0x0807_4b50;
const UTF8: u16 = 1 << 11;
const DATA_DESCRIPTOR: u16 = 1 << 3;
const REGULAR_MODE: u32 = 0o100644;
const METADATA_BUDGET: usize = 16 * 1024 * 1024;
const EXTRA_BUDGET: usize = 4096;
const COMMENT_BUDGET: usize = 4096;
const PATH_DEPTH_LIMIT: usize = 64;

/// Limits apply to input bytes, advertised sizes and observed decoded bytes.
/// Trusted callers may lower or raise defaults within the implementation's
/// finite ceilings (512 MiB archive, 128 MiB member, 256 MiB total, 16384
/// members, ratio 10000 and 1024-byte paths). Metadata has a separate 16 MiB
/// ceiling; each local/central extra field and comment is at most 4096 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub max_archive_bytes: u64,
    pub max_member_bytes: u64,
    pub max_total_bytes: u64,
    pub max_members: usize,
    pub max_ratio: u64,
    pub max_path_bytes: usize,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 64 * 1024 * 1024,
            max_member_bytes: 16 * 1024 * 1024,
            max_total_bytes: 32 * 1024 * 1024,
            max_members: 4096,
            max_ratio: 100,
            max_path_bytes: 240,
        }
    }
}

impl ArchiveLimits {
    fn validate(self) -> ExchangeResult<()> {
        if !(1..=512 * 1024 * 1024).contains(&self.max_archive_bytes)
            || !(1..=128 * 1024 * 1024).contains(&self.max_member_bytes)
            || !(1..=256 * 1024 * 1024).contains(&self.max_total_bytes)
            || self.max_member_bytes > self.max_total_bytes
            || !(1..=16_384).contains(&self.max_members)
            || !(1..=10_000).contains(&self.max_ratio)
            || !(1..=1024).contains(&self.max_path_bytes)
        {
            return Err(limit("Archive limits exceed the finite codec profile"));
        }
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> ExchangeError {
    ExchangeError::new("ARCHIVE_INVALID", message)
}
fn limit(message: impl Into<String>) -> ExchangeError {
    ExchangeError::new("BUDGET_EXCEEDED", message)
}

fn check_cancel(cancelled: &mut dyn FnMut() -> bool) -> ExchangeResult<()> {
    if cancelled() {
        Err(ExchangeError::new(
            "CANCELLED",
            "Archive work was cancelled",
        ))
    } else {
        Ok(())
    }
}

/// Validates a file resource key without converting it to an OS path.
/// Case/normalization and ancestor conflicts require the whole archive and
/// are checked by both codecs in addition to this single-name validation.
pub fn validate_member_path(path: &str, limits: ArchiveLimits) -> ExchangeResult<()> {
    limits.validate()?;
    if path.is_empty() || path.len() > limits.max_path_bytes {
        return Err(limit("Archive member path length is outside its budget"));
    }
    if path.starts_with('/')
        || path.ends_with('/')
        || path
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err(invalid("Archive path is not a portable relative file key"));
    }
    let mut depth = 0;
    for component in path.split('/') {
        depth += 1;
        if depth > PATH_DEPTH_LIMIT {
            return Err(limit("Archive path component depth exceeds its budget"));
        }
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with(['.', ' '])
            || component.starts_with(' ')
        {
            return Err(invalid("Archive path contains an ambiguous component"));
        }
        let lower = component.to_lowercase();
        if lower == ".env"
            || lower.starts_with(".env.")
            || lower == ".ssh"
            || lower.contains("credential")
            || lower.contains("api-key")
            || lower.contains("api_key")
            || lower.contains("apikey")
            || ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]
                .iter()
                .any(|prefix| lower.starts_with(prefix))
            || [".pem", ".key", ".ppk", ".p12", ".pfx"]
                .iter()
                .any(|suffix| lower.ends_with(suffix))
            || (lower.ends_with(".json")
                && ["service-account", "service_account", "serviceaccount"]
                    .iter()
                    .any(|part| lower.contains(part)))
        {
            return Err(invalid(
                "Secret file names are forbidden before archive member bytes are read",
            ));
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or(component)
            .to_uppercase();
        let numbered_device = stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            });
        if matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || numbered_device
        {
            return Err(invalid("Archive path contains a reserved DOS device"));
        }
    }
    Ok(())
}

#[derive(Default)]
struct Names {
    // Each intermediate directory is registered too: `A/x` and `a/y` cannot
    // silently collapse into the same directory on a case-insensitive host.
    nodes: BTreeMap<String, (String, bool)>,
    metadata_bytes: usize,
}

impl Names {
    fn insert(&mut self, path: &str, limits: ArchiveLimits) -> ExchangeResult<()> {
        validate_member_path(path, limits)?;
        let endpoints = path
            .match_indices('/')
            .map(|(index, _)| index)
            .chain(std::iter::once(path.len()));
        for end in endpoints {
            let literal = &path[..end];
            let folded: String = literal
                .nfc()
                .collect::<String>()
                .to_lowercase()
                .to_uppercase()
                .nfc()
                .collect();
            let is_file = end == path.len();
            if let Some((existing, existing_file)) = self.nodes.get(&folded) {
                if existing != literal || *existing_file != is_file || is_file {
                    return Err(invalid(
                        "Archive names duplicate, alias, or conflict with a file ancestor",
                    ));
                }
                continue;
            }
            self.metadata_bytes = self
                .metadata_bytes
                .checked_add(literal.len())
                .and_then(|n| n.checked_add(folded.len()))
                .and_then(|n| n.checked_add(96))
                .ok_or_else(|| limit("Archive path metadata overflow"))?;
            if self.metadata_bytes > METADATA_BUDGET {
                return Err(limit("Archive path metadata exceeds its budget"));
            }
            self.nodes.insert(folded, (literal.to_owned(), is_file));
        }
        Ok(())
    }
}

/// Validates all logical bundle file keys, including referenced-only resources,
/// with the same portable tree and alias rules as the ZIP codecs. The exact
/// root manifest must appear once and counts toward `max_members`; callers
/// append it only if it is not already represented by their logical member set.
/// No payload bytes, ZIP directory, filesystem path or URI are accessed.
pub fn validate_member_paths<'a>(
    paths: impl IntoIterator<Item = &'a str>,
    limits: ArchiveLimits,
) -> ExchangeResult<()> {
    limits.validate()?;
    let mut names = Names::default();
    let mut count = 0usize;
    let mut has_manifest = false;
    for path in paths {
        count = count
            .checked_add(1)
            .ok_or_else(|| limit("Logical bundle member count overflow"))?;
        if count > limits.max_members {
            return Err(limit("Logical bundle member count exceeds its budget"));
        }
        names.insert(path, limits)?;
        has_manifest |= path == MANIFEST;
    }
    if !has_manifest {
        return Err(invalid("Logical bundle root exchange manifest is missing"));
    }
    Ok(())
}

#[derive(Debug)]
struct Member {
    name: String,
    flags: u16,
    method: u16,
    crc: u32,
    compressed: u32,
    uncompressed: u32,
    local_start: usize,
    data_start: usize,
    local_end: usize,
}

fn range(bytes: &[u8], start: usize, length: usize) -> ExchangeResult<&[u8]> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| invalid("ZIP offset overflow"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| invalid("ZIP header or payload is truncated"))
}
fn u16_at(bytes: &[u8], start: usize) -> ExchangeResult<u16> {
    let b = range(bytes, start, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn u32_at(bytes: &[u8], start: usize) -> ExchangeResult<u32> {
    let b = range(bytes, start, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn check_extra(bytes: &[u8]) -> ExchangeResult<()> {
    if bytes.len() > EXTRA_BUDGET {
        return Err(limit("ZIP extra fields exceed the metadata budget"));
    }
    let mut offset = 0;
    while offset < bytes.len() {
        let tag = u16_at(bytes, offset)?;
        let length = usize::from(u16_at(bytes, offset + 2)?);
        range(bytes, offset + 4, length)?;
        // Unicode path overrides would give one file two names. AES and ZIP64
        // cannot be made harmless by ignoring their extra-field declarations.
        if matches!(tag, 0x0001 | 0x7075 | 0x9901) {
            return Err(invalid(
                "ZIP64, Unicode path overrides and encryption extras are unsupported",
            ));
        }
        offset += 4 + length;
    }
    Ok(())
}

fn check_flags(flags: u16, method: u16, version: u16) -> ExchangeResult<()> {
    // Only UTF-8, a data descriptor, and Deflate compression-level hints are
    // supported. Encryption, patched data and masked headers are rejected.
    let allowed = UTF8 | DATA_DESCRIPTOR | if method == 8 { 0b110 } else { 0 };
    if !matches!(method, 0 | 8)
        || !matches!(version, 10 | 20)
        || (method == 8 && version != 20)
        || flags & !allowed != 0
    {
        return Err(invalid(
            "ZIP method, version or flags are outside the supported profile",
        ));
    }
    Ok(())
}

fn check_sizes(compressed: u32, uncompressed: u32, limits: ArchiveLimits) -> ExchangeResult<()> {
    if compressed == u32::MAX || uncompressed == u32::MAX {
        return Err(invalid("ZIP64 size sentinels are unsupported"));
    }
    if u64::from(uncompressed) > limits.max_member_bytes {
        return Err(limit("ZIP member decoded size exceeds its budget"));
    }
    if u64::from(compressed) > limits.max_archive_bytes {
        return Err(limit("ZIP member compressed size exceeds its budget"));
    }
    if u64::from(uncompressed) > u64::from(compressed).saturating_mul(limits.max_ratio) {
        return Err(limit("ZIP member expansion ratio exceeds its budget"));
    }
    Ok(())
}

#[cfg(test)]
fn preflight(bytes: &[u8], limits: ArchiveLimits) -> ExchangeResult<Vec<Member>> {
    preflight_with_cancel(bytes, limits, &mut || false)
}

#[cfg(test)]
fn preflight_with_cancel(
    bytes: &[u8],
    limits: ArchiveLimits,
    cancelled: &mut dyn FnMut() -> bool,
) -> ExchangeResult<Vec<Member>> {
    preflight_with_required_root(bytes, limits, MANIFEST, cancelled)
}

fn preflight_with_required_root(
    bytes: &[u8],
    limits: ArchiveLimits,
    required_root: &str,
    cancelled: &mut dyn FnMut() -> bool,
) -> ExchangeResult<Vec<Member>> {
    limits.validate()?;
    check_cancel(cancelled)?;
    validate_member_path(required_root, limits)?;
    if required_root.contains('/') || !required_root.nfc().eq(required_root.chars()) {
        return Err(invalid(
            "Required ZIP root must be one canonical portable file name",
        ));
    }
    if bytes.len() as u64 > limits.max_archive_bytes {
        return Err(limit("ZIP archive bytes exceed their budget"));
    }
    if bytes.len() < 22 {
        return Err(invalid("ZIP end record is missing"));
    }
    let search_start = bytes.len().saturating_sub(22 + usize::from(u16::MAX));
    let mut end_record = None;
    for offset in (search_start..=bytes.len() - 22).rev() {
        if offset % 1024 == 0 {
            check_cancel(cancelled)?;
        }
        if u32_at(bytes, offset)? == END
            && offset + 22 + usize::from(u16_at(bytes, offset + 20)?) == bytes.len()
        {
            end_record = Some(offset);
            break;
        }
    }
    let end = end_record.ok_or_else(|| invalid("ZIP end record or comment length is invalid"))?;
    if usize::from(u16_at(bytes, end + 20)?) > COMMENT_BUDGET {
        return Err(limit("ZIP archive comment exceeds its metadata budget"));
    }
    if u16_at(bytes, end + 4)? != 0 || u16_at(bytes, end + 6)? != 0 {
        return Err(invalid("Multi-disk ZIP archives are unsupported"));
    }
    let disk_members = u16_at(bytes, end + 8)?;
    let total_members = u16_at(bytes, end + 10)?;
    if disk_members != total_members || total_members == u16::MAX {
        return Err(invalid("ZIP member counts disagree or declare ZIP64"));
    }
    let count = usize::from(total_members);
    if count == 0 || count > limits.max_members {
        return Err(limit("ZIP member count is outside its budget"));
    }
    let directory_size = u32_at(bytes, end + 12)?;
    let directory_start = u32_at(bytes, end + 16)?;
    if directory_size == u32::MAX || directory_start == u32::MAX {
        return Err(invalid("ZIP64 directory offsets are unsupported"));
    }
    let directory_start =
        usize::try_from(directory_start).map_err(|_| invalid("ZIP directory offset overflow"))?;
    let directory_size =
        usize::try_from(directory_size).map_err(|_| invalid("ZIP directory size overflow"))?;
    if directory_size > METADATA_BUDGET {
        return Err(limit("ZIP central directory exceeds its metadata budget"));
    }
    if directory_start.checked_add(directory_size) != Some(end)
        || directory_size < count.saturating_mul(46)
    {
        return Err(invalid(
            "ZIP central directory is not adjacent to its end record",
        ));
    }
    let directory = range(bytes, directory_start, directory_size)?;
    let mut offset = 0;
    let mut names = Names::default();
    let mut members = Vec::new();
    members
        .try_reserve_exact(count)
        .map_err(|_| limit("ZIP member index allocation failed"))?;
    let mut total_decoded = 0usize;
    let mut has_required_root = false;
    for _ in 0..count {
        check_cancel(cancelled)?;
        range(directory, offset, 46)?;
        if u32_at(directory, offset)? != CENTRAL {
            return Err(invalid("ZIP central directory member signature is invalid"));
        }
        let flags = u16_at(directory, offset + 8)?;
        let method = u16_at(directory, offset + 10)?;
        check_flags(flags, method, u16_at(directory, offset + 6)?)?;
        let compressed = u32_at(directory, offset + 20)?;
        let uncompressed = u32_at(directory, offset + 24)?;
        check_sizes(compressed, uncompressed, limits)?;
        if method == 0 && compressed != uncompressed {
            return Err(invalid("Stored ZIP member sizes disagree"));
        }
        total_decoded = total_decoded
            .checked_add(uncompressed as usize)
            .ok_or_else(|| limit("ZIP total size overflow"))?;
        if total_decoded as u64 > limits.max_total_bytes {
            return Err(limit("ZIP aggregate decoded size exceeds its budget"));
        }
        let name_len = usize::from(u16_at(directory, offset + 28)?);
        let extra_len = usize::from(u16_at(directory, offset + 30)?);
        let comment_len = usize::from(u16_at(directory, offset + 32)?);
        if name_len > limits.max_path_bytes
            || extra_len > EXTRA_BUDGET
            || comment_len > COMMENT_BUDGET
        {
            return Err(limit("ZIP member metadata exceeds its budget"));
        }
        if u16_at(directory, offset + 34)? != 0 {
            return Err(invalid("Multi-disk ZIP member is unsupported"));
        }
        let attributes = u32_at(directory, offset + 38)?;
        let mode = attributes >> 16;
        let file_type = mode & 0o170000;
        if !matches!(file_type, 0 | 0o100000)
            || mode & 0o7000 != 0
            || attributes & (0xffff & !0x00a7) != 0
        {
            return Err(invalid(
                "ZIP symlinks, directories and special file attributes are unsupported",
            ));
        }
        let name_raw = range(directory, offset + 46, name_len)?;
        let name =
            std::str::from_utf8(name_raw).map_err(|_| invalid("ZIP names must be valid UTF-8"))?;
        if flags & UTF8 == 0 && !name_raw.is_ascii() {
            return Err(invalid("Non-ASCII ZIP names must explicitly declare UTF-8"));
        }
        names.insert(name, limits)?;
        has_required_root |= name == required_root;
        check_extra(range(directory, offset + 46 + name_len, extra_len)?)?;
        range(directory, offset + 46 + name_len + extra_len, comment_len)?;
        let local_start = u32_at(directory, offset + 42)?;
        if local_start == u32::MAX {
            return Err(invalid("ZIP64 local offsets are unsupported"));
        }
        members.push(Member {
            name: name.to_owned(),
            flags,
            method,
            crc: u32_at(directory, offset + 16)?,
            compressed,
            uncompressed,
            local_start: local_start as usize,
            data_start: 0,
            local_end: 0,
        });
        offset += 46 + name_len + extra_len + comment_len;
    }
    if offset != directory.len() || !has_required_root {
        return Err(invalid(
            "ZIP directory count is inexact or the required root file is missing",
        ));
    }
    for member in &mut members {
        check_cancel(cancelled)?;
        preflight_local(bytes, directory_start, member)?;
    }
    let mut spans: Vec<(usize, usize)> = members
        .iter()
        .map(|m| (m.local_start, m.local_end))
        .collect();
    spans.sort_unstable();
    let mut previous_end = 0;
    for (start, local_end) in spans {
        check_cancel(cancelled)?;
        if start != previous_end || local_end <= start || local_end > directory_start {
            return Err(invalid(
                "ZIP local entries overlap, contain gaps or have an unindexed prefix",
            ));
        }
        previous_end = local_end;
    }
    if previous_end != directory_start {
        return Err(invalid(
            "ZIP contains unindexed data before its central directory",
        ));
    }
    Ok(members)
}

fn preflight_local(
    bytes: &[u8],
    directory_start: usize,
    member: &mut Member,
) -> ExchangeResult<()> {
    let offset = member.local_start;
    if offset
        .checked_add(30)
        .is_none_or(|end| end > directory_start)
    {
        return Err(invalid("ZIP local header crosses the central directory"));
    }
    range(bytes, offset, 30)?;
    if u32_at(bytes, offset)? != LOCAL {
        return Err(invalid("ZIP local header signature is invalid"));
    }
    let flags = u16_at(bytes, offset + 6)?;
    let method = u16_at(bytes, offset + 8)?;
    check_flags(flags, method, u16_at(bytes, offset + 4)?)?;
    if flags != member.flags || method != member.method {
        return Err(invalid("ZIP local and central method or flags disagree"));
    }
    let name_len = usize::from(u16_at(bytes, offset + 26)?);
    let extra_len = usize::from(u16_at(bytes, offset + 28)?);
    if name_len != member.name.len() || extra_len > EXTRA_BUDGET {
        return Err(invalid("ZIP local name or extra length is invalid"));
    }
    let data_start = offset
        .checked_add(30 + name_len + extra_len)
        .ok_or_else(|| invalid("ZIP local data offset overflow"))?;
    if data_start > directory_start
        || range(bytes, offset + 30, name_len)? != member.name.as_bytes()
    {
        return Err(invalid("ZIP local and central names disagree"));
    }
    check_extra(range(bytes, offset + 30 + name_len, extra_len)?)?;
    let local_crc = u32_at(bytes, offset + 14)?;
    let local_compressed = u32_at(bytes, offset + 18)?;
    let local_uncompressed = u32_at(bytes, offset + 22)?;
    if local_compressed == u32::MAX || local_uncompressed == u32::MAX {
        return Err(invalid("ZIP64 local size sentinels are unsupported"));
    }
    let mut local_end = data_start
        .checked_add(member.compressed as usize)
        .ok_or_else(|| invalid("ZIP payload offset overflow"))?;
    if local_end > directory_start {
        return Err(invalid("ZIP member payload crosses the central directory"));
    }
    if flags & DATA_DESCRIPTOR == 0 {
        if local_crc != member.crc
            || local_compressed != member.compressed
            || local_uncompressed != member.uncompressed
        {
            return Err(invalid("ZIP local and central CRC or sizes disagree"));
        }
    } else {
        if (local_crc != 0 && local_crc != member.crc)
            || (local_compressed != 0 && local_compressed != member.compressed)
            || (local_uncompressed != 0 && local_uncompressed != member.uncompressed)
        {
            return Err(invalid(
                "ZIP local descriptor placeholders disagree with the directory",
            ));
        }
        // A signature is optional, except that its numeric value could also
        // be the CRC. Try both layouts and require a fully matching record.
        let matches_descriptor = |at: usize| -> ExchangeResult<bool> {
            if at.checked_add(12).is_none_or(|end| end > directory_start) {
                return Ok(false);
            }
            Ok(u32_at(bytes, at)? == member.crc
                && u32_at(bytes, at + 4)? == member.compressed
                && u32_at(bytes, at + 8)? == member.uncompressed)
        };
        if local_end
            .checked_add(16)
            .is_some_and(|end| end <= directory_start)
            && u32_at(bytes, local_end)? == DESCRIPTOR
            && matches_descriptor(local_end + 4)?
        {
            local_end += 16;
        } else if matches_descriptor(local_end)? {
            local_end += 12;
        } else {
            return Err(invalid(
                "ZIP data descriptor is missing or disagrees with the directory",
            ));
        }
    }
    member.data_start = data_start;
    member.local_end = local_end;
    Ok(())
}

/// Reads all members into bounded memory and verifies every decoded byte and
/// CRC. A partially decoded archive never becomes an import input.
pub fn read_zip(bytes: &[u8], limits: ArchiveLimits) -> ExchangeResult<BTreeMap<String, Vec<u8>>> {
    read_zip_with_cancel(bytes, limits, || false)
}

/// Request-facing callers pass their trusted cancellation state here. Checks
/// happen between bounded headers and 8192-byte input/output chunks. The plain
/// wrapper is intended for already bounded immutable jobs and local fixtures.
pub fn read_zip_with_cancel(
    bytes: &[u8],
    limits: ArchiveLimits,
    cancelled: impl FnMut() -> bool,
) -> ExchangeResult<BTreeMap<String, Vec<u8>>> {
    read_zip_with_required_root(bytes, limits, MANIFEST, cancelled)
}

/// Trusted codecs select their exact required root (for example, pack.mcmeta).
/// It must be one bounded portable NFC file name, with literal case matching.
/// All other members pass the same exchange ZIP preflight and byte decoder;
/// choosing a root does not approve member contents or authorize source use.
pub fn read_zip_with_required_root(
    bytes: &[u8],
    limits: ArchiveLimits,
    required_root: &str,
    mut cancelled: impl FnMut() -> bool,
) -> ExchangeResult<BTreeMap<String, Vec<u8>>> {
    let metadata = preflight_with_required_root(bytes, limits, required_root, &mut cancelled)?;
    check_cancel(&mut cancelled)?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| invalid(format!("ZIP decoder rejected directory: {e}")))?;
    check_cancel(&mut cancelled)?;
    if archive.len() != metadata.len() {
        return Err(invalid(
            "ZIP decoder directory count changed after preflight",
        ));
    }
    let mut result = BTreeMap::new();
    let mut total = 0usize;
    for (index, expected) in metadata.into_iter().enumerate() {
        check_cancel(&mut cancelled)?;
        // The zip crate provides an independent interpretation of directory
        // identity. Raw access creates no decompressor whose hidden buffering
        // could make an apparent EOF conceal trailing compressed bytes.
        let file = archive
            .by_index_raw(index)
            .map_err(|e| invalid(format!("ZIP decoder rejected member: {e}")))?;
        if file.name_raw() != expected.name.as_bytes()
            || file.name() != expected.name
            || file.size() != u64::from(expected.uncompressed)
            || file.compressed_size() != u64::from(expected.compressed)
            || file.crc32() != expected.crc
            || file.header_start() != expected.local_start as u64
            || file.data_start() != expected.data_start as u64
            || !file.is_file()
        {
            return Err(invalid(
                "ZIP decoder member identity disagrees with preflight",
            ));
        }
        drop(file);
        let mut decoded = Vec::new();
        decoded
            .try_reserve_exact(expected.uncompressed as usize)
            .map_err(|_| limit("ZIP member allocation failed"))?;
        let mut crc = crc32fast::Hasher::new();
        let compressed = range(bytes, expected.data_start, expected.compressed as usize)?;
        if expected.method == 0 {
            for chunk in compressed.chunks(8192) {
                check_cancel(&mut cancelled)?;
                append_decoded(chunk, &expected, limits, &mut decoded, &mut total, &mut crc)?;
            }
        } else {
            let mut inflater = flate2::Decompress::new(false);
            let mut scratch = [0u8; 8192];
            loop {
                check_cancel(&mut cancelled)?;
                let before_in = inflater.total_in();
                let before_out = inflater.total_out();
                let input_start = usize::try_from(before_in)
                    .map_err(|_| invalid("Deflate input offset overflow"))?;
                if input_start > compressed.len() {
                    return Err(invalid("Deflate consumed bytes beyond its declared member"));
                }
                let input_end = input_start.saturating_add(8192).min(compressed.len());
                let status = inflater
                    .decompress(
                        &compressed[input_start..input_end],
                        &mut scratch,
                        flate2::FlushDecompress::None,
                    )
                    .map_err(|e| invalid(format!("ZIP Deflate decode failed: {e}")))?;
                let produced = inflater
                    .total_out()
                    .checked_sub(before_out)
                    .ok_or_else(|| invalid("Deflate output count regressed"))?;
                let consumed = inflater
                    .total_in()
                    .checked_sub(before_in)
                    .ok_or_else(|| invalid("Deflate input count regressed"))?;
                if produced > scratch.len() as u64 || consumed > (input_end - input_start) as u64 {
                    return Err(invalid(
                        "Deflate byte accounting exceeded its bounded buffers",
                    ));
                }
                append_decoded(
                    &scratch[..produced as usize],
                    &expected,
                    limits,
                    &mut decoded,
                    &mut total,
                    &mut crc,
                )?;
                if status == flate2::Status::StreamEnd {
                    if inflater.total_in() != compressed.len() as u64 {
                        return Err(invalid(
                            "ZIP Deflate member contains trailing compressed bytes",
                        ));
                    }
                    break;
                }
                // Empty output is not EOF. A final block marker and exact
                // consumed input are required, even when headers advertise 0.
                if produced == 0 && consumed == 0 {
                    return Err(invalid(
                        "ZIP Deflate stream is incomplete or made no progress",
                    ));
                }
            }
        }
        if decoded.len() != expected.uncompressed as usize || crc.finalize() != expected.crc {
            return Err(invalid(
                "ZIP decoded size or CRC does not match its headers",
            ));
        }
        check_cancel(&mut cancelled)?;
        if result.insert(expected.name, decoded).is_some() {
            return Err(invalid("ZIP decoder produced a duplicate member"));
        }
    }
    check_cancel(&mut cancelled)?;
    Ok(result)
}

fn append_decoded(
    chunk: &[u8],
    expected: &Member,
    limits: ArchiveLimits,
    decoded: &mut Vec<u8>,
    total: &mut usize,
    crc: &mut crc32fast::Hasher,
) -> ExchangeResult<()> {
    let next_member = decoded
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| limit("ZIP member size overflow"))?;
    let next_total = total
        .checked_add(chunk.len())
        .ok_or_else(|| limit("ZIP decoded total overflow"))?;
    if next_member as u64 > limits.max_member_bytes
        || next_member > expected.uncompressed as usize
        || next_total as u64 > limits.max_total_bytes
    {
        return Err(limit(
            "Observed ZIP decoded bytes exceed their budget or declared size",
        ));
    }
    crc.update(chunk);
    decoded.extend_from_slice(chunk);
    *total = next_total;
    Ok(())
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

/// Produces ZIP32 Stored entries in sorted resource-key order with fixed
/// 1980-01-01 timestamps, UTF-8 names and regular 0644 Unix modes. No ambient
/// timestamps, host permissions, filesystem reads or comments enter the bytes.
pub fn write_zip(
    members: &BTreeMap<String, Vec<u8>>,
    limits: ArchiveLimits,
) -> ExchangeResult<Vec<u8>> {
    write_zip_with_cancel(members, limits, || false)
}

/// The same deterministic writer with trusted cancellation between headers,
/// payload CRC/copy chunks and central directory entries.
pub fn write_zip_with_cancel(
    members: &BTreeMap<String, Vec<u8>>,
    limits: ArchiveLimits,
    cancelled: impl FnMut() -> bool,
) -> ExchangeResult<Vec<u8>> {
    write_zip_with_required_root_and_cancel(members, limits, MANIFEST, cancelled)
}

/// Trusted codecs select their exact required root (for example, pack.mcmeta).
/// It must be one bounded portable NFC file name, with literal case matching.
/// The same deterministic writer preserves the caller's exact member bytes;
/// choosing a root does not approve member contents or authorize source use.
pub fn write_zip_with_required_root_and_cancel(
    members: &BTreeMap<String, Vec<u8>>,
    limits: ArchiveLimits,
    required_root: &str,
    mut cancelled: impl FnMut() -> bool,
) -> ExchangeResult<Vec<u8>> {
    limits.validate()?;
    check_cancel(&mut cancelled)?;
    validate_member_path(required_root, limits)?;
    if required_root.contains('/') || !required_root.nfc().eq(required_root.chars()) {
        return Err(invalid(
            "Required ZIP root must be one canonical portable file name",
        ));
    }
    if members.is_empty() || members.len() > limits.max_members {
        return Err(limit("ZIP member count is outside its budget"));
    }
    if !members.contains_key(required_root) {
        return Err(invalid(if required_root == MANIFEST {
            "ZIP root exchange manifest is missing"
        } else {
            "ZIP required root file is missing"
        }));
    }
    let mut names = Names::default();
    let mut predicted = 22usize;
    let mut total = 0usize;
    for (name, payload) in members {
        check_cancel(&mut cancelled)?;
        names.insert(name, limits)?;
        if payload.len() as u64 > limits.max_member_bytes {
            return Err(limit("ZIP member bytes exceed their budget"));
        }
        total = total
            .checked_add(payload.len())
            .ok_or_else(|| limit("ZIP total size overflow"))?;
        predicted = predicted
            .checked_add(76)
            .and_then(|n| n.checked_add(name.len() * 2))
            .and_then(|n| n.checked_add(payload.len()))
            .ok_or_else(|| limit("ZIP output size overflow"))?;
        if total as u64 > limits.max_total_bytes || predicted as u64 > limits.max_archive_bytes {
            return Err(limit("ZIP aggregate or encoded bytes exceed their budget"));
        }
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(predicted)
        .map_err(|_| limit("ZIP output allocation failed"))?;
    let mut offsets = Vec::new();
    offsets
        .try_reserve_exact(members.len())
        .map_err(|_| limit("ZIP index allocation failed"))?;
    for (name, payload) in members {
        check_cancel(&mut cancelled)?;
        let offset = bytes.len() as u32;
        let mut crc = crc32fast::Hasher::new();
        for chunk in payload.chunks(8192) {
            check_cancel(&mut cancelled)?;
            crc.update(chunk);
        }
        let crc = crc.finalize();
        let size = payload.len() as u32;
        offsets.push((offset, crc));
        push_u32(&mut bytes, LOCAL);
        push_u16(&mut bytes, 20);
        push_u16(&mut bytes, UTF8);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0); // DOS time, midnight
        push_u16(&mut bytes, 0x21); // DOS date, 1980-01-01
        push_u32(&mut bytes, crc);
        push_u32(&mut bytes, size);
        push_u32(&mut bytes, size);
        push_u16(&mut bytes, name.len() as u16);
        push_u16(&mut bytes, 0);
        bytes.extend_from_slice(name.as_bytes());
        for chunk in payload.chunks(8192) {
            check_cancel(&mut cancelled)?;
            bytes.extend_from_slice(chunk);
        }
    }
    let directory_start = bytes.len() as u32;
    for ((name, payload), (local_offset, crc)) in members.iter().zip(offsets) {
        check_cancel(&mut cancelled)?;
        push_u32(&mut bytes, CENTRAL);
        push_u16(&mut bytes, (3 << 8) | 20); // Unix, ZIP 2.0
        push_u16(&mut bytes, 20);
        push_u16(&mut bytes, UTF8);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0x21);
        push_u32(&mut bytes, crc);
        push_u32(&mut bytes, payload.len() as u32);
        push_u32(&mut bytes, payload.len() as u32);
        push_u16(&mut bytes, name.len() as u16);
        push_u16(&mut bytes, 0); // extra
        push_u16(&mut bytes, 0); // comment
        push_u16(&mut bytes, 0); // start disk
        push_u16(&mut bytes, 0); // internal attributes
        push_u32(&mut bytes, REGULAR_MODE << 16);
        push_u32(&mut bytes, local_offset);
        bytes.extend_from_slice(name.as_bytes());
    }
    let directory_size = bytes.len() as u32 - directory_start;
    check_cancel(&mut cancelled)?;
    push_u32(&mut bytes, END);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, members.len() as u16);
    push_u16(&mut bytes, members.len() as u16);
    push_u32(&mut bytes, directory_size);
    push_u32(&mut bytes, directory_start);
    push_u16(&mut bytes, 0);
    if bytes.len() != predicted {
        return Err(invalid(
            "ZIP writer byte accounting disagrees with its output",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members() -> BTreeMap<String, Vec<u8>> {
        BTreeMap::from([
            (
                MANIFEST.to_owned(),
                br#"{"schemaVersion":"0.2.0"}"#.to_vec(),
            ),
            ("geometry/triangle.bin".to_owned(), vec![0, 1, 2, 3]),
        ])
    }
    fn bytes() -> Vec<u8> {
        write_zip(&members(), ArchiveLimits::default()).unwrap()
    }
    fn end(bytes: &[u8]) -> usize {
        bytes.len() - 22
    }
    fn directory(bytes: &[u8]) -> usize {
        u32_at(bytes, end(bytes) + 16).unwrap() as usize
    }
    fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn rejected(bytes: &[u8]) {
        assert!(read_zip(bytes, ArchiveLimits::default()).is_err());
    }

    // The original examples are already unpacked JSON; none exercises ZIP
    // envelope parsing or corrupt headers. These in-memory adversarial bytes
    // cover that missing EX10 boundary without extracting or downloading.
    #[test]
    fn deterministic_stored_round_trip_including_utf8_and_empty_member() {
        let mut data = members();
        data.insert("assets/표면.bin".into(), Vec::new());
        let first = write_zip(&data, ArchiveLimits::default()).unwrap();
        let second = write_zip(&data, ArchiveLimits::default()).unwrap();
        assert_eq!(first, second);
        assert_eq!(read_zip(&first, ArchiveLimits::default()).unwrap(), data);
        let metadata = preflight(&first, ArchiveLimits::default()).unwrap();
        for entry in metadata {
            assert_eq!(u16_at(&first, entry.local_start + 10).unwrap(), 0);
            assert_eq!(u16_at(&first, entry.local_start + 12).unwrap(), 0x21);
            assert_eq!(entry.method, 0);
        }
    }

    #[test]
    fn portable_paths_reject_traversal_uri_devices_and_ambiguous_components() {
        for path in [
            "../outside",
            "a/../../x",
            "/root",
            "C:/file",
            "file:///x",
            "https://host/x",
            "a\\b",
            "a//b",
            "a/./b",
            "a/../b",
            "a/",
            "CON.txt",
            "x/LPT².bin",
            "x/NUL",
            "x/COM1.bin",
            "x/CONIN$",
            "x/trailing.",
            "x/trailing ",
            "x/ leading",
            "x/\u{0}name",
            "x/a:b",
            "x/a?b",
            ".env",
            "x/.env.production",
            "x/credentials.json",
            "x/id_rsa",
            "x/service-account.json",
            "x/api_key.json",
        ] {
            assert!(
                validate_member_path(path, ArchiveLimits::default()).is_err(),
                "{path:?}"
            );
        }
        validate_member_path("assets/sub/normal-표면.bin", ArchiveLimits::default()).unwrap();
    }

    #[test]
    fn archive_names_reject_nfc_case_directory_and_file_ancestor_aliases() {
        for (first, second) in [
            ("assets/A", "assets/a"),
            ("assets/é", "assets/e\u{301}"),
            ("A/x", "a/y"),
            ("assets", "assets/x"),
            ("ASSETS", "assets/x"),
        ] {
            let mut data = members();
            data.insert(first.into(), Vec::new());
            data.insert(second.into(), Vec::new());
            assert!(
                write_zip(&data, ArchiveLimits::default()).is_err(),
                "{first} / {second}"
            );
        }
    }

    #[test]
    fn logical_member_paths_share_directory_alias_rules_and_count_root_once() {
        let limits = ArchiveLimits::default();
        validate_member_paths([MANIFEST, "A/x", "A/y"], limits).unwrap();
        for paths in [
            [MANIFEST, "A/x", "a/y"],
            [MANIFEST, "assets/é", "assets/e\u{301}"],
            [MANIFEST, "assets", "assets/x"],
            [MANIFEST, MANIFEST, "assets/x"],
        ] {
            assert_eq!(
                validate_member_paths(paths, limits).unwrap_err().code,
                "ARCHIVE_INVALID"
            );
        }
        assert_eq!(
            validate_member_paths(["assets/x"], limits)
                .unwrap_err()
                .code,
            "ARCHIVE_INVALID"
        );
        let limits = ArchiveLimits {
            max_members: 1,
            ..limits
        };
        validate_member_paths([MANIFEST], limits).unwrap();
        assert_eq!(
            validate_member_paths([MANIFEST, "assets/x"], limits)
                .unwrap_err()
                .code,
            "BUDGET_EXCEEDED"
        );
    }

    #[test]
    fn both_codecs_require_the_exact_root_manifest() {
        let mut data = members();
        let manifest = data.remove(MANIFEST).unwrap();
        assert!(write_zip(&data, ArchiveLimits::default()).is_err());
        data.insert("MMMM-exchange.json".into(), manifest);
        assert!(write_zip(&data, ArchiveLimits::default()).is_err());
        let mut archive = bytes();
        let metadata = preflight(&archive, ArchiveLimits::default()).unwrap();
        let root = metadata.iter().find(|m| m.name == MANIFEST).unwrap();
        archive[root.local_start + 30] = b'M';
        let root_central = directory(&archive) + 46 + metadata[0].name.len();
        archive[root_central + 46] = b'M';
        rejected(&archive);
    }

    // These three in-memory members exercise the trusted pack-root writer.
    // Their bytes are codec fixtures, not admitted game sources.
    #[test]
    fn required_root_writer_preserves_exact_members_and_default_boundary() {
        let data = BTreeMap::from([
            (
                "pack.mcmeta".into(),
                br#"{"pack":{"pack_format":1}}"#.to_vec(),
            ),
            (
                "data/mmmm_calibration/function/pack/entry.mcfunction".into(),
                b"function mmmm_calibration:pack/child\n".to_vec(),
            ),
            (
                "data/mmmm_calibration/function/pack/child.mcfunction".into(),
                b"scoreboard players set #marker mcalpack 1337\n".to_vec(),
            ),
        ]);
        let limits = ArchiveLimits::default();
        let archive =
            write_zip_with_required_root_and_cancel(&data, limits, "pack.mcmeta", || false)
                .unwrap_or_else(|cause| panic!("{}: {}", cause.code, cause.message));
        assert_eq!(
            archive,
            write_zip_with_required_root_and_cancel(&data, limits, "pack.mcmeta", || false)
                .unwrap_or_else(|cause| panic!("{}: {}", cause.code, cause.message))
        );
        assert_eq!(
            read_zip_with_required_root(&archive, limits, "pack.mcmeta", || false)
                .unwrap_or_else(|cause| panic!("{}: {}", cause.code, cause.message)),
            data
        );
        let metadata = preflight_with_required_root(&archive, limits, "pack.mcmeta", &mut || false)
            .unwrap_or_else(|cause| panic!("{}: {}", cause.code, cause.message));
        assert_eq!(metadata.len(), 3);
        assert_eq!(
            metadata
                .iter()
                .map(|member| &member.name)
                .collect::<Vec<_>>(),
            data.keys().collect::<Vec<_>>()
        );
        assert!(metadata.iter().all(|member| member.method == 0));
        assert_eq!(
            write_zip(&data, limits).unwrap_err().code,
            "ARCHIVE_INVALID"
        );
        assert_eq!(
            read_zip(&archive, limits).unwrap_err().code,
            "ARCHIVE_INVALID"
        );
        let exchange = members();
        assert_eq!(
            write_zip_with_cancel(&exchange, limits, || false)
                .unwrap_or_else(|cause| panic!("{}: {}", cause.code, cause.message)),
            write_zip_with_required_root_and_cancel(&exchange, limits, MANIFEST, || false)
                .unwrap_or_else(|cause| panic!("{}: {}", cause.code, cause.message))
        );
    }

    #[test]
    fn required_root_writer_reuses_cancellation_limits_and_exact_root_checks() {
        let data = BTreeMap::from([("pack.mcmeta".to_owned(), vec![1, 2, 3])]);
        let limits = ArchiveLimits::default();
        assert_eq!(
            write_zip_with_required_root_and_cancel(&data, limits, "pack.mcmeta", || true)
                .unwrap_err()
                .code,
            "CANCELLED"
        );
        assert_eq!(
            write_zip_with_required_root_and_cancel(
                &data,
                ArchiveLimits {
                    max_archive_bytes: 22,
                    ..limits
                },
                "pack.mcmeta",
                || false
            )
            .unwrap_err()
            .code,
            "BUDGET_EXCEEDED"
        );
        for required in [
            "packs/pack.mcmeta",
            "../pack.mcmeta",
            "pack.mcmeta/",
            "PACK.MCMETA",
            "e\u{301}.json",
        ] {
            assert_eq!(
                write_zip_with_required_root_and_cancel(&data, limits, required, || false)
                    .unwrap_err()
                    .code,
                "ARCHIVE_INVALID"
            );
        }
        let oversized = "a".repeat(limits.max_path_bytes + 1);
        for required in ["", oversized.as_str()] {
            assert_eq!(
                write_zip_with_required_root_and_cancel(&data, limits, required, || false)
                    .unwrap_err()
                    .code,
                "BUDGET_EXCEEDED"
            );
        }
        for name in ["mmmm-exchange.json", "PACK.MCMETA", "packs/pack.mcmeta"] {
            let wrong_root = BTreeMap::from([(name.to_owned(), vec![1, 2, 3])]);
            assert_eq!(
                write_zip_with_required_root_and_cancel(&wrong_root, limits, "pack.mcmeta", || {
                    false
                })
                .unwrap_err()
                .code,
                "ARCHIVE_INVALID"
            );
        }
    }

    // Existing exchange fixtures intentionally require mmmm-exchange.json.
    // A second in-memory root exercises the production pack reader without
    // changing that contract or extracting any member to the filesystem.
    #[test]
    fn required_root_reader_reuses_deflate_crc_and_cancellation_checks() {
        let data = BTreeMap::from([
            (
                "pack.mcmeta".into(),
                br#"{"pack":{"pack_format":1}}"#.to_vec(),
            ),
            ("assets/triangle.bin".into(), vec![1, 2, 3, 4]),
        ]);
        let archive = deflated(&data);
        assert_eq!(
            read_zip_with_required_root(&archive, ArchiveLimits::default(), "pack.mcmeta", || {
                false
            })
            .unwrap(),
            data
        );
        assert_eq!(
            read_zip(&archive, ArchiveLimits::default())
                .unwrap_err()
                .code,
            "ARCHIVE_INVALID"
        );
        assert_eq!(
            read_zip_with_required_root(&archive, ArchiveLimits::default(), "pack.mcmeta", || true)
                .unwrap_err()
                .code,
            "CANCELLED"
        );

        let metadata = preflight_with_required_root(
            &archive,
            ArchiveLimits::default(),
            "pack.mcmeta",
            &mut || false,
        )
        .unwrap();
        let first = &metadata[0];
        let mut corrupt = archive.clone();
        corrupt[first.data_start] ^= 1;
        assert_eq!(
            read_zip_with_required_root(&corrupt, ArchiveLimits::default(), "pack.mcmeta", || {
                false
            })
            .unwrap_err()
            .code,
            "ARCHIVE_INVALID"
        );
    }

    #[test]
    fn selected_root_requires_exact_canonical_root_file_before_decoding() {
        for name in ["mmmm-exchange.json", "PACK.MCMETA", "packs/pack.mcmeta"] {
            let data = BTreeMap::from([(name.to_owned(), vec![1, 2, 3])]);
            let archive = deflated(&data);
            assert_eq!(
                read_zip_with_required_root(
                    &archive,
                    ArchiveLimits::default(),
                    "pack.mcmeta",
                    || false
                )
                .unwrap_err()
                .code,
                "ARCHIVE_INVALID"
            );
        }
        let data = BTreeMap::from([("pack.mcmeta".to_owned(), vec![1, 2, 3])]);
        let archive = deflated(&data);
        for required in [
            "packs/pack.mcmeta",
            "../pack.mcmeta",
            "pack.mcmeta/",
            "PACK.MCMETA",
            "e\u{301}.json",
        ] {
            assert_eq!(
                read_zip_with_required_root(&archive, ArchiveLimits::default(), required, || false)
                    .unwrap_err()
                    .code,
                "ARCHIVE_INVALID"
            );
        }
        let oversized = "a".repeat(ArchiveLimits::default().max_path_bytes + 1);
        assert_eq!(
            read_zip_with_required_root(&archive, ArchiveLimits::default(), &oversized, || false)
                .unwrap_err()
                .code,
            "BUDGET_EXCEEDED"
        );
    }

    #[test]
    fn bounded_writer_checks_encoded_size_and_aggregate_before_output() {
        let data = members();
        let limits = ArchiveLimits {
            max_archive_bytes: 50,
            ..ArchiveLimits::default()
        };
        assert_eq!(
            write_zip(&data, limits).unwrap_err().code,
            "BUDGET_EXCEEDED"
        );
        let limits = ArchiveLimits {
            max_member_bytes: 1,
            ..ArchiveLimits::default()
        };
        assert_eq!(
            write_zip(&data, limits).unwrap_err().code,
            "BUDGET_EXCEEDED"
        );
        let limits = ArchiveLimits {
            max_members: 1,
            ..ArchiveLimits::default()
        };
        assert_eq!(
            read_zip(&bytes(), limits).unwrap_err().code,
            "BUDGET_EXCEEDED"
        );
    }

    #[test]
    fn forged_member_counts_and_extra_central_records_are_rejected() {
        let original = bytes();
        for count in [0, 1, 3, u16::MAX] {
            let mut archive = original.clone();
            let at = end(&archive);
            set_u16(&mut archive, at + 8, count);
            set_u16(&mut archive, at + 10, count);
            rejected(&archive);
        }
    }

    #[test]
    fn multi_disk_zip64_and_encryption_flags_are_rejected() {
        let original = bytes();
        for (offset, value) in [
            (end(&original) + 4, 1),
            (end(&original) + 6, 1),
            (directory(&original) + 34, 1),
            (directory(&original) + 8, UTF8 | 1),
            (directory(&original) + 8, UTF8 | (1 << 6)),
            (directory(&original) + 6, 45),
        ] {
            let mut archive = original.clone();
            set_u16(&mut archive, offset, value);
            rejected(&archive);
        }
        for offset in [
            end(&original) + 12,
            end(&original) + 16,
            directory(&original) + 20,
            directory(&original) + 24,
            directory(&original) + 42,
            18,
            22,
        ] {
            let mut archive = original.clone();
            set_u32(&mut archive, offset, u32::MAX);
            rejected(&archive);
        }
    }

    #[test]
    fn symlinks_special_files_and_directory_attributes_are_rejected() {
        let original = bytes();
        for mode in [
            0o120777, 0o040755, 0o060644, 0o020644, 0o010644, 0o140644, 0o104644, 0o102644,
            0o101644,
        ] {
            let mut archive = original.clone();
            let at = directory(&archive);
            set_u32(&mut archive, at + 38, mode << 16);
            rejected(&archive);
        }
        for attr in [0x08, 0x10, 0x40, 0x400] {
            let mut archive = original.clone();
            let at = directory(&archive);
            set_u32(&mut archive, at + 38, (REGULAR_MODE << 16) | attr);
            rejected(&archive);
        }
    }

    #[test]
    fn local_identity_and_directory_payload_boundaries_cannot_disagree() {
        let original = bytes();
        for (offset, value) in [(6, 0), (8, 8), (26, 1)] {
            let mut archive = original.clone();
            set_u16(&mut archive, offset, value);
            rejected(&archive);
        }
        let mut archive = original.clone();
        archive[30] = b'X';
        rejected(&archive);
        for offset in [14, 18, 22] {
            let mut archive = original.clone();
            set_u32(&mut archive, offset, 0x00ab_cdef);
            rejected(&archive);
        }
        let mut archive = original.clone();
        let at = directory(&archive);
        set_u32(&mut archive, at + 42, at as u32);
        rejected(&archive);
    }

    #[test]
    fn duplicate_directory_names_and_duplicate_local_offsets_are_rejected() {
        let mut data = members();
        data.insert("geometry/duplicate.bn".into(), Vec::new());
        let original = write_zip(&data, ArchiveLimits::default()).unwrap();
        let at = directory(&original);
        let first_len = usize::from(u16_at(&original, at + 28).unwrap());
        let second = at + 46 + first_len;
        // Duplicate offsets are rejected before any decompressor is created.
        let mut archive = original.clone();
        let first_offset = u32_at(&archive, at + 42).unwrap();
        set_u32(&mut archive, second + 42, first_offset);
        rejected(&archive);
        // The two geometry names have equal lengths; forge both local and
        // central names to cover a decoder that would otherwise deduplicate.
        assert_eq!(
            first_len,
            usize::from(u16_at(&original, second + 28).unwrap())
        );
        let mut archive = original.clone();
        let name = archive[at + 46..at + 46 + first_len].to_vec();
        archive[second + 46..second + 46 + first_len].copy_from_slice(&name);
        let second_local = u32_at(&archive, second + 42).unwrap() as usize;
        archive[second_local + 30..second_local + 30 + first_len].copy_from_slice(&name);
        rejected(&archive);
    }

    #[test]
    fn actual_payload_corruption_and_truncation_are_rejected() {
        let original = bytes();
        let mut archive = original.clone();
        let metadata = preflight(&archive, ArchiveLimits::default()).unwrap();
        archive[metadata[0].data_start] ^= 0xff;
        rejected(&archive);
        for cut in [0, 1, 21, 22, original.len() / 2, original.len() - 1] {
            rejected(&original[..cut]);
        }
        let mut archive = original.clone();
        archive.extend_from_slice(b"trailing");
        rejected(&archive);
    }

    #[test]
    fn advertised_bomb_ratio_and_aggregate_size_are_rejected_before_decode() {
        let original = bytes();
        let at = directory(&original);
        let mut archive = original.clone();
        set_u16(&mut archive, at + 10, 8);
        set_u32(&mut archive, at + 24, 16 * 1024 * 1024);
        assert_eq!(
            read_zip(&archive, ArchiveLimits::default())
                .unwrap_err()
                .code,
            "BUDGET_EXCEEDED"
        );
        let mut archive = original;
        set_u32(&mut archive, at + 24, 16 * 1024 * 1024 + 1);
        assert_eq!(
            read_zip(&archive, ArchiveLimits::default())
                .unwrap_err()
                .code,
            "BUDGET_EXCEEDED"
        );
    }

    #[test]
    fn excessive_metadata_and_extra_alias_formats_are_rejected() {
        for tag in [0x0001, 0x7075, 0x9901] {
            let mut extra = Vec::new();
            push_u16(&mut extra, tag);
            push_u16(&mut extra, 0);
            assert!(check_extra(&extra).is_err());
        }
        assert!(check_extra(&[1, 2, 3]).is_err());
        assert!(check_extra(&vec![0; EXTRA_BUDGET + 1]).is_err());
        let mut archive = bytes();
        let at = directory(&archive);
        set_u16(&mut archive, at + 30, (EXTRA_BUDGET + 1) as u16);
        rejected(&archive);
    }

    #[test]
    fn signatureless_and_signed_descriptors_are_verified() {
        for signed in [false, true] {
            let original = bytes();
            let metadata = preflight(&original, ArchiveLimits::default()).unwrap();
            let entry = &metadata[0];
            let mut descriptor = Vec::new();
            if signed {
                push_u32(&mut descriptor, DESCRIPTOR);
            }
            push_u32(&mut descriptor, entry.crc);
            push_u32(&mut descriptor, entry.compressed);
            push_u32(&mut descriptor, entry.uncompressed);
            let mut archive = original.clone();
            archive.splice(entry.local_end..entry.local_end, descriptor.iter().copied());
            set_u16(&mut archive, entry.local_start + 6, UTF8 | DATA_DESCRIPTOR);
            for field in [14, 18, 22] {
                set_u32(&mut archive, entry.local_start + field, 0);
            }
            let at = directory(&original) + descriptor.len();
            set_u16(&mut archive, at + 8, UTF8 | DATA_DESCRIPTOR);
            let second = at + 46 + metadata[0].name.len();
            set_u32(
                &mut archive,
                second + 42,
                (metadata[1].local_start + descriptor.len()) as u32,
            );
            let at_end = end(&archive);
            set_u32(&mut archive, at_end + 16, at as u32);
            assert_eq!(
                read_zip(&archive, ArchiveLimits::default()).unwrap(),
                members()
            );
            archive[entry.local_end + if signed { 4 } else { 0 }] ^= 1;
            rejected(&archive);
        }
    }

    #[test]
    fn deflate_round_trip_uses_actual_bounded_decoder() {
        let data = members();
        let archive = deflated(&data);
        assert_eq!(read_zip(&archive, ArchiveLimits::default()).unwrap(), data);
    }

    fn deflated(data: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, value) in data {
            writer.start_file(name, options).unwrap();
            writer.write_all(value).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn deflate_stream_end_rejects_physically_present_trailing_compressed_bytes() {
        let original = deflated(&members());
        let metadata = preflight(&original, ArchiveLimits::default()).unwrap();
        let first = &metadata[0];
        assert_eq!(first.flags & DATA_DESCRIPTOR, 0);
        let inserted = first.data_start + first.compressed as usize;
        let mut archive = original.clone();
        archive.insert(inserted, 0);
        set_u32(&mut archive, first.local_start + 18, first.compressed + 1);
        let at = directory(&original) + 1;
        set_u32(&mut archive, at + 20, first.compressed + 1);
        let second = at + 46 + first.name.len();
        set_u32(
            &mut archive,
            second + 42,
            metadata[1].local_start as u32 + 1,
        );
        let at_end = end(&archive);
        set_u32(&mut archive, at_end + 16, at as u32);
        // The ZIP envelope and advertised sizes remain self-consistent. Only
        // the real inflater's consumed-input evidence detects this junk.
        preflight(&archive, ArchiveLimits::default()).unwrap();
        let error = read_zip(&archive, ArchiveLimits::default()).unwrap_err();
        assert_eq!(error.code, "ARCHIVE_INVALID");
        assert!(error.message.contains("trailing compressed"));
    }

    #[test]
    fn deflate_actual_output_cannot_exceed_even_a_small_forged_declared_size() {
        let mut archive = deflated(&members());
        let metadata = preflight(&archive, ArchiveLimits::default()).unwrap();
        set_u32(&mut archive, metadata[0].local_start + 22, 1);
        let at = directory(&archive);
        set_u32(&mut archive, at + 24, 1);
        preflight(&archive, ArchiveLimits::default()).unwrap();
        let error = read_zip(&archive, ArchiveLimits::default()).unwrap_err();
        assert_eq!(error.code, "BUDGET_EXCEEDED");
    }

    #[test]
    fn known_secret_member_names_stop_preflight_before_payload_decoding() {
        let mut archive = bytes();
        let metadata = preflight(&archive, ArchiveLimits::default()).unwrap();
        let name = b"assets/credentials.xy";
        assert_eq!(name.len(), metadata[0].name.len());
        let local = metadata[0].local_start + 30;
        archive[local..local + name.len()].copy_from_slice(name);
        let central = directory(&archive) + 46;
        archive[central..central + name.len()].copy_from_slice(name);
        let error = read_zip(&archive, ArchiveLimits::default()).unwrap_err();
        assert!(error.message.contains("Secret file names"));
        let mut data = members();
        data.insert("assets/private.key".into(), Vec::new());
        assert!(
            write_zip(&data, ArchiveLimits::default())
                .unwrap_err()
                .message
                .contains("Secret file names")
        );
    }

    #[test]
    fn trusted_cancellation_interrupts_metadata_and_actual_payload_work() {
        let mut data = members();
        data.insert("geometry/triangle.bin".into(), vec![7; 100_000]);
        let archive = write_zip(&data, ArchiveLimits::default()).unwrap();
        assert_eq!(
            read_zip_with_cancel(&archive, ArchiveLimits::default(), || true)
                .unwrap_err()
                .code,
            "CANCELLED"
        );
        let mut preflight_checks = 0;
        preflight_with_cancel(&archive, ArchiveLimits::default(), &mut || {
            preflight_checks += 1;
            false
        })
        .unwrap();
        let mut checks = 0;
        let error = read_zip_with_cancel(&archive, ArchiveLimits::default(), || {
            checks += 1;
            checks > preflight_checks + 6
        })
        .unwrap_err();
        assert_eq!(error.code, "CANCELLED");
        assert!(checks > preflight_checks + 6);
        let mut checks = 0;
        let error = write_zip_with_cancel(&data, ArchiveLimits::default(), || {
            checks += 1;
            checks > 10
        })
        .unwrap_err();
        assert_eq!(error.code, "CANCELLED");
    }

    #[test]
    fn truncated_deflate_with_self_consistent_header_sizes_still_needs_stream_end() {
        let original = deflated(&members());
        let metadata = preflight(&original, ArchiveLimits::default()).unwrap();
        let first = &metadata[0];
        assert!(first.compressed > 0);
        let removed = first.data_start + first.compressed as usize - 1;
        let mut archive = original.clone();
        archive.remove(removed);
        set_u32(&mut archive, first.local_start + 18, first.compressed - 1);
        let at = directory(&original) - 1;
        set_u32(&mut archive, at + 20, first.compressed - 1);
        let second = at + 46 + first.name.len();
        set_u32(
            &mut archive,
            second + 42,
            metadata[1].local_start as u32 - 1,
        );
        let at_end = end(&archive);
        set_u32(&mut archive, at_end + 16, at as u32);
        preflight(&archive, ArchiveLimits::default()).unwrap();
        rejected(&archive);
    }
}
