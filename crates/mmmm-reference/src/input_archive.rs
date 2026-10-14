//! Bounded observations of one caller-selected ZIP/JAR byte slice.
//! No files are opened or extracted. These facts grant no source rights,
//! loaded-definition identity, effective pack order, or SourceAdmission.
//! Control checks surround finite buffer work; decompression is cooperative,
//! not a syscall preemption or CPU quota guarantee. ZIP64 is unsupported.

use crate::CaptureControl;
use mmmm_contracts::Sha256Digest;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap, error::Error, fmt, io::Cursor, sync::atomic::Ordering, time::Instant,
};
use unicode_normalization::UnicodeNormalization;

const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const END: u32 = 0x0605_4b50;
const ZIP64_LOCATOR: u32 = 0x0706_4b50;
const DESCRIPTOR: u32 = 0x0807_4b50;
const UTF8: u16 = 1 << 11;
const DESCRIBED: u16 = 1 << 3;
const CHUNK: usize = 8192;
const EXTRA: usize = 4096;

/// Initial finite profile: 64 MiB input/member, 256 MiB decoded aggregate,
/// 65,535 entries, ratio 1,000, 16 MiB metadata, and 1,024-byte names.
/// Callers may lower these ceilings only. Real game compatibility and speed
/// remain unverified; unsupported formats never trigger an automatic retry.
#[derive(Clone, Copy, Debug)]
pub struct InputArchiveLimits {
    pub input_bytes: u64,
    pub member_bytes: u64,
    pub total_bytes: u64,
    pub entries: usize,
    pub ratio: u64,
    pub metadata_bytes: usize,
    pub name_bytes: usize,
}
impl Default for InputArchiveLimits {
    fn default() -> Self {
        Self {
            input_bytes: 64 * 1024 * 1024,
            member_bytes: 64 * 1024 * 1024,
            total_bytes: 256 * 1024 * 1024,
            entries: 65_535,
            ratio: 1000,
            metadata_bytes: 16 * 1024 * 1024,
            name_bytes: 1024,
        }
    }
}
impl InputArchiveLimits {
    fn validate(self) -> Result<(), InputArchiveError> {
        let ceiling = Self::default();
        if self.input_bytes == 0
            || self.input_bytes > ceiling.input_bytes
            || self.member_bytes == 0
            || self.member_bytes > ceiling.member_bytes
            || self.total_bytes == 0
            || self.total_bytes > ceiling.total_bytes
            || self.member_bytes > self.total_bytes
            || self.entries == 0
            || self.entries > ceiling.entries
            || self.ratio == 0
            || self.ratio > ceiling.ratio
            || self.metadata_bytes == 0
            || self.metadata_bytes > ceiling.metadata_bytes
            || self.name_bytes == 0
            || self.name_bytes > ceiling.name_bytes
        {
            return Err(failure("INPUT_ARCHIVE_LIMITS"));
        }
        Ok(())
    }
}

/// A static public classification and the original local parser/decoder cause.
/// Display/Debug never include a member name, decoded body, or cause text.
pub struct InputArchiveError {
    code: &'static str,
    cause: Option<Box<dyn Error + Send + Sync>>,
}
impl InputArchiveError {
    pub fn code(&self) -> &'static str {
        self.code
    }
    fn caused(code: &'static str, cause: impl Error + Send + Sync + 'static) -> Self {
        Self {
            code,
            cause: Some(Box::new(cause)),
        }
    }
}
impl fmt::Display for InputArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: Selected input archive was not inventoried",
            self.code
        )
    }
}
impl fmt::Debug for InputArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InputArchiveError")
            .field("code", &self.code)
            .field("has_cause", &self.cause.is_some())
            .finish()
    }
}
impl Error for InputArchiveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| cause.as_ref() as &(dyn Error + 'static))
    }
}
fn failure(code: &'static str) -> InputArchiveError {
    InputArchiveError { code, cause: None }
}
type Result<T, E = InputArchiveError> = std::result::Result<T, E>;
type Check<'a> = dyn FnMut() -> Result<()> + 'a;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputArchiveMemberKind {
    File,
    Directory,
}

/// Exact original logical name and observed whole-member bytes, never a path.
pub struct InputArchiveMember {
    name: String,
    kind: InputArchiveMemberKind,
    length: u64,
    sha256: Sha256Digest,
}
impl InputArchiveMember {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn kind(&self) -> InputArchiveMemberKind {
        self.kind
    }
    pub fn byte_length(&self) -> u64 {
        self.length
    }
    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }
}

/// Constructed only after every selected container/member check succeeds.
/// Complete means this input inventory finished; it is not game compatibility,
/// source authorization, pack effectiveness, or loaded-definition finality.
pub struct InputArchiveInventory {
    input_length: u64,
    input_sha256: Sha256Digest,
    members: Vec<InputArchiveMember>,
    decoded_bytes: u64,
}
impl InputArchiveInventory {
    pub fn input_byte_length(&self) -> u64 {
        self.input_length
    }
    pub fn input_sha256(&self) -> &Sha256Digest {
        &self.input_sha256
    }
    /// Original central-directory order, including explicit empty directories.
    pub fn members(&self) -> &[InputArchiveMember] {
        &self.members
    }
    pub fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }
    pub fn complete(&self) -> bool {
        true
    }
}
impl fmt::Debug for InputArchiveInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InputArchiveInventory")
            .field("input_length", &self.input_length)
            .field("members", &self.members.len())
            .field("decoded_bytes", &self.decoded_bytes)
            .finish()
    }
}

/// Stored/Deflate classic ZIP with literal UTF-8 names and explicit empty
/// directories. No manifest or executable/source authority is inferred.
pub fn inventory_input_archive(
    bytes: &[u8],
    limits: InputArchiveLimits,
    control: &CaptureControl<'_>,
) -> Result<InputArchiveInventory> {
    inventory(bytes, limits, &mut || {
        if control.cancellation.load(Ordering::Acquire) {
            return Err(failure("CANCELLED"));
        }
        if Instant::now() >= control.deadline {
            return Err(failure("TIME_BUDGET_EXCEEDED"));
        }
        Ok(())
    })
}

struct Header {
    name: String,
    kind: InputArchiveMemberKind,
    flags: u16,
    method: u16,
    crc: u32,
    compressed: u32,
    decoded: u32,
    local: usize,
    data: usize,
    end: usize,
}
fn range(bytes: &[u8], at: usize, length: usize) -> Result<&[u8]> {
    let end = at
        .checked_add(length)
        .ok_or_else(|| failure("INPUT_ARCHIVE_OVERFLOW"))?;
    bytes
        .get(at..end)
        .ok_or_else(|| failure("INPUT_ARCHIVE_TRUNCATED"))
}
fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    let b = range(bytes, at, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    let b = range(bytes, at, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn charge(total: &mut usize, added: usize, limits: InputArchiveLimits) -> Result<()> {
    *total = total
        .checked_add(added)
        .filter(|n| *n <= limits.metadata_bytes)
        .ok_or_else(|| failure("INPUT_ARCHIVE_METADATA_LIMIT"))?;
    Ok(())
}
fn flags(flags: u16, method: u16, version: u16) -> Result<()> {
    if flags & ((1 << 0) | (1 << 6) | (1 << 13)) != 0 {
        return Err(failure("INPUT_ARCHIVE_ENCRYPTED"));
    }
    if !matches!(method, 0 | 8) {
        return Err(failure("INPUT_ARCHIVE_COMPRESSION_UNSUPPORTED"));
    }
    let allowed = UTF8 | DESCRIBED | if method == 8 { 6 } else { 0 };
    if flags & !allowed != 0 || !matches!(version, 10 | 20) || (method == 8 && version != 20) {
        return Err(failure("INPUT_ARCHIVE_PROFILE_UNSUPPORTED"));
    }
    Ok(())
}
fn extra(bytes: &[u8]) -> Result<()> {
    if bytes.len() > EXTRA {
        return Err(failure("INPUT_ARCHIVE_METADATA_LIMIT"));
    }
    let mut at = 0;
    while at < bytes.len() {
        let tag = u16_at(bytes, at)?;
        let len = usize::from(u16_at(bytes, at + 2)?);
        range(bytes, at + 4, len)?;
        if matches!(tag, 0x0001 | 0x7075 | 0x6375 | 0x9901) {
            return Err(failure("INPUT_ARCHIVE_EXTRA_UNSUPPORTED"));
        }
        at += 4 + len;
    }
    Ok(())
}
fn portable_fold(name: &str) -> String {
    name.to_lowercase().to_uppercase().nfc().collect()
}
fn secret(component: &str) -> bool {
    let folded = portable_fold(component);
    folded == ".ENV"
        || folded.starts_with(".ENV.")
        || folded == ".SSH"
        || ["CREDENTIAL", "API-KEY", "API_KEY", "APIKEY"]
            .iter()
            .any(|part| folded.contains(part))
        || ["ID_RSA", "ID_ED25519", "ID_ECDSA", "ID_DSA"]
            .iter()
            .any(|prefix| folded.starts_with(prefix))
        || [".PEM", ".KEY", ".PPK", ".P12", ".PFX"]
            .iter()
            .any(|suffix| folded.ends_with(suffix))
        || (folded.ends_with(".JSON")
            && ["SERVICE-ACCOUNT", "SERVICE_ACCOUNT", "SERVICEACCOUNT"]
                .iter()
                .any(|part| folded.contains(part)))
}
struct NameNode {
    literal: String,
    file: bool,
    explicit: bool,
}
#[derive(Default)]
struct Names {
    nodes: BTreeMap<String, NameNode>,
}
impl Names {
    fn insert(
        &mut self,
        name: &str,
        kind: InputArchiveMemberKind,
        metadata: &mut usize,
        limits: InputArchiveLimits,
    ) -> Result<()> {
        if name.is_empty() || name.len() > limits.name_bytes {
            return Err(failure("INPUT_ARCHIVE_NAME_LIMIT"));
        }
        let logical = if kind == InputArchiveMemberKind::Directory {
            name.strip_suffix('/').unwrap_or(name)
        } else {
            name
        };
        if logical.is_empty()
            || logical.starts_with('/')
            || logical.ends_with('/')
            || logical.chars().any(|c| {
                c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
            })
        {
            return Err(failure("INPUT_ARCHIVE_NAME_INVALID"));
        }
        if !logical.nfc().eq(logical.chars()) {
            return Err(failure("INPUT_ARCHIVE_NAME_ALIAS"));
        }
        for (depth, component) in logical.split('/').enumerate() {
            if depth >= 64 {
                return Err(failure("INPUT_ARCHIVE_NAME_LIMIT"));
            }
            if secret(component) {
                return Err(failure("INPUT_ARCHIVE_SECRET_MEMBER"));
            }
            if component.is_empty()
                || matches!(component, "." | "..")
                || component.ends_with(['.', ' '])
                || component.starts_with(' ')
            {
                return Err(failure("INPUT_ARCHIVE_NAME_INVALID"));
            }
            let stem = component
                .split('.')
                .next()
                .unwrap_or(component)
                .to_uppercase();
            let numbered = stem
                .strip_prefix("COM")
                .or_else(|| stem.strip_prefix("LPT"))
                .is_some_and(|n| {
                    matches!(
                        n,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                });
            if numbered
                || matches!(
                    stem.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                )
            {
                return Err(failure("INPUT_ARCHIVE_NAME_ALIAS"));
            }
        }
        for end in logical
            .match_indices('/')
            .map(|(at, _)| at)
            .chain(std::iter::once(logical.len()))
        {
            let literal = &logical[..end];
            let leaf = end == logical.len();
            let file = leaf && kind == InputArchiveMemberKind::File;
            let folded = portable_fold(literal);
            if let Some(node) = self.nodes.get_mut(&folded) {
                if node.literal != literal || node.file != file || (leaf && node.explicit) {
                    return Err(failure("INPUT_ARCHIVE_NAME_ALIAS"));
                }
                if leaf {
                    node.explicit = true;
                }
            } else {
                charge(
                    metadata,
                    literal
                        .len()
                        .checked_add(folded.len())
                        .and_then(|n| n.checked_add(96))
                        .ok_or_else(|| failure("INPUT_ARCHIVE_OVERFLOW"))?,
                    limits,
                )?;
                self.nodes.insert(
                    folded,
                    NameNode {
                        literal: literal.to_owned(),
                        file,
                        explicit: leaf,
                    },
                );
            }
        }
        Ok(())
    }
}

fn preflight(
    bytes: &[u8],
    limits: InputArchiveLimits,
    check: &mut Check<'_>,
) -> Result<Vec<Header>> {
    limits.validate()?;
    check()?;
    if bytes.len() as u64 > limits.input_bytes {
        return Err(failure("INPUT_ARCHIVE_INPUT_LIMIT"));
    }
    if bytes.len() < 22 {
        return Err(failure("INPUT_ARCHIVE_TRUNCATED"));
    }
    let mut found = None;
    let first = bytes.len().saturating_sub(22 + usize::from(u16::MAX));
    for at in (first..=bytes.len() - 22).rev() {
        if at % 1024 == 0 {
            check()?;
        }
        if u32_at(bytes, at)? == END
            && at + 22 + usize::from(u16_at(bytes, at + 20)?) == bytes.len()
        {
            found = Some(at);
            break;
        }
    }
    let end = found.ok_or_else(|| failure("INPUT_ARCHIVE_END_INVALID"))?;
    if end >= 20 && u32_at(bytes, end - 20)? == ZIP64_LOCATOR {
        return Err(failure("INPUT_ARCHIVE_ZIP64_UNSUPPORTED"));
    }
    if u16_at(bytes, end + 4)? != 0 || u16_at(bytes, end + 6)? != 0 {
        return Err(failure("INPUT_ARCHIVE_MULTIDISK_UNSUPPORTED"));
    }
    let count = usize::from(u16_at(bytes, end + 10)?);
    if u16_at(bytes, end + 8)? as usize != count {
        return Err(failure("INPUT_ARCHIVE_DIRECTORY_INVALID"));
    }
    if count > limits.entries {
        return Err(failure("INPUT_ARCHIVE_ENTRY_LIMIT"));
    }
    let directory_size = u32_at(bytes, end + 12)?;
    let directory_at = u32_at(bytes, end + 16)?;
    if directory_size == u32::MAX || directory_at == u32::MAX {
        return Err(failure("INPUT_ARCHIVE_ZIP64_UNSUPPORTED"));
    }
    let directory_at =
        usize::try_from(directory_at).map_err(|_| failure("INPUT_ARCHIVE_OVERFLOW"))?;
    let directory_size =
        usize::try_from(directory_size).map_err(|_| failure("INPUT_ARCHIVE_OVERFLOW"))?;
    if directory_size > limits.metadata_bytes {
        return Err(failure("INPUT_ARCHIVE_METADATA_LIMIT"));
    }
    if directory_at.checked_add(directory_size) != Some(end)
        || count.checked_mul(46).is_none_or(|n| n > directory_size)
    {
        return Err(failure("INPUT_ARCHIVE_DIRECTORY_INVALID"));
    }
    let comment = usize::from(u16_at(bytes, end + 20)?);
    if comment > EXTRA {
        return Err(failure("INPUT_ARCHIVE_METADATA_LIMIT"));
    }
    let mut metadata = directory_size;
    charge(&mut metadata, 22 + comment, limits)?;
    let directory = range(bytes, directory_at, directory_size)?;
    let mut headers = Vec::new();
    headers
        .try_reserve_exact(count)
        .map_err(|cause| InputArchiveError::caused("INPUT_ARCHIVE_ALLOCATION_LIMIT", cause))?;
    let mut names = Names::default();
    let mut at = 0;
    let mut decoded = 0u64;
    for _ in 0..count {
        check()?;
        range(directory, at, 46)?;
        if u32_at(directory, at)? != CENTRAL || u16_at(directory, at + 34)? != 0 {
            return Err(failure("INPUT_ARCHIVE_DIRECTORY_INVALID"));
        }
        let flags_value = u16_at(directory, at + 8)?;
        let method = u16_at(directory, at + 10)?;
        flags(flags_value, method, u16_at(directory, at + 6)?)?;
        let compressed = u32_at(directory, at + 20)?;
        let length = u32_at(directory, at + 24)?;
        let local = u32_at(directory, at + 42)?;
        if [compressed, length, local].contains(&u32::MAX) {
            return Err(failure("INPUT_ARCHIVE_ZIP64_UNSUPPORTED"));
        }
        if u64::from(length) > limits.member_bytes
            || u64::from(length)
                > u64::from(compressed)
                    .max(1)
                    .checked_mul(limits.ratio)
                    .ok_or_else(|| failure("INPUT_ARCHIVE_OVERFLOW"))?
        {
            return Err(failure("INPUT_ARCHIVE_DECODE_LIMIT"));
        }
        decoded = decoded
            .checked_add(u64::from(length))
            .filter(|n| *n <= limits.total_bytes)
            .ok_or_else(|| failure("INPUT_ARCHIVE_DECODE_LIMIT"))?;
        if method == 0 && compressed != length {
            return Err(failure("INPUT_ARCHIVE_SIZE_MISMATCH"));
        }
        let name_len = usize::from(u16_at(directory, at + 28)?);
        let extra_len = usize::from(u16_at(directory, at + 30)?);
        let comment_len = usize::from(u16_at(directory, at + 32)?);
        if name_len > limits.name_bytes || extra_len > EXTRA || comment_len > EXTRA {
            return Err(failure("INPUT_ARCHIVE_METADATA_LIMIT"));
        }
        let raw_name = range(directory, at + 46, name_len)?;
        let name = std::str::from_utf8(raw_name)
            .map_err(|cause| InputArchiveError::caused("INPUT_ARCHIVE_NAME_ENCODING", cause))?;
        if flags_value & UTF8 == 0 && !name.is_ascii() {
            return Err(failure("INPUT_ARCHIVE_NAME_ENCODING"));
        }
        let attrs = u32_at(directory, at + 38)?;
        let mode = (attrs >> 16) & 0o170000;
        let is_directory = name.ends_with('/');
        if attrs & 8 != 0
            || !matches!(mode, 0 | 0o100000 | 0o040000)
            || (mode == 0o040000 && !is_directory)
            || (mode == 0o100000 && is_directory)
            || (attrs & 0x10 != 0 && !is_directory)
        {
            return Err(failure("INPUT_ARCHIVE_MEMBER_TYPE_UNSUPPORTED"));
        }
        let kind = if is_directory {
            InputArchiveMemberKind::Directory
        } else {
            InputArchiveMemberKind::File
        };
        names.insert(name, kind, &mut metadata, limits)?;
        if is_directory
            && (compressed != 0 || length != 0 || method != 0 || u32_at(directory, at + 16)? != 0)
        {
            return Err(failure("INPUT_ARCHIVE_DIRECTORY_PAYLOAD"));
        }
        extra(range(directory, at + 46 + name_len, extra_len)?)?;
        range(directory, at + 46 + name_len + extra_len, comment_len)?;
        headers.push(Header {
            name: name.to_owned(),
            kind,
            flags: flags_value,
            method,
            crc: u32_at(directory, at + 16)?,
            compressed,
            decoded: length,
            local: usize::try_from(local).map_err(|_| failure("INPUT_ARCHIVE_OVERFLOW"))?,
            data: 0,
            end: 0,
        });
        at += 46 + name_len + extra_len + comment_len;
        check()?;
    }
    if at != directory.len() {
        return Err(failure("INPUT_ARCHIVE_DIRECTORY_INVALID"));
    }
    // Central-directory order need not be physical order. Each local member
    // must end at the next actual local start, or at the central directory.
    let mut physical: Vec<_> = (0..headers.len()).collect();
    physical.sort_unstable_by_key(|index| headers[*index].local);
    let mut previous = 0;
    for (position, index) in physical.iter().copied().enumerate() {
        check()?;
        let boundary = physical
            .get(position + 1)
            .map_or(directory_at, |next| headers[*next].local);
        let header = &mut headers[index];
        if header.local != previous || boundary <= header.local || boundary > directory_at {
            return Err(failure("INPUT_ARCHIVE_COVERAGE_INVALID"));
        }
        local_header(bytes, boundary, header, &mut metadata, limits)?;
        check()?;
        if header.end != boundary {
            return Err(failure("INPUT_ARCHIVE_COVERAGE_INVALID"));
        }
        previous = boundary;
    }
    if previous != directory_at {
        return Err(failure("INPUT_ARCHIVE_COVERAGE_INVALID"));
    }
    check()?;
    Ok(headers)
}

fn local_header(
    bytes: &[u8],
    boundary: usize,
    header: &mut Header,
    metadata: &mut usize,
    limits: InputArchiveLimits,
) -> Result<()> {
    let at = header.local;
    range(bytes, at, 30)?;
    if u32_at(bytes, at)? != LOCAL
        || u16_at(bytes, at + 6)? != header.flags
        || u16_at(bytes, at + 8)? != header.method
    {
        return Err(failure("INPUT_ARCHIVE_LOCAL_MISMATCH"));
    }
    flags(header.flags, header.method, u16_at(bytes, at + 4)?)?;
    let name_len = usize::from(u16_at(bytes, at + 26)?);
    let extra_len = usize::from(u16_at(bytes, at + 28)?);
    if name_len != header.name.len()
        || extra_len > EXTRA
        || range(bytes, at + 30, name_len)? != header.name.as_bytes()
    {
        return Err(failure("INPUT_ARCHIVE_LOCAL_MISMATCH"));
    }
    extra(range(bytes, at + 30 + name_len, extra_len)?)?;
    charge(metadata, 30 + name_len + extra_len, limits)?;
    header.data = at
        .checked_add(30 + name_len + extra_len)
        .ok_or_else(|| failure("INPUT_ARCHIVE_OVERFLOW"))?;
    header.end = header
        .data
        .checked_add(header.compressed as usize)
        .filter(|end| *end <= boundary)
        .ok_or_else(|| failure("INPUT_ARCHIVE_TRUNCATED"))?;
    let crc = u32_at(bytes, at + 14)?;
    let compressed = u32_at(bytes, at + 18)?;
    let decoded = u32_at(bytes, at + 22)?;
    if header.flags & DESCRIBED == 0 {
        if (crc, compressed, decoded) != (header.crc, header.compressed, header.decoded) {
            return Err(failure("INPUT_ARCHIVE_LOCAL_MISMATCH"));
        }
    } else {
        if ![(0, 0, 0), (header.crc, header.compressed, header.decoded)]
            .contains(&(crc, compressed, decoded))
        {
            return Err(failure("INPUT_ARCHIVE_LOCAL_MISMATCH"));
        }
        // CRC may itself equal the optional signature. Select only a complete
        // 12/16-byte candidate whose values AND next physical boundary agree.
        let mut selected = None;
        for (length, value_at) in [(12, 0), (16, 4)] {
            if header.end.checked_add(length) != Some(boundary) {
                continue;
            }
            let candidate = range(bytes, header.end, length)?;
            if value_at != 0 && u32_at(candidate, 0)? != DESCRIPTOR {
                continue;
            }
            if (
                u32_at(candidate, value_at)?,
                u32_at(candidate, value_at + 4)?,
                u32_at(candidate, value_at + 8)?,
            ) != (header.crc, header.compressed, header.decoded)
            {
                continue;
            }
            if selected.replace(length).is_some() {
                return Err(failure("INPUT_ARCHIVE_DESCRIPTOR_AMBIGUOUS"));
            }
        }
        let length = selected.ok_or_else(|| failure("INPUT_ARCHIVE_DESCRIPTOR_MISMATCH"))?;
        header.end = header
            .end
            .checked_add(length)
            .ok_or_else(|| failure("INPUT_ARCHIVE_OVERFLOW"))?;
        charge(metadata, length, limits)?;
    }
    Ok(())
}

fn digest(hash: Sha256) -> Result<Sha256Digest> {
    Sha256Digest::new(format!("{:x}", hash.finalize()))
        .map_err(|cause| InputArchiveError::caused("INPUT_ARCHIVE_DIGEST", cause))
}
fn inventory(
    bytes: &[u8],
    limits: InputArchiveLimits,
    check: &mut Check<'_>,
) -> Result<InputArchiveInventory> {
    // Entire name preflight precedes even the whole-container hash: a known
    // secret member is never opened, decompressed, or hashed by this producer.
    let headers = preflight(bytes, limits, check)?;
    check()?;
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|cause| InputArchiveError::caused("INPUT_ARCHIVE_DIRECTORY_DECODE", cause))?;
    check()?;
    if archive.len() != headers.len() {
        return Err(failure("INPUT_ARCHIVE_DIRECTORY_MISMATCH"));
    }
    let mut input_hash = Sha256::new();
    for chunk in bytes.chunks(CHUNK) {
        check()?;
        input_hash.update(chunk);
        check()?;
    }
    let input_sha256 = digest(input_hash)?;
    check()?;
    let mut members = Vec::new();
    members
        .try_reserve_exact(headers.len())
        .map_err(|cause| InputArchiveError::caused("INPUT_ARCHIVE_ALLOCATION_LIMIT", cause))?;
    let mut total = 0u64;
    for (index, header) in headers.into_iter().enumerate() {
        check()?;
        let file = archive
            .by_index_raw(index)
            .map_err(|cause| InputArchiveError::caused("INPUT_ARCHIVE_MEMBER_DECODE", cause))?;
        if file.name_raw() != header.name.as_bytes()
            || file.name() != header.name
            || file.size() != u64::from(header.decoded)
            || file.compressed_size() != u64::from(header.compressed)
            || file.crc32() != header.crc
            || file.header_start() != header.local as u64
            || file.data_start() != header.data as u64
            || (file.is_dir() != (header.kind == InputArchiveMemberKind::Directory))
            || (file.is_file() != (header.kind == InputArchiveMemberKind::File))
            || file.compression()
                != if header.method == 0 {
                    zip::CompressionMethod::Stored
                } else {
                    zip::CompressionMethod::Deflated
                }
        {
            return Err(failure("INPUT_ARCHIVE_DIRECTORY_MISMATCH"));
        }
        drop(file);
        check()?;
        let compressed = range(bytes, header.data, header.compressed as usize)?;
        let mut hash = Sha256::new();
        let mut crc = crc32fast::Hasher::new();
        let mut length = 0u64;
        {
            let mut consume = |chunk: &[u8]| -> Result<()> {
                check()?;
                length = length
                    .checked_add(chunk.len() as u64)
                    .ok_or_else(|| failure("INPUT_ARCHIVE_OVERFLOW"))?;
                if length > u64::from(header.decoded) {
                    return Err(failure("INPUT_ARCHIVE_SIZE_MISMATCH"));
                }
                total = total
                    .checked_add(chunk.len() as u64)
                    .filter(|n| *n <= limits.total_bytes)
                    .ok_or_else(|| failure("INPUT_ARCHIVE_DECODE_LIMIT"))?;
                if length > limits.member_bytes {
                    return Err(failure("INPUT_ARCHIVE_DECODE_LIMIT"));
                }
                hash.update(chunk);
                crc.update(chunk);
                check()?;
                Ok(())
            };
            if header.method == 0 {
                for chunk in compressed.chunks(CHUNK) {
                    consume(chunk)?;
                }
            } else {
                let mut inflater = flate2::Decompress::new(false);
                let mut scratch = [0u8; CHUNK];
                loop {
                    let before_in = inflater.total_in();
                    let before_out = inflater.total_out();
                    let start = usize::try_from(before_in)
                        .map_err(|_| failure("INPUT_ARCHIVE_OVERFLOW"))?;
                    if start > compressed.len() {
                        return Err(failure("INPUT_ARCHIVE_DEFLATE_ACCOUNTING"));
                    }
                    let end = start.saturating_add(CHUNK).min(compressed.len());
                    // consume's pre/post checks also bracket each decoder call.
                    consume(&[])?;
                    let status = inflater
                        .decompress(
                            &compressed[start..end],
                            &mut scratch,
                            flate2::FlushDecompress::None,
                        )
                        .map_err(|cause| {
                            InputArchiveError::caused("INPUT_ARCHIVE_DEFLATE", cause)
                        })?;
                    let produced = inflater
                        .total_out()
                        .checked_sub(before_out)
                        .filter(|n| *n <= CHUNK as u64)
                        .ok_or_else(|| failure("INPUT_ARCHIVE_DEFLATE_ACCOUNTING"))?;
                    let used = inflater
                        .total_in()
                        .checked_sub(before_in)
                        .filter(|n| *n <= (end - start) as u64)
                        .ok_or_else(|| failure("INPUT_ARCHIVE_DEFLATE_ACCOUNTING"))?;
                    consume(&scratch[..produced as usize])?;
                    if status == flate2::Status::StreamEnd {
                        if inflater.total_in() != compressed.len() as u64 {
                            return Err(failure("INPUT_ARCHIVE_DEFLATE_TRAILING"));
                        }
                        break;
                    }
                    if produced == 0 && used == 0 {
                        return Err(failure("INPUT_ARCHIVE_DEFLATE_TRUNCATED"));
                    }
                }
            }
        }
        if length != u64::from(header.decoded) {
            return Err(failure("INPUT_ARCHIVE_SIZE_MISMATCH"));
        }
        if crc.finalize() != header.crc {
            return Err(failure("INPUT_ARCHIVE_CRC_MISMATCH"));
        }
        check()?;
        members.push(InputArchiveMember {
            name: header.name,
            kind: header.kind,
            length,
            sha256: digest(hash)?,
        });
        check()?;
    }
    check()?;
    Ok(InputArchiveInventory {
        input_length: bytes.len() as u64,
        input_sha256,
        members,
        decoded_bytes: total,
    })
}

#[cfg(test)]
#[path = "input_archive_tests.rs"]
mod tests;
