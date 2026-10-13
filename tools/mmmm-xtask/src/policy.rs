//! Git index structure inspection. Only the staged policy blob is read as content.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use unicode_normalization::UnicodeNormalization;

pub const POLICY_PATH: &str = ".github/repository-policy.json";
pub const MAX_POLICY_BYTES: usize = 65_536;
const MAX_METADATA_BYTES: usize = 32 * 1024 * 1024;
const MAX_INDEX_RECORDS: usize = 100_000;
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Serialize)]
pub struct PolicyError {
    pub code: &'static str,
    pub message: String,
}

impl PolicyError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryPolicy {
    pub schema_version: u32,
    pub allowed_root_files: Vec<String>,
    pub allowed_root_directories: Vec<String>,
    pub forbidden_directory_names: Vec<String>,
    pub forbidden_secret_file_names: Vec<String>,
    pub forbidden_secret_file_patterns: Vec<String>,
    pub forbidden_file_suffixes: Vec<String>,
    pub forbidden_generated_file_patterns: Vec<String>,
    pub max_tracked_file_bytes: u64,
    pub max_policy_file_bytes: u64,
    pub path_rules: PathRules,
    pub exceptions: Vec<PolicyException>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PathRules {
    pub require_stage_zero: bool,
    pub portable_paths: bool,
    pub reject_case_unicode_collisions: bool,
    pub allowed_git_modes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyException {
    pub path: String,
    pub allow: Vec<ExceptionKind>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExceptionKind {
    Generated,
    Size,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRecord {
    pub mode: String,
    pub oid: String,
    pub stage: u8,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMetadata {
    pub kind: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PolicyViolation {
    pub code: &'static str,
    /// Relative Git path only; malformed or absolute names are omitted.
    pub path: Option<String>,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct PolicyReport {
    pub checked_files: usize,
    pub read_blobs: Vec<String>,
    pub violations: Vec<PolicyViolation>,
}

impl PolicyReport {
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Parse the single bounded policy document without accepting duplicate or unknown fields.
pub fn parse_policy(bytes: &[u8]) -> Result<RepositoryPolicy, PolicyError> {
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(PolicyError::new(
            "POLICY_TOO_LARGE",
            "policy exceeds 64 KiB",
        ));
    }
    let policy: RepositoryPolicy = serde_json::from_slice(bytes).map_err(|error| {
        PolicyError::new(
            "INVALID_POLICY_JSON",
            format!(
                "invalid policy JSON at line {}, column {}",
                error.line(),
                error.column()
            ),
        )
    })?;
    validate_policy(&policy)?;
    if bytes.len() as u64 > policy.max_policy_file_bytes {
        return Err(PolicyError::new(
            "POLICY_TOO_LARGE",
            "policy exceeds its declared limit",
        ));
    }
    Ok(policy)
}

fn validate_policy(policy: &RepositoryPolicy) -> Result<(), PolicyError> {
    let invalid = |message| PolicyError::new("INVALID_POLICY", message);
    if policy.schema_version != 1 {
        return Err(invalid("unsupported policy schemaVersion"));
    }
    if policy.max_tracked_file_bytes == 0
        || policy.max_policy_file_bytes == 0
        || policy.max_policy_file_bytes > MAX_POLICY_BYTES as u64
    {
        return Err(invalid(
            "file limits must be positive; policy limit is at most 64 KiB",
        ));
    }
    if !policy.path_rules.require_stage_zero
        || !policy.path_rules.portable_paths
        || !policy.path_rules.reject_case_unicode_collisions
    {
        return Err(invalid("mandatory path checks cannot be disabled"));
    }
    validate_list(&policy.path_rules.allowed_git_modes, false, |mode| {
        mode == "100644" || mode == "100755"
    })?;
    if policy.path_rules.allowed_git_modes.is_empty() {
        return Err(invalid("at least one regular Git mode is required"));
    }
    for names in [
        &policy.allowed_root_files,
        &policy.allowed_root_directories,
        &policy.forbidden_directory_names,
        &policy.forbidden_secret_file_names,
    ] {
        validate_list(names, true, |name| portable_component(name).is_ok())?;
    }
    let root_files: BTreeSet<_> = policy
        .allowed_root_files
        .iter()
        .map(|name| folded(name))
        .collect();
    if policy
        .allowed_root_directories
        .iter()
        .any(|name| root_files.contains(&folded(name)))
    {
        return Err(invalid(
            "a root name cannot be registered as both file and directory",
        ));
    }
    for patterns in [
        &policy.forbidden_secret_file_patterns,
        &policy.forbidden_generated_file_patterns,
    ] {
        validate_list(patterns, true, valid_pattern)?;
    }
    validate_list(&policy.forbidden_file_suffixes, true, |suffix| {
        suffix.starts_with('.')
            && suffix.len() > 1
            && !suffix.contains(['*', '?'])
            && valid_pattern(suffix)
    })?;
    let mut exceptions = BTreeSet::new();
    for exception in &policy.exceptions {
        if portable_path(&exception.path).is_err()
            || exception.reason.trim().is_empty()
            || exception.reason.len() > 4096
            || exception.allow.is_empty()
            || exception
                .allow
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != exception.allow.len()
            || !exceptions.insert(folded(&exception.path))
        {
            return Err(invalid(
                "exceptions require unique exact portable paths, kinds and reasons",
            ));
        }
    }
    Ok(())
}

fn validate_list(
    values: &[String],
    case_fold: bool,
    valid: impl Fn(&str) -> bool,
) -> Result<(), PolicyError> {
    let mut seen = BTreeSet::new();
    for value in values {
        let key = if case_fold {
            folded(value)
        } else {
            value.clone()
        };
        if !valid(value) || !seen.insert(key) {
            return Err(PolicyError::new(
                "INVALID_POLICY",
                "policy list has an invalid or duplicate entry",
            ));
        }
    }
    Ok(())
}

fn valid_pattern(pattern: &str) -> bool {
    !pattern.is_empty()
        && pattern.len() <= 256
        && !pattern
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':' | '"' | '<' | '>' | '|'))
}

fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse `git ls-files --stage -z`; NUL framing preserves tabs and spaces in names.
pub fn parse_index(bytes: &[u8]) -> Result<Vec<IndexRecord>, PolicyError> {
    if bytes.len() > MAX_METADATA_BYTES || (!bytes.is_empty() && bytes.last() != Some(&0)) {
        return Err(PolicyError::new(
            "INVALID_INDEX_METADATA",
            "oversized or truncated NUL index metadata",
        ));
    }
    let mut records = Vec::new();
    let mut seen = BTreeSet::new();
    let mut hash_length = None;
    if bytes.is_empty() {
        return Ok(records);
    }
    for entry in bytes[..bytes.len() - 1].split(|byte| *byte == 0) {
        if records.len() >= MAX_INDEX_RECORDS {
            return Err(PolicyError::new(
                "INDEX_LIMIT",
                "index record budget exceeded",
            ));
        }
        let text = std::str::from_utf8(entry).map_err(|_| {
            PolicyError::new("INVALID_INDEX_METADATA", "Git paths must be valid UTF-8")
        })?;
        let (header, path) = text.split_once('\t').ok_or_else(|| {
            PolicyError::new(
                "INVALID_INDEX_METADATA",
                "index record lacks path separator",
            )
        })?;
        let parts: Vec<_> = header.split(' ').collect();
        if parts.len() != 3
            || parts[0].len() != 6
            || !parts[0].bytes().all(|b| matches!(b, b'0'..=b'7'))
            || !valid_oid(parts[1])
            || !matches!(parts[2], "0" | "1" | "2" | "3")
            || path.is_empty()
        {
            return Err(PolicyError::new(
                "INVALID_INDEX_METADATA",
                "invalid Git mode, hash, stage or path framing",
            ));
        }
        if hash_length.is_some_and(|length| length != parts[1].len()) {
            return Err(PolicyError::new(
                "INVALID_INDEX_METADATA",
                "mixed Git hash formats",
            ));
        }
        hash_length = Some(parts[1].len());
        let stage = parts[2].as_bytes()[0] - b'0';
        if !seen.insert((path.to_owned(), stage)) {
            return Err(PolicyError::new(
                "INVALID_INDEX_METADATA",
                "duplicate index path and stage",
            ));
        }
        records.push(IndexRecord {
            mode: parts[0].to_owned(),
            oid: parts[1].to_owned(),
            stage,
            path: path.to_owned(),
        });
    }
    Ok(records)
}

/// Parse `cat-file --batch-check` output; never request blob bodies here.
pub fn parse_object_metadata(
    bytes: &[u8],
) -> Result<BTreeMap<String, ObjectMetadata>, PolicyError> {
    if bytes.len() > MAX_METADATA_BYTES || (!bytes.is_empty() && bytes.last() != Some(&b'\n')) {
        return Err(PolicyError::new(
            "INVALID_OBJECT_METADATA",
            "oversized or truncated object metadata",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| PolicyError::new("INVALID_OBJECT_METADATA", "object metadata is not UTF-8"))?;
    let mut objects = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split(' ').collect();
        if fields.len() != 3
            || !valid_oid(fields[0])
            || !matches!(fields[1], "blob" | "tree" | "commit" | "tag")
            || fields[2].is_empty()
            || !fields[2].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(PolicyError::new(
                "INVALID_OBJECT_METADATA",
                "missing or invalid object metadata",
            ));
        }
        let bytes = fields[2].parse::<u64>().map_err(|_| {
            PolicyError::new(
                "INVALID_OBJECT_METADATA",
                "object size is outside u64 range",
            )
        })?;
        if objects
            .insert(
                fields[0].to_owned(),
                ObjectMetadata {
                    kind: fields[1].to_owned(),
                    bytes,
                },
            )
            .is_some()
        {
            return Err(PolicyError::new(
                "INVALID_OBJECT_METADATA",
                "duplicate object metadata",
            ));
        }
    }
    Ok(objects)
}

fn folded(value: &str) -> String {
    // Conservative portable equivalence, not Unicode Default Case Folding or an
    // exact filesystem model. Uppercasing after lowercasing also catches final
    // sigma, long s and sharp-s case variants. Root registration stays exact.
    value
        .nfc()
        .flat_map(char::to_lowercase)
        .flat_map(char::to_uppercase)
        .collect::<String>()
        .nfc()
        .collect()
}

fn portable_component(component: &str) -> Result<(), &'static str> {
    if component.is_empty() || component == "." || component == ".." {
        return Err("empty, dot and parent components are forbidden");
    }
    if component.encode_utf16().count() > 255
        || component.chars().any(|c| {
            c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
    {
        return Err("nonportable component characters or length");
    }
    if component.ends_with(['.', ' ']) {
        return Err("components cannot end in dot or space");
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_uppercase();
    let numbered_device = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|number| {
            matches!(
                number,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) || numbered_device
    {
        return Err("Windows device name is forbidden");
    }
    Ok(())
}

fn portable_path(path: &str) -> Result<(), &'static str> {
    if path.len() > 4096 {
        return Err("path byte budget exceeded");
    }
    for component in path.split('/') {
        portable_component(component)?;
    }
    Ok(())
}

/// Basename glob matching. `*` and `?` never cross a directory separator.
pub fn basename_matches(pattern: &str, basename: &str) -> bool {
    if pattern.contains(['/', '\\']) || basename.contains(['/', '\\']) {
        return false;
    }
    let pattern: Vec<_> = folded(pattern).chars().collect();
    let basename: Vec<_> = folded(basename).chars().collect();
    let (mut p, mut b, mut star, mut retry) = (0, 0, None, 0);
    while b < basename.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == basename[b]) {
            p += 1;
            b += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = b;
        } else if let Some(index) = star {
            retry += 1;
            b = retry;
            p = index + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

fn safe_report_path(path: &str) -> Option<String> {
    portable_path(path).ok().map(|()| path.to_owned())
}

fn violation(code: &'static str, path: &str, message: &str) -> PolicyViolation {
    PolicyViolation {
        code,
        path: safe_report_path(path),
        message: message.to_owned(),
    }
}

/// Inspect staged records with supplied object metadata, without any file reads.
pub fn check_records(
    policy: &RepositoryPolicy,
    records: &[IndexRecord],
    objects: &BTreeMap<String, ObjectMetadata>,
) -> Result<PolicyReport, PolicyError> {
    validate_policy(policy)?;
    if records.len() > MAX_INDEX_RECORDS || objects.len() > MAX_INDEX_RECORDS {
        return Err(PolicyError::new(
            "INDEX_LIMIT",
            "index record budget exceeded",
        ));
    }
    let mut violations = Vec::new();
    let exceptions: BTreeMap<_, _> = policy
        .exceptions
        .iter()
        .map(|exception| (exception.path.as_str(), exception))
        .collect();
    let mut used_exceptions = BTreeSet::new();
    let mut prefixes: BTreeMap<String, (String, bool)> = BTreeMap::new();
    let mut seen_paths = BTreeSet::new();
    for record in records {
        if record.stage != 0 {
            violations.push(violation(
                "UNMERGED_INDEX",
                &record.path,
                "only stage zero is supported",
            ));
        }
        if !seen_paths.insert(record.path.as_str()) {
            violations.push(violation(
                "DUPLICATE_PATH",
                &record.path,
                "duplicate staged path",
            ));
        }
        if !policy.path_rules.allowed_git_modes.contains(&record.mode) {
            violations.push(violation(
                "FORBIDDEN_MODE",
                &record.path,
                "only registered regular file modes are allowed",
            ));
        }
        let metadata = objects.get(&record.oid).ok_or_else(|| {
            PolicyError::new("MISSING_OBJECT_METADATA", "a staged object has no metadata")
        })?;
        if metadata.kind != "blob" {
            violations.push(violation(
                "NON_BLOB",
                &record.path,
                "staged files must reference blobs",
            ));
        }
        if let Err(message) = portable_path(&record.path) {
            violations.push(violation("NONPORTABLE_PATH", &record.path, message));
            continue;
        }
        let components: Vec<_> = record.path.split('/').collect();
        let basename = components[components.len() - 1];
        let registered = if components.len() == 1 {
            policy
                .allowed_root_files
                .iter()
                .any(|name| name == components[0])
        } else {
            policy
                .allowed_root_directories
                .iter()
                .any(|name| name == components[0])
        };
        if !registered {
            violations.push(violation(
                "UNREGISTERED_ROOT",
                &record.path,
                "top-level path is not registered exactly",
            ));
        }
        let mut prefix = String::new();
        for (index, component) in components.iter().enumerate() {
            if index > 0 {
                prefix.push('/');
            }
            prefix.push_str(component);
            let is_file = index + 1 == components.len();
            match prefixes.get(&folded(&prefix)) {
                Some((existing, was_file)) => {
                    if existing != &prefix {
                        violations.push(violation(
                            "CASE_UNICODE_COLLISION",
                            &record.path,
                            "path components collide after Unicode NFC and case normalization",
                        ));
                    }
                    if *was_file != is_file {
                        violations.push(violation(
                            "FILE_DIRECTORY_COLLISION",
                            &record.path,
                            "a staged file collides with a directory component",
                        ));
                    }
                }
                None => {
                    prefixes.insert(folded(&prefix), (prefix.clone(), is_file));
                }
            }
        }
        let normalized_basename = folded(basename);
        let secret = policy
            .forbidden_secret_file_names
            .iter()
            .any(|name| folded(name) == normalized_basename)
            || policy
                .forbidden_secret_file_patterns
                .iter()
                .any(|pattern| basename_matches(pattern, basename));
        if secret {
            violations.push(violation(
                "SECRET_PATH",
                &record.path,
                "secret filename is forbidden regardless of exceptions",
            ));
        }
        let generated = components[..components.len() - 1].iter().any(|component| {
            policy
                .forbidden_directory_names
                .iter()
                .any(|name| folded(name) == folded(component))
        }) || policy
            .forbidden_file_suffixes
            .iter()
            .any(|suffix| normalized_basename.ends_with(&folded(suffix)))
            || policy
                .forbidden_generated_file_patterns
                .iter()
                .any(|pattern| basename_matches(pattern, basename));
        let oversized = metadata.bytes > policy.max_tracked_file_bytes;
        for (kind, needed, code, message) in [
            (
                ExceptionKind::Generated,
                generated,
                "GENERATED_PATH",
                "generated path requires an exact generated exception",
            ),
            (
                ExceptionKind::Size,
                oversized,
                "FILE_TOO_LARGE",
                "blob exceeds the tracked file size limit",
            ),
        ] {
            if needed {
                if exceptions
                    .get(record.path.as_str())
                    .is_some_and(|exception| exception.allow.contains(&kind))
                {
                    used_exceptions.insert((record.path.as_str(), kind));
                } else {
                    violations.push(violation(code, &record.path, message));
                }
            }
        }
    }
    for exception in &policy.exceptions {
        for kind in &exception.allow {
            if !used_exceptions.contains(&(exception.path.as_str(), *kind)) {
                violations.push(violation(
                    "STALE_EXCEPTION",
                    &exception.path,
                    "exception path is absent or this exception kind is unnecessary",
                ));
            }
        }
    }
    violations.sort_by(|a, b| (&a.path, a.code).cmp(&(&b.path, b.code)));
    violations.dedup_by(|a, b| a.path == b.path && a.code == b.code);
    Ok(PolicyReport {
        checked_files: records.len(),
        read_blobs: Vec::new(),
        violations,
    })
}

/// Transport seam used to verify exactly which Git objects are read.
pub trait GitReader {
    fn run(
        &mut self,
        root: &Path,
        args: &[&str],
        input: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>, PolicyError>;
}

pub fn check_repository(root: &Path) -> Result<PolicyReport, PolicyError> {
    check_repository_with_git(root, &mut ProcessGit)
}

pub fn check_repository_with_git(
    root: &Path,
    git: &mut impl GitReader,
) -> Result<PolicyReport, PolicyError> {
    let index = git.run(
        root,
        &["ls-files", "--stage", "-z"],
        &[],
        MAX_METADATA_BYTES,
    )?;
    let records = parse_index(&index)?;
    if records.iter().any(|record| record.stage != 0) {
        return Err(PolicyError::new(
            "UNMERGED_INDEX",
            "unmerged index is rejected before reading any blob",
        ));
    }
    let policy_record = records
        .iter()
        .find(|record| record.path == POLICY_PATH)
        .ok_or_else(|| {
            PolicyError::new(
                "MISSING_STAGED_POLICY",
                "stage the repository policy before inspection",
            )
        })?;
    if !matches!(policy_record.mode.as_str(), "100644" | "100755") {
        return Err(PolicyError::new(
            "INVALID_POLICY_MODE",
            "policy must be a regular staged blob",
        ));
    }
    let oids: BTreeSet<_> = records.iter().map(|record| record.oid.as_str()).collect();
    let input = oids
        .iter()
        .map(|oid| format!("{oid}\n"))
        .collect::<String>();
    let metadata = git.run(
        root,
        &[
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
        input.as_bytes(),
        MAX_METADATA_BYTES,
    )?;
    let objects = parse_object_metadata(&metadata)?;
    if objects.len() != oids.len() || oids.iter().any(|oid| !objects.contains_key(*oid)) {
        return Err(PolicyError::new(
            "MISSING_OBJECT_METADATA",
            "Git returned an unexpected set of object metadata",
        ));
    }
    let policy_metadata = &objects[&policy_record.oid];
    if policy_metadata.kind != "blob" || policy_metadata.bytes > MAX_POLICY_BYTES as u64 {
        return Err(PolicyError::new(
            "INVALID_POLICY_BLOB",
            "policy must be a blob no larger than 64 KiB",
        ));
    }
    let bytes = git.run(
        root,
        &["cat-file", "blob", &policy_record.oid],
        &[],
        MAX_POLICY_BYTES,
    )?;
    if bytes.len() as u64 != policy_metadata.bytes {
        return Err(PolicyError::new(
            "POLICY_SIZE_CHANGED",
            "policy bytes differ from the inspected object size",
        ));
    }
    let policy = parse_policy(&bytes)?;
    let mut report = check_records(&policy, &records, &objects)?;
    report.read_blobs.push(POLICY_PATH.to_owned());
    Ok(report)
}

/// Local built-in Git commands, with finite time and output; stderr content is not disclosed.
/// Execute the containing xtask through the managed runner: this reader reports
/// uncertain process/pipe termination and does not claim descendant-family drain.
pub struct ProcessGit;

impl GitReader for ProcessGit {
    fn run(
        &mut self,
        root: &Path,
        args: &[&str],
        input: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>, PolicyError> {
        if input.len() > MAX_METADATA_BYTES || limit > MAX_METADATA_BYTES {
            return Err(PolicyError::new(
                "GIT_IO_LIMIT",
                "Git input or output budget exceeded",
            ));
        }
        let started = Instant::now();
        let mut child = Command::new("git")
            .current_dir(root)
            .args(["--no-optional-locks", "-c", "core.fsmonitor=false"])
            .args(args)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_ALLOW_PROTOCOL", "")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                PolicyError::new(
                    "GIT_START_FAILED",
                    format!("cannot start Git: {:?}", error.kind()),
                )
            })?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| PolicyError::new("GIT_PIPE_FAILED", "missing Git stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PolicyError::new("GIT_PIPE_FAILED", "missing Git stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| PolicyError::new("GIT_PIPE_FAILED", "missing Git stderr"))?;
        let input = input.to_vec();
        let (writer_tx, writer_rx) = mpsc::sync_channel(1);
        let (reader_tx, reader_rx) = mpsc::sync_channel(1);
        let (errors_tx, errors_rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = writer_tx.send(stdin.write_all(&input));
        });
        thread::spawn(move || {
            let _ = reader_tx.send(read_bounded(stdout, limit));
        });
        thread::spawn(move || {
            let _ = errors_tx.send(read_bounded(stderr, MAX_POLICY_BYTES));
        });
        let (status, timed_out) = loop {
            match child.try_wait() {
                Ok(Some(status)) => break (Some(status), false),
                Ok(None) if started.elapsed() < GIT_TIMEOUT => {
                    thread::sleep(Duration::from_millis(10))
                }
                Ok(None) => {
                    let _ = child.kill();
                    break (
                        poll_exit(&mut child, Instant::now() + GIT_DRAIN_TIMEOUT),
                        true,
                    );
                }
                Err(_) => {
                    let _ = child.kill();
                    break (
                        poll_exit(&mut child, Instant::now() + GIT_DRAIN_TIMEOUT),
                        false,
                    );
                }
            }
        };
        if status.is_none() {
            return Err(PolicyError::new(
                "GIT_TERMINATION_UNCERTAIN",
                "Git process termination was not confirmed; managed runner must drain its family",
            ));
        }
        // Never join a thread with an unbounded inherited pipe. The outer managed
        // runner retains process-family responsibility if this bounded capture fails.
        let drain_deadline = Instant::now() + GIT_DRAIN_TIMEOUT;
        receive_capture(&writer_rx, drain_deadline)?;
        let output = receive_capture(&reader_rx, drain_deadline)?;
        let diagnostic = receive_capture(&errors_rx, drain_deadline)?;
        if timed_out {
            return Err(PolicyError::new(
                "GIT_TIMEOUT",
                "Git inspection exceeded 30 seconds",
            ));
        }
        if output.len() > limit || diagnostic.len() > MAX_POLICY_BYTES {
            return Err(PolicyError::new(
                "GIT_IO_LIMIT",
                "Git inspection output budget exceeded",
            ));
        }
        if !status.is_some_and(|status| status.success()) {
            return Err(PolicyError::new(
                "GIT_FAILED",
                "Git inspection failed; no file contents were disclosed",
            ));
        }
        Ok(output)
    }
}

fn poll_exit(
    child: &mut std::process::Child,
    deadline: Instant,
) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => return None,
        }
    }
}

fn receive_capture<T>(
    receiver: &Receiver<std::io::Result<T>>,
    deadline: Instant,
) -> Result<T, PolicyError> {
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| {
            PolicyError::new(
                "GIT_DRAIN_UNCERTAIN",
                "Git pipe completion was not confirmed; managed runner must drain its family",
            )
        })?
        .map_err(|_| PolicyError::new("GIT_IO_FAILED", "Git inspection pipe failed"))
}

fn read_bounded(reader: impl Read, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.take((limit + 1) as u64).read_to_end(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn policy() -> RepositoryPolicy {
        RepositoryPolicy {
            schema_version: 1,
            allowed_root_files: vec!["README.md".into(), "Cargo.toml".into()],
            allowed_root_directories: vec![".github".into(), "tools".into(), "docs".into()],
            forbidden_directory_names: vec!["target".into(), "dist".into()],
            forbidden_secret_file_names: vec![".env".into(), "credentials.json".into()],
            forbidden_secret_file_patterns: vec![
                ".env.*".into(),
                "*credential*.json".into(),
                "*.key".into(),
            ],
            forbidden_file_suffixes: vec![".nbt".into(), ".tar.gz".into(), ".jar".into()],
            forbidden_generated_file_patterns: vec!["*.so.*".into(), "*.db-wal".into()],
            max_tracked_file_bytes: 10 * 1024 * 1024,
            max_policy_file_bytes: MAX_POLICY_BYTES as u64,
            path_rules: PathRules {
                require_stage_zero: true,
                portable_paths: true,
                reject_case_unicode_collisions: true,
                allowed_git_modes: vec!["100644".into(), "100755".into()],
            },
            exceptions: Vec::new(),
        }
    }

    fn records(paths: &[&str]) -> (Vec<IndexRecord>, BTreeMap<String, ObjectMetadata>) {
        let oid = "a".repeat(40);
        let records = paths
            .iter()
            .map(|path| IndexRecord {
                mode: "100644".into(),
                oid: oid.clone(),
                stage: 0,
                path: (*path).to_owned(),
            })
            .collect();
        let objects = BTreeMap::from([(
            oid,
            ObjectMetadata {
                kind: "blob".into(),
                bytes: 32,
            },
        )]);
        (records, objects)
    }

    fn codes(report: &PolicyReport) -> BTreeSet<&'static str> {
        report
            .violations
            .iter()
            .map(|violation| violation.code)
            .collect()
    }

    #[test]
    fn strict_policy_fields_types_duplicates_and_invariants() {
        let bytes = serde_json::to_vec(&policy()).unwrap();
        assert!(parse_policy(&bytes).is_ok());
        let mut value = serde_json::to_value(policy()).unwrap();
        value["unexpected"] = true.into();
        assert_eq!(
            parse_policy(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code,
            "INVALID_POLICY_JSON"
        );
        let text = String::from_utf8(bytes.clone()).unwrap().replacen(
            "\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1",
            1,
        );
        assert_eq!(
            parse_policy(text.as_bytes()).unwrap_err().code,
            "INVALID_POLICY_JSON"
        );
        let mut value = serde_json::to_value(policy()).unwrap();
        value["maxTrackedFileBytes"] = "10485760".into();
        assert!(parse_policy(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value = serde_json::to_value(policy()).unwrap();
        value["pathRules"]["portablePaths"] = false.into();
        assert_eq!(
            parse_policy(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code,
            "INVALID_POLICY"
        );
        let mut value = serde_json::to_value(policy()).unwrap();
        value["maxPolicyFileBytes"] = 65_537_u64.into();
        assert!(parse_policy(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value = serde_json::to_value(policy()).unwrap();
        value["maxPolicyFileBytes"] = 1_u64.into();
        assert_eq!(
            parse_policy(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code,
            "POLICY_TOO_LARGE"
        );
        assert_eq!(
            parse_policy(&vec![b' '; MAX_POLICY_BYTES + 1])
                .unwrap_err()
                .code,
            "POLICY_TOO_LARGE"
        );
        let mut invalid = policy();
        invalid.allowed_root_directories.push("TOOLS".into());
        assert!(parse_policy(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }

    #[test]
    fn metadata_preserves_nul_framing_and_both_git_hash_formats() {
        for length in [40, 64] {
            let oid = "a".repeat(length);
            let index = format!("100644 {oid} 0\tdocs/a\tb.md\0");
            let parsed = parse_index(index.as_bytes()).unwrap();
            assert_eq!(parsed[0].path, "docs/a\tb.md");
            assert_eq!(
                parse_object_metadata(format!("{oid} blob 0\n").as_bytes()).unwrap()[&oid].bytes,
                0
            );
        }
        let oid = "a".repeat(40);
        for input in [
            format!("100644 {oid} 0\tdocs/a.md"),
            format!("100644 {oid} 0\tdocs/a.md\0\0"),
            format!("100644 {oid} 0\tdocs/a.md\0") + &format!("100644 {oid} 0\tdocs/a.md\0"),
        ] {
            assert!(parse_index(input.as_bytes()).is_err());
        }
        assert!(parse_index(format!("100644 {oid} 4\tdocs/a.md\0").as_bytes()).is_err());
        assert!(
            parse_index(format!("100644 {} 0\tdocs/a.md\0", "a".repeat(39)).as_bytes()).is_err()
        );
        assert!(
            parse_index(
                format!(
                    "100644 {oid} 0\tdocs/a.md\0\
            100644 {} 0\tdocs/b.md\0",
                    "b".repeat(64)
                )
                .as_bytes()
            )
            .is_err()
        );
        let mut non_utf8 = format!("100644 {oid} 0\tdocs/").into_bytes();
        non_utf8.extend_from_slice(&[0xff, 0]);
        assert!(parse_index(&non_utf8).is_err());
        for body in [
            format!("{oid} missing\n"),
            format!("{oid} blob 32"),
            format!("{oid} blob -1\n"),
            format!("{oid} blob 18446744073709551616\n"),
            format!("{oid} blob 1\n{oid} blob 1\n"),
        ] {
            assert!(parse_object_metadata(body.as_bytes()).is_err());
        }
    }

    #[test]
    fn names_modes_generation_and_exact_roots_are_checked_from_metadata() {
        let (mut entries, mut objects) = records(&[
            "README.md",
            "tools/build.rs",
            "tools/main.rs",
            "docs/DIST/result.json",
            "docs/file.TAR.GZ",
            "tools/lib.SO.1",
            "docs/.ENV.production",
            "tools/CREDENTIALS.JSON",
            "tools/a.KEY",
            "Tools/wrong-root.rs",
            "unknown.md",
            "docs/AUX.txt",
            "docs/COM¹.txt",
            "docs/CON .txt",
            "docs/LPT9/file.md",
            "docs/trailing. ",
            "docs/back\\slash.rs",
            "docs/../parent.md",
            "C:/private/file.rs",
        ]);
        entries[2].mode = "120000".into();
        let report = check_records(&policy(), &entries, &objects).unwrap();
        let found = codes(&report);
        for expected in [
            "GENERATED_PATH",
            "SECRET_PATH",
            "UNREGISTERED_ROOT",
            "FORBIDDEN_MODE",
            "NONPORTABLE_PATH",
        ] {
            assert!(found.contains(expected), "missing {expected}");
        }
        assert!(
            !report
                .violations
                .iter()
                .any(|violation| violation.path.as_deref() == Some("tools/build.rs"))
        );
        assert!(
            report
                .violations
                .iter()
                .filter(|violation| violation.code == "NONPORTABLE_PATH")
                .all(|violation| violation.path.is_none())
        );
        entries[2].mode = "160000".into();
        objects.values_mut().next().unwrap().kind = "commit".into();
        assert!(codes(&check_records(&policy(), &entries, &objects).unwrap()).contains("NON_BLOB"));
        objects.clear();
        assert_eq!(
            check_records(&policy(), &entries, &objects)
                .unwrap_err()
                .code,
            "MISSING_OBJECT_METADATA"
        );
    }

    #[test]
    fn case_nfc_directory_and_file_collisions_are_detected() {
        let (entries, objects) = records(&[
            "docs/Foo/a.md",
            "docs/foo/b.md",
            "docs/café.md",
            "docs/cafe\u{301}.md",
            "tools/shared",
            "tools/shared/item.rs",
            "docs/σ.md",
            "docs/ς.md",
            "docs/s.md",
            "docs/ſ.md",
            "docs/ß.md",
            "docs/ẞ.md",
        ]);
        let report = check_records(&policy(), &entries, &objects).unwrap();
        assert!(codes(&report).contains("CASE_UNICODE_COLLISION"));
        assert!(codes(&report).contains("FILE_DIRECTORY_COLLISION"));
        assert!(
            report
                .violations
                .iter()
                .any(
                    |violation| violation.path.as_deref() == Some("docs/cafe\u{301}.md")
                        && violation.code == "CASE_UNICODE_COLLISION"
                )
        );
        for path in ["docs/ς.md", "docs/ſ.md", "docs/ẞ.md"] {
            assert!(
                report
                    .violations
                    .iter()
                    .any(|violation| violation.path.as_deref() == Some(path)
                        && violation.code == "CASE_UNICODE_COLLISION")
            );
        }
    }

    #[test]
    fn basename_globs_are_case_insensitive_and_do_not_cross_directories() {
        assert!(basename_matches("*.so.*", "LIB.SO.12"));
        assert!(basename_matches(".env.*", ".ENV.local"));
        assert!(basename_matches("a?c*", "AbCd"));
        assert!(!basename_matches("a?c", "ac"));
        assert!(!basename_matches("*", "dir/name"));
        assert!(!basename_matches("dir/*", "name"));
        assert!(!basename_matches("*.so.*", "build.rs"));
    }

    #[test]
    fn pipe_capture_has_finite_output_and_reports_unconfirmed_completion() {
        let bytes = read_bounded(std::io::Cursor::new(vec![b'x'; 100]), 12).unwrap();
        assert_eq!(bytes.len(), 13);
        let (sender, receiver) = mpsc::sync_channel::<std::io::Result<()>>(1);
        assert_eq!(
            receive_capture(&receiver, Instant::now()).unwrap_err().code,
            "GIT_DRAIN_UNCERTAIN"
        );
        sender.send(Ok(())).unwrap();
        assert!(receive_capture(&receiver, Instant::now()).is_ok());
        assert_eq!(
            ProcessGit
                .run(Path::new("."), &[], &[], MAX_METADATA_BYTES + 1)
                .unwrap_err()
                .code,
            "GIT_IO_LIMIT"
        );
    }

    #[test]
    fn exceptions_exempt_only_needed_exact_generated_and_size_rules() {
        let mut policy = policy();
        policy.max_tracked_file_bytes = 31;
        policy.exceptions.push(PolicyException {
            path: "docs/fixture.nbt".into(),
            allow: vec![ExceptionKind::Generated, ExceptionKind::Size],
            reason: "small contract fixture".into(),
        });
        let (entries, objects) = records(&["docs/fixture.nbt"]);
        assert!(check_records(&policy, &entries, &objects).unwrap().passed());
        let (entries, objects) = records(&["docs/Fixture.nbt"]);
        assert_eq!(
            codes(&check_records(&policy, &entries, &objects).unwrap()),
            BTreeSet::from(["FILE_TOO_LARGE", "GENERATED_PATH", "STALE_EXCEPTION"])
        );
        policy.max_tracked_file_bytes = 32;
        let (entries, objects) = records(&["docs/fixture.nbt"]);
        assert_eq!(
            codes(&check_records(&policy, &entries, &objects).unwrap()),
            BTreeSet::from(["STALE_EXCEPTION"])
        );
        assert!(
            codes(&check_records(&policy, &[], &BTreeMap::new()).unwrap())
                .contains("STALE_EXCEPTION")
        );
        let mut value = serde_json::to_value(&policy).unwrap();
        value["exceptions"][0]["allow"] = serde_json::json!(["secret"]);
        assert_eq!(
            parse_policy(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code,
            "INVALID_POLICY_JSON"
        );
        for path in ["docs/*.nbt", "../file.nbt", "C:/file.nbt"] {
            policy.exceptions[0].path = path.into();
            assert!(parse_policy(&serde_json::to_vec(&policy).unwrap()).is_err());
        }
        policy.exceptions[0].path = "docs/fixture.nbt".into();
        policy.exceptions.push(policy.exceptions[0].clone());
        assert!(parse_policy(&serde_json::to_vec(&policy).unwrap()).is_err());
    }

    #[test]
    fn exceptions_cannot_bypass_secret_root_or_mode_restrictions() {
        let mut policy = policy();
        policy.max_tracked_file_bytes = 31;
        let (mut entries, objects) =
            records(&["tools/.env", "unregistered/fixture.nbt", "docs/fixture.nbt"]);
        entries[2].mode = "120000".into();
        policy.exceptions = entries
            .iter()
            .map(|record| PolicyException {
                path: record.path.clone(),
                allow: if record.path.ends_with(".nbt") {
                    vec![ExceptionKind::Generated, ExceptionKind::Size]
                } else {
                    vec![ExceptionKind::Size]
                },
                reason: "metadata fixture exception".into(),
            })
            .collect();
        assert_eq!(
            codes(&check_records(&policy, &entries, &objects).unwrap()),
            BTreeSet::from(["SECRET_PATH", "UNREGISTERED_ROOT", "FORBIDDEN_MODE"])
        );
    }

    struct TempRepository {
        path: PathBuf,
        parent: PathBuf,
    }

    impl TempRepository {
        fn new() -> Self {
            Self::with_object_format("sha1")
        }

        fn with_object_format(format: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
            let path = parent.join(format!(
                "mmmm-policy-fixture-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let repository = Self { path, parent };
            repository.command(
                &[
                    "init",
                    "--quiet",
                    "--template=",
                    &format!("--object-format={format}"),
                ],
                b"",
            );
            repository
        }

        fn command(&self, args: &[&str], input: &[u8]) -> Vec<u8> {
            let mut child = Command::new("git")
                .current_dir(&self.path)
                .args(["--no-optional-locks", "-c", "core.fsmonitor=false"])
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(input).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success(), "fixture Git command failed");
            output.stdout
        }

        fn stage_blob(&self, path: &str, mode: &str, bytes: &[u8]) -> String {
            let oid = String::from_utf8(self.command(&["hash-object", "-w", "--stdin"], bytes))
                .unwrap()
                .trim()
                .to_owned();
            self.command(
                &[
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("{mode},{oid},{path}"),
                ],
                b"",
            );
            oid
        }

        fn stage_policy(&self, policy: &RepositoryPolicy) -> String {
            self.stage_blob(POLICY_PATH, "100644", &serde_json::to_vec(policy).unwrap())
        }
    }

    impl Drop for TempRepository {
        fn drop(&mut self) {
            // Only this newly created, canonical direct child is eligible for fixture removal.
            if let Ok(path) = fs::canonicalize(&self.path)
                && path.parent() == Some(self.parent.as_path())
                && path == self.path
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }

    #[derive(Default)]
    struct RecordingGit {
        calls: Vec<Vec<String>>,
    }

    impl GitReader for RecordingGit {
        fn run(
            &mut self,
            root: &Path,
            args: &[&str],
            input: &[u8],
            limit: usize,
        ) -> Result<Vec<u8>, PolicyError> {
            self.calls
                .push(args.iter().map(|argument| (*argument).to_owned()).collect());
            ProcessGit.run(root, args, input, limit)
        }
    }

    #[test]
    fn real_git_reads_only_staged_policy_content_and_ignores_worktree_contents() {
        let repository = TempRepository::new();
        let policy_oid = repository.stage_policy(&policy());
        repository.stage_blob("tools/probe.rs", "100644", &[0xff, 0x00, 0xfe]);
        fs::create_dir(repository.path.join(".github")).unwrap();
        fs::write(repository.path.join(POLICY_PATH), b"invalid unstaged JSON").unwrap();
        fs::write(repository.path.join(".gitignore"), b"ignored-probe.txt\n").unwrap();
        fs::write(repository.path.join("ignored-probe.txt"), b"ignored probe").unwrap();
        let mut git = RecordingGit::default();
        let report = check_repository_with_git(&repository.path, &mut git).unwrap();
        assert!(report.passed());
        assert_eq!(report.checked_files, 2);
        assert_eq!(report.read_blobs, vec![POLICY_PATH]);
        assert_eq!(
            git.calls,
            vec![
                vec!["ls-files", "--stage", "-z"],
                vec![
                    "cat-file",
                    "--batch-check=%(objectname) %(objecttype) %(objectsize)"
                ],
                vec!["cat-file", "blob", &policy_oid]
            ]
        );
    }

    #[test]
    fn real_git_rejects_secret_generated_and_link_metadata_without_reading_their_blobs() {
        let repository = TempRepository::new();
        let policy_oid = repository.stage_policy(&policy());
        // Forbidden names exist only in the index; no secret file or link target is created or read.
        repository.stage_blob("tools/.env", "100644", b"fixture blob");
        repository.stage_blob("docs/dist/result.json", "100644", b"fixture blob");
        repository.stage_blob("tools/link", "120000", b"unavailable-target");
        let mut git = RecordingGit::default();
        let report = check_repository_with_git(&repository.path, &mut git).unwrap();
        for expected in ["SECRET_PATH", "GENERATED_PATH", "FORBIDDEN_MODE"] {
            assert!(codes(&report).contains(expected));
        }
        let content_reads: Vec<_> = git
            .calls
            .iter()
            .filter(|args| args.get(1).is_some_and(|arg| arg == "blob"))
            .collect();
        assert_eq!(
            content_reads,
            vec![&vec!["cat-file".to_owned(), "blob".to_owned(), policy_oid]]
        );
    }

    #[test]
    fn real_sha256_git_index_is_supported_without_a_sha1_assumption() {
        let repository = TempRepository::with_object_format("sha256");
        let oid = repository.stage_policy(&policy());
        assert_eq!(oid.len(), 64);
        repository.stage_blob("tools/build.rs", "100644", b"fn main() {}\n");
        assert!(check_repository(&repository.path).unwrap().passed());
    }

    #[test]
    fn real_git_policy_size_mode_and_unmerged_checks_precede_any_content_read() {
        for invalid in ["oversized", "symlink", "unmerged"] {
            let repository = TempRepository::new();
            let policy_oid = repository.stage_policy(&policy());
            if invalid == "oversized" {
                repository.stage_blob(POLICY_PATH, "100644", &vec![b' '; MAX_POLICY_BYTES + 1]);
            } else if invalid == "symlink" {
                repository.stage_blob(POLICY_PATH, "120000", b"unavailable-target");
            } else {
                repository.command(&["update-index", "--index-info"],
                    format!("0 {}\ttools/conflict.rs\n100644 {policy_oid} 1\ttools/conflict.rs\n100644 {policy_oid} 2\ttools/conflict.rs\n", "0".repeat(40)).as_bytes());
            }
            let mut git = RecordingGit::default();
            assert!(check_repository_with_git(&repository.path, &mut git).is_err());
            assert!(
                !git.calls
                    .iter()
                    .any(|args| args.get(1).is_some_and(|arg| arg == "blob"))
            );
        }
    }
}
