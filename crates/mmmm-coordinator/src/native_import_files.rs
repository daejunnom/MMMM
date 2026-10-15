//! Explicitly selected native authoring files. This is not a directory import
//! or a file finder: lexical classification precedes every filesystem lookup.
//! Held handles, namespace checks and a second bounded digest pass reject
//! observed replacement/modification. POSIX provides no regular-file snapshot
//! or write exclusion here; its cooperative deadline cannot interrupt a blocked
//! kernel read. These checks are not a claim to discover every secret alias.

use crate::{service::RequestBudget, workspace_bootstrap::NativeOwnerWitness};
use mmmm_owned_files::{Control, HeldFile};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::path::Component;
use std::{
    collections::TryReserveError,
    error::Error,
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

const DOCUMENT_LIMIT: u64 = 8 * 1024 * 1024;
const DESCRIPTOR_LIMIT: u64 = 16 * 1024;
const DOCUMENT_TOTAL: u64 = 32 * 1024 * 1024;
const RESOURCE_TOTAL: u64 = 128 * 1024 * 1024;
const SELECTED_FILE_LIMIT: usize = 512;
const CHUNK: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputRole {
    Document,
    ResourceDescriptor,
    ResourceBytes,
}
impl InputRole {
    fn limit(self) -> u64 {
        match self {
            Self::Document => DOCUMENT_LIMIT,
            Self::ResourceDescriptor => DESCRIPTOR_LIMIT,
            Self::ResourceBytes => RESOURCE_TOTAL,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Document => "Selected source document",
            Self::ResourceDescriptor => "Selected resource descriptor",
            Self::ResourceBytes => "Selected resource bytes",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ErrorKind {
    UnsafeSelection,
    Limit,
    Changed,
    Io,
    Authority,
    Request,
    Allocation,
}

/// The public wrapper preserves original native/request causes privately.
/// Neither Display nor any error field contains a selected path or its bytes.
#[derive(Debug)]
pub struct ImportFileError {
    kind: ErrorKind,
    role: Option<InputRole>,
    cause: Option<Box<dyn Error + Send + Sync>>,
    checkpoint: Option<Box<ImportFileError>>,
}
impl ImportFileError {
    fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            role: None,
            cause: None,
            checkpoint: None,
        }
    }
    fn caused(kind: ErrorKind, cause: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            role: None,
            cause: Some(Box::new(cause)),
            checkpoint: None,
        }
    }
    fn for_role(mut self, role: InputRole) -> Self {
        self.role = Some(role);
        self
    }
    /// A checkpoint may fail immediately after the actual I/O has failed. The
    /// primary native cause remains Error::source; this preserves both facts
    /// for internal diagnostics without exposing a selected path or its bytes.
    pub fn checkpoint_failure(&self) -> Option<&Self> {
        self.checkpoint.as_deref()
    }
}
impl fmt::Display for ImportFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let role = self
            .role
            .map(InputRole::label)
            .unwrap_or("Selected source file");
        let detail = match self.kind {
            ErrorKind::UnsafeSelection => "requires an absolute ordinary non-secret local file",
            ErrorKind::Limit => "exceeds the finite source input budget",
            ErrorKind::Changed => "changed during checked source acquisition",
            ErrorKind::Io => "could not be acquired through its checked local handle",
            ErrorKind::Authority => "lost the original native owner authorization",
            ErrorKind::Request => "could not continue within the original request budget",
            ErrorKind::Allocation => "could not reserve its finite input buffer",
        };
        write!(f, "{role} {detail}")
    }
}
impl Error for ImportFileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| cause.as_ref() as &(dyn Error + 'static))
    }
}

/// Metadata/document allowance includes the original inline argv documents.
/// Reservations survive a failed read; callers stop the batch on any failure.
/// A resource item selects two files, so the parser's 256-item bound permits
/// at most 512 selected files. This independent bound also protects direct use.
pub(crate) struct ImportReadBudget {
    documents: u64,
    resources: u64,
    selected_files: usize,
}
impl ImportReadBudget {
    pub(crate) fn new(initial_document_bytes: usize) -> Result<Self, ImportFileError> {
        let documents = u64::try_from(initial_document_bytes)
            .map_err(|_| ImportFileError::new(ErrorKind::Limit))?;
        if documents > DOCUMENT_TOTAL {
            return Err(ImportFileError::new(ErrorKind::Limit));
        }
        Ok(Self {
            documents,
            resources: 0,
            selected_files: 0,
        })
    }
    fn reserve(&mut self, role: InputRole, length: u64) -> Result<usize, ImportFileError> {
        let count = self
            .selected_files
            .checked_add(1)
            .filter(|count| *count <= SELECTED_FILE_LIMIT)
            .ok_or_else(|| ImportFileError::new(ErrorKind::Limit))?;
        if length > role.limit() {
            return Err(ImportFileError::new(ErrorKind::Limit));
        }
        let (total, cap) = if role == InputRole::ResourceBytes {
            (&mut self.resources, RESOURCE_TOTAL)
        } else {
            (&mut self.documents, DOCUMENT_TOTAL)
        };
        let next = total
            .checked_add(length)
            .filter(|value| *value <= cap)
            .ok_or_else(|| ImportFileError::new(ErrorKind::Limit))?;
        let allocation =
            usize::try_from(length).map_err(|_| ImportFileError::new(ErrorKind::Limit))?;
        *total = next;
        self.selected_files = count;
        Ok(allocation)
    }
}

/// Pure lexical policy: no exists/canonicalize/metadata/open/hash occurs here.
pub(crate) fn validate_selection(path: &Path, role: InputRole) -> Result<(), ImportFileError> {
    validate_lexical(path, role).map_err(|error| error.for_role(role))
}
fn validate_lexical(path: &Path, role: InputRole) -> Result<(), ImportFileError> {
    if !mmmm_owned_files::is_ordinary_absolute_path(path)
        || (role != InputRole::ResourceBytes
            && path.extension() != Some(std::ffi::OsStr::new("json")))
    {
        return Err(ImportFileError::new(ErrorKind::UnsafeSelection));
    }
    Ok(())
}

struct Checks<'a> {
    owner: &'a NativeOwnerWitness,
    budget: &'a RequestBudget,
}
impl Checks<'_> {
    fn check(&self) -> Result<(), ImportFileError> {
        self.owner
            .check()
            .map_err(|error| ImportFileError::caused(ErrorKind::Authority, error))?;
        self.budget
            .check()
            .map_err(|error| ImportFileError::caused(ErrorKind::Request, error))
    }
}

impl Control for Checks<'_> {
    type Error = ImportFileError;
    fn check(&self) -> Result<(), Self::Error> {
        Checks::check(self)
    }
    fn io_error(&self, error: io::Error) -> Self::Error {
        ImportFileError::caused(ErrorKind::Io, error)
    }
    fn unsafe_selection(&self) -> Self::Error {
        ImportFileError::new(ErrorKind::UnsafeSelection)
    }
    fn changed(&self) -> Self::Error {
        ImportFileError::new(ErrorKind::Changed)
    }
    fn with_post_failure(&self, mut primary: Self::Error, post: Self::Error) -> Self::Error {
        let mut tail = &mut primary.checkpoint;
        while let Some(existing) = tail {
            tail = &mut existing.checkpoint;
        }
        *tail = Some(Box::new(post));
        primary
    }
}

pub(crate) fn read_selected(
    path: &Path,
    role: InputRole,
    owner: &NativeOwnerWitness,
    budget: &RequestBudget,
    totals: &mut ImportReadBudget,
) -> Result<Vec<u8>, ImportFileError> {
    read_selected_inner(path, role, owner, budget, totals, |_, _| {})
        .map_err(|error| error.for_role(role))
}

fn read_selected_inner(
    path: &Path,
    role: InputRole,
    owner: &NativeOwnerWitness,
    budget: &RequestBudget,
    totals: &mut ImportReadBudget,
    mut checkpoint: impl FnMut(usize, bool),
) -> Result<Vec<u8>, ImportFileError> {
    validate_selection(path, role)?;
    let checks = Checks { owner, budget };
    checks.check()?;
    let mut selected = HeldFile::open_selected(path, &checks)?;
    let length = selected.length();
    let capacity = totals.reserve(role, length)?;
    checks.check()?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error: TryReserveError| ImportFileError::caused(ErrorKind::Allocation, error))?;
    let mut first_digest = Sha256::new();
    read_pass(
        selected.file(),
        length,
        &checks,
        |chunk| {
            first_digest.update(chunk);
            bytes.extend_from_slice(chunk);
        },
        |length| checkpoint(length, false),
    )?;
    selected.revalidate(&checks)?;
    checks.io(|| selected.file().seek(SeekFrom::Start(0)))?;
    let mut second_digest = Sha256::new();
    read_pass(
        selected.file(),
        length,
        &checks,
        |chunk| second_digest.update(chunk),
        |length| checkpoint(length, true),
    )?;
    selected.revalidate(&checks)?;
    checks.check()?;
    if first_digest.finalize() != second_digest.finalize() {
        return Err(ImportFileError::new(ErrorKind::Changed));
    }
    checks.check()?;
    selected.close(&checks)?;
    checks.check()?;
    Ok(bytes)
}
fn read_pass(
    file: &mut File,
    expected: u64,
    checks: &Checks<'_>,
    mut consume: impl FnMut(&[u8]),
    mut checkpoint: impl FnMut(usize),
) -> Result<(), ImportFileError> {
    let mut total = 0u64;
    let mut buffer = [0u8; CHUNK];
    loop {
        let remaining = expected
            .checked_sub(total)
            .ok_or_else(|| ImportFileError::new(ErrorKind::Changed))?;
        // One extra byte proves EOF without growing the reserved allocation.
        let take = usize::try_from(remaining.saturating_add(1).min(CHUNK as u64))
            .map_err(|_| ImportFileError::new(ErrorKind::Limit))?;
        let count = checks.io(|| file.read(&mut buffer[..take]))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .filter(|total| *total <= expected)
            .ok_or_else(|| ImportFileError::new(ErrorKind::Changed))?;
        consume(&buffer[..count]);
        checkpoint(total as usize);
        checks.check()?;
    }
    if total != expected {
        return Err(ImportFileError::new(ErrorKind::Changed));
    }
    Ok(())
}

#[cfg(test)]
#[path = "native_import_files_tests.rs"]
mod tests;
