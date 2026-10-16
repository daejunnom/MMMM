//! Owned build storage. Uncertain process or filesystem state preserves the lease.
#[path = "retained_game.rs"]
pub mod retained_game;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "mmmm-managed-build/1";
const RECORD_LIMIT: u64 = 8 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_ENTRIES: usize = 100_000;
const MAX_RETRY_RECORDS: usize = 64;
const MAX_RETRY_LOG_BYTES: usize = 128 * 1024;
const MAX_EXTRA_METADATA_CALLS: usize = 16;
const MAX_RETRY_WAIT: Duration = Duration::from_millis(32);
const MAX_RETRY_WALL: Duration = Duration::from_millis(100);
static TOKEN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct Budgets {
    pub slot_bytes: u64,
    pub catalog_bytes: u64,
    pub completed_slots: usize,
    pub active_slots: usize,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            slot_bytes: 8 * 1024 * 1024 * 1024,
            catalog_bytes: 12 * 1024 * 1024 * 1024,
            completed_slots: 4,
            active_slots: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Development output root, not the catalog or a product data root.
    pub output_root: Option<PathBuf>,
    /// Explicit durable destination. It must not overlap the managed catalog.
    pub evidence_root: PathBuf,
    pub purpose: String,
    pub budgets: Budgets,
}

#[derive(Clone, Debug)]
pub struct BuildPaths {
    pub catalog: PathBuf,
    pub slot: PathBuf,
    pub cargo_target: PathBuf,
    pub cargo_home: PathBuf,
    pub gradle_build: PathBuf,
    pub gradle_project_cache: PathBuf,
    pub gradle_user_home: PathBuf,
    pub scratch: PathBuf,
    pub evidence: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogRecord {
    schema: String,
    catalog_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseRecord {
    schema: String,
    catalog_id: String,
    slot_id: String,
    token: String,
    pid: u32,
    started_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotRecord {
    schema: String,
    catalog_id: String,
    slot_id: String,
    checkout_digest: String,
    os: String,
    arch: String,
    purpose: String,
    token: String,
    pid: u32,
    state: SlotState,
    completed_ms: Option<u64>,
}

/// Exact identity supplied by the supervised, external first compilation.
/// This does not authorize adoption of any other interrupted slot or lease.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapOwnership {
    pub schema: String,
    pub catalog_id: String,
    pub slot_id: String,
    pub checkout_digest: String,
    pub os: String,
    pub arch: String,
    pub purpose: String,
    pub token: String,
    pub pid: u32,
    pub started_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SlotState {
    Active,
    Complete,
}

/// Only the process supervisor may assert `drained`; absent proof preserves storage.
#[derive(Clone, Debug)]
pub struct FinishOutcome {
    pub command_exit: Option<i32>,
    pub supervisor_errors: Vec<String>,
    pub drained: bool,
    pub evidence_exported: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct FinishReceipt {
    pub schema: &'static str,
    pub slot_id: String,
    pub command_exit: Option<i32>,
    pub supervisor_errors: Vec<String>,
    pub cleanup_errors: Vec<String>,
    pub scratch_removed: bool,
    pub slot_evicted: bool,
    pub evicted_completed_slots: Vec<String>,
    pub observed_slot_bytes: u64,
    pub observed_catalog_bytes: u64,
    pub lease_released: bool,
}

#[derive(Clone, Debug)]
pub struct Measurement {
    pub slot_bytes: u64,
    pub catalog_bytes: u64,
    pub within_budget: bool,
}

/// Nonfatal recovery facts are separate from supervisor_errors. A record is
/// retained even when a later checkpoint fails. This is build evidence only.
#[derive(Debug, Default, Serialize)]
pub struct ObservationRetryLog {
    records: Vec<ObservationRetryRecord>,
}
#[derive(Clone, Debug, Serialize)]
struct NativeIoDiagnostic {
    kind: String,
    raw_os_error: Option<i32>,
}
impl NativeIoDiagnostic {
    fn from_error(error: &std::io::Error) -> Self {
        Self {
            kind: format!("{:?}", error.kind()),
            raw_os_error: error.raw_os_error(),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
struct ObservationRetryRecord {
    stage: &'static str,
    first: NativeIoDiagnostic,
    attempts: u8,
    elapsed_ms: u64,
    final_observation: RetryFinalObservation,
    generated_relative: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_found_trigger: Option<ObservationNotFoundTrigger>,
}
#[derive(Clone, Debug, Serialize)]
struct ObservationNotFoundTrigger {
    stage: &'static str,
    first: NativeIoDiagnostic,
    generated_relative: String,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum RetryFinalObservation {
    Pending,
    Present {
        file_type: &'static str,
        byte_length: u64,
    },
    MissingValidated {
        last: NativeIoDiagnostic,
    },
    Failed {
        category: &'static str,
        final_io: Option<NativeIoDiagnostic>,
        last_metadata_io: Option<NativeIoDiagnostic>,
    },
}
impl ObservationRetryLog {
    pub fn encoded_evidence(&self) -> Result<Vec<u8>, StorageError> {
        let value = serde_json::json!({
            "schema":"mmmm-managed-observation-retries/1", "records":self.records,
        });
        let mut encoded = serde_json::to_vec_pretty(&value).map_err(|_| {
            StorageError::new("retry_evidence", "serialize observation retry evidence")
        })?;
        encoded.push(b'\n');
        if encoded.len() > MAX_RETRY_LOG_BYTES {
            return Err(StorageError::new(
                "retry_evidence",
                "observation retry evidence byte limit exceeded",
            ));
        }
        Ok(encoded)
    }
    #[cfg(test)]
    fn evidence(&self) -> Result<serde_json::Value, StorageError> {
        serde_json::from_slice(&self.encoded_evidence()?).map_err(|_| {
            StorageError::new("retry_evidence", "decode observation retry test evidence")
        })
    }
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "companion":"observation-retries.json", "records":self.records.len(),
            "recovered_present":self.records.iter().filter(|record| matches!(record.final_observation, RetryFinalObservation::Present { .. })).count(),
            "recovered_missing":self.records.iter().filter(|record| matches!(record.final_observation, RetryFinalObservation::MissingValidated { .. })).count(),
            "first":self.records.first(), "last":self.records.last(),
        })
    }
    fn retain(&mut self, record: ObservationRetryRecord) -> Result<(), StorageError> {
        if self.records.len() >= MAX_RETRY_RECORDS {
            return Err(StorageError::new(
                "retry_evidence",
                "observation retry record limit exceeded",
            ));
        }
        self.records.push(record);
        if let Err(error) = self.encoded_evidence() {
            self.records.pop();
            return Err(error);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct StorageError {
    pub kind: &'static str,
    pub message: String,
    cause: Option<Box<StorageError>>,
    native_io: Option<NativeIoDiagnostic>,
}

impl StorageError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            cause: None,
            native_io: None,
        }
    }
    fn io(context: &str, error: std::io::Error) -> Self {
        let mut result = Self::new("io", format!("{context}: {error}"));
        result.native_io = Some(NativeIoDiagnostic::from_error(&error));
        result
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}
impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_deref()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SupervisorFileIdentity {
    volume: u64,
    file: u64,
}

/// 실행 이미지가 있는 slot은 lease 상태와 별개로 이 supervisor가 끝날 때까지 보존한다.
/// Unix 경로 재검사는 협력적이며, 같은 UID의 적대적인 원자적 경로 변경을 격리하지 않는다.
struct SupervisorImagePin {
    path: PathBuf,
    file: File,
    identity: SupervisorFileIdentity,
    slot_id: Option<String>,
}

impl SupervisorImagePin {
    fn open(path: &Path) -> Result<Self, StorageError> {
        verify_supervisor_path(path)?;
        let original = open_supervisor_image(path)?;
        let original_identity = supervisor_file_identity(&original)?;
        let physical = fs::canonicalize(path)
            .map_err(|error| StorageError::io("resolve supervisor image path", error))?;
        verify_supervisor_path(&physical)?;
        let file = open_supervisor_image(&physical)?;
        let identity = supervisor_file_identity(&file)?;
        verify_supervisor_path(path)?;
        if identity != original_identity
            || supervisor_file_identity(&open_supervisor_image(path)?)? != original_identity
        {
            return Err(StorageError::new(
                "supervisor_image",
                "supervisor image changed while resolving its path",
            ));
        }
        let pin = Self {
            path: physical,
            file,
            identity,
            slot_id: None,
        };
        pin.recheck()?;
        Ok(pin)
    }

    fn bind_catalog(
        &mut self,
        catalog_path: &Path,
        catalog: &CatalogRecord,
    ) -> Result<(), StorageError> {
        self.recheck()?;
        verify_directory(catalog_path)?;
        let physical = fs::canonicalize(catalog_path)
            .map_err(|error| StorageError::io("resolve supervisor catalog", error))?;
        let catalog_identity = path_identity(&physical);
        let image_identity = path_identity(&self.path);
        if image_identity == catalog_identity {
            return Err(StorageError::new(
                "supervisor_image",
                "supervisor image is not a slot cache file",
            ));
        }
        let prefix = format!("{catalog_identity}{}", std::path::MAIN_SEPARATOR);
        let Some(relative) = image_identity.strip_prefix(&prefix) else {
            // 외부 이미지도 위의 실제 handle/ancestry 검사를 통과해야 한다.
            return Ok(());
        };
        let components: Vec<_> = Path::new(relative).components().collect();
        if components.len() < 4
            || components.len() > MAX_DEPTH
            || components
                .iter()
                .any(|part| !matches!(part, Component::Normal(_)))
            || components[0].as_os_str() != "slots"
            || components[2].as_os_str() != "cache"
        {
            return Err(StorageError::new(
                "supervisor_image",
                "supervisor inside catalog must use a recognized slot cache; scratch is not executable storage",
            ));
        }
        let slot_id = components[1]
            .as_os_str()
            .to_str()
            .ok_or_else(|| StorageError::new("supervisor_image", "supervisor slot is not UTF-8"))?;
        let slot_path = physical.join("slots").join(slot_id);
        verify_directory(&slot_path)?;
        let record: SlotRecord = read_record(&slot_path.join("owner.json"))?;
        validate_slot_record(&record, slot_id, catalog)?;
        validate_slot_entries(&slot_path)?;
        self.slot_id = Some(slot_id.to_owned());
        self.recheck()
    }

    fn recheck(&self) -> Result<(), StorageError> {
        verify_supervisor_path(&self.path)?;
        let physical = fs::canonicalize(&self.path)
            .map_err(|error| StorageError::io("recheck supervisor image path", error))?;
        if path_identity(&physical) != path_identity(&self.path)
            || supervisor_file_identity(&self.file)? != self.identity
            || supervisor_file_identity(&open_supervisor_image(&self.path)?)? != self.identity
        {
            return Err(StorageError::new(
                "supervisor_image",
                "supervisor image path or file identity changed",
            ));
        }
        Ok(())
    }
}

fn verify_supervisor_path(path: &Path) -> Result<(), StorageError> {
    validate_absolute_path(path)?;
    reject_secret_leaf_file(path)?;
    if path.to_str().is_none() {
        return Err(StorageError::new(
            "supervisor_image",
            "supervisor path identity must be lossless UTF-8",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| StorageError::new("supervisor_image", "supervisor image has no parent"))?;
    verify_directory(parent)?;
    reject_link(path)?;
    if !fs::symlink_metadata(path)
        .map_err(|error| StorageError::io("inspect supervisor image", error))?
        .is_file()
    {
        return Err(StorageError::new(
            "supervisor_image",
            "supervisor image must be an ordinary file",
        ));
    }
    Ok(())
}

fn open_supervisor_image(path: &Path) -> Result<File, StorageError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    let file = options.open(path).map_err(|error| {
        StorageError::io("open supervisor image without following links", error)
    })?;
    supervisor_file_identity(&file)?;
    Ok(file)
}

fn supervisor_file_identity(file: &File) -> Result<SupervisorFileIdentity, StorageError> {
    let metadata = file
        .metadata()
        .map_err(|error| StorageError::io("inspect supervisor image handle", error))?;
    if !metadata.is_file() || is_link(&metadata) {
        return Err(StorageError::new(
            "supervisor_image",
            "supervisor handle must be an ordinary file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // Cargo는 top-level/deps 이름을 hardlink할 수 있다. 보호하는 것은 확인한
        // 실제 path와 그 slot이며, 다른 alias의 존속이나 같은 UID의 쓰기를 보장하지 않는다.
        if metadata.nlink() == 0 {
            return Err(StorageError::new(
                "supervisor_image",
                "supervisor image has no live file link",
            ));
        }
        Ok(SupervisorFileIdentity {
            volume: metadata.dev(),
            file: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        // SAFETY: File owns the live handle and the initialized output buffer is writable.
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
            return Err(StorageError::io(
                "identify supervisor image handle",
                std::io::Error::last_os_error(),
            ));
        }
        if information.nNumberOfLinks == 0 {
            return Err(StorageError::new(
                "supervisor_image",
                "supervisor image has no live file link",
            ));
        }
        Ok(SupervisorFileIdentity {
            volume: u64::from(information.dwVolumeSerialNumber),
            file: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(StorageError::new(
            "supervisor_image",
            "native supervisor image identity is unsupported",
        ))
    }
}

fn plan_completed_evictions(
    slots: &[(PathBuf, SlotRecord)],
    sizes: &BTreeMap<String, u64>,
    budgets: &Budgets,
    current_slot: &str,
    include_current: bool,
    protected_slot: Option<&str>,
) -> Result<BTreeSet<String>, StorageError> {
    let mut total = 0;
    let mut completed = 0;
    for (_, record) in slots {
        total = checked_sum(total, sizes[&record.slot_id])?;
        completed += usize::from(record.state == SlotState::Complete);
    }
    let mut selected = BTreeSet::new();
    for (_, record) in slots {
        if record.state != SlotState::Complete
            || (!include_current && record.slot_id == current_slot)
            || protected_slot == Some(record.slot_id.as_str())
        {
            continue;
        }
        let size = sizes[&record.slot_id];
        if size > budgets.slot_bytes
            || total > budgets.catalog_bytes
            || completed > budgets.completed_slots
        {
            selected.insert(record.slot_id.clone());
            total -= size;
            completed -= 1;
        }
    }
    let oversized = slots.iter().any(|(_, record)| {
        (record.state == SlotState::Complete || protected_slot == Some(record.slot_id.as_str()))
            && !selected.contains(&record.slot_id)
            && sizes[&record.slot_id] > budgets.slot_bytes
    });
    if total > budgets.catalog_bytes || completed > budgets.completed_slots || oversized {
        return Err(StorageError::new(
            if protected_slot.is_some() {
                "eviction_blocked"
            } else {
                "budget"
            },
            "managed limits cannot be met without removing a protected or ineligible slot",
        ));
    }
    Ok(selected)
}

pub struct ManagedBuild {
    config: StorageConfig,
    paths: BuildPaths,
    catalog: CatalogRecord,
    lease: LeaseRecord,
    lease_bytes: Vec<u8>,
    slot: SlotRecord,
    slot_bytes: Vec<u8>,
    supervisor_image: SupervisorImagePin,
}

impl ManagedBuild {
    pub fn acquire(config: StorageConfig, checkout: &Path) -> Result<Self, StorageError> {
        let image = std::env::current_exe()
            .map_err(|error| StorageError::io("resolve supervisor image", error))?;
        Self::acquire_with_image(config, checkout, SupervisorImagePin::open(&image)?)
    }

    fn acquire_with_image(
        config: StorageConfig,
        checkout: &Path,
        mut supervisor_image: SupervisorImagePin,
    ) -> Result<Self, StorageError> {
        validate_config(&config)?;
        reject_secret_root(checkout)?;
        let checkout =
            fs::canonicalize(checkout).map_err(|e| StorageError::io("resolve checkout", e))?;
        reject_secret_root(&checkout)?;
        if !checkout.is_dir() {
            return Err(StorageError::new("path", "checkout is not a directory"));
        }
        let output = config
            .output_root
            .clone()
            .map(Ok)
            .unwrap_or_else(default_output_root)?;
        reject_secret_root(&output)?;
        reject_secret_root(&config.evidence_root)?;
        validate_absolute_path(&output)?;
        validate_absolute_path(&config.evidence_root)?;
        reject_overlap(&output, &checkout, "checkout and output root overlap")?;
        reject_overlap(
            &config.evidence_root,
            &checkout,
            "evidence and checkout overlap",
        )?;
        let output = prepare_directory(&output)?;
        reject_overlap(
            &output,
            &checkout,
            "physical checkout and output root overlap",
        )?;
        let catalog_path = output.join("build").join("managed-v1");
        reject_overlap(
            &catalog_path,
            &config.evidence_root,
            "evidence and catalog overlap",
        )?;
        let evidence_root = prepare_directory(&config.evidence_root)?;
        reject_overlap(
            &catalog_path,
            &evidence_root,
            "physical evidence and catalog overlap",
        )?;
        reject_overlap(&checkout, &evidence_root, "evidence and checkout overlap")?;
        let catalog_path = prepare_directory(&catalog_path)?;
        let catalog_file = catalog_path.join("catalog.json");
        let catalog = initialize_catalog(&catalog_path, &catalog_file)?;
        validate_catalog_entries(&catalog_path)?;
        supervisor_image.bind_catalog(&catalog_path, &catalog)?;
        let checkout_digest = digest_bytes(path_identity(&checkout).as_bytes());
        let slot_id = slot_id(&checkout_digest, &config.purpose);
        let token = new_token();
        let lease = LeaseRecord {
            schema: SCHEMA.into(),
            catalog_id: catalog.catalog_id.clone(),
            slot_id: slot_id.clone(),
            token: token.clone(),
            pid: std::process::id(),
            started_ms: now_ms()?,
        };
        let lease_bytes = record_bytes(&lease)?;
        // Any existing lease is busy, even if its PID has disappeared.
        write_new_record(&catalog_path.join("lease.json"), &lease_bytes).map_err(|e| {
            if e.kind == "exists" {
                StorageError::new(
                    "busy",
                    "catalog lease exists; no automatic interrupted-lease adoption",
                )
            } else {
                e
            }
        })?;
        // All errors after acquisition intentionally leave the lease for exact recovery.
        let slots = load_slots(&catalog_path, &catalog)?;
        for (_, record) in &slots {
            if record.state != SlotState::Complete {
                return Err(StorageError::new(
                    "interrupted",
                    "catalog contains an active or interrupted slot",
                ));
            }
        }
        let slots_path = catalog_path.join("slots");
        if !slots_path.exists() {
            create_directory(&slots_path)?;
        }
        let slot_path = slots_path.join(&slot_id);
        let previous = slots.iter().find(|(_, record)| record.slot_id == slot_id);
        if let Some((_, record)) = previous
            && (record.checkout_digest != checkout_digest
                || record.purpose != config.purpose
                || record.os != std::env::consts::OS
                || record.arch != std::env::consts::ARCH)
        {
            return Err(StorageError::new(
                "ownership",
                "fixed slot identity differs from the physical checkout",
            ));
        }
        if slot_path.exists() && previous.is_none() {
            return Err(StorageError::new(
                "ownership",
                "existing slot has no recognized complete ownership record",
            ));
        }
        let mut build = Self {
            paths: build_paths(
                &catalog_path,
                &slot_path,
                &evidence_root.join(&slot_id).join(&token),
            ),
            slot: SlotRecord {
                schema: SCHEMA.into(),
                catalog_id: catalog.catalog_id.clone(),
                slot_id,
                checkout_digest,
                os: std::env::consts::OS.into(),
                arch: std::env::consts::ARCH.into(),
                purpose: config.purpose.clone(),
                token,
                pid: std::process::id(),
                state: SlotState::Active,
                completed_ms: None,
            },
            config,
            catalog,
            lease,
            lease_bytes,
            slot_bytes: Vec::new(),
            supervisor_image,
        };
        // Reclaim recognized, complete caches before admitting this new build.
        build.evict_completed(true)?;
        if !slot_path.exists() {
            create_directory(&slot_path)?;
        }
        for path in [
            slot_path.join("cache"),
            build.paths.cargo_target.clone(),
            build.paths.cargo_home.clone(),
            build.paths.gradle_build.clone(),
            build.paths.gradle_project_cache.clone(),
            build.paths.gradle_user_home.clone(),
            build.paths.scratch.clone(),
        ] {
            prepare_directory(&path)?;
        }
        build.slot_bytes = record_bytes(&build.slot)?;
        atomic_record(&slot_path.join("owner.json"), &build.slot_bytes)?;
        prepare_directory(&build.paths.evidence)?;
        if !build.measure()?.within_budget {
            return Err(StorageError::new(
                "budget",
                "managed slot exceeds byte budget before command admission",
            ));
        }
        Ok(build)
    }

    pub fn adopt_bootstrap(
        config: StorageConfig,
        checkout: &Path,
        expected: BootstrapOwnership,
        drained: bool,
        evidence_exported: bool,
    ) -> Result<Self, StorageError> {
        let image = std::env::current_exe()
            .map_err(|error| StorageError::io("resolve supervisor image", error))?;
        let mut supervisor_image = SupervisorImagePin::open(&image)?;
        validate_config(&config)?;
        if !drained || !evidence_exported {
            return Err(StorageError::new(
                "bootstrap_proof",
                "bootstrap process drain and evidence export must be verified",
            ));
        }
        reject_secret_root(checkout)?;
        let checkout = fs::canonicalize(checkout)
            .map_err(|e| StorageError::io("resolve bootstrap checkout", e))?;
        reject_secret_root(&checkout)?;
        let output = config
            .output_root
            .clone()
            .map(Ok)
            .unwrap_or_else(default_output_root)?;
        reject_secret_root(&output)?;
        reject_secret_root(&config.evidence_root)?;
        validate_absolute_path(&output)?;
        verify_directory(&output)?;
        let output = fs::canonicalize(&output)
            .map_err(|e| StorageError::io("resolve bootstrap output", e))?;
        reject_overlap(&output, &checkout, "bootstrap checkout and output overlap")?;
        let catalog_path = output.join("build/managed-v1");
        verify_directory(&catalog_path)?;
        let checkout_digest = digest_bytes(path_identity(&checkout).as_bytes());
        if expected.schema != SCHEMA
            || expected.checkout_digest != checkout_digest
            || expected.os != std::env::consts::OS
            || expected.arch != std::env::consts::ARCH
            || expected.purpose != config.purpose
            || expected.slot_id != slot_id(&checkout_digest, &config.purpose)
            || !is_digest(&expected.catalog_id)
            || !is_digest(&expected.token)
            || expected.pid == 0
        {
            return Err(StorageError::new(
                "bootstrap_identity",
                "bootstrap identity does not match this checkout and purpose",
            ));
        }
        let catalog: CatalogRecord = read_record(&catalog_path.join("catalog.json"))?;
        if catalog.schema != expected.schema || catalog.catalog_id != expected.catalog_id {
            return Err(StorageError::new(
                "bootstrap_identity",
                "bootstrap catalog identity changed",
            ));
        }
        supervisor_image.bind_catalog(&catalog_path, &catalog)?;
        let lease_bytes = read_record_bytes(&catalog_path.join("lease.json"))?;
        let lease: LeaseRecord = serde_json::from_slice(&lease_bytes)
            .map_err(|e| StorageError::new("record", e.to_string()))?;
        if lease.schema != expected.schema
            || lease.catalog_id != expected.catalog_id
            || lease.slot_id != expected.slot_id
            || lease.token != expected.token
            || lease.pid != expected.pid
            || lease.started_ms != expected.started_ms
        {
            return Err(StorageError::new(
                "bootstrap_identity",
                "bootstrap lease identity changed",
            ));
        }
        let slots = load_slots(&catalog_path, &catalog)?;
        let own = slots
            .iter()
            .find(|(_, record)| record.slot_id == expected.slot_id)
            .ok_or_else(|| StorageError::new("bootstrap_identity", "bootstrap slot is missing"))?;
        if slots
            .iter()
            .any(|(_, r)| r.state == SlotState::Active && r.slot_id != expected.slot_id)
            || own.1.state != SlotState::Active
            || own.1.token != expected.token
            || own.1.pid != expected.pid
            || own.1.checkout_digest != expected.checkout_digest
            || own.1.os != expected.os
            || own.1.arch != expected.arch
            || own.1.purpose != expected.purpose
        {
            return Err(StorageError::new(
                "bootstrap_identity",
                "bootstrap slot identity changed or another active slot exists",
            ));
        }
        validate_absolute_path(&config.evidence_root)?;
        reject_overlap(
            &config.evidence_root,
            &catalog_path,
            "bootstrap evidence and catalog overlap",
        )?;
        reject_overlap(
            &config.evidence_root,
            &checkout,
            "bootstrap evidence and checkout overlap",
        )?;
        let evidence_root = prepare_directory(&config.evidence_root)?;
        reject_overlap(
            &evidence_root,
            &catalog_path,
            "bootstrap evidence and catalog overlap",
        )?;
        reject_overlap(
            &evidence_root,
            &checkout,
            "bootstrap evidence and checkout overlap",
        )?;
        let paths = build_paths(
            &catalog_path,
            &own.0,
            &evidence_root.join(&expected.slot_id).join(&expected.token),
        );
        prepare_directory(&paths.evidence)?;
        let mut build = Self {
            config,
            paths,
            catalog,
            lease,
            lease_bytes,
            slot: own.1.clone(),
            slot_bytes: read_record_bytes(&own.0.join("owner.json"))?,
            supervisor_image,
        };
        build.verify_ownership()?;
        // A crash between these atomic records remains an interrupted, preserved lease.
        let token = new_token();
        build.lease.token = token.clone();
        build.lease.pid = std::process::id();
        build.lease.started_ms = now_ms()?;
        build.lease_bytes = record_bytes(&build.lease)?;
        atomic_record(&build.paths.catalog.join("lease.json"), &build.lease_bytes)?;
        build.slot.token = token;
        build.slot.pid = std::process::id();
        build.slot_bytes = record_bytes(&build.slot)?;
        atomic_record(&build.paths.slot.join("owner.json"), &build.slot_bytes)?;
        if !build.measure()?.within_budget {
            return Err(StorageError::new(
                "budget",
                "bootstrap slot exceeds byte budget before managed admission",
            ));
        }
        Ok(build)
    }

    pub fn paths(&self) -> &BuildPaths {
        &self.paths
    }

    /// Recheck this already acquired owner's exact lease and slot records.
    /// This bounded checkpoint neither scans generated trees nor acquires or
    /// adopts another lease. Native filesystem calls remain cooperative.
    pub fn check_current_ownership(&self) -> Result<(), StorageError> {
        self.verify_ownership()
    }

    pub fn environment(&self) -> BTreeMap<String, String> {
        let mut result = BTreeMap::new();
        for (key, path) in [
            ("CARGO_TARGET_DIR", &self.paths.cargo_target),
            ("CARGO_HOME", &self.paths.cargo_home),
            ("GRADLE_USER_HOME", &self.paths.gradle_user_home),
            ("TMP", &self.paths.scratch),
            ("TEMP", &self.paths.scratch),
            ("TMPDIR", &self.paths.scratch),
        ] {
            result.insert(key.into(), path.to_string_lossy().into_owned());
        }
        result.insert("CARGO_INCREMENTAL".into(), "0".into());
        result
    }

    pub fn validate_environment_overrides(&self) -> Result<(), StorageError> {
        for (key, value) in self.environment() {
            // OS temp defaults are inherited context, then intentionally overridden
            // for a child. User-supplied temp overrides are checked separately.
            if ["TMP", "TEMP", "TMPDIR"].contains(&key.as_str()) {
                continue;
            }
            if let Some(existing) = std::env::var_os(&key)
                && !self.environment_override_matches(&key, &existing, &value)?
            {
                return Err(StorageError::new(
                    "override",
                    format!("conflicting managed environment override: {key}"),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_explicit_overrides(
        &self,
        overrides: &BTreeMap<String, String>,
    ) -> Result<(), StorageError> {
        for (key, managed_value) in self.environment() {
            if let Some(value) = overrides.get(&key)
                && !self.environment_override_matches(
                    &key,
                    std::ffi::OsStr::new(value),
                    &managed_value,
                )?
            {
                return Err(StorageError::new(
                    "override",
                    format!("conflicting explicit managed environment override: {key}"),
                ));
            }
        }
        Ok(())
    }

    fn environment_override_matches(
        &self,
        key: &str,
        value: &std::ffi::OsStr,
        managed: &str,
    ) -> Result<bool, StorageError> {
        if key == "CARGO_INCREMENTAL" {
            return Ok(value == std::ffi::OsStr::new(managed));
        }
        let path = Path::new(value);
        validate_absolute_path(path)?;
        if !path.exists() {
            return Ok(false);
        }
        verify_directory(path)?;
        let physical = fs::canonicalize(path)
            .map_err(|e| StorageError::io("resolve explicit environment path", e))?;
        Ok(path_identity(&physical) == path_identity(Path::new(managed)))
    }

    pub fn measure(&self) -> Result<Measurement, StorageError> {
        self.measure_with(|_| {})
    }

    pub fn measure_with_progress(
        &self,
        progress: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Measurement, StorageError> {
        self.measure_observed(|_| {}, progress)
    }

    /// Explicit Running-only opt-in. Existing pre-spawn, finish and other
    /// callers retain one-attempt observation. Extra target metadata calls are
    /// bounded across this complete measurement; ancestry/owner checks retain
    /// their existing finite traversal limits and caller checkpoints.
    pub fn measure_with_progress_and_diagnostics(
        &self,
        progress: &mut dyn FnMut() -> Result<(), String>,
        diagnostics: &mut ObservationRetryLog,
    ) -> Result<Measurement, StorageError> {
        let owner = || self.verify_ownership();
        let mut metadata = |path: &Path| fs::symlink_metadata(path);
        let mut wait = std::thread::sleep;
        let clock = Instant::now;
        let mut retry = MetadataReobservation::new(
            diagnostics,
            &owner,
            &mut metadata,
            &mut wait,
            cfg!(windows),
            &clock,
        );
        self.measure_observed_retry(|_| {}, progress, Some(&mut retry))
    }

    fn measure_with(
        &self,
        before_metadata: impl FnMut(&Path),
    ) -> Result<Measurement, StorageError> {
        self.measure_observed(before_metadata, &mut || Ok(()))
    }

    fn measure_observed(
        &self,
        mut before_metadata: impl FnMut(&Path),
        progress: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Measurement, StorageError> {
        self.measure_observed_retry(&mut before_metadata, progress, None)
    }

    fn measure_observed_retry(
        &self,
        mut before_metadata: impl FnMut(&Path),
        progress: &mut dyn FnMut() -> Result<(), String>,
        mut retry: Option<&mut MetadataReobservation<'_>>,
    ) -> Result<Measurement, StorageError> {
        observation_checkpoint(progress)?;
        self.verify_ownership()?;
        observation_checkpoint(progress)?;
        let observation_roots = self.observation_roots();
        self.verify_observation_roots(&observation_roots)?;
        observation_checkpoint(progress)?;
        let mut slot_bytes = None;
        let mut catalog_bytes = 0u64;
        let slots = load_slots_with_progress(&self.paths.catalog, &self.catalog, progress)?;
        self.validate_active_slots(&slots)?;
        observation_checkpoint(progress)?;
        for (path, record) in slots {
            observation_checkpoint(progress)?;
            let size = if record.slot_id == self.slot.slot_id && record.state == SlotState::Active {
                tree_bytes_observed_with_retry(
                    &path,
                    &path,
                    &observation_roots,
                    &mut before_metadata,
                    progress,
                    retry.as_deref_mut(),
                )?
            } else {
                tree_bytes_observed_with_progress(&path, &path, &[], |_| {}, progress)?
            };
            if record.slot_id == self.slot.slot_id {
                slot_bytes = Some(size);
            }
            catalog_bytes = checked_sum(catalog_bytes, size)?;
        }
        // Ephemeral entries may disappear during a finite observation. Fixed
        // roots and ownership records must still be intact when it completes.
        observation_checkpoint(progress)?;
        self.verify_observation_roots(&observation_roots)?;
        observation_checkpoint(progress)?;
        self.verify_ownership()?;
        observation_checkpoint(progress)?;
        let slot_bytes = slot_bytes.ok_or_else(|| {
            StorageError::new("ownership", "owned slot disappeared during measurement")
        })?;
        Ok(Measurement {
            slot_bytes,
            catalog_bytes,
            within_budget: slot_bytes <= self.config.budgets.slot_bytes
                && catalog_bytes <= self.config.budgets.catalog_bytes,
        })
    }

    fn observation_roots(&self) -> [PathBuf; 6] {
        [
            self.paths.cargo_target.clone(),
            self.paths.cargo_home.clone(),
            self.paths.gradle_build.clone(),
            self.paths.gradle_project_cache.clone(),
            self.paths.gradle_user_home.clone(),
            self.paths.scratch.clone(),
        ]
    }

    fn verify_observation_roots(&self, roots: &[PathBuf]) -> Result<(), StorageError> {
        verify_directory(&self.paths.slot.join("cache"))?;
        for root in roots {
            verify_directory(root)?;
        }
        Ok(())
    }

    pub fn finish(mut self, outcome: FinishOutcome) -> Result<FinishReceipt, StorageError> {
        self.verify_ownership()?;
        self.supervisor_image.recheck()?;
        if !outcome.drained {
            return Err(StorageError::new(
                "undrained",
                "process drain is unverified; slot and lease preserved",
            ));
        }
        if !outcome.evidence_exported {
            return Err(StorageError::new(
                "evidence",
                "required evidence export is unverified; slot and lease preserved",
            ));
        }
        let observed = self.measure()?;
        let mut receipt = FinishReceipt {
            schema: SCHEMA,
            slot_id: self.slot.slot_id.clone(),
            command_exit: outcome.command_exit,
            supervisor_errors: outcome.supervisor_errors,
            cleanup_errors: Vec::new(),
            scratch_removed: false,
            slot_evicted: false,
            evicted_completed_slots: Vec::new(),
            observed_slot_bytes: observed.slot_bytes,
            observed_catalog_bytes: observed.catalog_bytes,
            lease_released: false,
        };
        if let Err(error) = self.remove_owned_scratch() {
            receipt.cleanup_errors.push(error.to_string());
            self.write_receipt(&receipt)?;
            return Ok(receipt);
        }
        receipt.scratch_removed = true;
        self.slot.state = SlotState::Complete;
        self.slot.completed_ms = Some(now_ms()?);
        self.slot_bytes = record_bytes(&self.slot)?;
        atomic_record(&self.paths.slot.join("owner.json"), &self.slot_bytes)?;
        match self.evict_completed(true) {
            Ok(removed) => {
                receipt.slot_evicted = removed.contains(&self.slot.slot_id);
                receipt.evicted_completed_slots = removed;
            }
            Err(error) => {
                receipt.cleanup_errors.push(error.to_string());
                self.write_receipt(&receipt)?;
                return Ok(receipt);
            }
        }
        // Persist a receipt before releasing the exclusive lease.
        self.write_receipt(&receipt)?;
        self.verify_lease()?;
        fs::remove_file(self.paths.catalog.join("lease.json"))
            .map_err(|e| StorageError::io("release catalog lease", e))?;
        sync_directory(&self.paths.catalog)?;
        receipt.lease_released = true;
        self.write_receipt(&receipt)?;
        Ok(receipt)
    }

    fn write_receipt(&self, receipt: &FinishReceipt) -> Result<(), StorageError> {
        let bytes = serde_json::to_vec_pretty(receipt)
            .map_err(|e| StorageError::new("record", e.to_string()))?;
        // Identity fields contain no checkout or local absolute paths. Error
        // diagnostics are local evidence; shared exports must redact paths.
        atomic_record(&self.paths.evidence.join("finish.json"), &bytes)
    }

    fn verify_lease(&self) -> Result<(), StorageError> {
        verify_directory(&self.paths.catalog)?;
        let current: CatalogRecord = read_record(&self.paths.catalog.join("catalog.json"))?;
        if current.schema != SCHEMA || current.catalog_id != self.catalog.catalog_id {
            return Err(StorageError::new("ownership", "catalog ownership changed"));
        }
        verify_record_bytes(&self.paths.catalog.join("lease.json"), &self.lease_bytes)?;
        validate_catalog_entries(&self.paths.catalog)
    }

    fn verify_ownership(&self) -> Result<(), StorageError> {
        self.verify_lease()?;
        verify_directory(&self.paths.catalog.join("slots"))?;
        verify_directory(&self.paths.slot)?;
        verify_record_bytes(&self.paths.slot.join("owner.json"), &self.slot_bytes)?;
        validate_slot_entries(&self.paths.slot)
    }

    fn remove_owned_scratch(&self) -> Result<(), StorageError> {
        self.verify_ownership()?;
        remove_tree(
            &self.paths.scratch,
            &self.paths.slot,
            &self.paths.slot.join("owner.json"),
            &self.slot_bytes,
            &|| self.verify_lease(),
        )
    }

    fn evict_completed(&self, include_current: bool) -> Result<Vec<String>, StorageError> {
        self.verify_lease()?;
        self.supervisor_image.recheck()?;
        let mut slots = load_slots(&self.paths.catalog, &self.catalog)?;
        self.validate_active_slots(&slots)?;
        if let Some(protected) = &self.supervisor_image.slot_id
            && !slots.iter().any(|(_, record)| &record.slot_id == protected)
        {
            return Err(StorageError::new(
                "supervisor_image",
                "supervisor image slot ownership disappeared",
            ));
        }
        slots.sort_by_key(|(_, r)| (r.completed_ms.unwrap_or(u64::MAX), r.slot_id.clone()));
        let mut sizes = BTreeMap::new();
        let mut total = 0u64;
        let mut completed = 0usize;
        for (path, record) in &slots {
            let size = tree_bytes(path, path)?;
            sizes.insert(record.slot_id.clone(), size);
            total = checked_sum(total, size)?;
            completed += usize::from(record.state == SlotState::Complete);
        }
        let mut removed = Vec::new();
        // 부족이 이미 확정되면 다른 cache도 지우지 않고 원 lease와 모든 slot을 보존한다.
        let selected = plan_completed_evictions(
            &slots,
            &sizes,
            &self.config.budgets,
            &self.slot.slot_id,
            include_current,
            self.supervisor_image.slot_id.as_deref(),
        )?;
        let protected_size = self
            .supervisor_image
            .slot_id
            .as_ref()
            .and_then(|slot| sizes.get(slot))
            .copied();
        for (path, record) in slots {
            if !selected.contains(&record.slot_id) {
                continue;
            }
            let size = sizes[&record.slot_id];
            self.verify_lease()?;
            let expected = read_record_bytes(&path.join("owner.json"))?;
            let fresh: SlotRecord = serde_json::from_slice(&expected)
                .map_err(|e| StorageError::new("record", e.to_string()))?;
            if fresh.token != record.token
                || fresh.state != SlotState::Complete
                || fresh.catalog_id != self.catalog.catalog_id
            {
                return Err(StorageError::new(
                    "ownership",
                    "completed slot ownership changed before eviction",
                ));
            }
            validate_slot_record(&fresh, &record.slot_id, &self.catalog)?;
            validate_slot_entries(&path)?;
            verify_record_bytes(&path.join("owner.json"), &expected)?;
            self.supervisor_image.recheck()?;
            remove_tree(
                &path,
                &self.paths.catalog.join("slots"),
                &path.join("owner.json"),
                &expected,
                &|| self.verify_lease(),
            )?;
            self.supervisor_image.recheck()?;
            total = total.saturating_sub(size);
            completed = completed.saturating_sub(1);
            removed.push(record.slot_id);
        }
        if total > self.config.budgets.catalog_bytes
            || completed > self.config.budgets.completed_slots
            || protected_size.is_some_and(|size| size > self.config.budgets.slot_bytes)
        {
            return Err(StorageError::new(
                if protected_size.is_some() {
                    "eviction_blocked"
                } else {
                    "budget"
                },
                "managed limits cannot be met without removing a protected or ineligible slot",
            ));
        }
        Ok(removed)
    }

    fn validate_active_slots(&self, slots: &[(PathBuf, SlotRecord)]) -> Result<(), StorageError> {
        let active: Vec<_> = slots
            .iter()
            .filter(|(_, r)| r.state == SlotState::Active)
            .collect();
        if active.len() > 1
            || active.iter().any(|(_, record)| {
                record.token != self.lease.token
                    || record.slot_id != self.lease.slot_id
                    || record.pid != self.lease.pid
            })
        {
            return Err(StorageError::new(
                "interrupted",
                "foreign or additional active slot cannot be adopted or reclaimed",
            ));
        }
        Ok(())
    }
}

pub fn default_output_root() -> Result<PathBuf, StorageError> {
    let required = |name: &str| {
        std::env::var_os(name).map(PathBuf::from).ok_or_else(|| {
            StorageError::new("environment", format!("missing platform root: {name}"))
        })
    };
    if let Some(value) = std::env::var_os("RUNNER_TEMP") {
        return Ok(PathBuf::from(value).join("MMMM"));
    }
    if cfg!(target_os = "windows") {
        return Ok(required("APPDATA")?.join("MMMM"));
    }
    if cfg!(target_os = "macos") {
        return Ok(required("HOME")?.join("Library/Caches/MMMM"));
    }
    if let Some(value) = std::env::var_os("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(value).join("mmmm"));
    }
    Ok(required("HOME")?.join(".cache/mmmm"))
}

fn validate_config(config: &StorageConfig) -> Result<(), StorageError> {
    if config.purpose.is_empty()
        || config.purpose.len() > 48
        || !config
            .purpose
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(StorageError::new(
            "purpose",
            "purpose must be 1..48 lowercase ASCII letters, digits or hyphens",
        ));
    }
    if config.budgets.slot_bytes == 0
        || config.budgets.catalog_bytes == 0
        || config.budgets.slot_bytes > config.budgets.catalog_bytes
        || config.budgets.active_slots != 1
    {
        return Err(StorageError::new(
            "budget",
            "positive byte budgets and exactly one active catalog slot are required",
        ));
    }
    Ok(())
}

fn build_paths(catalog: &Path, slot: &Path, evidence: &Path) -> BuildPaths {
    let cache = slot.join("cache");
    BuildPaths {
        catalog: catalog.into(),
        slot: slot.into(),
        cargo_target: cache.join("cargo-target"),
        cargo_home: cache.join("cargo-home"),
        gradle_build: cache.join("gradle-build"),
        gradle_project_cache: cache.join("gradle-project-cache"),
        gradle_user_home: cache.join("gradle-user-home"),
        scratch: slot.join("scratch"),
        evidence: evidence.into(),
    }
}

fn slot_id(checkout_digest: &str, purpose: &str) -> String {
    format!(
        "{}-{}-{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        &checkout_digest[..24],
        purpose
    )
}

fn validate_catalog_entries(path: &Path) -> Result<(), StorageError> {
    for entry in fs::read_dir(path).map_err(|e| StorageError::io("read catalog entries", e))? {
        let entry = entry.map_err(|e| StorageError::io("read catalog entry", e))?;
        let name = entry.file_name();
        if !["catalog.json", "lease.json", "slots"]
            .iter()
            .any(|s| name == std::ffi::OsStr::new(s))
        {
            return Err(StorageError::new(
                "unknown",
                "unknown catalog entry is preserved",
            ));
        }
        reject_link(&entry.path())?;
    }
    Ok(())
}

fn initialize_catalog(root: &Path, path: &Path) -> Result<CatalogRecord, StorageError> {
    if path.exists() {
        let record: CatalogRecord = read_record(path)?;
        if record.schema != SCHEMA || !is_digest(&record.catalog_id) {
            return Err(StorageError::new(
                "record",
                "unknown catalog ownership schema or identity",
            ));
        }
        return Ok(record);
    }
    if fs::read_dir(root)
        .map_err(|e| StorageError::io("inspect new catalog", e))?
        .next()
        .is_some()
    {
        return Err(StorageError::new(
            "unknown",
            "unowned nonempty catalog is preserved",
        ));
    }
    let record = CatalogRecord {
        schema: SCHEMA.into(),
        catalog_id: new_token(),
    };
    write_new_record(path, &record_bytes(&record)?)?;
    Ok(record)
}

fn load_slots(
    catalog_path: &Path,
    catalog: &CatalogRecord,
) -> Result<Vec<(PathBuf, SlotRecord)>, StorageError> {
    load_slots_with_progress(catalog_path, catalog, &mut || Ok(()))
}

fn load_slots_with_progress(
    catalog_path: &Path,
    catalog: &CatalogRecord,
    progress: &mut dyn FnMut() -> Result<(), String>,
) -> Result<Vec<(PathBuf, SlotRecord)>, StorageError> {
    observation_checkpoint(progress)?;
    validate_catalog_entries(catalog_path)?;
    observation_checkpoint(progress)?;
    let slots_path = catalog_path.join("slots");
    if !slots_path.exists() {
        return Ok(Vec::new());
    }
    verify_directory(&slots_path)?;
    observation_checkpoint(progress)?;
    let mut slots = Vec::new();
    let mut directory = fs::read_dir(&slots_path).map_err(|e| StorageError::io("read slots", e))?;
    loop {
        observation_checkpoint(progress)?;
        let entry = directory.next();
        observation_checkpoint(progress)?;
        let Some(entry) = entry else { break };
        if slots.len() >= MAX_ENTRIES {
            return Err(StorageError::new("walk_limit", "too many managed slots"));
        }
        let entry = entry.map_err(|e| StorageError::io("read slot", e))?;
        let path = entry.path();
        verify_directory(&path)?;
        observation_checkpoint(progress)?;
        let slot_id = entry
            .file_name()
            .into_string()
            .map_err(|_| StorageError::new("path", "slot name is not UTF-8"))?;
        let record: SlotRecord = read_record(&path.join("owner.json"))?;
        observation_checkpoint(progress)?;
        validate_slot_record(&record, &slot_id, catalog)?;
        validate_slot_entries(&path)?;
        observation_checkpoint(progress)?;
        let scratch = path.join("scratch");
        if record.state == SlotState::Complete
            && scratch.exists()
            && fs::read_dir(&scratch)
                .map_err(|e| StorageError::io("inspect completed scratch", e))?
                .next()
                .is_some()
        {
            return Err(StorageError::new(
                "interrupted",
                "completed slot has unexplained residual scratch; preserved",
            ));
        }
        observation_checkpoint(progress)?;
        slots.push((path, record));
    }
    Ok(slots)
}

fn validate_slot_record(
    record: &SlotRecord,
    directory: &str,
    catalog: &CatalogRecord,
) -> Result<(), StorageError> {
    let expected = format!(
        "{}-{}-{}-{}",
        record.os,
        record.arch,
        record.checkout_digest.get(..24).unwrap_or(""),
        record.purpose
    );
    if record.schema != SCHEMA
        || record.catalog_id != catalog.catalog_id
        || record.slot_id != directory
        || expected != directory
        || !is_digest(&record.checkout_digest)
        || !is_digest(&record.token)
        || record.pid == 0
        || record.purpose.is_empty()
        || record.purpose.len() > 48
        || !record
            .purpose
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || (record.state == SlotState::Complete) != record.completed_ms.is_some()
    {
        return Err(StorageError::new(
            "ownership",
            "invalid or inconsistent slot ownership record",
        ));
    }
    Ok(())
}

fn validate_slot_entries(path: &Path) -> Result<(), StorageError> {
    for entry in fs::read_dir(path).map_err(|e| StorageError::io("read slot entries", e))? {
        let entry = entry.map_err(|e| StorageError::io("read slot entry", e))?;
        let name = entry.file_name();
        if !["owner.json", "cache", "scratch"]
            .iter()
            .any(|s| name == std::ffi::OsStr::new(s))
        {
            return Err(StorageError::new(
                "unknown",
                "unknown slot entry is preserved",
            ));
        }
        reject_link(&entry.path())?;
    }
    let cache = path.join("cache");
    if cache.exists() {
        verify_directory(&cache)?;
        for entry in fs::read_dir(&cache).map_err(|e| StorageError::io("read cache roots", e))? {
            let entry = entry.map_err(|e| StorageError::io("read cache root", e))?;
            if ![
                "cargo-target",
                "cargo-home",
                "gradle-build",
                "gradle-project-cache",
                "gradle-user-home",
            ]
            .iter()
            .any(|s| entry.file_name() == std::ffi::OsStr::new(s))
            {
                return Err(StorageError::new(
                    "unknown",
                    "unknown cache root is preserved",
                ));
            }
            verify_directory(&entry.path())?;
        }
    }
    Ok(())
}

fn read_record<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, StorageError> {
    let bytes = read_record_bytes(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| StorageError::new("record", format!("invalid ownership record: {e}")))
}

fn read_record_bytes(path: &Path) -> Result<Vec<u8>, StorageError> {
    reject_secret_path(path)?;
    reject_link(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|e| StorageError::io("inspect ownership record", e))?;
    if !metadata.is_file() || metadata.len() > RECORD_LIMIT {
        return Err(StorageError::new(
            "record",
            "ownership record must be regular and at most 8 KiB",
        ));
    }
    let file = open_record_without_following(path)?;
    let opened = file
        .metadata()
        .map_err(|e| StorageError::io("inspect open ownership record", e))?;
    if !opened.is_file() || is_link(&opened) || opened.len() > RECORD_LIMIT {
        return Err(StorageError::new(
            "record",
            "opened ownership record is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(RECORD_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| StorageError::io("read ownership record", e))?;
    if bytes.len() as u64 > RECORD_LIMIT {
        return Err(StorageError::new(
            "record",
            "ownership record grew beyond limit",
        ));
    }
    Ok(bytes)
}

fn open_record_without_following(path: &Path) -> Result<File, StorageError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options
            .open(path)
            .map_err(|e| StorageError::io("open non-following ownership record", e))?;
        if file
            .metadata()
            .map_err(|e| StorageError::io("inspect record links", e))?
            .nlink()
            != 1
        {
            return Err(StorageError::new(
                "link",
                "multiply-linked ownership record is preserved",
            ));
        }
        Ok(file)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT, GetFileInformationByHandle,
        };
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options
            .open(path)
            .map_err(|e| StorageError::io("open non-following ownership record", e))?;
        // SAFETY: the owned File handle remains alive and the zeroed native
        // information buffer is writable for this synchronous metadata query.
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
        if ok == 0 {
            return Err(StorageError::io(
                "inspect record links",
                std::io::Error::last_os_error(),
            ));
        }
        if information.nNumberOfLinks != 1 {
            return Err(StorageError::new(
                "link",
                "multiply-linked ownership record is preserved",
            ));
        }
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        options
            .open(path)
            .map_err(|e| StorageError::io("open ownership record", e))
    }
}

fn record_bytes<T: Serialize>(record: &T) -> Result<Vec<u8>, StorageError> {
    let bytes =
        serde_json::to_vec(record).map_err(|e| StorageError::new("record", e.to_string()))?;
    if bytes.len() as u64 > RECORD_LIMIT {
        return Err(StorageError::new("record", "record exceeds 8 KiB"));
    }
    Ok(bytes)
}

fn verify_record_bytes(path: &Path, expected: &[u8]) -> Result<(), StorageError> {
    if read_record_bytes(path)? != expected {
        return Err(StorageError::new(
            "ownership",
            "ownership record changed; lease and files preserved",
        ));
    }
    Ok(())
}

fn write_new_record(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.len() as u64 > RECORD_LIMIT {
        return Err(StorageError::new("record", "record exceeds 8 KiB"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                StorageError::new("exists", "owned record already exists")
            } else {
                StorageError::io("create ownership record", e)
            }
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| StorageError::io("flush ownership record", e))?;
    sync_directory(
        path.parent()
            .ok_or_else(|| StorageError::new("path", "record has no parent"))?,
    )
}

fn atomic_record(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let parent = path
        .parent()
        .ok_or_else(|| StorageError::new("path", "record has no parent"))?;
    verify_directory(parent)?;
    if path.exists() {
        reject_link(path)?;
    }
    let temporary = parent.join(format!(".record-{}.tmp", new_token()));
    write_new_record(&temporary, bytes)?;
    fs::rename(&temporary, path).map_err(|e| StorageError::io("atomic record replacement", e))?;
    sync_directory(parent)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), StorageError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| StorageError::io("flush directory", e))
}
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), StorageError> {
    // Record handles use sync_all. Portable Windows directory handles do not support fsync.
    Ok(())
}

fn validate_absolute_path(path: &Path) -> Result<(), StorageError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(StorageError::new(
            "path",
            "absolute paths without parent/current components are required",
        ));
    }
    reject_secret_path(path)
}

fn reject_secret_path(path: &Path) -> Result<(), StorageError> {
    for component in path.components() {
        if let Component::Normal(name) = component {
            let name = name.to_string_lossy().to_ascii_lowercase();
            if name == ".env"
                || name.starts_with(".env.")
                || name == ".ssh"
                || name == "id_rsa"
                || name == "id_ed25519"
                || ([
                    "credential",
                    "service-account",
                    "service_account",
                    "api-key",
                    "api_key",
                ]
                .iter()
                .any(|marker| name.contains(marker))
                    && [".json", ".toml", ".yaml", ".yml", ".pem", ".key"]
                        .iter()
                        .any(|suffix| name.ends_with(suffix)))
            {
                return Err(StorageError::new(
                    "secret_path",
                    "secret-named path is not inspected or managed",
                ));
            }
        }
    }
    Ok(())
}

fn reject_secret_root(path: &Path) -> Result<(), StorageError> {
    reject_secret_path(path)?;
    if path.components().any(|component| match component {
        Component::Normal(name) => {
            let name = name.to_string_lossy().to_ascii_lowercase();
            [
                "credential",
                "service-account",
                "service_account",
                "api-key",
                "api_key",
            ]
            .iter()
            .any(|marker| name.contains(marker))
        }
        _ => false,
    }) {
        return Err(StorageError::new(
            "secret_path",
            "secret-named input root is not managed",
        ));
    }
    Ok(())
}

fn reject_secret_leaf_file(path: &Path) -> Result<(), StorageError> {
    reject_secret_path(path)?;
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    if [
        "credentials",
        "credential",
        "api-key",
        "api_key",
        "api-keys",
        "api_keys",
        "private-key",
    ]
    .contains(&name.as_str())
    {
        return Err(StorageError::new(
            "secret_path",
            "secret file entry is not inspected or removed",
        ));
    }
    Ok(())
}

fn reject_overlap(first: &Path, second: &Path, message: &str) -> Result<(), StorageError> {
    let first = path_identity(first);
    let second = path_identity(second);
    let within = |child: &str, parent: &str| {
        child == parent
            || child
                .strip_prefix(parent)
                .is_some_and(|tail| tail.starts_with(std::path::MAIN_SEPARATOR))
    };
    if within(&first, &second) || within(&second, &first) {
        return Err(StorageError::new("overlap", message));
    }
    Ok(())
}

fn path_identity(path: &Path) -> String {
    let raw = path
        .to_string_lossy()
        .trim_end_matches(std::path::MAIN_SEPARATOR)
        .to_string();
    #[cfg(windows)]
    {
        let normalized = raw.replace('/', "\\");
        let normalized = normalized.trim_end_matches('\\');
        if let Some(tail) = normalized.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{tail}").to_lowercase()
        } else {
            normalized.trim_start_matches(r"\\?\").to_lowercase()
        }
    }
    #[cfg(not(windows))]
    {
        raw
    }
}

fn prepare_directory(path: &Path) -> Result<PathBuf, StorageError> {
    validate_absolute_path(path)?;
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(_) => verify_directory(&current)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_directory(&current)?,
            Err(e) => return Err(StorageError::io("inspect directory ancestry", e)),
        }
    }
    fs::canonicalize(path).map_err(|e| StorageError::io("resolve managed directory", e))
}

fn create_directory(path: &Path) -> Result<(), StorageError> {
    fs::create_dir(path).map_err(|e| StorageError::io("create managed directory", e))?;
    verify_directory(path)
}

fn verify_directory(path: &Path) -> Result<(), StorageError> {
    reject_secret_path(path)?;
    // Check all existing ancestry, including a replaced parent junction.
    for ancestor in path.ancestors() {
        if !ancestor.as_os_str().is_empty() {
            reject_link(ancestor)?;
        }
    }
    if !fs::symlink_metadata(path)
        .map_err(|e| StorageError::io("inspect managed directory", e))?
        .is_dir()
    {
        return Err(StorageError::new(
            "path",
            "managed directory changed file type",
        ));
    }
    Ok(())
}

fn is_link(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn link_is_directory(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x10 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.is_dir()
    }
}

fn reject_link(path: &Path) -> Result<(), StorageError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| StorageError::io("inspect link boundary", e))?;
    if is_link(&metadata) {
        return Err(StorageError::new(
            "link",
            "managed root or ownership record is a link/reparse point",
        ));
    }
    Ok(())
}

fn tree_bytes(path: &Path, boundary: &Path) -> Result<u64, StorageError> {
    tree_bytes_observed(path, boundary, &[], |_| {})
}

fn tree_bytes_observed(
    path: &Path,
    boundary: &Path,
    ephemeral_roots: &[PathBuf],
    before_metadata: impl FnMut(&Path),
) -> Result<u64, StorageError> {
    tree_bytes_observed_with_progress(
        path,
        boundary,
        ephemeral_roots,
        before_metadata,
        &mut || Ok(()),
    )
}

fn observation_checkpoint(
    progress: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), StorageError> {
    progress().map_err(|cause| StorageError::new("observation_failed", cause))
}

struct MetadataReobservation<'a> {
    diagnostics: &'a mut ObservationRetryLog,
    owner: &'a dyn Fn() -> Result<(), StorageError>,
    metadata: &'a mut dyn FnMut(&Path) -> std::io::Result<fs::Metadata>,
    wait: &'a mut dyn FnMut(Duration),
    windows_native5: bool,
    clock: &'a dyn Fn() -> Instant,
    extra_calls: usize,
    planned_wait: Duration,
    spent: Duration,
}
impl<'a> MetadataReobservation<'a> {
    fn new(
        diagnostics: &'a mut ObservationRetryLog,
        owner: &'a dyn Fn() -> Result<(), StorageError>,
        metadata: &'a mut dyn FnMut(&Path) -> std::io::Result<fs::Metadata>,
        wait: &'a mut dyn FnMut(Duration),
        windows_native5: bool,
        clock: &'a dyn Fn() -> Instant,
    ) -> Self {
        Self {
            diagnostics,
            owner,
            metadata,
            wait,
            windows_native5,
            clock,
            extra_calls: 0,
            planned_wait: Duration::ZERO,
            spent: Duration::ZERO,
        }
    }
    fn checkpoint(
        &self,
        progress: &mut dyn FnMut() -> Result<(), String>,
        started: Instant,
    ) -> Result<(), StorageError> {
        observation_checkpoint(progress)?;
        if self
            .spent
            .saturating_add((self.clock)().saturating_duration_since(started))
            >= MAX_RETRY_WALL
        {
            return Err(StorageError::new(
                "retry_budget",
                "metadata reobservation wall budget exceeded",
            ));
        }
        Ok(())
    }
    fn guard(
        &self,
        path: &Path,
        root: &Path,
        progress: &mut dyn FnMut() -> Result<(), String>,
        started: Instant,
    ) -> Result<(), StorageError> {
        self.checkpoint(progress, started)?;
        (self.owner)()?;
        self.checkpoint(progress, started)?;
        verify_retry_ancestry(path, root, progress)?;
        self.checkpoint(progress, started)?;
        (self.owner)()?;
        self.checkpoint(progress, started)
    }
    fn observe(
        &mut self,
        path: &Path,
        boundary: &Path,
        roots: &[PathBuf],
        progress: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Option<fs::Metadata>, StorageError> {
        // Preserve the existing directory namespace policy (for example a
        // public source namespace named Credentials). Lexically secret paths
        // are rejected before the first metadata call; ambiguous reserved leaf
        // names are never admitted to the new reobservation path.
        reject_secret_path(path)?;
        let first = match (self.metadata)(path) {
            Ok(metadata) => return Ok(Some(metadata)),
            Err(error) => error,
        };
        let root = roots
            .iter()
            .find(|root| path != root.as_path() && path.starts_with(root));
        if first.kind() == std::io::ErrorKind::NotFound && root.is_some() {
            return match self.vanished(path, boundary, roots, &first, "entry_metadata", progress)? {
                VanishedEntryObservation::MissingValidated => Ok(None),
                VanishedEntryObservation::Present(metadata) => Ok(Some(metadata)),
                VanishedEntryObservation::Ineligible => Err(measurement_io_error(
                    "managed entry metadata",
                    path,
                    boundary,
                    first,
                )),
            };
        }
        // Native Win32 5 has PermissionDenied semantics on Windows. Tests may
        // inject that native code on another OS without changing production.
        if !self.windows_native5 || first.raw_os_error() != Some(5) || root.is_none() {
            if vanished_ephemeral_entry(path, &first, roots)? {
                return Ok(None);
            }
            return Err(measurement_io_error(
                "managed entry metadata",
                path,
                boundary,
                first,
            ));
        }
        let root = root.expect("strict descendant was selected above");
        self.recorded_reobserve(path, boundary, root, &first, None, progress)
    }
    fn vanished(
        &mut self,
        path: &Path,
        boundary: &Path,
        roots: &[PathBuf],
        first: &std::io::Error,
        stage: &'static str,
        progress: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<VanishedEntryObservation, StorageError> {
        let trigger = ObservationNotFoundTrigger {
            stage,
            first: NativeIoDiagnostic::from_error(first),
            generated_relative: generated_entry_context(String::new(), path, boundary),
        };
        observation_checkpoint(progress)?;
        (self.owner)()?;
        let observed = vanished_ephemeral_observation_with_progress(
            path,
            first,
            roots,
            progress,
            &mut |component, root, progress| {
                match (self.metadata)(component) {
                    Ok(metadata) => Ok(Some(metadata)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(error) if self.windows_native5 && error.raw_os_error() == Some(5) => {
                        // Only this strict descendant component enters the existing shared
                        // budget. Its nested missing proof remains one-attempt, not recursive.
                        self.recorded_reobserve(
                            component,
                            boundary,
                            root,
                            &error,
                            Some(trigger.clone()),
                            progress,
                        )
                    }
                    Err(error) => Err(measurement_io_error(
                        "vanished-entry surviving ancestry",
                        component,
                        boundary,
                        error,
                    )),
                }
            },
        )?;
        observation_checkpoint(progress)?;
        (self.owner)()?;
        observation_checkpoint(progress)?;
        Ok(observed)
    }
    fn recorded_reobserve(
        &mut self,
        path: &Path,
        boundary: &Path,
        root: &Path,
        first: &std::io::Error,
        not_found_trigger: Option<ObservationNotFoundTrigger>,
        progress: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Option<fs::Metadata>, StorageError> {
        let started = (self.clock)();
        let mut record = ObservationRetryRecord {
            stage: if not_found_trigger.is_some() {
                "vanished_ancestry_metadata"
            } else {
                "entry_metadata"
            },
            first: NativeIoDiagnostic::from_error(first),
            attempts: 1,
            elapsed_ms: 0,
            final_observation: RetryFinalObservation::Pending,
            generated_relative: generated_entry_context(String::new(), path, boundary),
            not_found_trigger,
        };
        let mut last_io = Some(record.first.clone());
        let result = if self.diagnostics.records.len() >= MAX_RETRY_RECORDS {
            Err(StorageError::new(
                "retry_evidence",
                "observation retry record limit exceeded",
            ))
        } else {
            self.reobserve(path, root, progress, started, &mut record, &mut last_io)
        };
        let elapsed = (self.clock)().saturating_duration_since(started);
        self.spent = self.spent.saturating_add(elapsed);
        record.elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        if let Err(error) = &result {
            record.final_observation = RetryFinalObservation::Failed {
                category: error.kind,
                final_io: error.native_io.clone(),
                last_metadata_io: last_io,
            };
        }
        if let Err(error) = self.diagnostics.retain(record.clone()) {
            let cause = match result {
                Ok(_) => error,
                Err(primary) => StorageError {
                    kind: primary.kind,
                    message: format!("retry diagnostic retention failed: {}", error.kind),
                    native_io: primary.native_io.clone(),
                    cause: Some(Box::new(primary)),
                },
            };
            return Err(retry_failure(&record, cause));
        }
        result.map_err(|error| retry_failure(&record, error))
    }
    fn reobserve(
        &mut self,
        path: &Path,
        root: &Path,
        progress: &mut dyn FnMut() -> Result<(), String>,
        started: Instant,
        record: &mut ObservationRetryRecord,
        last_io: &mut Option<NativeIoDiagnostic>,
    ) -> Result<Option<fs::Metadata>, StorageError> {
        for delay in [Duration::from_millis(2), Duration::from_millis(4)] {
            if self.extra_calls >= MAX_EXTRA_METADATA_CALLS
                || self.planned_wait.saturating_add(delay) > MAX_RETRY_WAIT
            {
                return Err(StorageError::new(
                    "retry_budget",
                    "metadata reobservation call or planned wait limit exceeded",
                ));
            }
            self.guard(path, root, progress, started)?;
            self.planned_wait += delay;
            (self.wait)(delay);
            self.guard(path, root, progress, started)?;
            self.extra_calls += 1;
            record.attempts += 1;
            let observed = (self.metadata)(path);
            if let Err(error) = &observed {
                *last_io = Some(NativeIoDiagnostic::from_error(error));
            }
            self.checkpoint(progress, started)?;
            self.guard(path, root, progress, started)?;
            match observed {
                Ok(metadata) => {
                    if is_link(&metadata) || (!metadata.is_file() && !metadata.is_dir()) {
                        return Err(StorageError::new(
                            "file_type",
                            "reobserved entry is not an ordinary file or directory",
                        ));
                    }
                    record.final_observation = RetryFinalObservation::Present {
                        file_type: native_file_kind(&metadata),
                        byte_length: metadata.len(),
                    };
                    return Ok(Some(metadata));
                }
                Err(error) => {
                    // This is a newly observed NotFound, never a conversion
                    // of the original native 5 into a vanished allowance.
                    if error.kind() == std::io::ErrorKind::NotFound {
                        let vanished = vanished_ephemeral_one_attempt_with_progress(
                            path,
                            &error,
                            &[root.to_path_buf()],
                            progress,
                        )?;
                        self.guard(path, root, progress, started)?;
                        match vanished {
                            VanishedEntryObservation::MissingValidated => {
                                record.final_observation =
                                    RetryFinalObservation::MissingValidated {
                                        last: NativeIoDiagnostic::from_error(&error),
                                    };
                                return Ok(None);
                            }
                            VanishedEntryObservation::Present(metadata) => {
                                record.final_observation = RetryFinalObservation::Present {
                                    file_type: native_file_kind(&metadata),
                                    byte_length: metadata.len(),
                                };
                                return Ok(Some(metadata));
                            }
                            VanishedEntryObservation::Ineligible => {}
                        }
                    }
                    if error.raw_os_error() != Some(5) || record.attempts == 3 {
                        return Err(measurement_io_error(
                            "managed entry metadata",
                            path,
                            root,
                            error,
                        ));
                    }
                }
            }
        }
        Err(StorageError::new(
            "retry_budget",
            "metadata reobservation attempt limit exceeded",
        ))
    }
}

fn retry_failure(record: &ObservationRetryRecord, cause: StorageError) -> StorageError {
    let last_io = match &record.final_observation {
        RetryFinalObservation::Failed { final_io, .. } => final_io.as_ref(),
        RetryFinalObservation::MissingValidated { last } => Some(last),
        _ => None,
    };
    // Preserve the final original error behind source(), but do not copy an
    // arbitrary checkpoint/path message into shared evidence or diagnostics.
    let trigger = record.not_found_trigger.as_ref().map(|trigger| format!(
        "; not_found_stage={}; not_found_kind={}; not_found_raw_os_error={:?}; not_found_generated_relative={}",
        trigger.stage, trigger.first.kind, trigger.first.raw_os_error, trigger.generated_relative,
    )).unwrap_or_default();
    let message = format!(
        "metadata reobservation; first_kind={}; first_raw_os_error={:?}; attempts={}; final_kind={}; final_raw_os_error={:?}; generated_relative={}{}",
        record.first.kind,
        record.first.raw_os_error,
        record.attempts,
        cause.kind,
        last_io.and_then(|last| last.raw_os_error),
        record.generated_relative,
        trigger,
    );
    StorageError {
        kind: cause.kind,
        message,
        native_io: cause.native_io.clone(),
        cause: Some(Box::new(cause)),
    }
}

/// Only the known ephemeral strict descendant may be retried. Surviving
/// ancestors are ordinary directories; a missing ancestor is checked again by
/// the eventual NotFound/vanished proof. No target contents or link targets are
/// opened. This preserves the existing cooperative path-check guarantees.
fn verify_retry_ancestry(
    path: &Path,
    root: &Path,
    progress: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), StorageError> {
    reject_secret_leaf_file(path)?;
    observation_checkpoint(progress)?;
    verify_directory(root)?;
    observation_checkpoint(progress)?;
    let physical_root =
        fs::canonicalize(root).map_err(|error| StorageError::io("resolve retry root", error))?;
    if path_identity(&physical_root) != path_identity(root) {
        return Err(StorageError::new(
            "ownership",
            "retry root physical identity changed",
        ));
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| StorageError::new("path_escape", "retry left owned root"))?;
    let components: Vec<_> = relative.components().collect();
    if components.is_empty()
        || components.len() > MAX_DEPTH
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(StorageError::new(
            "path_escape",
            "retry requires a finite strict owned descendant",
        ));
    }
    let mut current = root.to_path_buf();
    for component in &components[..components.len() - 1] {
        observation_checkpoint(progress)?;
        current.push(component.as_os_str());
        reject_secret_path(&current)?;
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(StorageError::io("inspect retry ancestry", error)),
        };
        if is_link(&metadata) || !metadata.is_dir() {
            return Err(StorageError::new(
                "link",
                "retry ancestry is not an ordinary directory",
            ));
        }
        observation_checkpoint(progress)?;
        let physical = match fs::canonicalize(&current) {
            Ok(physical) => physical,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(StorageError::io("resolve retry ancestry", error)),
        };
        if !physical.starts_with(&physical_root) {
            return Err(StorageError::new(
                "link_escape",
                "retry ancestry left owned root",
            ));
        }
        observation_checkpoint(progress)?;
    }
    verify_directory(root)?;
    observation_checkpoint(progress)?;
    let after =
        fs::canonicalize(root).map_err(|error| StorageError::io("reverify retry root", error))?;
    if path_identity(&after) != path_identity(&physical_root) {
        return Err(StorageError::new(
            "ownership",
            "retry root physical identity changed",
        ));
    }
    Ok(())
}

fn tree_bytes_observed_with_progress(
    path: &Path,
    boundary: &Path,
    ephemeral_roots: &[PathBuf],
    mut before_metadata: impl FnMut(&Path),
    progress: &mut dyn FnMut() -> Result<(), String>,
) -> Result<u64, StorageError> {
    tree_bytes_observed_with_retry(
        path,
        boundary,
        ephemeral_roots,
        &mut before_metadata,
        progress,
        None,
    )
}

fn vanished_during_measurement(
    path: &Path,
    boundary: &Path,
    roots: &[PathBuf],
    error: &std::io::Error,
    stage: &'static str,
    progress: &mut dyn FnMut() -> Result<(), String>,
    retry: Option<&mut MetadataReobservation<'_>>,
) -> Result<VanishedEntryObservation, StorageError> {
    if let Some(retry) = retry {
        retry.vanished(path, boundary, roots, error, stage, progress)
    } else {
        // Pre-spawn, completed slots and other callers retain their existing
        // one-attempt policy; only Running receives the typed recovery path.
        Ok(if vanished_ephemeral_entry(path, error, roots)? {
            VanishedEntryObservation::MissingValidated
        } else {
            VanishedEntryObservation::Ineligible
        })
    }
}

fn tree_bytes_observed_with_retry(
    path: &Path,
    boundary: &Path,
    ephemeral_roots: &[PathBuf],
    mut before_metadata: impl FnMut(&Path),
    progress: &mut dyn FnMut() -> Result<(), String>,
    mut retry: Option<&mut MetadataReobservation<'_>>,
) -> Result<u64, StorageError> {
    observation_checkpoint(progress)?;
    let boundary =
        fs::canonicalize(boundary).map_err(|e| StorageError::io("resolve tree boundary", e))?;
    observation_checkpoint(progress)?;
    let mut pending = vec![(path.to_path_buf(), 0usize)];
    let mut entries = 0usize;
    let mut bytes = 0u64;
    while let Some((path, depth)) = pending.pop() {
        observation_checkpoint(progress)?;
        entries += 1;
        if depth > MAX_DEPTH || entries > MAX_ENTRIES {
            return Err(StorageError::new(
                "walk_limit",
                "managed tree depth or entry limit exceeded",
            ));
        }
        reject_secret_path(&path)?;
        before_metadata(&path);
        observation_checkpoint(progress)?;
        let metadata = if let Some(retry) = retry.as_deref_mut() {
            match retry.observe(&path, &boundary, ephemeral_roots, progress)? {
                Some(metadata) => metadata,
                None => continue,
            }
        } else {
            match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if vanished_ephemeral_entry(&path, &error, ephemeral_roots)? => continue,
                Err(error) => {
                    return Err(measurement_io_error(
                        "managed entry metadata",
                        &path,
                        &boundary,
                        error,
                    ));
                }
            }
        };
        observation_checkpoint(progress)?;
        if is_link(&metadata) {
            validate_internal_link(&path, &boundary)?;
            observation_checkpoint(progress)?;
            bytes = checked_sum(bytes, metadata.len())?;
        } else if metadata.is_dir() {
            let mut directory = match fs::read_dir(&path) {
                Ok(directory) => directory,
                Err(error) => {
                    match vanished_during_measurement(
                        &path,
                        &boundary,
                        ephemeral_roots,
                        &error,
                        "directory_open",
                        progress,
                        retry.as_deref_mut(),
                    )? {
                        VanishedEntryObservation::MissingValidated => continue,
                        VanishedEntryObservation::Present(_) => {
                            pending.push((path, depth));
                            continue;
                        }
                        VanishedEntryObservation::Ineligible => {}
                    }
                    return Err(measurement_io_error(
                        "directory open",
                        &path,
                        &boundary,
                        error,
                    ));
                }
            };
            observation_checkpoint(progress)?;
            let pending_before_directory = pending.len();
            loop {
                observation_checkpoint(progress)?;
                let entry = directory.next();
                observation_checkpoint(progress)?;
                let Some(entry) = entry else { break };
                if pending.len() + entries >= MAX_ENTRIES {
                    return Err(StorageError::new(
                        "walk_limit",
                        "managed tree entry limit exceeded",
                    ));
                }
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        match vanished_during_measurement(
                            &path,
                            &boundary,
                            ephemeral_roots,
                            &error,
                            "directory_enumeration",
                            progress,
                            retry.as_deref_mut(),
                        )? {
                            VanishedEntryObservation::MissingValidated => break,
                            VanishedEntryObservation::Present(_) => {
                                // These children have not been measured yet. Keep all other
                                // pending work, accumulated bytes and consumed walk budget.
                                pending.truncate(pending_before_directory);
                                pending.push((path.clone(), depth));
                                break;
                            }
                            VanishedEntryObservation::Ineligible => {}
                        }
                        return Err(measurement_io_error(
                            "directory enumeration",
                            &path,
                            &boundary,
                            error,
                        ));
                    }
                };
                pending.push((entry.path(), depth + 1));
            }
        } else if metadata.is_file() {
            reject_secret_leaf_file(&path)?;
            bytes = checked_sum(bytes, metadata.len())?;
        } else {
            return Err(special_entry_error(
                "measurement",
                &path,
                &boundary,
                &metadata,
            ));
        }
    }
    observation_checkpoint(progress)?;
    Ok(bytes)
}

fn measurement_io_error(
    stage: &'static str,
    path: &Path,
    boundary: &Path,
    error: std::io::Error,
) -> StorageError {
    // A failed metadata open cannot establish whether Windows access denial
    // came from deletion, sharing or access control. Keep the error fatal and
    // preserve its native cause, while identifying only the generated leaf.
    let context = format!(
        "measure {stage}; attempts=1; kind={:?}; raw_os_error={:?}; generated_relative=",
        error.kind(),
        error.raw_os_error()
    );
    StorageError::io(&generated_entry_context(context, path, boundary), error)
}

fn special_entry_error(
    stage: &'static str,
    path: &Path,
    boundary: &Path,
    metadata: &fs::Metadata,
) -> StorageError {
    // Classify only the metadata already observed by this walk. Do not open,
    // read, connect to or remove an entry in order to identify its producer.
    let native_kind = native_file_kind(metadata);
    StorageError::new(
        "file_type",
        generated_entry_context(
            format!(
                "special filesystem entry is preserved; stage={stage}; native_kind={native_kind}; generated_relative="
            ),
            path,
            boundary,
        ),
    )
}

fn native_file_kind(metadata: &fs::Metadata) -> &'static str {
    let file_type = metadata.file_type();
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if file_type.is_socket() {
            return "unix_socket";
        }
        if file_type.is_fifo() {
            return "unix_fifo";
        }
        if file_type.is_block_device() {
            return "unix_block_device";
        }
        if file_type.is_char_device() {
            return "unix_char_device";
        }
    }
    // Keep these distinctions available if an entry changes type between
    // bounded preflight and removal; no unexpected type grants permission.
    if file_type.is_file() {
        "regular_file"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_symlink() {
        "symlink"
    } else {
        "other_special"
    }
}

fn generated_entry_context(mut context: String, path: &Path, boundary: &Path) -> String {
    const CONTEXT_LIMIT: usize = 512;
    // Apply the path policy before even formatting a relative label. No file
    // contents or metadata are read to produce this diagnostic.
    let relative = if reject_secret_leaf_file(path).is_err() {
        std::borrow::Cow::Borrowed("<withheld by path policy>")
    } else {
        match path.strip_prefix(boundary) {
            Ok(relative) if relative.as_os_str().is_empty() => std::borrow::Cow::Borrowed("."),
            Ok(relative) => relative.to_string_lossy(),
            Err(_) => std::borrow::Cow::Borrowed("<outside generated boundary>"),
        }
    };
    for character in relative.chars().flat_map(char::escape_debug) {
        if context.len() + character.len_utf8() > CONTEXT_LIMIT - 3 {
            context.push_str("...");
            break;
        }
        context.push(character);
    }
    context
}

fn vanished_ephemeral_entry(
    path: &Path,
    error: &std::io::Error,
    roots: &[PathBuf],
) -> Result<bool, StorageError> {
    vanished_ephemeral_entry_with_progress(path, error, roots, &mut || Ok(()))
}

fn vanished_ephemeral_entry_with_progress(
    path: &Path,
    error: &std::io::Error,
    roots: &[PathBuf],
    progress: &mut dyn FnMut() -> Result<(), String>,
) -> Result<bool, StorageError> {
    Ok(!matches!(
        vanished_ephemeral_one_attempt_with_progress(path, error, roots, progress)?,
        VanishedEntryObservation::Ineligible
    ))
}

fn vanished_ephemeral_one_attempt_with_progress(
    path: &Path,
    error: &std::io::Error,
    roots: &[PathBuf],
    progress: &mut dyn FnMut() -> Result<(), String>,
) -> Result<VanishedEntryObservation, StorageError> {
    vanished_ephemeral_observation_with_progress(
        path,
        error,
        roots,
        progress,
        &mut |component, _, _| match fs::symlink_metadata(component) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StorageError::io(
                "verify vanished-entry surviving ancestry",
                error,
            )),
        },
    )
}

enum VanishedEntryObservation {
    Ineligible,
    MissingValidated,
    Present(fs::Metadata),
}

/// This remains a cooperative path observation, not an atomic filesystem
/// snapshot. The Running callback alone may use the shared bounded native-5
/// recovery; nested missing proofs use the one-attempt callback above.
fn vanished_ephemeral_observation_with_progress(
    path: &Path,
    error: &std::io::Error,
    roots: &[PathBuf],
    progress: &mut dyn FnMut() -> Result<(), String>,
    metadata: &mut impl FnMut(
        &Path,
        &Path,
        &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Option<fs::Metadata>, StorageError>,
) -> Result<VanishedEntryObservation, StorageError> {
    if error.kind() != std::io::ErrorKind::NotFound {
        return Ok(VanishedEntryObservation::Ineligible);
    }
    let Some(root) = roots
        .iter()
        .find(|root| path != root.as_path() && path.starts_with(root))
    else {
        return Ok(VanishedEntryObservation::Ineligible);
    };
    observation_checkpoint(progress)?;
    verify_directory(root)?;
    observation_checkpoint(progress)?;
    let physical_root = fs::canonicalize(root)
        .map_err(|e| StorageError::io("verify vanished-entry fixed root", e))?;
    if path_identity(&physical_root) != path_identity(root) {
        return Err(StorageError::new(
            "ownership",
            "observation fixed root physical identity changed",
        ));
    }
    let relative = path
        .strip_prefix(root)
        .map_err(|_| StorageError::new("path_escape", "vanished entry left fixed root"))?;
    let components: Vec<_> = relative.components().collect();
    if components.len() > MAX_DEPTH
        || components
            .iter()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(StorageError::new(
            "path_escape",
            "vanished entry has non-owned or excessive ancestry",
        ));
    }
    let mut current = root.clone();
    let mut target_metadata = None;
    for (index, component) in components.iter().enumerate() {
        observation_checkpoint(progress)?;
        current.push(component.as_os_str());
        reject_secret_path(&current)?;
        let metadata = match metadata(&current, root, progress)? {
            Some(metadata) => metadata,
            None => break,
        };
        observation_checkpoint(progress)?;
        if is_link(&metadata) {
            return Err(StorageError::new(
                "link",
                "vanished entry crosses surviving link or reparse point",
            ));
        }
        if (!metadata.is_dir() && index + 1 < components.len())
            || (!metadata.is_dir() && !metadata.is_file())
        {
            return Err(StorageError::new(
                "file_type",
                "vanished entry ancestry changed file type",
            ));
        }
        if metadata.is_file() {
            reject_secret_leaf_file(&current)?;
        }
        let physical = match fs::canonicalize(&current) {
            Ok(physical) => physical,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(StorageError::io(
                    "resolve vanished-entry surviving ancestry",
                    error,
                ));
            }
        };
        observation_checkpoint(progress)?;
        if !physical.starts_with(&physical_root) {
            return Err(StorageError::new(
                "link_escape",
                "vanished entry surviving ancestry left owned root",
            ));
        }
        if index + 1 == components.len() {
            target_metadata = Some(metadata);
        }
    }
    observation_checkpoint(progress)?;
    verify_directory(root)?;
    observation_checkpoint(progress)?;
    let after = fs::canonicalize(root)
        .map_err(|e| StorageError::io("reverify vanished-entry fixed root", e))?;
    if path_identity(&after) != path_identity(&physical_root) {
        return Err(StorageError::new(
            "ownership",
            "observation fixed root physical identity changed",
        ));
    }
    Ok(match target_metadata {
        Some(metadata) => VanishedEntryObservation::Present(metadata),
        None => VanishedEntryObservation::MissingValidated,
    })
}

fn validate_internal_link(path: &Path, boundary: &Path) -> Result<(), StorageError> {
    let target =
        fs::canonicalize(path).map_err(|e| StorageError::io("resolve internal link", e))?;
    if !target.starts_with(boundary) {
        return Err(StorageError::new(
            "link_escape",
            "external or unresolved link target is preserved",
        ));
    }
    reject_secret_path(&target)
}

fn remove_tree(
    path: &Path,
    boundary: &Path,
    owner_path: &Path,
    owner_bytes: &[u8],
    verify_lease: &dyn Fn() -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    validate_absolute_path(path)?;
    let boundary =
        fs::canonicalize(boundary).map_err(|e| StorageError::io("resolve removal boundary", e))?;
    let target =
        fs::canonicalize(path).map_err(|e| StorageError::io("resolve removal target", e))?;
    if target == boundary || !target.starts_with(&boundary) {
        return Err(StorageError::new(
            "path_escape",
            "removal target does not stay strictly within owned root",
        ));
    }
    reject_link(path)?;
    // Complete bounded validation before deleting any entry.
    tree_bytes(path, &boundary)?;
    unlink_internal_links(path, &boundary, owner_path, owner_bytes, verify_lease)?;
    let mut pending = vec![(path.to_path_buf(), false, 0usize)];
    let mut entries = 0usize;
    while let Some((path, visited, depth)) = pending.pop() {
        reject_secret_path(&path)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| StorageError::io("inspect removal entry", e))?;
        if !visited {
            entries += 1;
            if entries > MAX_ENTRIES || depth > MAX_DEPTH {
                return Err(StorageError::new(
                    "walk_limit",
                    "removal tree grew beyond limits; remaining entries preserved",
                ));
            }
        }
        let resolved_parent = fs::canonicalize(
            path.parent()
                .ok_or_else(|| StorageError::new("path", "removal entry has no parent"))?,
        )
        .map_err(|e| StorageError::io("resolve removal parent", e))?;
        verify_directory(
            path.parent()
                .ok_or_else(|| StorageError::new("path", "removal entry has no parent"))?,
        )?;
        if resolved_parent != boundary && !resolved_parent.starts_with(&boundary) {
            return Err(StorageError::new("path_escape", "removal ancestry changed"));
        }
        // Keep the top-level owner record until all other slot contents are gone.
        // After its final removal only removal of the empty slot root remains.
        if path != target || !visited || owner_path.exists() {
            verify_record_bytes(owner_path, owner_bytes)?;
        }
        if visited || !metadata.is_dir() || is_link(&metadata) {
            verify_lease()?;
        }
        if is_link(&metadata) {
            return Err(StorageError::new(
                "ownership",
                "new link appeared after validated unlink pass; remaining entries preserved",
            ));
        } else if metadata.is_dir() && !visited {
            pending.push((path.clone(), true, depth));
            let mut children = Vec::new();
            for entry in
                fs::read_dir(&path).map_err(|e| StorageError::io("read removal directory", e))?
            {
                if children.len() + pending.len() + entries > MAX_ENTRIES * 2 {
                    return Err(StorageError::new(
                        "walk_limit",
                        "removal pending entries exceeded bound",
                    ));
                }
                children.push(
                    entry
                        .map_err(|e| StorageError::io("read removal entry", e))?
                        .path(),
                );
            }
            // Stack order: links first, ordinary children next, owner record last.
            children.sort_by_key(|child| {
                if child == owner_path {
                    0
                } else if fs::symlink_metadata(child).is_ok_and(|m| is_link(&m)) {
                    2
                } else {
                    1
                }
            });
            pending.extend(children.into_iter().map(|child| (child, false, depth + 1)));
        } else if metadata.is_dir() {
            fs::remove_dir(&path).map_err(|e| StorageError::io("remove owned directory", e))?;
        } else if metadata.is_file() {
            reject_secret_leaf_file(&path)?;
            fs::remove_file(&path).map_err(|e| StorageError::io("remove owned file", e))?;
        } else {
            return Err(special_entry_error("removal", &path, &boundary, &metadata));
        }
    }
    Ok(())
}

fn unlink_internal_links(
    root: &Path,
    boundary: &Path,
    owner_path: &Path,
    owner_bytes: &[u8],
    verify_lease: &dyn Fn() -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut links = Vec::new();
    let mut entries = 0usize;
    while let Some((path, depth)) = pending.pop() {
        entries += 1;
        if entries > MAX_ENTRIES || depth > MAX_DEPTH {
            return Err(StorageError::new(
                "walk_limit",
                "link preflight exceeded managed tree bound",
            ));
        }
        reject_secret_path(&path)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| StorageError::io("inspect link preflight entry", e))?;
        if is_link(&metadata) {
            validate_internal_link(&path, boundary)?;
            let raw_target = fs::read_link(&path)
                .map_err(|e| StorageError::io("read owned link identity", e))?;
            links.push((path, raw_target, link_is_directory(&metadata)));
        } else if metadata.is_dir() {
            verify_directory(&path)?;
            for entry in fs::read_dir(&path)
                .map_err(|e| StorageError::io("read link preflight directory", e))?
            {
                if pending.len() + entries >= MAX_ENTRIES {
                    return Err(StorageError::new(
                        "walk_limit",
                        "link preflight entry bound exceeded",
                    ));
                }
                pending.push((
                    entry
                        .map_err(|e| StorageError::io("read link preflight entry", e))?
                        .path(),
                    depth + 1,
                ));
            }
        } else if metadata.is_file() {
            reject_secret_leaf_file(&path)?;
        } else {
            return Err(special_entry_error(
                "link_preflight",
                &path,
                boundary,
                &metadata,
            ));
        }
    }
    // Remove every validated link before removing any target subtree. A link
    // chain may become dangling during this pass; compare its raw identity and
    // remove only the link entry, without resolving or following it again.
    for (path, raw_target, directory_link) in links {
        verify_record_bytes(owner_path, owner_bytes)?;
        verify_lease()?;
        verify_directory(
            path.parent()
                .ok_or_else(|| StorageError::new("path", "link has no parent"))?,
        )?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| StorageError::io("verify link before unlink", e))?;
        if !is_link(&metadata)
            || link_is_directory(&metadata) != directory_link
            || fs::read_link(&path)
                .map_err(|e| StorageError::io("verify owned link identity", e))?
                != raw_target
        {
            return Err(StorageError::new(
                "ownership",
                "owned link identity changed before unlink",
            ));
        }
        if directory_link {
            fs::remove_dir(&path)
                .map_err(|e| StorageError::io("unlink owned directory link", e))?;
        } else {
            fs::remove_file(&path).map_err(|e| StorageError::io("unlink owned file link", e))?;
        }
    }
    Ok(())
}

fn checked_sum(first: u64, second: u64) -> Result<u64, StorageError> {
    first
        .checked_add(second)
        .ok_or_else(|| StorageError::new("budget", "observed tree size overflow"))
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn now_ms() -> Result<u64, StorageError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| StorageError::new("clock", e.to_string()))?
        .as_millis();
    u64::try_from(millis).map_err(|_| StorageError::new("clock", "timestamp exceeds record range"))
}
fn new_token() -> String {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    digest_bytes(
        format!(
            "{}:{time}:{}",
            std::process::id(),
            TOKEN_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )
        .as_bytes(),
    )
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
