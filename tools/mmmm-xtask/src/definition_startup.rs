// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
//! Bounded developer startup observations. Selected paths and their hashes do
//! not admit a JDK image, a transformer roster, game sources or a write profile.

use crate::{process, storage};
use serde::Serialize;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;

const MIB: u64 = 1024 * 1024;
const MAX_INPUTS: usize = 32;
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
const MAX_INPUT_BYTES: u64 = 512 * MIB;
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
const MAX_FRAME_BYTES: usize = 18 * 1024 * 1024;
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
const PROBE: &str = "io.github.daejunnom.mmmm.observer.DefinitionStartupProbe";
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
const OWNER: &str = "io/github/daejunnom/mmmm/observer/DefinitionStartupProbe";
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
const LAMBDA: &str = "io/github/daejunnom/mmmm/observer/DefinitionStartupProbe$$Lambda";
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
const TARGET: &str = "lambda$ownedRunnable$0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefinitionSourceRole {
    JavaExecutable,
    ObserverLibrary,
    ObserverJar,
    JdkArchive,
    JdkModules,
    JdkLibrary,
    BuildSourceManifest,
}
impl DefinitionSourceRole {
    pub fn max_bytes(self) -> u64 {
        match self {
            Self::JavaExecutable | Self::ObserverLibrary | Self::JdkLibrary => 64 * MIB,
            Self::ObserverJar => 16 * MIB,
            // The selected, already pinned Windows JDK ZIP is 141,167,264
            // bytes. This finite input cap fits that archive; the shared
            // 512 MiB total and all native process budgets remain fixed.
            Self::JdkArchive => 192 * MIB,
            Self::JdkModules => 256 * MIB,
            Self::BuildSourceManifest => MIB,
        }
    }
}

/// Developer-selected inputs, not a constructor for observed source authority.
#[derive(Clone, Debug)]
pub struct DefinitionSourceInput {
    role: DefinitionSourceRole,
    path: PathBuf,
}
impl DefinitionSourceInput {
    pub fn new(role: DefinitionSourceRole, path: PathBuf) -> Self {
        Self { role, path }
    }
}

#[derive(Clone, Debug)]
pub struct DefinitionStartupSelection {
    java_exe: PathBuf,
    observer_dll: PathBuf,
    observer_jar: PathBuf,
    source_inputs: Vec<DefinitionSourceInput>,
}
impl DefinitionStartupSelection {
    pub fn new(
        java_exe: PathBuf,
        observer_dll: PathBuf,
        observer_jar: PathBuf,
        source_inputs: Vec<DefinitionSourceInput>,
    ) -> Result<Self, DefinitionStartupError> {
        let selection = Self {
            java_exe,
            observer_dll,
            observer_jar,
            source_inputs,
        };
        selected_inputs(&selection)?;
        Ok(selection)
    }
}

/// Only role, actual size and actual SHA are serializable. Local paths, account
/// names, native file identities and file handles never enter this report.
#[derive(Clone, Debug, Serialize)]
pub struct DefinitionSourcePin {
    role: DefinitionSourceRole,
    size: u64,
    sha256: String,
}
impl DefinitionSourcePin {
    pub fn role(&self) -> DefinitionSourceRole {
        self.role
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct SourcePins {
    files: Vec<DefinitionSourcePin>,
}
impl SourcePins {
    pub fn files(&self) -> &[DefinitionSourcePin] {
        &self.files
    }
}

#[derive(Debug, Serialize)]
pub struct FixtureDefinitionSummary {
    class_identity: String,
    generation: String,
    attempt: String,
    observed_name: String,
    methods: u32,
    constant_pool_count: u32,
}
#[derive(Debug, Serialize)]
pub struct DefinitionFixtureSummary {
    observed_status: i32,
    issuer_epoch: String,
    ordinary: FixtureDefinitionSummary,
    samless_hidden: FixtureDefinitionSummary,
    positive_hidden: FixtureDefinitionSummary,
    target_class_status: i32,
}

/// Only run_owned constructs this observation; it is not SourceAdmission or a
/// NativeProof and has no deserialization/public field-construction route.
#[derive(Debug)]
pub struct DefinitionStartupRun {
    outcome: process::ProcessOutcome,
    process_started: bool,
    source_pins: SourcePins,
    raw_abi2: Vec<u8>,
    raw_sha256: String,
    summary: DefinitionFixtureSummary,
}
impl DefinitionStartupRun {
    pub fn outcome(&self) -> &process::ProcessOutcome {
        &self.outcome
    }
    pub fn process_started(&self) -> bool {
        self.process_started
    }
    pub fn source_pins(&self) -> &SourcePins {
        &self.source_pins
    }
    pub fn raw_abi2(&self) -> &[u8] {
        &self.raw_abi2
    }
    pub fn raw_sha256(&self) -> &str {
        &self.raw_sha256
    }
    pub fn summary(&self) -> &DefinitionFixtureSummary {
        &self.summary
    }
    pub fn into_outcome(self) -> process::ProcessOutcome {
        self.outcome
    }
}

#[derive(Debug)]
pub struct DefinitionStartupError {
    kind: &'static str,
    native_os_code: Option<i32>,
    process_error: Option<Box<process::ProcessError>>,
    storage_error: Option<Box<storage::StorageError>>,
    outcome: Option<Box<process::ProcessOutcome>>,
    process_started: Option<bool>,
    source_pins: Option<SourcePins>,
    raw_candidate: Option<Vec<u8>>,
    post_check_error: Option<Box<DefinitionStartupError>>,
}
impl DefinitionStartupError {
    fn new(kind: &'static str) -> Self {
        Self {
            kind,
            native_os_code: None,
            process_error: None,
            storage_error: None,
            outcome: None,
            // This module's local input/parse errors do not create a process.
            // Native supervisor failures explicitly reset this to unknown;
            // post-spawn errors receive the private capture receipt in attach.
            process_started: Some(false),
            source_pins: None,
            raw_candidate: None,
            post_check_error: None,
        }
    }
    pub fn kind(&self) -> &'static str {
        self.kind
    }
    pub fn native_os_code(&self) -> Option<i32> {
        self.native_os_code
    }
    pub fn process_error(&self) -> Option<&process::ProcessError> {
        self.process_error.as_deref()
    }
    pub fn storage_error(&self) -> Option<&storage::StorageError> {
        self.storage_error.as_deref()
    }
    pub fn outcome(&self) -> Option<&process::ProcessOutcome> {
        self.outcome.as_deref()
    }
    pub fn process_started(&self) -> Option<bool> {
        self.process_started
    }
    pub fn source_pins(&self) -> Option<&SourcePins> {
        self.source_pins.as_ref()
    }
    pub fn raw_candidate(&self) -> Option<&[u8]> {
        self.raw_candidate.as_deref()
    }
    pub fn post_check_error(&self) -> Option<&DefinitionStartupError> {
        self.post_check_error.as_deref()
    }
    pub fn into_outcome(self) -> Option<process::ProcessOutcome> {
        self.outcome.map(|outcome| *outcome)
    }
}
impl fmt::Display for DefinitionStartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MMMM_DEFINITION_STARTUP_{}", self.kind)
    }
}
impl std::error::Error for DefinitionStartupError {}

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn remaining_process_budget(
    remaining: std::time::Duration,
) -> Result<std::time::Duration, DefinitionStartupError> {
    if remaining < std::time::Duration::from_secs(1)
        || remaining > std::time::Duration::from_secs(60)
    {
        return Err(DefinitionStartupError::new("DEADLINE"));
    }
    Ok(remaining)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupPlatform {
    Windows,
    Linux,
    Macos,
}
impl StartupPlatform {
    fn current() -> Result<Self, DefinitionStartupError> {
        if cfg!(all(
            windows,
            target_arch = "x86_64",
            target_env = "msvc",
            target_endian = "little"
        )) {
            Ok(Self::Windows)
        } else if cfg!(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_env = "gnu",
            target_endian = "little"
        )) {
            Ok(Self::Linux)
        } else if cfg!(all(
            target_os = "macos",
            target_arch = "aarch64",
            target_endian = "little"
        )) {
            Ok(Self::Macos)
        } else {
            Err(DefinitionStartupError::new("UNSUPPORTED_PLATFORM"))
        }
    }
    fn marker(self) -> &'static str {
        match self {
            Self::Windows => "jdk25-windows-x64-msvc-controlled-startup-v1",
            Self::Linux => "jdk25-linux-x64-gnu-controlled-startup-v1",
            Self::Macos => "jdk25-macos-arm64-darwin-controlled-startup-v1",
        }
    }
    fn role_name(self, role: DefinitionSourceRole, name: &str) -> bool {
        match role {
            DefinitionSourceRole::JavaExecutable => {
                name == if self == Self::Windows {
                    "java.exe"
                } else {
                    "java"
                }
            }
            DefinitionSourceRole::ObserverLibrary | DefinitionSourceRole::JdkLibrary => name
                .ends_with(match self {
                    Self::Windows => ".dll",
                    Self::Linux => ".so",
                    Self::Macos => ".dylib",
                }),
            DefinitionSourceRole::ObserverJar => name.ends_with(".jar"),
            DefinitionSourceRole::JdkArchive => name.ends_with(if self == Self::Windows {
                ".zip"
            } else {
                ".tar.gz"
            }),
            DefinitionSourceRole::JdkModules => name == "modules",
            DefinitionSourceRole::BuildSourceManifest => name.ends_with(".json"),
        }
    }
}

fn selected_inputs(
    selection: &DefinitionStartupSelection,
) -> Result<Vec<(DefinitionSourceRole, &Path)>, DefinitionStartupError> {
    selected_inputs_for_platform(selection, StartupPlatform::current()?)
}

fn selected_inputs_for_platform(
    selection: &DefinitionStartupSelection,
    platform: StartupPlatform,
) -> Result<Vec<(DefinitionSourceRole, &Path)>, DefinitionStartupError> {
    if selection
        .source_inputs
        .len()
        .checked_add(3)
        .is_none_or(|n| n > MAX_INPUTS)
    {
        return Err(DefinitionStartupError::new("INPUT_COUNT"));
    }
    let mut inputs = vec![
        (
            DefinitionSourceRole::JavaExecutable,
            selection.java_exe.as_path(),
        ),
        (
            DefinitionSourceRole::ObserverLibrary,
            selection.observer_dll.as_path(),
        ),
        (
            DefinitionSourceRole::ObserverJar,
            selection.observer_jar.as_path(),
        ),
    ];
    for input in &selection.source_inputs {
        if !matches!(
            input.role,
            DefinitionSourceRole::JdkArchive
                | DefinitionSourceRole::JdkModules
                | DefinitionSourceRole::JdkLibrary
                | DefinitionSourceRole::BuildSourceManifest
        ) {
            return Err(DefinitionStartupError::new("INPUT_ROLE"));
        }
        inputs.push((input.role, input.path.as_path()));
    }
    for required in [
        DefinitionSourceRole::JdkArchive,
        DefinitionSourceRole::JdkModules,
        DefinitionSourceRole::BuildSourceManifest,
    ] {
        if inputs.iter().filter(|(role, _)| *role == required).count() != 1 {
            return Err(DefinitionStartupError::new("INPUT_ROLE"));
        }
    }
    if !inputs
        .iter()
        .any(|(role, _)| *role == DefinitionSourceRole::JdkLibrary)
    {
        return Err(DefinitionStartupError::new("INPUT_ROLE"));
    }
    let mut paths = std::collections::BTreeSet::new();
    for (role, path) in &inputs {
        validate_input_path(path)?;
        let text = path
            .to_str()
            .ok_or_else(|| DefinitionStartupError::new("INPUT_PATH"))?;
        let key = if platform == StartupPlatform::Windows {
            text.to_lowercase()
        } else {
            text.to_owned()
        };
        if matches!(
            role,
            DefinitionSourceRole::ObserverLibrary | DefinitionSourceRole::ObserverJar
        ) && key.contains('=')
            || *role == DefinitionSourceRole::ObserverJar
                && (key.contains(';') || key.contains('*'))
        {
            return Err(DefinitionStartupError::new("INPUT_ARGUMENT_DELIMITER"));
        }
        if !paths.insert(key) {
            return Err(DefinitionStartupError::new("INPUT_DUPLICATE"));
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| DefinitionStartupError::new("INPUT_PATH"))?;
        let name = if platform == StartupPlatform::Windows {
            name.to_ascii_lowercase()
        } else {
            name.to_owned()
        };
        let correct = platform.role_name(*role, &name);
        if !correct {
            return Err(DefinitionStartupError::new("INPUT_ROLE_PATH"));
        }
    }
    Ok(inputs)
}

fn validate_input_path(path: &Path) -> Result<(), DefinitionStartupError> {
    let text = path
        .to_str()
        .ok_or_else(|| DefinitionStartupError::new("INPUT_PATH"))?;
    #[cfg(unix)]
    if text.starts_with("//") {
        return Err(DefinitionStartupError::new("INPUT_PATH"));
    }
    if !path.is_absolute()
        || path.components().count() > 64
        || text.len() > 32760
        || text.contains(['\0', '\r', '\n'])
        || text
            .split(['/', '\\'])
            .any(|part| matches!(part, "." | ".."))
    {
        return Err(DefinitionStartupError::new("INPUT_PATH"));
    }
    for component in path.components() {
        match component {
            Component::CurDir | Component::ParentDir => {
                return Err(DefinitionStartupError::new("INPUT_PATH"));
            }
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .ok_or_else(|| DefinitionStartupError::new("INPUT_PATH"))?
                    .to_ascii_lowercase();
                if name.contains(['\0', ':']) || name.ends_with(['.', ' ']) {
                    return Err(DefinitionStartupError::new("INPUT_PATH"));
                }
                if name == ".env"
                    || name.starts_with(".env.")
                    || name == ".ssh"
                    || name.contains("credential")
                    || name.contains("api_key")
                    || name.contains("api-key")
                    || name.contains("apikey")
                    || name.contains("service-account")
                    || name.contains("service_account")
                    || name.contains("serviceaccount")
                    || ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"].contains(&name.as_str())
                    || [".pem", ".key", ".p12", ".pfx", ".keystore"]
                        .iter()
                        .any(|suffix| name.ends_with(suffix))
                {
                    return Err(DefinitionStartupError::new("SECRET_PATH"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// No evidence files or Store/ledger are written here. The root caller exports
/// the real outcome, source pin data and frame before ManagedBuild::finish.
pub fn run_owned(
    build: &storage::ManagedBuild,
    selection: &DefinitionStartupSelection,
    cancellation: &AtomicBool,
) -> Result<DefinitionStartupRun, DefinitionStartupError> {
    StartupPlatform::current()?;
    #[cfg(windows)]
    {
        windows_run::run(build, selection, cancellation)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix_run::run(build, selection, cancellation)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (build, selection, cancellation);
        Err(DefinitionStartupError::new("UNSUPPORTED_PLATFORM"))
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn fixed_java_args(dll: &Path, jar: &Path, platform: StartupPlatform) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    let mut native = OsString::from("-agentpath:");
    native.push(dll);
    native.push("=");
    native.push(platform.marker());
    let mut agent = OsString::from("-javaagent:");
    agent.push(jar);
    agent.push("=protocol=mmmm.definition-observer/1");
    let mut args: Vec<OsString> = [
        "--disable-@files",
        "-Xshare:off",
        // Rebuild the default warning/error selection on stderr so that JNI
        // diagnostics cannot precede the strict binary stdout frame. Keep the
        // diagnostics in the original bounded stderr capture.
        // https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html#enable-logging-with-the-jvm-unified-logging-framework
        "-Xlog:disable",
        "-Xlog:all=warning:stderr",
        "-XX:+DisableAttachMechanism",
        "-XX:-EnableDynamicAgentLoading",
        "--enable-native-access=ALL-UNNAMED",
        "--illegal-native-access=deny",
        "-Xms32m",
        "-Xmx256m",
        "-XX:MaxMetaspaceSize=256m",
        "-XX:ReservedCodeCacheSize=64m",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    if platform != StartupPlatform::Windows {
        // This developer fixture does not use shared perfdata monitoring.
        // HotSpot's POSIX perfdata store uses os::get_temp_directory(); managed
        // Java TMPDIR alone must not be treated as a containment guarantee.
        // https://github.com/openjdk/jdk25u/blob/jdk-25.0.4.1%2B1/src/hotspot/os/posix/perfMemory_posix.cpp
        args.push(OsString::from("-XX:-UsePerfData"));
        // The process cwd is this owner's scratch, so Java API temp creation
        // resolves here without depending on an inherited host temp property.
        args.push(OsString::from("-Djava.io.tmpdir=."));
    }
    args.extend([
        native,
        agent,
        OsString::from("-cp"),
        jar.as_os_str().to_owned(),
        OsString::from("io.github.daejunnom.mmmm.observer.DefinitionStartupEvidenceMain"),
    ]);
    args
}
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn fixed_environment(
    base: std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> {
    let mut result = base
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect::<std::collections::BTreeMap<_, _>>();
    for key in [
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_AOT_VM_OPTIONS",
    ] {
        result.insert(key.into(), std::ffi::OsString::new());
    }
    result
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use sha2::{Digest, Sha256};
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use std::sync::atomic::Ordering;
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
use std::time::{Duration, Instant};

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
struct Deadline<'a> {
    cancellation: &'a AtomicBool,
    deadline: Instant,
}
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
impl<'a> Deadline<'a> {
    fn new(cancellation: &'a AtomicBool) -> Self {
        Self {
            cancellation,
            deadline: Instant::now() + Duration::from_secs(60),
        }
    }
    fn check(&self) -> Result<(), DefinitionStartupError> {
        if self.cancellation.load(Ordering::Acquire) {
            return Err(DefinitionStartupError::new("CANCELLED"));
        }
        if Instant::now() >= self.deadline {
            return Err(DefinitionStartupError::new("DEADLINE"));
        }
        Ok(())
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
trait StartupInputPin: Sized {
    type Context: Default;
    fn acquire(
        context: &mut Self::Context,
        role: DefinitionSourceRole,
        path: &Path,
        build: &storage::ManagedBuild,
        check: &Deadline<'_>,
        remaining: u64,
    ) -> Result<Self, DefinitionStartupError>;
    fn source_identity(&self) -> (u64, u64);
    fn report(&self) -> &DefinitionSourcePin;
    fn recheck(
        &mut self,
        build: &storage::ManagedBuild,
        check: &Deadline<'_>,
    ) -> Result<(), DefinitionStartupError>;
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn measure(
    build: &storage::ManagedBuild,
    check: &Deadline<'_>,
) -> Result<(), DefinitionStartupError> {
    let value = build
        .measure_with_progress(&mut || check.check().map_err(|error| error.to_string()))
        .map_err(|original| {
            let mut error = DefinitionStartupError::new("OWNERSHIP");
            error.storage_error = Some(Box::new(original));
            error
        })?;
    if !value.within_budget {
        return Err(DefinitionStartupError::new("DISK_BUDGET"));
    }
    Ok(())
}
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn attach(
    mut error: DefinitionStartupError,
    capture: process::CapturedProcessOutcome,
    pins: SourcePins,
    raw: Option<Vec<u8>>,
) -> DefinitionStartupError {
    error.process_started = Some(capture.process_started());
    error.outcome = Some(Box::new(capture.into_outcome()));
    error.source_pins = Some(pins);
    error.raw_candidate = raw;
    error
}
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn post_check<P: StartupInputPin>(
    pins: &mut [P],
    build: &storage::ManagedBuild,
    check: &Deadline<'_>,
) -> Result<(), DefinitionStartupError> {
    for pin in pins {
        pin.recheck(build, check)?;
    }
    measure(build, check)
}
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn run_with_pins<P: StartupInputPin>(
    build: &storage::ManagedBuild,
    selection: &DefinitionStartupSelection,
    cancellation: &AtomicBool,
) -> Result<DefinitionStartupRun, DefinitionStartupError> {
    let check = Deadline::new(cancellation);
    measure(build, &check)?;
    let selected = selected_inputs(selection)?;
    let mut context = P::Context::default();
    let mut pins: Vec<P> = Vec::new();
    let mut total = 0_u64;
    for (role, path) in selected {
        let pin = P::acquire(
            &mut context,
            role,
            path,
            build,
            &check,
            MAX_INPUT_BYTES - total,
        )?;
        if pins
            .iter()
            .any(|other| other.source_identity() == pin.source_identity())
        {
            return Err(DefinitionStartupError::new("INPUT_DUPLICATE"));
        }
        total = total
            .checked_add(pin.report().size)
            .ok_or_else(|| DefinitionStartupError::new("INPUT_SIZE"))?;
        if total > MAX_INPUT_BYTES {
            return Err(DefinitionStartupError::new("INPUT_SIZE"));
        }
        pins.push(pin);
    }
    let source_pins = SourcePins {
        files: pins.iter().map(|pin| pin.report().clone()).collect(),
    };
    for pin in &mut pins {
        pin.recheck(build, &check)?;
    }
    measure(build, &check)?;
    let mut spec = process::ProcessSpec::new(
        selection.java_exe.clone(),
        build.paths().scratch.clone(),
        build.paths().scratch.join("definition-startup.stdout.bin"),
        build.paths().scratch.join("definition-startup.stderr.log"),
    );
    spec.args = fixed_java_args(
        &selection.observer_dll,
        &selection.observer_jar,
        StartupPlatform::current()?,
    );
    spec.env = fixed_environment(build.environment());
    #[cfg(unix)]
    {
        // The fixed absolute Java does not require inherited PATH or HOME.
        // Clear inherited native-loader injectors and diagnostics without
        // reading their values; explicit managed paths/Java overrides remain.
        spec.inherit_environment = false;
    }
    check.check()?;
    spec.timeout =
        remaining_process_budget(check.deadline.saturating_duration_since(Instant::now()))?;
    spec.absolute_deadline = Some(check.deadline);
    spec.drain_timeout = Duration::from_secs(15);
    spec.max_log_bytes = 64 * MIB;
    spec.tail_policy = process::TailPolicy::Reject;
    spec.resource_policy = process::ResourcePolicy::for_definition_startup();
    let mut capture =
        match process::supervise_with_progress_captured(&spec, cancellation, |progress| {
            check.check().map_err(|error| error.to_string())?;
            let value = build
                .measure_with_progress(&mut || {
                    check.check().map_err(|error| error.to_string())?;
                    progress()?;
                    check.check().map_err(|error| error.to_string())
                })
                .map_err(|error| error.to_string())?;
            check.check().map_err(|error| error.to_string())?;
            if value.within_budget {
                Ok(())
            } else {
                Err("MMMM_DEFINITION_STARTUP_DISK_BUDGET".into())
            }
        }) {
            Ok(capture) => capture,
            Err(original) => {
                let mut error = DefinitionStartupError::new("PROCESS");
                error.process_started = None;
                error.process_error = Some(Box::new(original));
                error.source_pins = Some(source_pins);
                error.post_check_error = post_check(&mut pins, build, &check).err().map(Box::new);
                return Err(error);
            }
        };
    let outcome = capture.outcome();
    if !capture.process_started()
        || outcome.command_exit != Some(0)
        || outcome.command_signal.is_some()
        || !outcome.drained
        || !outcome.output_complete
        || !outcome.supervisor_errors.is_empty()
        || outcome.termination_reason != process::TerminationReason::Completed
        || outcome.owned_tail_terminated
    {
        let mut error = DefinitionStartupError::new("PROCESS_INCOMPLETE");
        error.post_check_error = post_check(&mut pins, build, &check).err().map(Box::new);
        return Err(attach(error, capture, source_pins, None));
    }
    let mut capture_ownership_error = None;
    let raw = match capture.read_stdout(MAX_FRAME_BYTES, || {
        check.check().map_err(|error| error.to_string())?;
        if let Err(original) = build.check_current_ownership() {
            capture_ownership_error = Some(original);
            return Err("MMMM_DEFINITION_STARTUP_OWNERSHIP".into());
        }
        check.check().map_err(|error| error.to_string())
    }) {
        Ok(raw) => raw,
        Err(original) => {
            let mut error = DefinitionStartupError::new("CAPTURE");
            error.process_error = Some(Box::new(original));
            error.storage_error = capture_ownership_error.map(Box::new);
            error.post_check_error = post_check(&mut pins, build, &check).err().map(Box::new);
            return Err(attach(error, capture, source_pins, None));
        }
    };
    for pin in &mut pins {
        if let Err(error) = pin.recheck(build, &check) {
            return Err(attach(error, capture, source_pins, Some(raw)));
        }
    }
    if let Err(error) = measure(build, &check) {
        return Err(attach(error, capture, source_pins, Some(raw)));
    }
    if let Err(error) = check.check() {
        return Err(attach(error, capture, source_pins, Some(raw)));
    }
    let summary = match decode_abi2(&raw) {
        Ok(summary) => summary,
        Err(error) => {
            return Err(attach(error, capture, source_pins, Some(raw)));
        }
    };
    if let Err(error) = check.check() {
        return Err(attach(error, capture, source_pins, Some(raw)));
    }
    let raw_sha256 = format!("{:x}", Sha256::digest(&raw));
    if let Err(error) = check.check() {
        return Err(attach(error, capture, source_pins, Some(raw)));
    }
    // Converting releases the original stdout handle. Input and ancestor
    // handles remain held until this function returns, before root cleanup.
    Ok(DefinitionStartupRun {
        process_started: capture.process_started(),
        outcome: capture.into_outcome(),
        source_pins,
        raw_abi2: raw,
        raw_sha256,
        summary,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "definition_startup_unix.rs"]
mod unix_run;

#[cfg(windows)]
mod windows_run {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Prefix;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, GetDriveTypeW,
        GetFileInformationByHandle,
    };

    // Win32 GetDriveTypeW's fixed-drive return value, without adding a second
    // windows-sys feature solely for this numeric SDK constant.
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew
    const DRIVE_FIXED: u32 = 3;

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Identity {
        volume: u32,
        index: u64,
        size: u64,
        attributes: u32,
        links: u32,
        write_time: u64,
    }
    fn io_error(kind: &'static str, error: std::io::Error) -> DefinitionStartupError {
        let mut result = DefinitionStartupError::new(kind);
        result.native_os_code = error.raw_os_error();
        result
    }
    fn information(file: &File) -> Result<Identity, DefinitionStartupError> {
        // SAFETY: this is the actual owned File handle and a correctly sized
        // windows-sys output structure. No pathname or guessed ABI is supplied.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io_error(
                "FILE_INFORMATION",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(Identity {
            volume: info.dwVolumeSerialNumber,
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            attributes: info.dwFileAttributes,
            links: info.nNumberOfLinks,
            write_time: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
                | u64::from(info.ftLastWriteTime.dwLowDateTime),
        })
    }
    fn open(path: &Path, directory: bool) -> Result<File, DefinitionStartupError> {
        let mut options = OpenOptions::new();
        options.read(true).share_mode(FILE_SHARE_READ).custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        );
        options
            .open(path)
            .map_err(|error| io_error("OPEN_INPUT", error))
    }
    struct DirectoryPin {
        path: PathBuf,
        file: File,
        identity: Identity,
    }
    struct InputPin {
        path: PathBuf,
        file: File,
        identity: Identity,
        directories: Vec<DirectoryPin>,
        report: DefinitionSourcePin,
    }
    fn same_object(left: Identity, right: Identity) -> bool {
        left.volume == right.volume && left.index == right.index
    }
    fn directories(
        path: &Path,
        check: &Deadline<'_>,
    ) -> Result<Vec<DirectoryPin>, DefinitionStartupError> {
        let drive = match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(DefinitionStartupError::new("NONLOCAL_INPUT")),
            },
            _ => return Err(DefinitionStartupError::new("NONLOCAL_INPUT")),
        };
        let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
        // SAFETY: the fixed drive-root buffer is NUL terminated and alive for
        // the call. Remote, removable and unknown volumes are unsupported.
        if unsafe { GetDriveTypeW(root.as_ptr()) } != DRIVE_FIXED {
            return Err(DefinitionStartupError::new("NONLOCAL_INPUT"));
        }
        let mut result = Vec::new();
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|path| !path.as_os_str().is_empty())
        {
            check.check()?;
            let file = open(parent, true)?;
            let identity = information(&file)?;
            if identity.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || identity.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            {
                return Err(DefinitionStartupError::new("INPUT_ANCESTRY"));
            }
            result.push(DirectoryPin {
                path: parent.to_owned(),
                file,
                identity,
            });
        }
        Ok(result)
    }
    fn hash(
        file: &mut File,
        limit: u64,
        check: &Deadline<'_>,
    ) -> Result<(u64, String), DefinitionStartupError> {
        file.seek(SeekFrom::Start(0))
            .map_err(|error| io_error("READ_INPUT", error))?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            check.check()?;
            let count = file
                .read(&mut buffer)
                .map_err(|error| io_error("READ_INPUT", error))?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| DefinitionStartupError::new("INPUT_SIZE"))?;
            if total > limit {
                return Err(DefinitionStartupError::new("INPUT_SIZE"));
            }
            digest.update(&buffer[..count]);
        }
        check.check()?;
        if total == 0 {
            return Err(DefinitionStartupError::new("INPUT_SIZE"));
        }
        Ok((total, format!("{:x}", digest.finalize())))
    }
    impl StartupInputPin for InputPin {
        type Context = ();
        fn acquire(
            _context: &mut Self::Context,
            role: DefinitionSourceRole,
            path: &Path,
            _build: &storage::ManagedBuild,
            check: &Deadline<'_>,
            remaining: u64,
        ) -> Result<Self, DefinitionStartupError> {
            let directories = directories(path, check)?;
            let mut file = open(path, false)?;
            let identity = information(&file)?;
            if identity.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
                || identity.links != 1
                || identity.size == 0
                || identity.size > role.max_bytes()
                || identity.size > remaining
            {
                return Err(DefinitionStartupError::new("INPUT_FILE"));
            }
            let (size, sha256) = hash(&mut file, role.max_bytes().min(remaining), check)?;
            if size != identity.size || information(&file)? != identity {
                return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
            }
            Ok(Self {
                path: path.to_owned(),
                file,
                identity,
                directories,
                report: DefinitionSourcePin { role, size, sha256 },
            })
        }
        fn source_identity(&self) -> (u64, u64) {
            (u64::from(self.identity.volume), self.identity.index)
        }
        fn report(&self) -> &DefinitionSourcePin {
            &self.report
        }
        fn recheck(
            &mut self,
            _build: &storage::ManagedBuild,
            check: &Deadline<'_>,
        ) -> Result<(), DefinitionStartupError> {
            for directory in &self.directories {
                check.check()?;
                let held = information(&directory.file)?;
                let current = information(&open(&directory.path, true)?)?;
                if !same_object(held, directory.identity)
                    || !same_object(current, directory.identity)
                    || held.attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                        != FILE_ATTRIBUTE_DIRECTORY
                    || current.attributes
                        & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                        != FILE_ATTRIBUTE_DIRECTORY
                {
                    return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
                }
            }
            check.check()?;
            if information(&self.file)? != self.identity
                || information(&open(&self.path, false)?)? != self.identity
            {
                return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
            }
            let (size, digest) = hash(&mut self.file, self.report.role.max_bytes(), check)?;
            if size != self.report.size
                || digest != self.report.sha256
                || information(&self.file)? != self.identity
            {
                return Err(DefinitionStartupError::new("SOURCE_CHANGED"));
            }
            Ok(())
        }
    }
    pub(super) fn run(
        build: &storage::ManagedBuild,
        selection: &DefinitionStartupSelection,
        cancellation: &AtomicBool,
    ) -> Result<DefinitionStartupRun, DefinitionStartupError> {
        run_with_pins::<InputPin>(build, selection, cancellation)
    }
}
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], DefinitionStartupError> {
        let end = self.position.checked_add(length).ok_or_else(frame_error)?;
        let value = self.bytes.get(self.position..end).ok_or_else(frame_error)?;
        self.position = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, DefinitionStartupError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, DefinitionStartupError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| frame_error())?,
        ))
    }
    fn u32(&mut self) -> Result<u32, DefinitionStartupError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| frame_error())?,
        ))
    }
    fn u64(&mut self) -> Result<u64, DefinitionStartupError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| frame_error())?,
        ))
    }
    fn nonzero(&mut self) -> Result<u64, DefinitionStartupError> {
        let value = self.u64()?;
        require(value != 0)?;
        Ok(value)
    }
    fn i32(&mut self) -> Result<i32, DefinitionStartupError> {
        Ok(i32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| frame_error())?,
        ))
    }
    fn sized(&mut self, cap: usize, nonempty: bool) -> Result<&'a [u8], DefinitionStartupError> {
        let length = usize::try_from(self.u32()?).map_err(|_| frame_error())?;
        require(length <= cap && (!nonempty || length != 0))?;
        self.take(length)
    }
    fn ascii(&mut self, cap: usize, nonempty: bool) -> Result<&'a str, DefinitionStartupError> {
        let bytes = self.sized(cap, nonempty)?;
        // This accepts only this owned ASCII fixture, not generic JNI Modified
        // UTF-8. No alternate decoding is used to fabricate a matching name.
        require(bytes.iter().all(|byte| (0x20..=0x7e).contains(byte)))?;
        std::str::from_utf8(bytes).map_err(|_| frame_error())
    }
    fn utf8(&mut self) -> Result<&'a str, DefinitionStartupError> {
        let bytes = self.sized(4096, true)?;
        let value = std::str::from_utf8(bytes).map_err(|_| frame_error())?;
        require(!value.contains('\0'))?;
        Ok(value)
    }
    fn end(&self) -> Result<(), DefinitionStartupError> {
        require(self.position == self.bytes.len())
    }
}
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn frame_error() -> DefinitionStartupError {
    DefinitionStartupError::new("FRAME")
}
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn require(condition: bool) -> Result<(), DefinitionStartupError> {
    if condition {
        Ok(())
    } else {
        Err(frame_error())
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
struct Definition<'a> {
    id: u64,
    generation: u64,
    attempt: u64,
    epoch: u64,
    name: &'a str,
    ordinary: &'a [u8],
    input: &'a [u8],
    requested: &'a str,
    hidden_flags: i32,
    initialize: bool,
    lookup: u64,
    loader: u64,
    methods: u32,
    cp_count: u32,
    static_target: bool,
    instance_run: bool,
}
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn definition(bytes: &[u8], kind: u8) -> Result<Definition<'_>, DefinitionStartupError> {
    require(!bytes.is_empty() && bytes.len() <= 8 * 1024 * 1024)?;
    let mut r = Reader::new(bytes);
    require(r.take(8)? == b"MMMMDEF1")?;
    require(r.u8()? == kind && r.u8()? == 3 && r.u16()? == 0)?;
    let id = r.nonzero()?;
    let generation = r.nonzero()?;
    let attempt = r.nonzero()?;
    let epoch = r.nonzero()?;
    let name = r.ascii(16 * 1024, true)?;
    let ordinary = r.sized(8 * 1024 * 1024, false)?;
    let input = r.sized(64 * 1024, false)?;
    let hidden_flags = r.i32()?;
    let initialize = r.u8()?;
    require(initialize <= 1 && r.u8()? == 0 && r.u16()? == 0)?;
    let lookup = r.u64()?;
    let loader = r.u64()?;
    let requested = r.ascii(16 * 1024, false)?;
    if kind == 1 {
        require(
            !ordinary.is_empty()
                && input.is_empty()
                && hidden_flags == 0
                && initialize == 0
                && lookup == 0
                && loader == 0
                && requested.is_empty()
                && name == PROBE,
        )?;
    } else {
        require(
            ordinary.is_empty()
                && !input.is_empty()
                && lookup != 0
                && !requested.is_empty()
                && hidden_flags & 2 != 0
                && hidden_flags & !15 == 0,
        )?;
    }
    let cp_count = r.u32()?;
    require((1..=65535).contains(&cp_count))?;
    r.sized(8 * 1024 * 1024, true)?;
    let methods = r.u32()?;
    require((1..=4096).contains(&methods))?;
    let mut signatures = std::collections::BTreeSet::new();
    let mut static_target = false;
    let mut instance_run = false;
    for _ in 0..methods {
        let name = r.ascii(16 * 1024, true)?;
        let descriptor = r.ascii(16 * 1024, true)?;
        require(signatures.insert((name, descriptor)))?;
        let modifiers = r.i32()?;
        let code_kind = r.u8()?;
        let code = r.sized(65535, false)?;
        let native = modifiers & 0x100 != 0;
        let abstract_method = modifiers & 0x400 != 0;
        require(match code_kind {
            0 => !code.is_empty() && !native && !abstract_method,
            1 => code.is_empty() && native && !abstract_method,
            2 => code.is_empty() && abstract_method && !native,
            _ => false,
        })?;
        static_target |=
            name == TARGET && descriptor == "()V" && modifiers & 8 != 0 && code_kind == 0;
        instance_run |= name == "run"
            && descriptor == "()V"
            && modifiers & 1 != 0
            && modifiers & 8 == 0
            && code_kind == 0;
    }
    r.end()?;
    Ok(Definition {
        id,
        generation,
        attempt,
        epoch,
        name,
        ordinary,
        input,
        requested,
        hidden_flags,
        initialize: initialize != 0,
        lookup,
        loader,
        methods,
        cp_count,
        static_target,
        instance_run,
    })
}
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn summary(definition: &Definition<'_>) -> FixtureDefinitionSummary {
    FixtureDefinitionSummary {
        class_identity: definition.id.to_string(),
        generation: definition.generation.to_string(),
        attempt: definition.attempt.to_string(),
        observed_name: definition.name.to_owned(),
        methods: definition.methods,
        constant_pool_count: definition.cp_count,
    }
}
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn hidden_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|suffix| !suffix.is_empty() && !suffix.contains('/'))
}
#[cfg(any(windows, target_os = "linux", target_os = "macos", test))]
fn decode_abi2(bytes: &[u8]) -> Result<DefinitionFixtureSummary, DefinitionStartupError> {
    require(!bytes.is_empty() && bytes.len() <= MAX_FRAME_BYTES)?;
    let mut outer = Reader::new(bytes);
    require(outer.take(8)? == b"MMMMABI2" && outer.u16()? == 1 && outer.u16()? == 0)?;
    let mut legacy = Reader::new(outer.sized(36 + 16 * 1024 * 1024, true)?);
    require(legacy.take(8)? == b"MMMMABI1" && legacy.u16()? == 1 && legacy.u16()? == 0)?;
    let status = legacy.i32()?;
    require(status == 255)?;
    let epoch = legacy.nonzero()?;
    require(legacy.u8()? == 1 && legacy.u8()? == 0 && legacy.u16()? == 0)?;
    let ordinary = definition(legacy.sized(8 * 1024 * 1024, true)?, 1)?;
    let samless = definition(legacy.sized(8 * 1024 * 1024, true)?, 2)?;
    legacy.end()?;
    let positive = definition(outer.sized(8 * 1024 * 1024, true)?, 2)?;
    let mut sam = Reader::new(outer.sized(1024 * 1024, true)?);
    outer.end()?;
    require(
        ordinary.epoch == epoch
            && samless.epoch == epoch
            && positive.epoch == epoch
            && ordinary.id != samless.id
            && ordinary.id != positive.id
            && samless.id != positive.id
            && ordinary.static_target
            && positive.instance_run
            && samless.hidden_flags == 10
            && !samless.initialize
            && samless.loader == 0
            && positive.hidden_flags == 7
            && positive.initialize
            && positive.lookup == ordinary.id
            && positive.loader != 0
            && samless.input == ordinary.ordinary
            && positive.input != ordinary.ordinary
            && samless.requested.replace('.', "/") == OWNER
            && positive.requested.replace('.', "/") == LAMBDA
            && hidden_name(samless.name, &format!("{PROBE}/"))
            && hidden_name(positive.name, &format!("{PROBE}$$Lambda/")),
    )?;
    require(sam.take(8)? == b"MMMMSAM1" && sam.u16()? == 1 && sam.u16()? == 0)?;
    require(
        sam.nonzero()? == epoch
            && sam.nonzero()? == positive.id
            && sam.nonzero()? == positive.generation
            && sam.nonzero()? == ordinary.id
            && sam.nonzero()? == ordinary.generation,
    )?;
    let target_status = sam.i32()?;
    require(
        target_status & !0x3f == 0 && target_status & (2 | 4) == (2 | 4) && target_status & 8 == 0,
    )?;
    for expected in [
        LAMBDA,
        "java/lang/Runnable",
        "run",
        "()V",
        OWNER,
        TARGET,
        "()V",
    ] {
        require(sam.utf8()? == expected)?;
    }
    require(sam.u8()? == 0 && sam.u8()? == 0 && sam.u16()? == 0)?;
    let count = sam.u32()?;
    require((1..=256).contains(&count))?;
    let mut refs = std::collections::BTreeSet::new();
    let expected = [OWNER, "java/lang/Object", "java/lang/Runnable"];
    require(count as usize == expected.len())?;
    for expected in expected {
        let actual = sam.utf8()?;
        require(refs.insert(actual) && actual == expected)?;
    }
    sam.end()?;
    Ok(DefinitionFixtureSummary {
        observed_status: status,
        issuer_epoch: epoch.to_string(),
        ordinary: summary(&ordinary),
        samless_hidden: summary(&samless),
        positive_hidden: summary(&positive),
        target_class_status: target_status,
    })
}

#[cfg(test)]
#[path = "definition_startup_tests.rs"]
mod tests;
