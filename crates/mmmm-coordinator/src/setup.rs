//! Public game-host setup. This metadata contains no capability, grant or
//! policy revision. Registration hashes ordinary local files selected by the
//! user; runtime pairing still checks live native/player authority separately.

use mmmm_contracts::{ContractValidator, ProjectId, Sha256Digest, encode_json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicHostSetup {
    pub executable: PathBuf,
    pub executable_sha256: Sha256Digest,
    pub data_root: PathBuf,
    pub project_id: ProjectId,
    pub scope: Value,
    pub host_artifact_digest: Sha256Digest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupError {
    UnsafePath,
    InvalidSetup,
    InputLimit,
    Timeout,
    Io,
    ExistingConfig,
}
impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsafePath => "Host setup requires an absolute ordinary local path",
            Self::InvalidSetup => "Host setup metadata violates its public contract",
            Self::InputLimit => "Host setup artifact exceeds its byte budget",
            Self::Timeout => "Host setup verification exceeded its finite deadline",
            Self::Io => "Host setup local file access failed",
            Self::ExistingConfig => {
                "Host setup already exists; the current public setup was retained"
            }
        })
    }
}
impl std::error::Error for SetupError {}
impl PublicHostSetup {
    pub fn create(
        executable: &Path,
        installed_host_jar: &Path,
        data_root: &Path,
        project_id: ProjectId,
        scope: Value,
    ) -> Result<Self, SetupError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let executable = verified_regular_path(executable, ArtifactKind::Executable)?;
        let jar = verified_regular_path(installed_host_jar, ArtifactKind::HostJar)?;
        verify_local_path(data_root, true)?;
        validate_scope(&project_id, &scope)?;
        let executable_sha256 = hash_regular(&executable, ArtifactKind::Executable, deadline)?;
        let host_artifact_digest = hash_regular(&jar, ArtifactKind::HostJar, deadline)?;
        Ok(Self {
            executable,
            executable_sha256,
            data_root: data_root.to_path_buf(),
            project_id,
            scope,
            host_artifact_digest,
        })
    }
    pub fn validate(&self) -> Result<(), SetupError> {
        verified_regular_path(&self.executable, ArtifactKind::Executable)?;
        verify_local_path(&self.data_root, true)?;
        validate_scope(&self.project_id, &self.scope)
    }
    /// A host or bridge repeats this immediately before launch/use; editing
    /// metadata or replacing the binary does not retain the approved digest.
    pub fn verify_executable(&self) -> Result<(), SetupError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        self.validate()?;
        if hash_regular(&self.executable, ArtifactKind::Executable, deadline)?
            != self.executable_sha256
        {
            return Err(SetupError::InvalidSetup);
        }
        Ok(())
    }
    /// The caller explicitly selects its game config directory. Only the fixed
    /// public config name is eligible, and an existing file is never replaced.
    pub fn write_new(&self, destination: &Path) -> Result<(), SetupError> {
        self.validate()?;
        if destination
            .file_name()
            .is_none_or(|name| name != "mmmm-host.json")
        {
            return Err(SetupError::UnsafePath);
        }
        validate_path(destination)?;
        let value = serde_json::to_value(self).map_err(|_| SetupError::InvalidSetup)?;
        let bytes = encode_json(&value).map_err(|_| SetupError::InvalidSetup)?;
        if bytes.len() > 65_536 {
            return Err(SetupError::InputLimit);
        }
        let mut owned = platform::create_new(destination)?;
        owned.file.write_all(&bytes).map_err(|_| SetupError::Io)?;
        owned.file.sync_all().map_err(|_| SetupError::Io)?;
        #[cfg(unix)]
        owned
            ._parents
            .last()
            .ok_or(SetupError::UnsafePath)?
            .sync_all()
            .map_err(|_| SetupError::Io)?;
        Ok(())
    }
}
fn validate_scope(project: &ProjectId, scope: &Value) -> Result<(), SetupError> {
    ContractValidator::shared()
        .and_then(|validator| validator.validate("Scope", scope))
        .map_err(|_| SetupError::InvalidSetup)?;
    if scope["projectId"] != project.as_str() {
        return Err(SetupError::InvalidSetup);
    }
    let parsed: mmmm_runtime::storage::WriteScope =
        serde_json::from_value(scope.clone()).map_err(|_| SetupError::InvalidSetup)?;
    parsed.validate().map_err(|_| SetupError::InvalidSetup)
}
#[derive(Clone, Copy)]
enum ArtifactKind {
    Executable,
    HostJar,
}

/// Ancestors remain owned for the complete verification/hash or config write.
/// Unix resolves descendants relative to these descriptors. Windows denies
/// ancestor deletion and final-file write/delete sharing, and checks the actual
/// opened handle's reparse attributes rather than following path metadata.
struct PlainFile {
    file: File,
    _parents: Vec<File>,
}

fn checked_artifact(path: &Path, kind: ArtifactKind) -> Result<PlainFile, SetupError> {
    validate_path(path)?;
    match kind {
        ArtifactKind::HostJar
            if !path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("jar")) =>
        {
            return Err(SetupError::UnsafePath);
        }
        #[cfg(windows)]
        ArtifactKind::Executable
            if !path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("exe")) =>
        {
            return Err(SetupError::UnsafePath);
        }
        _ => (),
    }
    let opened = platform::open_regular(path)?;
    #[cfg(unix)]
    if matches!(kind, ArtifactKind::Executable) {
        use std::os::unix::fs::PermissionsExt;
        if opened
            .file
            .metadata()
            .map_err(|_| SetupError::Io)?
            .permissions()
            .mode()
            & 0o111
            == 0
        {
            return Err(SetupError::UnsafePath);
        }
    }
    Ok(opened)
}

fn verified_regular_path(path: &Path, kind: ArtifactKind) -> Result<PathBuf, SetupError> {
    let _opened = checked_artifact(path, kind)?;
    // Preserve the explicitly selected absolute path. No later canonicalize
    // lookup can adopt a replaced ancestor; every actual use opens it again.
    Ok(path.to_path_buf())
}

fn hash_regular(
    path: &Path,
    kind: ArtifactKind,
    deadline: Instant,
) -> Result<Sha256Digest, SetupError> {
    if Instant::now() >= deadline {
        return Err(SetupError::Timeout);
    }
    let mut opened = checked_artifact(path, kind)?;
    let before = opened.file.metadata().map_err(|_| SetupError::Io)?;
    if before.len() > 512 * 1024 * 1024 {
        return Err(SetupError::InputLimit);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut length = 0u64;
    loop {
        if Instant::now() >= deadline {
            return Err(SetupError::Timeout);
        }
        let count = opened.file.read(&mut buffer).map_err(|_| SetupError::Io)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .ok_or(SetupError::InputLimit)?;
        if length > 512 * 1024 * 1024 {
            return Err(SetupError::InputLimit);
        }
        digest.update(&buffer[..count]);
    }
    let after = opened.file.metadata().map_err(|_| SetupError::Io)?;
    if length != before.len()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
    {
        return Err(SetupError::InvalidSetup);
    }
    let text: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if Instant::now() >= deadline {
        return Err(SetupError::Timeout);
    }
    Sha256Digest::new(text).map_err(|_| SetupError::InvalidSetup)
}
fn verify_local_path(path: &Path, allow_missing_leaf: bool) -> Result<(), SetupError> {
    validate_path(path)?;
    platform::verify_directory(path, allow_missing_leaf)
}

fn validate_path(path: &Path) -> Result<(), SetupError> {
    if !path.is_absolute()
        || path.components().count() > 66
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(SetupError::UnsafePath);
    }
    #[cfg(windows)]
    if path.components().any(|component|matches!(component, Component::Prefix(prefix) if !matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)))) { return Err(SetupError::UnsafePath); }
    if path.file_name().is_none() {
        return Err(SetupError::UnsafePath);
    }
    for component in path.components() {
        if let Component::Normal(name) = component {
            let Some(value) = name.to_str() else {
                return Err(SetupError::UnsafePath);
            };
            let lower = value.to_ascii_lowercase();
            // Reject known secret-file and SSH directory selectors before any
            // open/hash. No secret bytes are inspected to classify a path.
            if lower == ".env"
                || lower.starts_with(".env.")
                || lower == ".ssh"
                || matches!(
                    lower.as_str(),
                    "credentials"
                        | "credential"
                        | "credentials.json"
                        | "credential.json"
                        | "service-account.json"
                        | "service_account.json"
                        | "serviceaccount.json"
                )
                || ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]
                    .iter()
                    .any(|stem| {
                        lower
                            .strip_prefix(*stem)
                            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('.'))
                    })
            {
                return Err(SetupError::UnsafePath);
            }
            #[cfg(windows)]
            {
                let stem = lower.split('.').next().unwrap_or_default();
                if value.encode_utf16().count() > 255
                    || value.ends_with('.')
                    || value.ends_with(' ')
                    || value.chars().any(|character| {
                        character.is_control()
                            || matches!(
                                character,
                                ':' | '/' | '\\' | '<' | '>' | '"' | '|' | '?' | '*'
                            )
                    })
                    || matches!(stem, "con" | "prn" | "aux" | "nul" | "clock$")
                    || stem
                        .strip_prefix("com")
                        .or_else(|| stem.strip_prefix("lpt"))
                        .is_some_and(|suffix| {
                            matches!(
                                suffix,
                                "1" | "2"
                                    | "3"
                                    | "4"
                                    | "5"
                                    | "6"
                                    | "7"
                                    | "8"
                                    | "9"
                                    | "¹"
                                    | "²"
                                    | "³"
                            )
                        })
                {
                    return Err(SetupError::UnsafePath);
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::{
        ffi::{CString, OsStr},
        fs::OpenOptions,
        io,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        },
    };

    fn child_name(name: &OsStr) -> Result<CString, SetupError> {
        CString::new(name.as_bytes()).map_err(|_| SetupError::UnsafePath)
    }
    fn open_at(
        parent: &File,
        name: &OsStr,
        flags: i32,
        mode: libc::mode_t,
    ) -> Result<File, io::Error> {
        #[cfg(target_os = "macos")]
        let mode = libc::c_uint::from(mode);
        let name = child_name(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: live parent descriptor, one NUL-terminated child name and
        // bounded fixed flags. O_NONBLOCK avoids waiting on a swapped FIFO;
        // O_NOFOLLOW forbids adopting a symlink at this resolution step.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                mode,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful new descriptor transfers exactly once.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
    fn parents(path: &Path) -> Result<Vec<File>, SetupError> {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        );
        let root = options.open("/").map_err(|_| SetupError::Io)?;
        let mut parents = vec![root];
        let components: Vec<_> = path.components().collect();
        for component in &components[1..components.len() - 1] {
            let Component::Normal(name) = component else {
                return Err(SetupError::UnsafePath);
            };
            let parent = parents.last().ok_or(SetupError::UnsafePath)?;
            let directory = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                .map_err(|_| SetupError::Io)?;
            if !directory.metadata().map_err(|_| SetupError::Io)?.is_dir() {
                return Err(SetupError::UnsafePath);
            }
            parents.push(directory);
        }
        Ok(parents)
    }
    pub(super) fn open_regular(path: &Path) -> Result<PlainFile, SetupError> {
        let parents = parents(path)?;
        let parent = parents.last().ok_or(SetupError::UnsafePath)?;
        let file = open_at(
            parent,
            path.file_name().ok_or(SetupError::UnsafePath)?,
            libc::O_RDONLY,
            0,
        )
        .map_err(|_| SetupError::Io)?;
        if !file.metadata().map_err(|_| SetupError::Io)?.is_file() {
            return Err(SetupError::UnsafePath);
        }
        Ok(PlainFile {
            file,
            _parents: parents,
        })
    }
    pub(super) fn create_new(path: &Path) -> Result<PlainFile, SetupError> {
        let parents = parents(path)?;
        let parent = parents.last().ok_or(SetupError::UnsafePath)?;
        let file = open_at(
            parent,
            path.file_name().ok_or(SetupError::UnsafePath)?,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                SetupError::ExistingConfig
            } else {
                SetupError::Io
            }
        })?;
        if !file.metadata().map_err(|_| SetupError::Io)?.is_file() {
            return Err(SetupError::UnsafePath);
        }
        Ok(PlainFile {
            file,
            _parents: parents,
        })
    }
    pub(super) fn verify_directory(path: &Path, allow_missing: bool) -> Result<(), SetupError> {
        let parents = parents(path)?;
        match open_at(
            parents.last().ok_or(SetupError::UnsafePath)?,
            path.file_name().ok_or(SetupError::UnsafePath)?,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            Ok(file) if file.metadata().map_err(|_| SetupError::Io)?.is_dir() => Ok(()),
            Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(SetupError::UnsafePath),
            Err(_) => Err(SetupError::Io),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture_root() -> PathBuf {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("physical fixture parent");
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).expect("public fixture ownership nonce");
        let root = parent.join(format!(
            "mmmm-setup-{}-{:016x}",
            std::process::id(),
            u64::from_be_bytes(nonce)
        ));
        let checkout = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .expect("physical checkout");
        assert!(root.is_absolute() && !root.starts_with(checkout));
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).expect("exclusive owned fixture root");
        root
    }

    #[test]
    fn public_setup_retains_config_and_rejects_replaced_binary_digest() {
        let root = fixture_root();
        let executable = root.join("mmmm-coordinator.exe");
        let jar = root.join("mmmm-host.jar");
        // These public bytes test filesystem/digest behavior only. This fixture
        // neither executes a binary nor claims a valid JVM host installation.
        fs::write(&executable, b"owned setup executable fixture\n").unwrap();
        fs::write(&jar, b"owned setup jar fixture\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let project = ProjectId::new("project-setup").unwrap();
        let scope = serde_json::json!({"projectId":"project-setup","resourceIds":[],"objectIds":[],"regions":[],"externalTargetIds":[]});
        let setup = PublicHostSetup::create(
            &executable,
            &jar,
            &root.join("data"),
            project.clone(),
            scope.clone(),
        )
        .unwrap();
        setup.verify_executable().unwrap();
        let destination = root.join("mmmm-host.json");
        setup.write_new(&destination).unwrap();
        assert_eq!(
            setup.write_new(&destination),
            Err(SetupError::ExistingConfig)
        );
        fs::write(&executable, b"changed public executable fixture\n").unwrap();
        assert_eq!(setup.verify_executable(), Err(SetupError::InvalidSetup));
        let invalid_root = root.join("not-directory");
        fs::write(&invalid_root, b"ordinary public file\n").unwrap();
        assert!(PublicHostSetup::create(&executable, &jar, &invalid_root, project, scope).is_err());
        // Exact generated fixture entries only. Any failure before this point
        // retains its owned root; no recursive cleanup crosses a link boundary.
        for file in [executable, jar, destination, invalid_root] {
            fs::remove_file(file).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fifo_artifact_is_rejected_without_waiting_for_a_writer() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let root = fixture_root();
        let path = root.join("mmmm-host.jar");
        let encoded = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: one new public fixture entry below the exclusive owned root.
        assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        assert!(matches!(
            hash_regular(
                &path,
                ArtifactKind::HostJar,
                started + Duration::from_millis(100)
            ),
            Err(SetupError::UnsafePath)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn both_leaf_and_ancestor_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let root = fixture_root();
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        let jar = target.join("mmmm-host.jar");
        fs::write(&jar, b"public artifact bytes\n").unwrap();
        let leaf = root.join("leaf.jar");
        let ancestor = root.join("ancestor");
        symlink(&jar, &leaf).unwrap();
        symlink(&target, &ancestor).unwrap();
        assert!(
            hash_regular(
                &leaf,
                ArtifactKind::HostJar,
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            hash_regular(
                &ancestor.join("mmmm-host.jar"),
                ArtifactKind::HostJar,
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
        );
        fs::remove_file(leaf).unwrap();
        fs::remove_file(ancestor).unwrap();
        assert!(
            !fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(jar).unwrap();
        fs::remove_dir(target).unwrap();
        fs::remove_dir(root).unwrap();
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        fs::OpenOptions,
        io,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
    };
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;

    fn plain(file: &File, directory: bool) -> Result<(), SetupError> {
        let metadata = file.metadata().map_err(|_| SetupError::Io)?;
        if metadata.file_attributes() & 0x400 != 0
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            return Err(SetupError::UnsafePath);
        }
        Ok(())
    }
    fn directory(path: &Path) -> Result<File, io::Error> {
        OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(OPEN_REPARSE_POINT | BACKUP_SEMANTICS)
            .open(path)
    }
    fn parents(path: &Path) -> Result<Vec<File>, SetupError> {
        let components: Vec<_> = path.components().collect();
        if components.len() < 3 {
            return Err(SetupError::UnsafePath);
        }
        let mut current = PathBuf::new();
        current.push(components[0]);
        current.push(components[1]);
        let root = directory(&current).map_err(|_| SetupError::Io)?;
        plain(&root, true)?;
        let mut parents = vec![root];
        for component in &components[2..components.len() - 1] {
            current.push(component.as_os_str());
            let held = directory(&current).map_err(|_| SetupError::Io)?;
            plain(&held, true)?;
            parents.push(held);
        }
        Ok(parents)
    }
    pub(super) fn open_regular(path: &Path) -> Result<PlainFile, SetupError> {
        let parents = parents(path)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| SetupError::Io)?;
        plain(&file, false)?;
        Ok(PlainFile {
            file,
            _parents: parents,
        })
    }
    pub(super) fn create_new(path: &Path) -> Result<PlainFile, SetupError> {
        let parents = parents(path)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(1)
            .custom_flags(OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    SetupError::ExistingConfig
                } else {
                    SetupError::Io
                }
            })?;
        plain(&file, false)?;
        Ok(PlainFile {
            file,
            _parents: parents,
        })
    }
    pub(super) fn verify_directory(path: &Path, allow_missing: bool) -> Result<(), SetupError> {
        let _parents = parents(path)?;
        match directory(path) {
            Ok(file) => plain(&file, true),
            Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SetupError::Io),
        }
    }
}
