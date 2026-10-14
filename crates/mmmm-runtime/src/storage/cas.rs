use super::{BlobRef, GcReport, StorageError, StorageResult};
use mmmm_contracts::{Sha256Digest, raw_digest};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn verify_plain_path(path: &Path) -> StorageResult<()> {
    if !path.is_absolute() {
        return Err(StorageError::UnsafePath);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err(StorageError::UnsafePath);
        }
        current.push(component);
        #[cfg(windows)]
        if let Component::Prefix(prefix) = component {
            // A lexical drive prefix is not a filesystem entry. In particular,
            // querying bare \\?\C: opens a volume/device path rather than C:\.
            // Inspect it only after RootDir supplies the rooted path. Every
            // actual directory/file component below is still reparse-checked.
            // https://learn.microsoft.com/windows/win32/fileio/naming-a-file
            if !matches!(
                prefix.kind(),
                std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
            ) {
                return Err(StorageError::UnsafePath);
            }
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(StorageError::UnsafePath);
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(StorageError::UnsafePath);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(crate) fn create_private_dir(path: &Path) -> StorageResult<()> {
    verify_plain_path(path)?;
    if !path.exists() {
        let mut created = Vec::new();
        let mut candidate = path.to_path_buf();
        while !candidate.exists() {
            created.push(candidate.clone());
            candidate = candidate
                .parent()
                .ok_or(StorageError::UnsafePath)?
                .to_path_buf();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(path)?;
        for directory in created.iter().rev() {
            sync_dir(directory.parent().ok_or(StorageError::UnsafePath)?)?;
        }
    }
    verify_plain_path(path)?;
    if !fs::metadata(path)?.is_dir() {
        return Err(StorageError::UnsafePath);
    }
    Ok(())
}

pub(crate) fn verify_private_root(path: &Path) -> StorageResult<()> {
    verify_plain_path(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path)?;
        // An existing shared writable root is not silently chmod'ed or adopted.
        // SAFETY: geteuid has no arguments or pointers and does not mutate state.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(StorageError::UnsafePath);
        }
    }
    Ok(())
}

pub(crate) fn private_new_file(path: &Path) -> StorageResult<File> {
    verify_plain_path(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

pub(crate) fn verify_local_filesystem(path: &Path) -> StorageResult<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
        // fileapi.h defines DRIVE_FIXED as 3. Keep this documented return value
        // beside the existing binding instead of enabling an unrelated module.
        // https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getdrivetypew
        const DRIVE_TYPE_FIXED: u32 = 3;
        let component = path.components().next().ok_or(StorageError::UnsafePath)?;
        let Component::Prefix(prefix) = component else {
            return Err(StorageError::UnsafePath);
        };
        let drive = match prefix.kind() {
            std::path::Prefix::Disk(letter) | std::path::Prefix::VerbatimDisk(letter) => {
                PathBuf::from(format!("{}:\\", char::from(letter)))
            }
            _ => return Err(StorageError::NonLocalFilesystem),
        };
        let wide: Vec<u16> = drive.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: the buffer is NUL-terminated and remains live for the call.
        if unsafe { GetDriveTypeW(wide.as_ptr()) } != DRIVE_TYPE_FIXED {
            return Err(StorageError::NonLocalFilesystem);
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::{ffi::CString, mem::MaybeUninit, os::unix::ffi::OsStrExt};
        let name =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| StorageError::UnsafePath)?;
        let mut stat = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: stat points to writable statfs storage; name is NUL-terminated.
        if unsafe { libc::statfs(name.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: statfs succeeded and initialized the structure.
        let kind = unsafe { stat.assume_init() }.f_type as u64;
        // NFS, SMB/CIFS, CODA, AFS, 9P and FUSE may be remote; fail closed for FUSE.
        if matches!(
            kind,
            0x6969
                | 0x517b
                | 0xff534d42
                | 0xfe534d42
                | 0x73757245
                | 0x5346414f
                | 0x01021997
                | 0x65735546
        ) {
            return Err(StorageError::NonLocalFilesystem);
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::{ffi::CString, mem::MaybeUninit, os::unix::ffi::OsStrExt};
        let name =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| StorageError::UnsafePath)?;
        let mut stat = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: arguments are a valid C string and writable statfs storage.
        if unsafe { libc::statfs(name.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: statfs initialized the structure successfully.
        if unsafe { stat.assume_init() }.f_flags & libc::MNT_LOCAL as u32 == 0 {
            return Err(StorageError::NonLocalFilesystem);
        }
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    return Err(StorageError::NonLocalFilesystem);
    Ok(())
}

#[cfg(unix)]
pub(crate) fn sync_dir(path: &Path) -> StorageResult<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
pub(crate) fn sync_dir(_path: &Path) -> StorageResult<()> {
    Ok(())
}

fn publish(source: &Path, target: &Path) -> StorageResult<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
        let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let target: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both arguments are valid NUL-terminated buffers. Replacement is
        // deliberately not enabled: an existing immutable digest is never overwritten.
        if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(unix)]
    {
        // One Coordinator owns the root. hard_link provides no-clobber atomic
        // publication on the same filesystem, then directory fsync commits it.
        fs::hard_link(source, target)?;
        sync_dir(target.parent().ok_or(StorageError::UnsafePath)?)?;
        fs::remove_file(source)?;
        sync_dir(source.parent().ok_or(StorageError::UnsafePath)?)?;
    }
    Ok(())
}

pub(crate) struct Cas {
    pub(crate) root: PathBuf,
    max_bytes: u64,
}
impl Cas {
    pub(crate) fn open_existing(root: PathBuf, max_bytes: u64) -> StorageResult<Self> {
        if max_bytes == 0 || max_bytes > i64::MAX as u64 {
            return Err(StorageError::InvalidInput(
                "Blob limit must be positive and fit SQLite's signed length".into(),
            ));
        }
        for directory in [&root, &root.join("incoming")] {
            verify_plain_path(directory)?;
            if !fs::metadata(directory)?.is_dir() {
                return Err(StorageError::UnsafePath);
            }
        }
        Ok(Self { root, max_bytes })
    }

    pub(crate) fn open(root: PathBuf, max_bytes: u64) -> StorageResult<Self> {
        if max_bytes == 0 || max_bytes > i64::MAX as u64 {
            return Err(StorageError::InvalidInput(
                "Blob limit must be positive and fit SQLite's signed length".into(),
            ));
        }
        create_private_dir(&root)?;
        create_private_dir(&root.join("incoming"))?;
        sync_dir(root.parent().ok_or(StorageError::UnsafePath)?)?;
        sync_dir(&root)?;
        Ok(Self { root, max_bytes })
    }
    pub(crate) fn path(&self, digest: &Sha256Digest) -> PathBuf {
        self.root
            .join(&digest.as_str()[..2])
            .join(&digest.as_str()[2..])
    }
    pub(crate) fn put(&self, bytes: &[u8]) -> StorageResult<BlobRef> {
        if bytes.len() as u64 > self.max_bytes {
            return Err(StorageError::InvalidInput(
                "Blob exceeds byte budget".into(),
            ));
        }
        let blob = BlobRef {
            digest: raw_digest(bytes),
            byte_length: bytes.len() as u64,
        };
        let target = self.path(&blob.digest);
        verify_plain_path(&target)?;
        if target.exists() {
            self.verify(&blob)?;
            return Ok(blob);
        }
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StorageError::InvalidInput("System clock precedes the Unix epoch".into()))?
            .as_nanos();
        let incoming = self.root.join("incoming").join(format!(
            "{}-{created}-{sequence}.pending",
            std::process::id()
        ));
        let mut file = private_new_file(&incoming)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        let (digest, length) = self.hash_file(&incoming)?;
        if digest != blob.digest || length != blob.byte_length {
            return Err(StorageError::Corrupt(
                "Staged blob failed flushed readback".into(),
            ));
        }
        create_private_dir(target.parent().ok_or(StorageError::UnsafePath)?)?;
        sync_dir(&self.root)?;
        publish(&incoming, &target)?;
        self.verify(&blob)?;
        Ok(blob)
    }
    fn hash_file(&self, path: &Path) -> StorageResult<(Sha256Digest, u64)> {
        verify_plain_path(path)?;
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() || metadata.len() > self.max_bytes {
            return Err(StorageError::Corrupt(
                "CAS entry has invalid type or exceeds byte budget".into(),
            ));
        }
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        let mut length = 0u64;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            length = length
                .checked_add(count as u64)
                .ok_or_else(|| StorageError::Corrupt("Blob length overflow".into()))?;
            if length > self.max_bytes {
                return Err(StorageError::Corrupt(
                    "CAS entry grew beyond byte budget".into(),
                ));
            }
            hasher.update(&buffer[..count]);
        }
        Ok((Sha256Digest::from_bytes(hasher.finalize().into()), length))
    }
    pub(crate) fn verify(&self, blob: &BlobRef) -> StorageResult<()> {
        let (digest, length) = self.hash_file(&self.path(&blob.digest))?;
        if digest != blob.digest || length != blob.byte_length {
            return Err(StorageError::Corrupt(
                "CAS entry does not match its digest and length".into(),
            ));
        }
        Ok(())
    }
    pub(crate) fn read(&self, blob: &BlobRef) -> StorageResult<Vec<u8>> {
        // Read once and verify those exact returned bytes, not a separate handle's contents.
        let path = self.path(&blob.digest);
        verify_plain_path(&path)?;
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(StorageError::Corrupt(
                "CAS entry is not a regular file".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(self.max_bytes + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > self.max_bytes
            || bytes.len() as u64 != blob.byte_length
            || raw_digest(&bytes) != blob.digest
        {
            return Err(StorageError::Corrupt(
                "CAS read failed digest and length verification".into(),
            ));
        }
        Ok(bytes)
    }
    /// Capture a bounded range while verifying its whole immutable blob in one
    /// streaming pass. Hashing followed by a seek/read would introduce a second
    /// observation and could return bytes different from those just hashed.
    pub(crate) fn read_verified_slice<E, F>(
        &self,
        blob: &BlobRef,
        offset: u64,
        limit: usize,
        check: F,
    ) -> Result<Vec<u8>, E>
    where
        E: From<StorageError>,
        F: FnMut() -> Result<(), E>,
    {
        if limit == 0 || limit > 65_536 {
            return Err(
                StorageError::InvalidInput("CAS slice exceeds its byte budget".into()).into(),
            );
        }
        self.read_verified_range(blob, offset, limit, check)
    }

    pub(crate) fn read_verified_document<E, F>(
        &self,
        blob: &BlobRef,
        max_document_bytes: u64,
        check: F,
    ) -> Result<Vec<u8>, E>
    where
        E: From<StorageError>,
        F: FnMut() -> Result<(), E>,
    {
        if blob.byte_length > max_document_bytes {
            return Err(
                StorageError::InvalidInput("CAS document exceeds its byte budget".into()).into(),
            );
        }
        let limit = usize::try_from(blob.byte_length).map_err(|_| {
            E::from(StorageError::InvalidInput(
                "CAS document length exceeds addressable memory".into(),
            ))
        })?;
        self.read_verified_range(blob, 0, limit, check)
    }

    fn read_verified_range<E, F>(
        &self,
        blob: &BlobRef,
        offset: u64,
        limit: usize,
        mut check: F,
    ) -> Result<Vec<u8>, E>
    where
        E: From<StorageError>,
        F: FnMut() -> Result<(), E>,
    {
        check()?;
        if blob.byte_length > self.max_bytes {
            return Err(
                StorageError::InvalidInput("CAS read exceeds its byte budget".into()).into(),
            );
        }
        let end = offset
            .checked_add(limit as u64)
            .ok_or_else(|| {
                E::from(StorageError::InvalidInput(
                    "CAS slice range overflow".into(),
                ))
            })?
            .min(blob.byte_length);
        if offset > blob.byte_length {
            return Err(
                StorageError::InvalidInput("CAS slice starts beyond its blob".into()).into(),
            );
        }
        let path = self.path(&blob.digest);
        verify_plain_path(&path).map_err(E::from)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // A raced final symlink or FIFO is never followed/blockingly read.
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
            };
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN);
        }
        check()?;
        let mut file = options
            .open(path)
            .map_err(StorageError::from)
            .map_err(E::from)?;
        let metadata = file
            .metadata()
            .map_err(StorageError::from)
            .map_err(E::from)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(StorageError::UnsafePath.into());
            }
        }
        if !metadata.is_file() || metadata.len() != blob.byte_length {
            return Err(StorageError::Corrupt(
                "CAS slice source differs from its length pin".into(),
            )
            .into());
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0; 65_536];
        let mut position = 0u64;
        let mut slice = Vec::with_capacity((end - offset) as usize);
        loop {
            check()?;
            // Read at most the declared length plus one byte: even concurrent
            // growth has a finite read bound and can never be silently ignored.
            let allowance = blob.byte_length.saturating_sub(position).saturating_add(1);
            let read_length = allowance.min(buffer.len() as u64) as usize;
            let count = file
                .read(&mut buffer[..read_length])
                .map_err(StorageError::from)
                .map_err(E::from)?;
            check()?;
            if count == 0 {
                break;
            }
            let next = position.checked_add(count as u64).ok_or_else(|| {
                E::from(StorageError::Corrupt(
                    "CAS slice source length overflow".into(),
                ))
            })?;
            if next > blob.byte_length {
                return Err(StorageError::Corrupt(
                    "CAS slice source grew beyond its length pin".into(),
                )
                .into());
            }
            hasher.update(&buffer[..count]);
            let start_in_chunk = offset.max(position);
            let end_in_chunk = end.min(next);
            if start_in_chunk < end_in_chunk {
                slice.extend_from_slice(
                    &buffer
                        [(start_in_chunk - position) as usize..(end_in_chunk - position) as usize],
                );
            }
            position = next;
        }
        let digest = Sha256Digest::from_bytes(hasher.finalize().into());
        if position != blob.byte_length || digest != blob.digest {
            return Err(StorageError::Corrupt(
                "CAS slice failed digest and length verification".into(),
            )
            .into());
        }
        check()?;
        Ok(slice)
    }
    pub(crate) fn collect(
        &self,
        keep: &std::collections::BTreeSet<Sha256Digest>,
        max_entries: usize,
    ) -> StorageResult<GcReport> {
        if max_entries == 0 {
            return Err(StorageError::InvalidInput(
                "GC entry budget must be positive".into(),
            ));
        }
        let mut report = GcReport::default();
        let mut examined = 0usize;
        // Only exact CAS digest paths are candidates. Unknown names, incoming
        // files and interruption artifacts are preserved for explicit recovery.
        for bucket in fs::read_dir(&self.root)? {
            examined += 1;
            if examined > max_entries {
                return Err(StorageError::InvalidInput(
                    "GC traversal entry budget exceeded".into(),
                ));
            }
            let bucket = bucket?;
            let name = bucket.file_name().to_string_lossy().into_owned();
            if name.len() != 2
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                continue;
            }
            verify_plain_path(&bucket.path())?;
            if !bucket.file_type()?.is_dir() {
                return Err(StorageError::Corrupt(
                    "CAS bucket is not a directory".into(),
                ));
            }
            for entry in fs::read_dir(bucket.path())? {
                examined += 1;
                if examined > max_entries {
                    return Err(StorageError::InvalidInput(
                        "GC traversal entry budget exceeded".into(),
                    ));
                }
                let entry = entry?;
                let tail = entry.file_name().to_string_lossy().into_owned();
                let Ok(digest) = Sha256Digest::new(format!("{name}{tail}")) else {
                    continue;
                };
                verify_plain_path(&entry.path())?;
                if !entry.file_type()?.is_file() {
                    return Err(StorageError::Corrupt(
                        "CAS digest entry is not a regular file".into(),
                    ));
                }
                if keep.contains(&digest) {
                    report.preserved_referenced += 1;
                    continue;
                }
                let bytes = entry.metadata()?.len();
                fs::remove_file(entry.path())?;
                sync_dir(&bucket.path())?;
                report.removed_blobs += 1;
                report.removed_bytes = report.removed_bytes.saturating_add(bytes);
            }
        }
        Ok(report)
    }
}
