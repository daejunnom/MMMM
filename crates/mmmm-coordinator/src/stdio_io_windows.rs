//! Native Windows ownership: atomic Job association and an inherited handle
//! allowlist. The parent never starts an overlapped or blocking stdio operation.
use super::{Executable, StdioError};
use std::{
    fs::{File, OpenOptions},
    mem::{size_of, size_of_val, zeroed},
    net::SocketAddr,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, GENERIC_WRITE, HANDLE,
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TYPE_PIPE, FILE_TYPE_UNKNOWN, GetFileInformationByHandle,
        GetFileType, OPEN_EXISTING, ReadFile, WriteFile,
    },
    System::{
        Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        JobObjects::{
            CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Pipes::{CreatePipe, PeekNamedPipe},
        SystemInformation::GetSystemWindowsDirectoryW,
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
            GetExitCodeProcess, InitializeProcThreadAttributeList,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
            ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

struct Handle(HANDLE);
// A handle is uniquely owned; operations are serialized by the parent Mutex.
unsafe impl Send for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
struct Attributes {
    storage: Vec<usize>,
}
impl Attributes {
    fn ptr(&mut self) -> *mut std::ffi::c_void {
        self.storage.as_mut_ptr().cast()
    }
    fn new() -> Result<Self, StdioError> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(StdioError::new("native_attributes"));
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 2, 0, &mut bytes)
        } == 0
        {
            // A failed Initialize must not invoke Delete on uninitialized data.
            return Err(StdioError::new("native_attributes"));
        }
        Ok(Self { storage })
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.ptr());
        }
    }
}

pub(super) fn open_executable(path: &Path) -> Result<File, StdioError> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| StdioError::io("executable_open", e))?;
    if file
        .metadata()
        .map_err(|e| StdioError::io("executable_metadata", e))?
        .file_attributes()
        & FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        return Err(StdioError::new("executable_limits"));
    }
    Ok(file)
}
fn identity(file: &File) -> Result<(u32, u32, u32), StdioError> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(StdioError::io(
            "executable_identity",
            std::io::Error::last_os_error(),
        ));
    }
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}
pub(super) fn same_file(file: &File, path: &Path) -> Result<bool, StdioError> {
    Ok(identity(file)? == identity(&open_executable(path)?)?)
}
fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
pub(super) fn minimal_environment(directory: &[u16]) -> Result<Vec<u16>, StdioError> {
    // Winsock provider paths can contain %SystemRoot%. Derive this value from
    // the OS API, never from the parent environment, a file or worker args.
    if directory.len() < 3
        || directory.len() > 32_767
        || !matches!(directory[0], 65..=90 | 97..=122)
        || directory[1] != b':' as u16
        || directory[2] != b'\\' as u16
        || directory.contains(&0)
    {
        return Err(StdioError::new("system_directory"));
    }
    let mut block = Vec::with_capacity(2 * directory.len() + 22);
    // Case-insensitive alphabetical order, with one terminating NUL per entry
    // and a final second NUL. No inherited variables or capability are copied.
    for name in ["SystemRoot=", "windir="] {
        block.extend(name.encode_utf16());
        block.extend_from_slice(directory);
        block.push(0);
    }
    block.push(0);
    Ok(block)
}
fn system_environment() -> Result<Vec<u16>, StdioError> {
    let mut directory = vec![0u16; 32_768];
    let n = unsafe { GetSystemWindowsDirectoryW(directory.as_mut_ptr(), directory.len() as u32) };
    if n == 0 {
        return Err(StdioError::io(
            "system_directory",
            std::io::Error::last_os_error(),
        ));
    }
    if n as usize >= directory.len() {
        return Err(StdioError::new("system_directory"));
    }
    directory.truncate(n as usize);
    // The OS API documents a bare drive prefix when Windows is installed at
    // the volume root. Normalize that case to an absolute root directory.
    if directory.len() == 2 {
        directory.push(b'\\' as u16);
    }
    minimal_environment(&directory)
}
fn duplicate_stdio(which: u32) -> Result<Handle, StdioError> {
    let source = unsafe { GetStdHandle(which) };
    if source.is_null() || source == INVALID_HANDLE_VALUE {
        return Err(StdioError::new("external_stdio"));
    }
    let mut copy = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &mut copy,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(StdioError::new("external_stdio"));
    }
    Ok(Handle(copy))
}
pub(super) fn worker_stdio() -> Result<(File, File), StdioError> {
    fn file(which: u32) -> Result<File, StdioError> {
        let source = unsafe { GetStdHandle(which) };
        if source.is_null() || source == INVALID_HANDLE_VALUE {
            return Err(StdioError::new("external_stdio"));
        }
        let mut copy = null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &mut copy,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(StdioError::new("external_stdio"));
        }
        // File owns this noninheritable duplicate; no standard-library input
        // or output buffer can capture a raw capability beyond the request.
        Ok(unsafe { File::from_raw_handle(copy) })
    }
    Ok((file(STD_INPUT_HANDLE)?, file(STD_OUTPUT_HANDLE)?))
}
fn bootstrap(packet: &[u8]) -> Result<(Handle, Handle), StdioError> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read = null_mut();
    let mut write = null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 4096) } == 0 {
        return Err(StdioError::new("bootstrap_pipe"));
    }
    let read = Handle(read);
    let write = Handle(write);
    if unsafe { SetHandleInformation(write.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(StdioError::new("bootstrap_pipe"));
    }
    // A fresh 4 KiB pipe contains no previous data. This fixed 96-byte packet
    // fits before the worker exists; no external sink or pipe writer competes.
    let mut n = 0;
    if packet.len() != 96
        || unsafe { WriteFile(write.0, packet.as_ptr(), 96, &mut n, null_mut()) } == 0
        || n != 96
    {
        return Err(StdioError::new("bootstrap_pipe"));
    }
    Ok((read, write))
}
pub(super) fn read_bootstrap(value: usize) -> Result<zeroize::Zeroizing<[u8; 96]>, StdioError> {
    if value == 0 || value == usize::MAX {
        return Err(StdioError::new("bootstrap_handle"));
    }
    let handle = value as HANDLE;
    let kind = unsafe { GetFileType(handle) };
    if kind != FILE_TYPE_PIPE {
        return Err(if kind == FILE_TYPE_UNKNOWN {
            StdioError::io("bootstrap_type", std::io::Error::last_os_error())
        } else {
            StdioError::new("bootstrap_type")
        });
    }
    // Reject ordinary file handles before any read. The hidden entry owns the
    // single pipe read end explicitly inherited by its parent. The full fixed
    // packet was buffered before spawn; no blocking read is started otherwise.
    let _owned = unsafe { File::from_raw_handle(handle) };
    let mut available = 0;
    if unsafe {
        PeekNamedPipe(
            handle,
            null_mut(),
            0,
            null_mut(),
            &mut available,
            null_mut(),
        )
    } == 0
    {
        return Err(StdioError::io(
            "bootstrap_peek",
            std::io::Error::last_os_error(),
        ));
    }
    if available != 96 {
        return Err(StdioError::new("bootstrap_length"));
    }
    let mut packet = zeroize::Zeroizing::new([0u8; 96]);
    let mut n = 0;
    if unsafe { ReadFile(handle, packet.as_mut_ptr(), 96, &mut n, null_mut()) } == 0 {
        return Err(StdioError::io(
            "bootstrap_read",
            std::io::Error::last_os_error(),
        ));
    }
    if n != 96 {
        return Err(StdioError::new("bootstrap_length"));
    }
    Ok(packet)
}

pub(super) struct Process {
    job: Handle,
    leader: Handle,
    pid: u32,
    reaped: bool,
}
impl Process {
    pub(super) fn spawn(
        executable: &Executable,
        address: SocketAddr,
        packet: &[u8],
    ) -> Result<Self, StdioError> {
        let job = Handle(unsafe { CreateJobObjectW(null(), null()) });
        if job.0.is_null() {
            return Err(StdioError::new("native_job"));
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.JobMemoryLimit = 256 * 1024 * 1024;
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(StdioError::new("native_job"));
        }
        let (read, write) = bootstrap(packet)?;
        let stdin = duplicate_stdio(STD_INPUT_HANDLE)?;
        let stdout = duplicate_stdio(STD_OUTPUT_HANDLE)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let stderr = Handle(unsafe {
            CreateFileW(
                wide(std::ffi::OsStr::new("NUL")).as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        });
        if stderr.0 == INVALID_HANDLE_VALUE {
            return Err(StdioError::new("external_stdio"));
        }
        let mut handles = [stdin.0, stdout.0, stderr.0, read.0];
        let mut jobs = [job.0];
        let mut attrs = Attributes::new()?;
        if unsafe {
            UpdateProcThreadAttribute(
                attrs.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_mut_ptr().cast(),
                size_of_val(&handles),
                null_mut(),
                null_mut(),
            )
        } == 0
            || unsafe {
                UpdateProcThreadAttribute(
                    attrs.ptr(),
                    0,
                    PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                    jobs.as_mut_ptr().cast(),
                    size_of_val(&jobs),
                    null_mut(),
                    null_mut(),
                )
            } == 0
        {
            return Err(StdioError::new("native_attributes"));
        }
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = stdin.0;
        startup.StartupInfo.hStdOutput = stdout.0;
        startup.StartupInfo.hStdError = stderr.0;
        startup.lpAttributeList = attrs.ptr();
        // Only the trusted executable path can need quoting. Numeric handle and
        // IPv4 endpoint arguments cannot contain shell syntax. No shell runs.
        let path = executable
            .path
            .to_str()
            .ok_or_else(|| StdioError::new("executable"))?;
        if path.contains('"') || path.contains('\0') {
            return Err(StdioError::new("executable"));
        }
        let command = format!(
            "\"{path}\" {} {address} {}",
            super::WORKER_COMMAND,
            read.0 as usize
        );
        let mut command = wide(std::ffi::OsStr::new(&command));
        if command.len() > 32767 {
            return Err(StdioError::new("executable"));
        }
        let application = wide(executable.path.as_os_str());
        let environment = system_environment()?;
        let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                null(),
                &startup.StartupInfo,
                &mut info,
            )
        } == 0
        {
            return Err(StdioError::io(
                "native_spawn",
                std::io::Error::last_os_error(),
            ));
        }
        let mut process = Self {
            job,
            leader: Handle(info.hProcess),
            pid: info.dwProcessId,
            reaped: false,
        };
        let thread = Handle(info.hThread);
        drop(write);
        drop(read);
        let mut inside = 0;
        let identity = same_file(&executable.file, &executable.path);
        if unsafe { IsProcessInJob(process.leader.0, process.job.0, &mut inside) } == 0
            || inside == 0
            || !matches!(identity, Ok(true))
        {
            unsafe {
                TerminateProcess(process.leader.0, 125);
            }
            let mut error = StdioError::new("native_identity");
            error.drained = process
                .drain_blocking(Instant::now() + Duration::from_secs(5))
                .is_ok();
            return Err(error);
        }
        if unsafe { ResumeThread(thread.0) } != 1 {
            let mut error = StdioError::new("native_resume");
            error.drained = process
                .drain_blocking(Instant::now() + Duration::from_secs(5))
                .is_ok();
            return Err(error);
        }
        Ok(process)
    }
    pub(super) fn id(&self) -> u64 {
        self.pid as u64
    }
    pub(super) fn exit_code(&mut self) -> Result<Option<i32>, StdioError> {
        match unsafe { WaitForSingleObject(self.leader.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                if unsafe { GetExitCodeProcess(self.leader.0, &mut code) } == 0 {
                    Err(StdioError::new("native_observe"))
                } else {
                    Ok(Some(code as i32))
                }
            }
            _ => Err(StdioError::new("native_observe")),
        }
    }
    pub(super) fn scope_empty(&self) -> Result<bool, StdioError> {
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        if unsafe {
            QueryInformationJobObject(
                self.job.0,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            )
        } == 0
        {
            Err(StdioError::new("native_observe"))
        } else {
            Ok(accounting.ActiveProcesses == 0)
        }
    }
    pub(super) fn terminate(&mut self) -> Result<(), StdioError> {
        if self.reaped {
            return Ok(());
        }
        if unsafe { TerminateJobObject(self.job.0, 124) } == 0 {
            Err(StdioError::new("native_terminate"))
        } else {
            Ok(())
        }
    }
    pub(super) fn reap(&mut self) -> Result<Option<i32>, StdioError> {
        let code = self
            .exit_code()?
            .ok_or_else(|| StdioError::new("native_reap"))?;
        self.reaped = true;
        Ok(Some(code))
    }
    pub(super) fn drain_blocking(&mut self, deadline: Instant) -> Result<(), StdioError> {
        self.terminate()?;
        let mut empty = None;
        loop {
            if self.exit_code()?.is_some() && self.scope_empty()? {
                if empty.is_some_and(|t: Instant| t.elapsed() >= Duration::from_millis(10)) {
                    if Instant::now() >= deadline {
                        return Err(StdioError::new("drain_uncertain"));
                    }
                    self.reap()?;
                    if Instant::now() >= deadline {
                        return Err(StdioError {
                            code: "drain_deadline",
                            drained: true,
                            native_code: None,
                            native_code_unknown: false,
                        });
                    }
                    return Ok(());
                }
                empty.get_or_insert_with(Instant::now);
            } else {
                empty = None;
            }
            if Instant::now() >= deadline {
                return Err(StdioError::new("drain_uncertain"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.drain_blocking(Instant::now() + Duration::from_secs(5));
        }
    }
}
