#!/usr/bin/env python3
"""First Cargo compilation only; later commands use the Rust managed runner.

This stdlib launcher is build infrastructure, not a product contract consumer.
Linux and Darwin require different native process observations. A reserved
session leader stays unreaped until drain proof; no PID-only stale recovery is
provided. Deliberate daemon/session escape is outside this cooperative boundary.
"""

import argparse
import ctypes
import errno
import functools
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import selectors
import shutil
import signal
import stat
import sys
import time


SCHEMA = "mmmm-managed-build/1"
RECORD_LIMIT = 8192
SLOT_LIMIT = 8 * 1024**3
CATALOG_LIMIT = 12 * 1024**3
LOG_LIMIT = 128 * 1024**2
MEMORY_LIMIT = 2 * 1024**3
PROCESS_LIMIT = 32
DARWIN_VM_LIMIT = 512 * 1024**3
DARWIN_SAMPLE_TARGET = 0.1
DARWIN_SAMPLE_GAP = 1.0
U64_MAX = 2**64 - 1
MAX_ENTRIES = 100000
CATALOG_FIELDS = {"schema", "catalog_id"}
LEASE_FIELDS = {"schema", "catalog_id", "slot_id", "token", "pid", "started_ms"}
OWNER_FIELDS = {"schema", "catalog_id", "slot_id", "checkout_digest", "os", "arch",
                "purpose", "token", "pid", "state", "completed_ms"}
cancelled = False
DIRECTORY_PINS = {}
CURRENT_PHASE = "startup"
FAILURE_EVIDENCE = None


def native_call(operation, function, *args, **kwargs):
    """Tag only static operation names; retain native exception subclasses."""
    try:
        return function(*args, **kwargs)
    except (OSError, ValueError) as error:
        if not hasattr(error, "mmmm_operation"):
            error.mmmm_operation = operation
        if isinstance(error, ValueError) and function is resource.setrlimit:
            # CPython maps these native failures to ValueError without errno.
            # Only its fixed resource messages are classified; arbitrary error
            # messages and arguments are never copied into build evidence.
            error.mmmm_classification = {
                "current limit exceeds maximum limit": "resource native EINVAL",
                "not allowed to raise maximum limit": "resource native EPERM",
                "invalid resource specified": "resource index invalid",
            }.get(str(error), "resource ValueError unclassified")
        raise


def native_operation(operation):
    def decorate(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            return native_call(operation, function, *args, **kwargs)
        return wrapped
    return decorate


def script_frames(error):
    """Only public-script function names and line numbers, never local values."""
    frames, inspected = [], 0
    traceback = error.__traceback__
    while traceback is not None and inspected < 64:
        inspected += 1
        code = traceback.tb_frame.f_code
        if (code.co_filename == __file__
                and code.co_name not in ("native_call", "wrapped", "failure_details", "script_frames")):
            name = "".join(character if character.isascii() and (character.isalnum() or character == "_")
                           else "?" for character in code.co_name)[:64]
            frames.append({"function": name, "line": traceback.tb_lineno})
            frames = frames[-5:]
        traceback = traceback.tb_next
    return frames


def failure_details(error):
    # OSError.__str__ can include filenames. These diagnostics contain only
    # static source labels and the OS's numeric error and standard message.
    operation = getattr(error, "mmmm_operation", "unspecified")
    if isinstance(error, OSError):
        number = error.errno if isinstance(error.errno, int) else None
        message = os.strerror(number) if number is not None else "native error unavailable"
        detail = "errno=" + str(number) + " " + message
    elif isinstance(error, RuntimeError):
        detail = str(error)
    elif isinstance(error, ValueError):
        detail = "ValueError"
        if hasattr(error, "mmmm_classification"):
            detail += ": " + error.mmmm_classification
    else:
        detail = type(error).__name__
    detail = "".join(character if 32 <= ord(character) < 127 else "?" for character in detail)[:384]
    details = {"phase": CURRENT_PHASE, "operation": operation, "error": detail}
    frames = script_frames(error)
    if frames:
        details["script_frames"] = frames
    if hasattr(error, "mmmm_cleanup_errors"):
        details["cleanup_errors"] = error.mmmm_cleanup_errors
    return details


def phase(name):
    global CURRENT_PHASE
    CURRENT_PHASE = name


def safe_name(name):
    lower = name.lower()
    if (lower == ".env" or lower.startswith(".env.") or lower == ".ssh"
            or lower.startswith(("id_rsa", "id_ed25519"))
            or any(marker in lower for marker in ("credential", "service-account",
                                                   "service_account", "api-key", "api_key"))
            or lower.endswith((".pem", ".key", ".p12", ".pfx"))):
        raise RuntimeError("secret-named paths are not accessed")


@native_operation("directory traversal")
def open_directory(path, create=False, pin=False):
    path = Path(path)
    if not path.is_absolute() or path.anchor != "/" or ".." in path.parts or "." in path.parts:
        raise RuntimeError("regular absolute directory required")
    current = Path(path.anchor)
    descriptor = native_call("open directory root", os.open, current,
                             os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            safe_name(part)
            current /= part
            if create:
                try:
                    native_call("create directory component", os.mkdir, part, mode=0o700, dir_fd=descriptor)
                    native_call("sync created directory parent", os.fsync, descriptor)
                except FileExistsError:
                    pass
            child = native_call("open directory component", os.open, part,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            physical = metadata.st_dev, metadata.st_ino
            if current in DIRECTORY_PINS and DIRECTORY_PINS[current] != physical:
                raise RuntimeError("opened directory identity changed")
            if pin:
                DIRECTORY_PINS[current] = physical
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def directory(path, create=False):
    path = Path(path)
    os.close(open_directory(path, create, pin=True))
    return path


def separate(first, second):
    if first == second or first in second.parents or second in first.parents:
        raise RuntimeError("managed paths overlap")


def identity(path):
    descriptor = open_directory(path)
    try:
        value = os.fstat(descriptor)
        return value.st_dev, value.st_ino
    finally:
        os.close(descriptor)


def encode_record(record):
    result = json.dumps(record, ensure_ascii=False, separators=(",", ":"),
                        allow_nan=False).encode("utf-8")
    if len(result) > RECORD_LIMIT:
        raise RuntimeError("ownership record exceeds 8 KiB")
    return result


def sync_directory(path):
    descriptor = open_directory(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@native_operation("create and sync record")
def write_new(path, data):
    safe_name(path.name)
    parent = open_directory(path.parent)
    try:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def replace_record(path, record):
    temporary = path.parent / (".record-" + os.urandom(32).hex() + ".tmp")
    write_new(temporary, encode_record(record))
    parent = open_directory(path.parent)
    try:
        os.replace(temporary.name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


@native_operation("read regular file")
def read_regular(path, limit):
    safe_name(path.name)
    parent = open_directory(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > limit:
            raise RuntimeError("record or log kind, link count or size invalid")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise RuntimeError("record or log grew beyond limit")
        return data


def unique_pairs(pairs):
    record = {}
    for key, value in pairs:
        if key in record:
            raise RuntimeError("duplicate ownership field")
        record[key] = value
    return record


def read_record(path, fields):
    record = json.loads(read_regular(path, RECORD_LIMIT), object_pairs_hook=unique_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    if not isinstance(record, dict) or set(record) != fields:
        raise RuntimeError("ownership record fields differ from schema")
    for key, value in record.items():
        if key in ("pid", "started_ms", "completed_ms"):
            if key == "completed_ms" and value is None:
                continue
            if type(value) is not int or not 0 <= value <= 2**64 - 1:
                raise RuntimeError("ownership integer outside u64")
            if key == "pid" and not 1 <= value <= 2**32 - 1:
                raise RuntimeError("ownership PID outside u32")
        elif not isinstance(value, str):
            raise RuntimeError("ownership identity must be string")
    return record


def digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@native_operation("enumerate bounded entries")
def entries(path, allowed):
    descriptor = open_directory(path)
    try:
        with os.scandir(descriptor) as iterator:
            count = 0
            for entry in iterator:
                count += 1
                if count > MAX_ENTRIES:
                    raise RuntimeError("directory entry bound exceeded")
                safe_name(entry.name)
                if entry.name not in allowed or entry.is_symlink():
                    raise RuntimeError("unknown entry or link preserved")
    finally:
        os.close(descriptor)


@native_operation("enumerate directory names")
def names(path, checkpoint=None):
    if checkpoint is not None:
        checkpoint()
    descriptor = open_directory(path)
    try:
        result = []
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                if checkpoint is not None:
                    checkpoint()
                if len(result) >= MAX_ENTRIES:
                    raise RuntimeError("directory entry bound exceeded")
                safe_name(entry.name)
                result.append(entry.name)
        if checkpoint is not None:
            checkpoint()
        return result
    finally:
        os.close(descriptor)


@native_operation("read entry metadata")
def metadata(path):
    safe_name(path.name)
    descriptor = open_directory(path.parent)
    try:
        return os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
    finally:
        os.close(descriptor)


def vanished_active_descendant(path, roots):
    """Check a missing suffix without following or repinning surviving ancestry."""
    root = next((root for root in roots if path != root and root in path.parents), None)
    if root is None:
        return False
    if root not in DIRECTORY_PINS:
        raise RuntimeError("transient observation root is not pinned")
    relative = path.relative_to(root).parts
    if not relative or len(relative) > 64 or any(part in (".", "..") for part in relative):
        raise RuntimeError("transient observation left its fixed boundary")
    for part in relative:
        safe_name(part)
    descriptor = open_directory(root)
    before = os.fstat(descriptor)
    expected = before.st_dev, before.st_ino
    try:
        for index, part in enumerate(relative):
            try:
                value = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                # Only an absent suffix is accepted. The exact fixed root and
                # every surviving parent were opened without following links.
                break
            if not stat.S_ISDIR(value.st_mode) and not stat.S_ISREG(value.st_mode):
                raise RuntimeError("transient observation crosses link or special entry")
            if index + 1 != len(relative):
                if not stat.S_ISDIR(value.st_mode):
                    raise RuntimeError("transient observation parent changed file type")
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                except FileNotFoundError:
                    break
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (value.st_dev, value.st_ino):
                    os.close(child)
                    raise RuntimeError("transient observation parent changed while opening")
                os.close(descriptor)
                descriptor = child
    finally:
        os.close(descriptor)
    if identity(root) != expected:
        raise RuntimeError("transient observation fixed root changed")
    return True


def measure(path, transient_roots=(), checkpoint=None):
    pending = [(path, 0, False)]
    count, length = 0, 0
    while pending:
        if checkpoint is not None:
            checkpoint()
        current, depth, enumerated = pending.pop()
        count += 1
        safe_name(current.name)
        if count > MAX_ENTRIES or depth > 64:
            raise RuntimeError("managed tree observation bound exceeded")
        try:
            value = metadata(current)
        except FileNotFoundError:
            if not enumerated or not vanished_active_descendant(current, transient_roots):
                raise
            continue
        if checkpoint is not None:
            checkpoint()
        if stat.S_ISDIR(value.st_mode):
            try:
                children = names(current, checkpoint)
            except FileNotFoundError:
                if not enumerated or not vanished_active_descendant(current, transient_roots):
                    raise
                continue
            for name in children:
                if checkpoint is not None:
                    checkpoint()
                if count + len(pending) >= MAX_ENTRIES:
                    raise RuntimeError("managed tree entry bound exceeded")
                pending.append((current / name, depth + 1, True))
        elif stat.S_ISREG(value.st_mode):
            length += value.st_size
        else:
            raise RuntimeError("managed tree contains symbolic link or special entry")
    return length


class BsdInfo(ctypes.Structure):
    # Public Darwin proc_bsdinfo ABI, PROC_PIDTBSDINFO=3, SZOMB=5.
    _fields_ = [(name, ctypes.c_uint32) for name in
                ("flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid",
                 "rgid", "svuid", "svgid", "rfu")]
    _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "jobc", "tdev", "tpgid")]
    _fields_ += [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64),
                 ("start_usec", ctypes.c_uint64)]


class TaskInfo(ctypes.Structure):
    # Public PROC_PIDTASKINFO=4: adjusted virtual_size, not raw vm_map size.
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("virtual_size", "resident_size", "total_user", "total_system",
                 "threads_user", "threads_system")]
    _fields_ += [("counters", ctypes.c_int32 * 12)]


class RusageInfoV0(ctypes.Structure):
    # Public RUSAGE_INFO_V0=0. UUID is never emitted into evidence.
    _fields_ = [("uuid", ctypes.c_ubyte * 16)]
    _fields_ += [(name, ctypes.c_uint64) for name in
                ("user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups",
                 "pageins", "wired_size", "resident_size", "phys_footprint",
                 "start_abstime", "exit_abstime")]


def checked_resource_sum(total, value):
    if not 0 <= value <= U64_MAX or not 0 <= total <= U64_MAX - value:
        raise RuntimeError("Darwin native resource sum overflow")
    return total + value


class DarwinProcessExited(RuntimeError):
    """An exit-class resource result still requires native identity proof."""


class NativeSnapshot:
    def __init__(self, target_os):
        self.target_os = target_os
        self.leader_start = None
        if target_os == "macos":
            self.libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            self.libproc.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                                                  ctypes.c_void_p, ctypes.c_int]
            self.libproc.proc_listpids.restype = ctypes.c_int
            self.libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                                 ctypes.c_void_p, ctypes.c_int]
            self.libproc.proc_pidinfo.restype = ctypes.c_int
            self.libproc.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
            self.libproc.proc_pid_rusage.restype = ctypes.c_int
            if (ctypes.sizeof(BsdInfo) != 136 or ctypes.sizeof(TaskInfo) != 96
                    or ctypes.sizeof(RusageInfoV0) != 96):
                raise RuntimeError("unexpected Darwin native process/resource ABI")
            self.last_sample = None
            self.resources = {
                "policy": "managed-darwin-resources/1", "configured_rlimit_as_bytes": DARWIN_VM_LIMIT,
                "rlimit_as_readback_bytes": None, "adjusted_vm_per_pid_limit_bytes": DARWIN_VM_LIMIT,
                "aggregate_rss_limit_bytes": MEMORY_LIMIT, "aggregate_footprint_limit_bytes": MEMORY_LIMIT,
                "worker_limit": PROCESS_LIMIT, "wrapper_limit": 1, "wrapper_in_memory_sum": True,
                "sample_target_ms": 100, "max_successful_sample_gap_ms": 1000,
                "taskinfo_flavor": 4, "rusage_flavor": 0, "sample_count": 0,
                "peak_observed_adjusted_vm_bytes": 0, "peak_observed_aggregate_rss_bytes": 0,
                "peak_observed_aggregate_footprint_bytes": 0, "peak_observed_workers": 0,
                "max_observed_sample_gap_ms": 0, "sampling_may_overshoot": True,
                "kernel_resident_quota": False,
            }
            before = self.bsd_info(os.getpid())
            values = self.memory_info(os.getpid())
            after = self.bsd_info(os.getpid())
            self.verify_memory_identity(before, after, os.getpid())
            self.check_resources(*values, 0)
            self.resources["preflight_self_adjusted_vm_bytes"] = values[0]
            self.resources["preflight_self_rss_bytes"] = values[1]
            self.resources["preflight_self_footprint_bytes"] = values[2]

    def bsd_info(self, pid, zombie=False):
        info = BsdInfo()
        ctypes.set_errno(0)
        size = self.libproc.proc_pidinfo(pid, 3, int(zombie), ctypes.byref(info), ctypes.sizeof(info))
        if size == 0 and ctypes.get_errno() == errno.ESRCH:
            return None
        if size != ctypes.sizeof(info):
            raise RuntimeError("Darwin native process identity unavailable")
        return info

    def memory_info(self, pid):
        task, usage = TaskInfo(), RusageInfoV0()
        ctypes.set_errno(0)
        size = native_call("observe Darwin task memory", self.libproc.proc_pidinfo,
                           pid, 4, 0, ctypes.byref(task), ctypes.sizeof(task))
        if size != ctypes.sizeof(task):
            if size == 0 and ctypes.get_errno() == errno.ESRCH:
                raise DarwinProcessExited("Darwin task resource process exit requires identity confirmation")
            raise RuntimeError("Darwin task resource observation unavailable; bytes=" + str(size)
                               + "; errno=" + str(ctypes.get_errno()))
        ctypes.set_errno(0)
        result = native_call("observe Darwin physical footprint", self.libproc.proc_pid_rusage,
                             pid, 0, ctypes.byref(usage))
        if result != 0:
            if ctypes.get_errno() == errno.ESRCH:
                raise DarwinProcessExited("Darwin footprint process exit requires identity confirmation")
            raise RuntimeError("Darwin footprint observation unavailable; errno=" + str(ctypes.get_errno()))
        if usage.start_abstime == 0:
            raise RuntimeError("Darwin resource observation does not identify a live process")
        if usage.exit_abstime != 0:
            raise DarwinProcessExited("Darwin resource process exit requires identity confirmation")
        return task.virtual_size, max(task.resident_size, usage.resident_size), usage.phys_footprint

    def memory_or_confirmed_zombie(self, pid, before):
        try:
            return self.memory_info(pid)
        except DarwinProcessExited:
            after = self.bsd_info(pid, True)
            self.verify_memory_identity(before, after, pid)
            if after.status != 5:
                raise RuntimeError("Darwin resource process exit not confirmed by native zombie identity")
            # The reserved group ID plus unchanged start/PGID identifies a
            # departed member. This omits an ended process, never a zero sample.
            return None

    @staticmethod
    def verify_memory_identity(before, after, pid):
        if (before is None or after is None or before.pid != pid or after.pid != pid
                or before.uid != os.geteuid() or after.uid != os.geteuid()
                or (before.start_sec, before.start_usec, before.pgid)
                != (after.start_sec, after.start_usec, after.pgid)):
            raise RuntimeError("Darwin resource process identity changed or unavailable")

    @staticmethod
    def check_resources(vm, rss, footprint, workers):
        if vm > DARWIN_VM_LIMIT or rss > MEMORY_LIMIT or footprint > MEMORY_LIMIT or workers > PROCESS_LIMIT:
            raise RuntimeError("Darwin resource budget exceeded; adjusted_vm=" + str(vm)
                               + "; aggregate_rss=" + str(rss) + "; aggregate_footprint=" + str(footprint)
                               + "; workers=" + str(workers))

    def sample_gap(self, started, finished):
        gap = finished - (self.last_sample if self.last_sample is not None else started)
        self.resources["max_observed_sample_gap_ms"] = max(
            self.resources["max_observed_sample_gap_ms"], int(gap * 1000))
        if gap > DARWIN_SAMPLE_GAP:
            raise RuntimeError("Darwin successful resource sample gap exceeded 1000ms")

    def observe(self, leader, resources=True):
        if self.target_os == "linux":
            count, seen = 0, False
            with os.scandir("/proc") as iterator:
                for position, entry in enumerate(iterator):
                    if position >= MAX_ENTRIES:
                        raise RuntimeError("native process snapshot bound exceeded")
                    if not entry.name.isascii() or not entry.name.isdigit():
                        continue
                    try:
                        with open(Path(entry.path) / "stat", "rb") as stream:
                            raw = stream.read(RECORD_LIMIT + 1)
                    except FileNotFoundError:
                        continue
                    if len(raw) > RECORD_LIMIT or b")" not in raw:
                        raise RuntimeError("native process metadata invalid")
                    fields = raw[raw.rfind(b")") + 1:].split()
                    if len(fields) < 20:
                        raise RuntimeError("native process metadata incomplete")
                    group, session = int(fields[2]), int(fields[3])
                    if int(entry.name) == leader:
                        start = int(fields[19])
                        if group != leader or session != leader:
                            raise RuntimeError("reserved leader changed session identity")
                        if self.leader_start is not None and self.leader_start != start:
                            raise RuntimeError("reserved leader identity changed")
                        self.leader_start, seen = start, True
                    if session == leader and group != leader and fields[0] not in (b"Z", b"X"):
                        raise RuntimeError("owned session member changed process group")
                    if group == leader and int(entry.name) != leader and fields[0] not in (b"Z", b"X"):
                        count += 1
            if not seen:
                raise RuntimeError("reserved leader missing from native snapshot")
            return count
        sample_started = time.monotonic()
        sample_memory = resources and (self.last_sample is None or sample_started - self.last_sample >= DARWIN_SAMPLE_TARGET)
        if resources and self.last_sample is not None:
            self.sample_gap(sample_started, sample_started)
        vm_peak, rss_sum, footprint_sum = 0, 0, 0
        capacity = 1024
        while True:
            pids = (ctypes.c_int * capacity)()
            size = self.libproc.proc_listpids(1, 0, pids, ctypes.sizeof(pids))
            if size <= 0 or size % 4:
                raise RuntimeError("Darwin native PID snapshot unavailable")
            if size < ctypes.sizeof(pids):
                break
            if capacity >= MAX_ENTRIES:
                raise RuntimeError("Darwin native PID snapshot bound exceeded")
            capacity = min(MAX_ENTRIES, capacity * 2)
        count, seen = 0, False
        for pid in pids[:size // 4]:
            if pid <= 0:
                continue
            if pid == leader:
                before = self.bsd_info(pid, True)
                if before is not None and before.status != 5 and os.getsid(pid) != leader:
                    raise RuntimeError("reserved Darwin leader changed session identity")
                values = self.memory_or_confirmed_zombie(pid, before) if sample_memory and before is not None and before.status != 5 else None
                after = self.bsd_info(pid, True)
                if before is None or after is None or before.pid != leader or after.pid != leader:
                    raise RuntimeError("reserved Darwin leader disappeared")
                start = before.start_sec, before.start_usec
                if (before.pgid != leader or after.pgid != leader
                        or start != (after.start_sec, after.start_usec)
                        or self.leader_start is not None and self.leader_start != start):
                    raise RuntimeError("reserved Darwin leader changed identity")
                self.leader_start, seen = start, True
                if values is not None:
                    self.verify_memory_identity(before, after, pid)
                    if after.status == 5:
                        raise RuntimeError("Darwin wrapper exited during resource observation")
                    if os.getsid(pid) != leader:
                        raise RuntimeError("reserved Darwin leader changed session during resource observation")
                    vm_peak = max(vm_peak, values[0])
                    rss_sum = checked_resource_sum(rss_sum, values[1])
                    footprint_sum = checked_resource_sum(footprint_sum, values[2])
                continue
            try:
                session = os.getsid(pid)
            except ProcessLookupError:
                continue
            if session != leader:
                continue
            before = self.bsd_info(pid)
            if before is None:
                continue
            values = self.memory_or_confirmed_zombie(pid, before) if sample_memory and before.status != 5 else None
            try:
                session_after = os.getsid(pid)
            except ProcessLookupError:
                continue
            after = self.bsd_info(pid)
            if after is None:
                continue
            if (session_after != leader or before.pid != pid or after.pid != pid
                    or (before.start_sec, before.start_usec) != (after.start_sec, after.start_usec)
                    or before.pgid != after.pgid):
                raise RuntimeError("Darwin process identity changed during snapshot")
            if after.pgid != leader and after.status != 5:
                raise RuntimeError("owned Darwin session member changed process group")
            if after.pgid == leader and after.status != 5:
                count += 1
                if values is not None:
                    self.verify_memory_identity(before, after, pid)
                    vm_peak = max(vm_peak, values[0])
                    rss_sum = checked_resource_sum(rss_sum, values[1])
                    footprint_sum = checked_resource_sum(footprint_sum, values[2])
        if not seen:
            raise RuntimeError("reserved Darwin leader missing from snapshot")
        if sample_memory:
            finished = time.monotonic()
            self.resources["sample_count"] += 1
            for name, value in (("peak_observed_adjusted_vm_bytes", vm_peak),
                                ("peak_observed_aggregate_rss_bytes", rss_sum),
                                ("peak_observed_aggregate_footprint_bytes", footprint_sum),
                                ("peak_observed_workers", count)):
                self.resources[name] = max(self.resources[name], value)
            self.sample_gap(sample_started, finished)
            self.last_sample = finished
            self.check_resources(vm_peak, rss_sum, footprint_sum, count)
        return count


def cancellation(_signum, _frame):
    global cancelled
    cancelled = True


def supervise(program, args, cwd, environment, stdout, stderr, timeout, observe, target_os,
              invocation=None, owned_tail_policy="reject"):
    """Reserve a session leader before exec; snapshot twice and close pipes before reap."""
    snapshot = native_call("load supervision process API", NativeSnapshot, target_os)
    if owned_tail_policy not in ("reject", "terminate-build"):
        raise RuntimeError("unsupported owned-tail policy")
    streams, descriptors = [], set()
    selector = native_call("create output selector", selectors.DefaultSelector)

    def pipe():
        ends = native_call("create owned pipe", os.pipe)
        descriptors.update(ends)
        return ends

    def close(descriptor):
        native_call("close owned pipe", os.close, descriptor)
        descriptors.discard(descriptor)

    # Prepare every parent-side resource before creating any executable child.
    try:
        for path in (stdout, stderr):
            safe_name(path.name)
            parent = open_directory(path.parent)
            try:
                descriptor = native_call("create owned command log", os.open, path.name,
                                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=parent)
                descriptors.add(descriptor)
            except BaseException as log_error:
                try:
                    native_call("close failed owned log parent", os.close, parent)
                except OSError as parent_error:
                    details = failure_details(parent_error)
                    log_error.mmmm_cleanup_errors = [details["operation"] + ": " + details["error"]]
                raise
            else:
                native_call("close owned log parent", os.close, parent)
            stream = native_call("open owned command log stream", os.fdopen, descriptor, "wb")
            streams.append(stream)
            descriptors.discard(descriptor)
        out_read, out_write = pipe()
        err_read, err_write = pipe()
        report_read, report_write = pipe()
        release_read, release_write = pipe()
        start_read, start_write = pipe()
        for descriptor, key in ((out_read, 0), (err_read, 1), (report_read, 2)):
            native_call("set owned pipe nonblocking", os.set_blocking, descriptor, False)
            native_call("register owned pipe selector", selector.register, descriptor, selectors.EVENT_READ, key)
        leader = native_call("fork reserved session leader", os.fork)
    except BaseException as preparation_error:
        cleanup_errors = list(getattr(preparation_error, "mmmm_cleanup_errors", []))

        def cleanup(operation, function, *args):
            try:
                native_call(operation, function, *args)
            except OSError as cleanup_error:
                details = failure_details(cleanup_error)
                cleanup_errors.append(details["operation"] + ": " + details["error"])

        for stream in streams:
            cleanup("close unstarted command log", stream.close)
        for descriptor in descriptors:
            cleanup("close unstarted owned pipe", os.close, descriptor)
        cleanup("close unstarted output selector", selector.close)
        if cleanup_errors:
            # At most two logs, ten pipe ends, one selector and a failed log
            # parent close can contribute bounded cleanup facts.
            # Preserve the first failure while recording every cleanup attempt.
            preparation_error.mmmm_cleanup_errors = cleanup_errors
        raise
    if leader == 0:
        session_id = None
        try:
            native_call("close child output selector", selector.close)
            for stream in streams:
                native_call("close child command log stream", stream.close)
            for descriptor in (out_read, err_read, report_read, release_write, start_write):
                native_call("close child unneeded pipe", os.close, descriptor)
            native_call("establish reserved session", os.setsid)
            session_id = os.getpid()
            # Establish ownership before quota configuration can fail. The
            # parent still withholds admission until the separate limit proof.
            native_call("report session readiness", os.write, report_write, b"ready\n")
            vm_limit = DARWIN_VM_LIMIT if target_os == "macos" else MEMORY_LIMIT
            if target_os == "macos":
                native_call("set core dump limit", resource.setrlimit, resource.RLIMIT_CORE, (0, 0))
                native_call("set address space limit", resource.setrlimit, resource.RLIMIT_AS, (vm_limit, vm_limit))
                readback = native_call("read address space limit", resource.getrlimit, resource.RLIMIT_AS)
                if readback != (vm_limit, vm_limit):
                    raise RuntimeError("configured address space limit readback mismatch")
                native_call("set descriptor limit", resource.setrlimit, resource.RLIMIT_NOFILE, (256, 256))
                native_call("report verified address space limit", os.write, report_write,
                            ("limit:" + str(vm_limit) + "\n").encode("ascii"))
            # The still-live wrapper reserves SID/PGID until parent drain checks.
            # Parent must verify the native SID/PGID and start-time identity
            # before any build worker may execute.
            if native_call("await verified session admission", os.read, start_read, 1) != b"x":
                os._exit(126)
            native_call("close child admission pipe", os.close, start_read)
            if target_os == "linux":
                native_call("set core dump limit", resource.setrlimit, resource.RLIMIT_CORE, (0, 0))
                native_call("set address space limit", resource.setrlimit, resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))
                native_call("set descriptor limit", resource.setrlimit, resource.RLIMIT_NOFILE, (256, 256))
            worker = native_call("fork bounded build worker", os.fork)
            if worker == 0:
                native_call("close worker report pipe", os.close, report_write)
                native_call("close worker release pipe", os.close, release_read)
                native_call("redirect worker stdout", os.dup2, out_write, 1)
                native_call("redirect worker stderr", os.dup2, err_write, 2)
                native_call("close worker stdout pipe", os.close, out_write)
                native_call("close worker stderr pipe", os.close, err_write)
                native_call("set worker checkout directory", os.chdir, cwd)
                native_call("execute bounded build worker", os.execve, program,
                            [invocation or program, *args], environment)
            native_call("close leader stdout pipe", os.close, out_write)
            native_call("close leader stderr pipe", os.close, err_write)
            native_call("set leader release pipe nonblocking", os.set_blocking, release_read, False)
            watchdog = time.monotonic() + timeout + 2
            while True:
                exited, status = native_call("observe build worker exit", os.waitpid, worker, os.WNOHANG)
                if exited == worker:
                    break
                try:
                    release = native_call("observe controlling launcher pipe", os.read, release_read, 1)
                except BlockingIOError:
                    release = None
                # EOF means the controlling launcher died. This watchdog is
                # independent of the parent's resource observation loop.
                if release is not None or time.monotonic() >= watchdog:
                    native_call("watchdog terminate owned session", os.killpg, os.getpid(), signal.SIGKILL)
                    os._exit(126)
                time.sleep(0.05)
            code = os.waitstatus_to_exitcode(status)
            if code < 0:
                code = 128 - code
            native_call("report build worker exit", os.write, report_write,
                        ("exit:" + str(code) + "\n").encode("ascii"))
            native_call("close leader report pipe", os.close, report_write)
            while True:
                try:
                    release = native_call("await verified session release", os.read, release_read, 1)
                except BlockingIOError:
                    release = None
                if release == b"x":
                    break
                if release is not None or time.monotonic() >= watchdog:
                    native_call("watchdog terminate unreleased session", os.killpg, os.getpid(), signal.SIGKILL)
                    os._exit(126)
                time.sleep(0.05)
            os._exit(0)
        except BaseException as child_error:
            try:
                details = failure_details(child_error)
                diagnostic = details["operation"] + ": " + details["error"]
                if details.get("script_frames"):
                    frame = details["script_frames"][-1]
                    diagnostic += " [" + frame["function"] + ":" + str(frame["line"]) + "]"
                os.write(report_write, ("launcher-error:" + diagnostic[:192] + "\n").encode("ascii"))
            except OSError:
                pass
            if session_id is not None:
                try:
                    os.killpg(session_id, signal.SIGKILL)
                except OSError:
                    pass
            os._exit(126)
    for descriptor in (out_write, err_write, report_write, release_read, start_read):
        close(descriptor)
    errors, report, command_exit = [], bytearray(), None
    ready, approved, killed, drained, empty = False, False, False, False, 0
    resource_proved = target_os != "macos"
    started, observed, kill_started = time.monotonic(), time.monotonic(), None
    total = 0
    reaped = False
    tail_started = None
    owned_tail_terminated = False

    def checkpoint():
        # A cooperative checkpoint observes the complete native owned scope.
        # Its throttle uses only the last successfully completed resource
        # sample; a blocked syscall or late sample still fails the 1s limit.
        if target_os != "macos" or not approved or killed:
            return
        if snapshot.last_sample is None or time.monotonic() - snapshot.last_sample >= DARWIN_SAMPLE_TARGET:
            native_call("observe resources during bounded parent work", snapshot.observe, leader, True)
        if cancelled:
            if "command cancelled" not in errors:
                errors.append("command cancelled")
            raise RuntimeError("command cancelled during bounded parent work")
        if time.monotonic() - started >= timeout:
            if "command timeout" not in errors:
                errors.append("command timeout")
            raise RuntimeError("command timeout during bounded parent work")

    try:
        while True:
            now = time.monotonic()
            for key, _ in native_call("observe owned output selector", selector.select, 0.1):
                descriptor, channel = key.fd, key.data
                for _batch in range(32):
                    try:
                        chunk = native_call("read owned output pipe", os.read, descriptor, 8192)
                    except BlockingIOError:
                        break
                    if not chunk:
                        native_call("unregister closed owned output", selector.unregister, descriptor)
                        close(descriptor)
                        if channel == 2 and command_exit is None:
                            raise RuntimeError("native control ended without command result")
                        break
                    if channel == 2:
                        report.extend(chunk)
                        if len(report) > 256:
                            raise RuntimeError("native control report exceeded bound")
                        while b"\n" in report:
                            line, _, rest = report.partition(b"\n")
                            report = bytearray(rest)
                            if line == b"ready" and not ready:
                                ready = True
                            elif (target_os == "macos" and ready and not resource_proved
                                  and line == ("limit:" + str(DARWIN_VM_LIMIT)).encode("ascii")):
                                snapshot.resources["rlimit_as_readback_bytes"] = DARWIN_VM_LIMIT
                                resource_proved = True
                            elif line.startswith(b"exit:") and ready and command_exit is None:
                                command_exit = int(line[5:])
                            elif line.startswith(b"launcher-error:"):
                                raise RuntimeError("reserved launcher: " + line[15:].decode("ascii"))
                            else:
                                raise RuntimeError("native control report invalid")
                    else:
                        retain = min(len(chunk), max(0, LOG_LIMIT - total))
                        native_call("capture owned command output", streams[channel].write, chunk[:retain])
                        total += retain
                        if retain != len(chunk) and "combined output limit exceeded" not in errors:
                            errors.append("combined output limit exceeded")
                    checkpoint()
            now = time.monotonic()
            if now - started >= timeout and "command timeout" not in errors:
                errors.append("command timeout")
            if cancelled and "command cancelled" not in errors:
                errors.append("command cancelled")
            if now - observed >= 5:
                if target_os == "macos":
                    observe(checkpoint)
                else:
                    observe()
                observed = time.monotonic()
            if ready:
                members = native_call("observe reserved session membership", snapshot.observe, leader, not killed)
                if not approved and not errors and resource_proved:
                    native_call("admit verified session build worker", os.write, start_write, b"x")
                    close(start_write)
                    approved = True
                if members > PROCESS_LIMIT and "owned process limit exceeded" not in errors:
                    errors.append("owned process limit exceeded")
                if not resource_proved and now - started >= 5:
                    raise RuntimeError("Darwin address space limit proof unavailable before admission")
                if command_exit is not None and members and not killed:
                    if tail_started is None:
                        tail_started = now
                    if now - tail_started >= 2:
                        if owned_tail_policy == "terminate-build" and not errors:
                            # This is explicit build-tool cleanup after the
                            # observed command exit, never a command retry.
                            native_call("terminate owned build tail", os.killpg, leader, signal.SIGKILL)
                            killed, kill_started = True, time.monotonic()
                            owned_tail_terminated = True
                        elif "command left running owned descendants" not in errors:
                            errors.append("command left running owned descendants")
                pipes_closed = all(key.data == 2 for key in selector.get_map().values())
                if command_exit is not None or killed:
                    empty = empty + 1 if members == 0 and pipes_closed else 0
                    if empty >= 2:
                        drained = True
                        break
            elif now - started >= 5:
                raise RuntimeError("native session readiness unavailable")
            if errors and not killed:
                if not ready:
                    raise RuntimeError("failure before native session identity was established")
                native_call("terminate failed owned session", os.killpg, leader, signal.SIGKILL)
                killed, kill_started = True, time.monotonic()
                if command_exit is None:
                    command_exit = 124 if "command timeout" in errors else 125
            if killed and time.monotonic() - kill_started >= 15:
                errors.append("owned process drain deadline exceeded")
                break
        if drained:
            if not killed:
                native_call("release drained session leader", os.write, release_write, b"x")
            deadline = time.monotonic() + 2
            while True:
                finished, _ = native_call("reap drained session leader", os.waitpid, leader, os.WNOHANG)
                if finished == leader:
                    reaped = True
                    break
                if time.monotonic() >= deadline:
                    drained = False
                    errors.append("reserved leader reap deadline exceeded")
                    break
                time.sleep(0.05)
        observe()
    except BaseException as error:
        details = failure_details(error)
        errors.append("native supervision: " + details["operation"] + ": " + details["error"])
        if ready and not reaped:
            try:
                native_call("terminate errored owned session", os.killpg, leader, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as termination_error:
                details = failure_details(termination_error)
                errors.append("error-path termination: " + details["operation"] + ": " + details["error"])
            deadline, empty = time.monotonic() + 15, 0
            drained = False
            while time.monotonic() < deadline:
                try:
                    events = native_call("observe error drain output selector", selector.select, 0.1)
                except OSError as drain_selector_error:
                    details = failure_details(drain_selector_error)
                    errors.append("error-path output observation: " + details["operation"] + ": " + details["error"])
                    break
                for key, _ in events:
                    descriptor, channel = key.fd, key.data
                    try:
                        chunk = native_call("read error drain output pipe", os.read, descriptor, 8192)
                        if not chunk:
                            native_call("unregister closed error drain output", selector.unregister, descriptor)
                            close(descriptor)
                        elif channel != 2:
                            retain = min(len(chunk), max(0, LOG_LIMIT - total))
                            native_call("capture error drain output", streams[channel].write, chunk[:retain])
                            total += retain
                    except BlockingIOError:
                        pass
                    except OSError as capture_error:
                        errors.append("drain output capture: " + str(capture_error))
                        # Missing EOF cannot be converted to a successful drain.
                        break
                try:
                    members = native_call("observe error drain session membership", snapshot.observe, leader, False)
                    pipes_closed = all(key.data == 2 for key in selector.get_map().values())
                    empty = empty + 1 if members == 0 and pipes_closed else 0
                    if empty >= 2:
                        drained = True
                        finished, _ = native_call("reap errored session leader", os.waitpid, leader, os.WNOHANG)
                        reaped = finished == leader
                        if not reaped:
                            drained = False
                            errors.append("terminated reserved leader was not reapable")
                        break
                except Exception:
                    # The initial error remains in the result. A later native
                    # snapshot may recover, but unavailable observations never
                    # grant drain proof or lease release.
                    empty = 0
            if not drained:
                errors.append("error-path owned process drain unconfirmed")
    finally:
        for stream in streams:
            try:
                native_call("flush owned command log", stream.flush)
                native_call("sync owned command log", os.fsync, stream.fileno())
            except OSError as flush_error:
                errors.append("owned log flush: " + str(flush_error))
            finally:
                try:
                    native_call("close completed command log", stream.close)
                except OSError as close_error:
                    errors.append("owned log close: " + str(close_error))
        for descriptor in descriptors:
            try:
                native_call("close completed owned pipe", os.close, descriptor)
            except OSError as close_error:
                errors.append("owned descriptor close: " + str(close_error))
        try:
            native_call("close completed output selector", selector.close)
        except OSError as selector_error:
            details = failure_details(selector_error)
            errors.append("owned selector close: " + details["operation"] + ": " + details["error"])
    reason = "completed_after_owned_tail_cleanup" if owned_tail_terminated and not errors else "completed"
    if errors:
        reason = ("timeout" if "command timeout" in errors else "cancelled" if "command cancelled" in errors
                  else "output_limit" if "combined output limit exceeded" in errors
                  else "remaining_children" if "command left running owned descendants" in errors
                  else "supervisor_failure")
    result = {"command_exit": command_exit, "drained": drained, "supervisor_errors": errors,
              "owned_tail_terminated": owned_tail_terminated, "termination_reason": reason}
    if target_os == "macos":
        result["darwin_resources"] = snapshot.resources
    return result


def default_output(target_os):
    if os.environ.get("RUNNER_TEMP"):
        return Path(os.environ["RUNNER_TEMP"]) / "MMMM"
    if target_os == "macos":
        return Path.home() / "Library/Caches/MMMM"
    return Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "mmmm"


def entry():
    global FAILURE_EVIDENCE
    if sys.version_info < (3, 10) or sys.platform not in ("linux", "darwin"):
        raise RuntimeError("bootstrap requires Python 3.10+ on Linux or macOS")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    parser.add_argument("--update-lock", action="store_true",
                        help="explicitly allow approved dependency resolution to update Cargo.lock")
    options = parser.parse_args()
    if not 1 <= options.timeout_seconds <= 3600:
        raise RuntimeError("timeout must be 1..3600 seconds")
    os.umask(0o077)
    target_os = "macos" if sys.platform == "darwin" else "linux"
    arch = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(platform.machine())
    if arch is None:
        raise RuntimeError("unsupported Unix architecture")
    # Check the physical native API before any ownership mutation.
    phase("native preflight")
    native_call("load native process API", NativeSnapshot, target_os)
    phase("validate managed roots")
    checkout = directory(options.checkout)
    output = options.output_root or default_output(target_os)
    evidence = options.evidence_root
    separate(output, checkout)
    separate(evidence, checkout)
    separate(output / "build/managed-v1", evidence)
    output = directory(output, True)
    evidence = directory(evidence, True)
    FAILURE_EVIDENCE = evidence
    phase("reserve bootstrap ownership")
    catalog = directory(output / "build/managed-v1", True)
    checkout_digest = hashlib.sha256(str(checkout).rstrip("/").encode("utf-8")).hexdigest()
    slot_id = target_os + "-" + arch + "-" + checkout_digest[:24] + "-bootstrap"
    catalog_file, lease_file = catalog / "catalog.json", catalog / "lease.json"
    if "catalog.json" not in names(catalog):
        if names(catalog):
            raise RuntimeError("unowned nonempty catalog preserved")
        write_new(catalog_file, encode_record({"schema": SCHEMA, "catalog_id": os.urandom(32).hex()}))
    catalog_record = read_record(catalog_file, CATALOG_FIELDS)
    if catalog_record["schema"] != SCHEMA or not digest(catalog_record["catalog_id"]):
        raise RuntimeError("catalog identity unknown")
    entries(catalog, {"catalog.json", "lease.json", "slots"})
    token = os.urandom(32).hex()
    started = time.time_ns() // 1000000
    lease = {"schema": SCHEMA, "catalog_id": catalog_record["catalog_id"], "slot_id": slot_id,
             "token": token, "pid": os.getpid(), "started_ms": started}
    # Exclusive creation is the catalog lock. Unknown or interrupted leases remain untouched.
    write_new(lease_file, encode_record(lease))
    slots = directory(catalog / "slots", True)
    completed = 0
    for position, name in enumerate(names(slots)):
        if position >= MAX_ENTRIES:
            raise RuntimeError("slot catalog entry bound exceeded")
        existing = directory(slots / name)
        owner = read_record(existing / "owner.json", OWNER_FIELDS)
        expected_name = (owner["os"] + "-" + owner["arch"] + "-"
                         + owner["checkout_digest"][:24] + "-" + owner["purpose"])
        if (owner["schema"] != SCHEMA or owner["catalog_id"] != catalog_record["catalog_id"]
                or owner["slot_id"] != name or expected_name != name
                or not digest(owner["checkout_digest"]) or not digest(owner["token"])
                or owner["os"] not in ("linux", "macos", "windows")
                or owner["arch"] not in ("aarch64", "x86_64")
                or not 1 <= len(owner["purpose"]) <= 48
                or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in owner["purpose"])
                or owner["state"] != "complete" or owner["completed_ms"] is None):
            raise RuntimeError("unknown or interrupted slot preserved")
        entries(existing, {"owner.json", "cache", "scratch"})
        if "scratch" in names(existing) and names(existing / "scratch"):
            raise RuntimeError("unexplained completed scratch preserved")
        if "cache" in names(existing):
            entries(existing / "cache", {"cargo-target", "cargo-home", "gradle-build",
                                          "gradle-project-cache", "gradle-user-home"})
        completed += 1
    if completed > 4 or completed == 4 and slot_id not in names(slots):
        raise RuntimeError("bootstrap cannot admit a new slot within completed-slot limit")
    slot = directory(slots / slot_id, True)
    owner_file = slot / "owner.json"
    owner = {key: value for key, value in lease.items() if key != "started_ms"}
    owner.update(checkout_digest=checkout_digest, os=target_os, arch=arch, purpose="bootstrap",
                 state="active", completed_ms=None)
    replace_record(owner_file, owner)
    cache = directory(slot / "cache", True)
    for name in ("cargo-target", "cargo-home", "gradle-build", "gradle-project-cache", "gradle-user-home"):
        directory(cache / name, True)
    scratch = directory(slot / "scratch", True)
    if names(scratch):
        raise RuntimeError("nonempty bootstrap scratch preserved")
    pins = {path: identity(path) for path in (checkout, output, evidence, catalog, slots, slot, scratch)}
    records = {path: read_regular(path, RECORD_LIMIT) for path in (catalog_file, lease_file, owner_file)}
    observation_roots = tuple(cache / name for name in
                              ("cargo-target", "cargo-home", "gradle-build", "gradle-project-cache", "gradle-user-home")) + (scratch,)

    def verify_active_observation(checkpoint=None):
        for path, expected in pins.items():
            if checkpoint is not None:
                checkpoint()
            if identity(path) != expected:
                raise RuntimeError("pinned directory identity changed")
        for root in observation_roots:
            if checkpoint is not None:
                checkpoint()
            if identity(root) != DIRECTORY_PINS[root]:
                raise RuntimeError("active observation fixed root changed")
        for path, expected in records.items():
            if checkpoint is not None:
                checkpoint()
            if read_regular(path, RECORD_LIMIT) != expected:
                raise RuntimeError("active observation ownership record changed")

    def observe(checkpoint=None):
        verify_active_observation(checkpoint)
        slot_bytes = measure(slot, observation_roots, checkpoint)
        catalog_bytes = measure(catalog, observation_roots, checkpoint)
        verify_active_observation(checkpoint)
        if slot_bytes > SLOT_LIMIT or catalog_bytes > CATALOG_LIMIT:
            raise RuntimeError("managed bootstrap byte budget exceeded")

    ownership = {**lease, "checkout_digest": checkout_digest, "os": target_os, "arch": arch,
                 "purpose": "bootstrap"}
    ownership_file = evidence / "bootstrap-ownership.json"
    write_new(ownership_file, encode_record(ownership))
    phase("prepare build environment")
    environment = os.environ.copy()
    overrides = {"CARGO_TARGET_DIR": str(cache / "cargo-target"), "CARGO_HOME": str(cache / "cargo-home"),
                 "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": str(options.jobs),
                 "TMP": str(scratch), "TEMP": str(scratch), "TMPDIR": str(scratch)}
    for key in ("CARGO_TARGET_DIR", "CARGO_HOME", "CARGO_INCREMENTAL"):
        if key in environment and environment[key] != overrides[key]:
            raise RuntimeError("conflicting managed environment override; lease preserved")
    environment.update(overrides)
    cargo = shutil.which("cargo")
    if cargo is None:
        raise RuntimeError("Cargo executable unavailable; lease preserved")
    cargo_invocation = cargo
    cargo = str(native_call("resolve Cargo executable", Path(cargo).resolve, strict=True))
    stdout, stderr = scratch / ("cargo-" + token + ".stdout.log"), scratch / ("cargo-" + token + ".stderr.log")
    signal.signal(signal.SIGINT, cancellation)
    signal.signal(signal.SIGTERM, cancellation)
    phase("initial managed resource observation")
    observe()
    phase("inspect Cargo lock")
    try:
        lock_exists = stat.S_ISREG(metadata(checkout / "Cargo.lock").st_mode)
        if not lock_exists:
            raise RuntimeError("Cargo.lock must be a regular source file")
    except FileNotFoundError:
        lock_exists = False
    build_args = ["build", "-p", "mmmm-xtask", "--jobs", str(options.jobs)]
    if lock_exists and not options.update_lock:
        build_args.insert(1, "--locked")
    phase("prepare and supervise Cargo build")
    result = supervise(cargo, build_args,
                       str(checkout), environment, stdout, stderr, options.timeout_seconds, observe, target_os,
                       invocation=cargo_invocation, owned_tail_policy="terminate-build")
    phase("export Cargo supervision evidence")
    exported = False
    if result["drained"]:
        logs = [read_regular(path, LOG_LIMIT) for path in (stdout, stderr)]
        if sum(map(len, logs)) <= LOG_LIMIT:
            for name, data in zip(("cargo.stdout.log", "cargo.stderr.log"), logs):
                write_new(evidence / name, data)
            exported = True
    write_new(evidence / "bootstrap-supervision.json", encode_record({
        "schema": "mmmm-bootstrap-supervision/1", "token": token, **result}))
    proof = {"schema": "mmmm-bootstrap-process/1", "token": token,
             "command_exit": result["command_exit"], "drained": result["drained"],
             "supervisor_errors": result["supervisor_errors"], "evidence_exported": exported,
             "owned_tail_terminated": result["owned_tail_terminated"]}
    write_new(evidence / "bootstrap-process.json", encode_record(proof))
    if (result["command_exit"] != 0 or not result["drained"]
            or result["supervisor_errors"] or not exported):
        # No automatic failed/stale lease recovery is implemented here.
        raise RuntimeError("bootstrap failed; exported proof, slot and lease preserved")
    phase("validate completed bootstrap for adoption")
    for path, expected in records.items():
        if read_regular(path, RECORD_LIMIT) != expected:
            raise RuntimeError("bootstrap ownership record changed before adoption")
    tool = cache / "cargo-target/debug/mmmm-xtask"
    tool_metadata = metadata(tool)
    if not stat.S_ISREG(tool_metadata.st_mode):
        raise RuntimeError("built Rust tool is not a regular owned file")
    completion_args = ["bootstrap-complete", "--checkout", str(checkout), "--ownership", str(ownership_file),
                       "--proof", str(evidence / "bootstrap-process.json"), "--evidence-root", str(evidence),
                       "--purpose", "bootstrap", "--output-root", str(output)]
    def observe_completion(checkpoint=None):
        # Rust adoption may remove scratch or evict the completed slot. Only
        # stable catalog/output/evidence roots remain pinned for this command.
        for path in (checkout, output, evidence, catalog, slots):
            if checkpoint is not None:
                checkpoint()
            if identity(path) != pins[path]:
                raise RuntimeError("completion root identity changed")
        # The trusted Rust completion itself measures its catalog. Traversing
        # mutable slot trees here would race its authorized scratch deletion
        # and completed-slot eviction. This phase is separately capped at 60s.

    phase("supervise Rust bootstrap adoption")
    completion = supervise(str(tool), completion_args, str(checkout), environment,
                           evidence / "bootstrap-complete.stdout.log", evidence / "bootstrap-complete.stderr.log",
                           60, observe_completion, target_os)
    if completion["command_exit"] != 0 or not completion["drained"] or completion["supervisor_errors"]:
        raise RuntimeError("Rust bootstrap completion failed; ownership and receipts retained")
    phase("verify Rust bootstrap completion receipt")
    receipt = json.loads(read_regular(evidence / "bootstrap-complete.json", RECORD_LIMIT),
                         object_pairs_hook=unique_pairs)
    if (receipt.get("schema") != "mmmm-bootstrap-complete/1" or receipt.get("token") != token
            or receipt.get("slot_id") != slot_id or receipt.get("lease_released") is not True
            or "lease.json" in names(catalog)):
        raise RuntimeError("Rust completion receipt does not establish lease release")
    print(json.dumps({"schema": "mmmm-bootstrap-result/1", "slot_id": slot_id, "command_exit": 0,
                      "drained": True, "evidence_exported": True, "lease_released": True,
                      "tool": str(tool)}, separators=(",", ":")))


if __name__ == "__main__":
    try:
        entry()
    except Exception as failure:
        details = failure_details(failure)
        if FAILURE_EVIDENCE is not None:
            try:
                write_new(FAILURE_EVIDENCE / "bootstrap-failure.json", encode_record({
                    "schema": "mmmm-bootstrap-failure/1", **details}))
            except Exception as export_error:
                export_details = failure_details(export_error)
                print("mmmm-bootstrap: diagnostic export failed: " + export_details["operation"]
                      + ": " + export_details["error"], file=sys.stderr)
        print("mmmm-bootstrap: phase=" + details["phase"] + "; operation=" + details["operation"]
              + "; " + details["error"], file=sys.stderr)
        if details.get("script_frames"):
            print("mmmm-bootstrap: source frames=" + json.dumps(details["script_frames"], separators=(",", ":")),
                  file=sys.stderr)
        sys.exit(1)
