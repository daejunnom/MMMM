#!/usr/bin/env python3
"""Pure source fixtures; never load libproc, fork, spawn, sleep, or inspect /proc."""
import ast
import ctypes
import errno
import json
from pathlib import Path
from types import SimpleNamespace


LEADER = 12001
MEMBER = 12002
MOCK_UID = 13001
MOCK_BIRTH = (14001, 15001)
UNCONFIRMED = "Darwin resource process exit not confirmed by native zombie identity"
IDENTITY_CHANGED = "Darwin resource process identity changed or unavailable"
FIELDS = {
    "stage", "native_result", "native_errno", "rusage_start_observed", "rusage_exit_observed",
    "role", "before_status", "after_status", "before_inexit", "after_inexit",
    "memory_identity_check_performed", "memory_identity_match",
    "leader_anchor_check_performed", "leader_anchor_match",
}


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def forbidden(*_args, **_kwargs):
    raise AssertionError("native or filesystem execution is outside this pure fixture")


def load_production():
    # No existing Unix bootstrap fixture covers these ctypes result paths.
    # Select the actual definitions instead of importing the Unix entry point:
    # Windows has no resource module, and constructors must not load libproc.
    path = Path(__file__).with_name("bootstrap-unix.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename="bootstrap-unix.py")
    constants = {
        "U64_MAX", "DARWIN_VM_LIMIT", "MEMORY_LIMIT", "PROCESS_LIMIT", "MAX_ENTRIES",
        "DARWIN_SAMPLE_TARGET", "DARWIN_SAMPLE_GAP", "PROC_FLAG_INEXIT",
    }
    definitions = {
        "BsdInfo", "TaskInfo", "RusageInfoV0", "DarwinProcessExited", "NativeSnapshot",
        "DarwinMissingAfterTaskExit", "DarwinPendingObservation", "native_call", "checked_resource_sum",
    }
    selected = []
    found = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in constants:
                selected.append(node)
                found.add(target.id)
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in definitions:
            selected.append(node)
            found.add(node.name)
    require(found == constants | definitions, "required production definitions changed")
    ctypes_view = SimpleNamespace(**{
        name: getattr(ctypes, name) for name in (
            "Structure", "c_uint32", "c_uint64", "c_int32", "c_int", "c_ubyte", "c_char",
            "sizeof", "byref", "get_errno", "set_errno",
        )
    }, CDLL=forbidden)
    namespace = {
        "__name__": "mmmm_bootstrap_darwin_pure",
        "ctypes": ctypes_view, "errno": errno,
        "os": SimpleNamespace(geteuid=lambda: MOCK_UID, getpid=lambda: LEADER,
                              getsid=lambda _pid: LEADER, scandir=forbidden),
        "resource": SimpleNamespace(setrlimit=forbidden),
        "time": SimpleNamespace(monotonic=lambda: 10.0), "open": forbidden,
    }
    exec(compile(ast.Module(body=selected, type_ignores=[]), "bootstrap-unix.py", "exec"), namespace)
    return namespace


def bsd(namespace, pid=MEMBER, status=2, flags=4, **changes):
    value = namespace["BsdInfo"]()
    fields = {
        "pid": pid, "uid": MOCK_UID, "pgid": LEADER, "status": status, "flags": flags,
        "start_sec": MOCK_BIRTH[0], "start_usec": MOCK_BIRTH[1],
    }
    fields.update(changes)
    for name, item in fields.items():
        setattr(value, name, item)
    return value


class FakeLibproc:
    def __init__(self, namespace, mode, after, failure_pid=MEMBER, pids=(), bsd_rows=None):
        self.namespace, self.mode, self.after = namespace, mode, after
        self.failure_pid, self.pids, self.calls = failure_pid, pids, []
        self.bsd_rows = {pid: list(rows) for pid, rows in (bsd_rows or {}).items()}
        self.queries = []

    def proc_listpids(self, _kind, _argument, buffer, _size):
        self.calls.append("list_pids")
        for index, pid in enumerate(self.pids):
            buffer[index] = pid
        return 4 * len(self.pids)

    def proc_pidinfo(self, pid, flavor, _argument, buffer, _size):
        self.queries.append((pid, flavor))
        if flavor == 3:
            self.calls.append("bsd_info")
            rows = self.bsd_rows.get(pid)
            value = rows.pop(0) if rows else (
                self.after if pid == self.failure_pid else bsd(self.namespace, pid=pid, flags=0))
            if value is None:
                ctypes.set_errno(errno.ESRCH)
                return 0
            if value == "unavailable":
                ctypes.set_errno(errno.EPERM)
                return 1
            for name in ("pid", "uid", "pgid", "status", "flags", "start_sec", "start_usec"):
                setattr(buffer._obj, name, getattr(value, name))
            ctypes.set_errno(0)
            return ctypes.sizeof(self.namespace["BsdInfo"])
        require(flavor == 4, "unexpected native flavor in pure fixture")
        self.calls.append("task_info")
        mode = self.mode if pid == self.failure_pid else {}
        buffer._obj.virtual_size = mode.get("vm", 4096)
        buffer._obj.resident_size = mode.get("rss", 512)
        ctypes.set_errno(mode.get("task_errno", 0))
        return mode.get("task_size", ctypes.sizeof(self.namespace["TaskInfo"]))

    def proc_pid_rusage(self, pid, _flavor, buffer):
        self.calls.append("rusage")
        mode = self.mode if pid == self.failure_pid else {}
        buffer._obj.resident_size = 768
        buffer._obj.phys_footprint = 128
        # Failed calls may leave bytes; diagnostics must not attest timestamps.
        buffer._obj.start_abstime = mode.get("start", 16001)
        buffer._obj.exit_abstime = mode.get("exit", 0)
        ctypes.set_errno(mode.get("usage_errno", 0))
        return mode.get("usage_result", 0)


def snapshot(namespace, mode, after, **options):
    value = namespace["NativeSnapshot"].__new__(namespace["NativeSnapshot"])
    value.target_os, value.leader_start, value.last_sample = "macos", None, None
    value.leader_identity, value.last_attempt, value._held_leader = None, None, None
    value._effective_uid = MOCK_UID
    value._missing, value._pending = {}, False
    value.resources = {
        "sample_count": 0, "max_observed_sample_gap_ms": 0,
        "peak_observed_adjusted_vm_bytes": 0, "peak_observed_aggregate_rss_bytes": 0,
        "peak_observed_aggregate_footprint_bytes": 0, "peak_observed_workers": 0,
    }
    value.libproc = FakeLibproc(namespace, mode, after, **options)
    return value


def capture(function):
    try:
        return function(), None
    except RuntimeError as error:
        return None, str(error)


def owned_scope(namespace):
    # Reuse the same fake native boundary and actual reducer for prior Complete;
    # no hand-authored counter or caller DTO can substitute for that observation.
    clock = [10.0]
    namespace["time"].monotonic = lambda: clock[0]
    native = snapshot(namespace, {}, bsd(namespace, flags=0), pids=(LEADER, MEMBER))
    native.bind_reserved_leader(LEADER)
    require(native.observe(LEADER, True) == 1 and native.resources["sample_count"] == 1,
            "prior owned complete fixture failed")
    native.libproc.calls.clear()
    native.libproc.queries.clear()
    clock[0] = 10.125
    return native, clock


def missing_scope(namespace):
    native, clock = owned_scope(namespace)
    native.libproc.mode = {"task_size": 0, "task_errno": errno.ESRCH}
    native.libproc.after = None
    native.libproc.bsd_rows = {MEMBER: [bsd(namespace), None, None]}
    return native, clock


def missing_cases(namespace):
    pending_type = namespace["DarwinPendingObservation"]
    native, clock = missing_scope(namespace)
    result = native.observe(LEADER, True)
    require(isinstance(result, pending_type) and not native.normal_scope_empty(result),
            "missing resource observation became numeric count or drain")
    require(native.resources["sample_count"] == 1 and native.last_sample == 10.0 and native._pending,
            "Pending refreshed successful count or timestamp")
    facts = native.resources["native_memory_exits"]["last"]
    require(set(facts) == FIELDS | {"after_bsd_kind", "after_bsd_native_result", "after_bsd_native_errno",
                                   "pending_admission_anchor_match"}, "missing facts are not closed")
    require((facts["after_bsd_kind"], facts["after_bsd_native_result"], facts["after_bsd_native_errno"]) ==
            ("missing_esrch", 0, errno.ESRCH), "actual missing BSD result lost")
    require(facts["after_status"] is None and facts["memory_identity_check_performed"] is False and
            facts["memory_identity_match"] is None and facts["leader_anchor_check_performed"] is False and
            facts["leader_anchor_match"] is None and facts["pending_admission_anchor_match"] is None,
            "missing boundary invented an identity or earlier anchor comparison")
    history = native.resources["pending_member_exit"]
    require(history["last"]["pending_admission_anchor_match"] is True and history["observations"] == 1 and
            history["last"]["pending_admission_kind"] == "fresh_missing_after_task_exit",
            "later held leader admission was not recorded separately")
    encoded = json.dumps({"native": native.resources["native_memory_exits"], "pending": history}, separators=(",", ":"))
    require(len(encoded) < 8192, "missing history exceeded its closed bounded shape")
    for identity in (LEADER, MEMBER, MOCK_UID, *MOCK_BIRTH):
        require(str(identity) not in encoded, "private pending identity entered shared history")
    require(native.libproc.queries[-1] == (LEADER, 3) and
            native.libproc.queries[0] == (MEMBER, 3), "leader branch did not finish captured scan")
    previous_calls = len(native.libproc.calls)
    clock[0] = 10.224
    require(not native.resource_due(), "Pending triggered an immediate same-read retry")
    require(native.observe(LEADER, True) == 0 and native._missing and native._pending and
            not native.normal_scope_empty(0), "NotDue membership scan cleared missing latch or reap fence")
    require(native.observe(LEADER, False) == 0 and native._missing and native._pending and
            not native.normal_scope_empty(0), "membership-only cleanup observation cleared normal reap fence")
    require("task_info" not in native.libproc.calls[previous_calls:], "NotDue added memory queries")
    clock[0] = 10.226
    require(native.resource_due(), "Pending attempt cadence was extended")
    require(isinstance(native.observe(LEADER, True), pending_type) and
            history["observations"] == 2 and native.last_sample == 10.0 and
            history["last"]["pending_admission_kind"] == "retained_missing_after_task_exit" and
            native.resources["native_memory_exits"]["observations"] == 1,
            "later unavailable same candidate lost bounded history or reset Complete age")
    clock[0] = 11.001
    _, error = capture(native.resource_due)
    require(error is not None and "1000ms" in error and native.resources["sample_count"] == 1,
            "original complete gap was reset by Pending")

    for failure in ("initial", "reservation", "leader", "flags", "uid", "group", "rusage", "malformed",
                    "permission", "after_unknown", "after_identity", "outer_unknown", "outer_identity"):
        native, _ = missing_scope(namespace)
        if failure == "initial":
            native.resources["sample_count"], native.last_sample = 0, None
        elif failure == "reservation":
            native.release_reserved_leader()
        elif failure == "leader":
            native.libproc.bsd_rows[LEADER] = [bsd(namespace, pid=LEADER), bsd(namespace, pid=LEADER, start_usec=1)]
        elif failure in ("flags", "uid", "group"):
            changes = {"flags": {"flags": 0}, "uid": {"uid": MOCK_UID + 1}, "group": {"pgid": MEMBER}}[failure]
            native.libproc.bsd_rows[MEMBER][0] = bsd(namespace, **changes)
        elif failure == "rusage":
            native.libproc.mode = {"usage_result": -1, "usage_errno": errno.ESRCH}
        elif failure == "malformed":
            native.libproc.mode = {"task_size": 8, "task_errno": errno.ESRCH}
        elif failure == "permission":
            native.libproc.mode = {"task_size": 0, "task_errno": errno.EPERM}
        elif failure == "after_unknown":
            native.libproc.bsd_rows[MEMBER][1] = "unavailable"
        elif failure == "after_identity":
            native.libproc.bsd_rows[MEMBER][1] = bsd(namespace, start_usec=1)
        elif failure == "outer_unknown":
            native.libproc.bsd_rows[MEMBER][2] = "unavailable"
        else:
            native.libproc.bsd_rows[MEMBER][2] = bsd(namespace, uid=MOCK_UID + 1)
        _, error = capture(lambda: native.observe(LEADER, True))
        require(error is not None and native.resources["sample_count"] <= 1 and
                "pending_member_exit" not in native.resources, "unsafe missing condition was admitted: " + failure)
        if failure in ("leader", "initial", "reservation", "group"):
            require(native.resources["native_memory_exits"]["observations"] == 1,
                    "later hard failure lost original native exit facts")

    for changed in ("identity", "pid", "session"):
        for mode in ("resource", "not_due", "membership"):
            native, clock = missing_scope(namespace)
            native.observe(LEADER, True)
            clock[0] = 10.224 if mode == "not_due" else 10.25
            if changed == "identity":
                native.libproc.bsd_rows[MEMBER] = [bsd(namespace, start_sec=1)]
            elif changed == "pid":
                native.libproc.bsd_rows[MEMBER] = [bsd(namespace, pid=MEMBER + 1)]
            else:
                namespace["os"].getsid = lambda pid: LEADER + 1 if pid == MEMBER else LEADER
            try:
                _, error = capture(lambda: native.observe(LEADER, mode != "membership"))
                require(error is not None and "latched Darwin member" in error and native._pending,
                        "latched identity or foreign session was silently skipped")
            finally:
                namespace["os"].getsid = lambda _pid: LEADER

    native, clock = missing_scope(namespace)
    native.observe(LEADER, True)
    clock[0] = 10.25
    native.libproc.mode = {"rss": namespace["MEMORY_LIMIT"] + 1}
    native.libproc.bsd_rows = {MEMBER: [bsd(namespace, flags=0), None]}
    require(isinstance(native.observe(LEADER, True), pending_type) and native._missing and
            native.resources["sample_count"] == 1 and native.last_sample == 10.0 and
            native.resources["peak_observed_aggregate_rss_bytes"] == 1536 and
            native.resources["native_memory_exits"]["observations"] == 1,
            "memory without after identity became an owned value, zero, or fresh native exit")

    for resolution in ("measured", "absent", "late"):
        native, clock = missing_scope(namespace)
        native.observe(LEADER, True)
        clock[0] = 10.25
        native.libproc.mode = {}
        native.libproc.after = bsd(namespace, flags=0)
        native.libproc.bsd_rows.clear()
        if resolution == "absent":
            native.libproc.pids = (LEADER,)
        if resolution == "late":
            # Begin within the original window, finish after it. The real
            # reducer must reject before count/peak/last-success mutation.
            times = iter((10.9, 11.001))
            namespace["time"].monotonic = lambda: next(times)
        result, error = capture(lambda: native.observe(LEADER, True))
        if resolution == "late":
            require(error is not None and "1000ms" in error and native._pending and
                    native.resources["sample_count"] == 1 and native.last_sample == 10.0,
                    "late Complete changed metrics or cleared normal reap fence")
        else:
            require(error is None and result == (0 if resolution == "absent" else 1) and
                    not native._pending and not native._missing and native.resources["sample_count"] == 2,
                    "actual full Complete did not resolve missing latch")

    for bound in ("rss", "vm", "workers", "latch"):
        native, _ = missing_scope(namespace)
        if bound in ("rss", "vm"):
            # A different actually measured row exceeds the unchanged budget;
            # the missing member cannot replace its usage with zero.
            native.libproc.failure_pid = LEADER
            native.libproc.after = bsd(namespace, pid=LEADER, flags=0)
            native.libproc.mode = {bound: namespace["MEMORY_LIMIT" if bound == "rss" else "DARWIN_VM_LIMIT"] + 1}
            original = native.memory_info
            def observe_memory(pid):
                if pid == MEMBER:
                    raise namespace["DarwinProcessExited"]("fixture task exit", "task_info", 0, errno.ESRCH)
                return original(pid)
            native.memory_info = observe_memory
        elif bound == "workers":
            others = tuple(range(MEMBER + 1, MEMBER + namespace["PROCESS_LIMIT"] + 1))
            native.libproc.pids = (LEADER, MEMBER, *others)
        else:
            prototype = {"identity": native.bsd_identity(bsd(namespace)), "observation": {}}
            native._missing = {pid: dict(prototype, identity=(pid, MOCK_UID, LEADER, *MOCK_BIRTH))
                               for pid in range(MEMBER + 1, MEMBER + namespace["PROCESS_LIMIT"] + 2)}
        _, error = capture(lambda: native.observe(LEADER, True))
        require(error is not None and ("budget exceeded" in error or "bound exceeded" in error) and
                native.resources["sample_count"] == 1 and native.last_sample == 10.0,
                "partial usage or unique pending workers bypassed original cap")
    namespace["time"].monotonic = lambda: 10.0


def run():
    namespace = load_production()
    before = bsd(namespace)
    exits = [
        ({"task_size": 0, "task_errno": errno.ESRCH}, "task_info", 0, errno.ESRCH,
         None, None, ["task_info", "bsd_info"]),
        ({"usage_result": -1, "usage_errno": errno.ESRCH, "exit": 17001}, "rusage", -1,
         errno.ESRCH, None, None, ["task_info", "rusage", "bsd_info"]),
        ({"exit": 17001}, "rusage", 0, 0, True, True, ["task_info", "rusage", "bsd_info"]),
    ]
    for mode, stage, result, number, start, exited, calls in exits:
        for reserved in (False, True):
            native = snapshot(namespace, mode, bsd(namespace))
            value, error = capture(lambda: native.memory_or_confirmed_zombie(
                MEMBER, before, reserved, False, None))
            require(value is None and error == UNCONFIRMED, "strict non-zombie failure changed")
            facts = native.resources["native_memory_exits"]["last"]
            require(set(facts) == FIELDS, "diagnostic keys are not closed")
            require((facts["stage"], facts["native_result"], facts["native_errno"]) ==
                    (stage, result, number), "original native result or errno lost after BSD query")
            require((facts["rusage_start_observed"], facts["rusage_exit_observed"]) ==
                    (start, exited), "unusable rusage bytes became timestamp evidence")
            require(facts["role"] == ("reserved_leader" if reserved else "observed_member"),
                    "native role projection changed")
            require(facts["before_status"] == 2 and facts["after_status"] == 2 and
                    facts["before_inexit"] is True and facts["after_inexit"] is True,
                    "BSD facts lost")
            require(facts["memory_identity_check_performed"] is True and
                    facts["memory_identity_match"] is True, "performed identity proof lost")
            require(facts["leader_anchor_check_performed"] is False and
                    facts["leader_anchor_match"] is None, "early anchor proof invented")
            require(native.libproc.calls == calls, "native observation sequence changed")
            require(native.resources["sample_count"] == 0 and native.last_sample is None,
                    "failed observation refreshed a successful sample")

    strict = [
        ({"task_size": 8, "task_errno": errno.ESRCH},
         "Darwin task resource observation unavailable; bytes=8; errno=" + str(errno.ESRCH)),
        ({"task_size": 0, "task_errno": errno.EPERM},
         "Darwin task resource observation unavailable; bytes=0; errno=" + str(errno.EPERM)),
        ({"usage_result": -1, "usage_errno": errno.EPERM},
         "Darwin footprint observation unavailable; errno=" + str(errno.EPERM)),
        ({"start": 0, "exit": 17001}, "Darwin resource observation does not identify a live process"),
    ]
    for mode, expected in strict:
        native = snapshot(namespace, mode, before)
        _, error = capture(lambda: native.memory_or_confirmed_zombie(MEMBER, before, False, False, None))
        require(error == expected and "native_memory_exits" not in native.resources,
                "non-exit error was normalized or given exit facts")
    native = snapshot(namespace, {}, before)
    value, error = capture(lambda: native.memory_or_confirmed_zombie(MEMBER, before, False, False, None))
    require(error is None and value == (4096, 768, 128), "live memory result changed")
    require("native_memory_exits" not in native.resources, "absent history compatibility changed")
    native = snapshot(namespace, {}, bsd(namespace, flags=0), pids=(LEADER, MEMBER))
    native.leader_start = MOCK_BIRTH
    require(native.observe(LEADER, True) == 1 and native.resources["sample_count"] == 1 and
            native.last_sample == 10.0 and "native_memory_exits" not in native.resources,
            "complete scope success or absent history compatibility changed")

    confirmation = [
        (bsd(namespace, status=5), None, True, True),
        (bsd(namespace, uid=MOCK_UID + 1), IDENTITY_CHANGED, True, False),
        (None, IDENTITY_CHANGED, True, False),
        ("unavailable", "Darwin native process identity unavailable", False, None),
    ]
    for after, expected, checked, matched in confirmation:
        native = snapshot(namespace, exits[0][0], after)
        _, error = capture(lambda: native.memory_or_confirmed_zombie(MEMBER, before, False, False, None))
        require(error == expected, "strict BSD confirmation outcome changed")
        facts = native.resources["native_memory_exits"]["last"]
        require(facts["native_errno"] == errno.ESRCH, "BSD failure replaced original memory errno")
        require((facts["memory_identity_check_performed"], facts["memory_identity_match"]) ==
                (checked, matched), "unknown identity check became a performed proof")
        require(facts["after_status"] == (after.status if hasattr(after, "status") else None),
                "missing BSD status became a numeric status")

    contexts = [
        ((MEMBER, LEADER), MOCK_BIRTH, MEMBER, False, None),
        ((LEADER, MEMBER), MOCK_BIRTH, MEMBER, False, None),
        ((LEADER, MEMBER), None, MEMBER, False, None),
        ((LEADER, MEMBER), (1, 2), LEADER, False, None),
    ]
    for pids, anchor, failure_pid, checked, matched in contexts:
        native = snapshot(namespace, exits[0][0], bsd(namespace, pid=failure_pid),
                          failure_pid=failure_pid, pids=pids)
        native.leader_start = anchor
        _, error = capture(lambda: native.observe(LEADER, True))
        require(error == UNCONFIRMED, "memory exit no longer fails before the original anchor check")
        facts = native.resources["native_memory_exits"]["last"]
        require((facts["leader_anchor_check_performed"], facts["leader_anchor_match"]) ==
                (checked, matched), "memory boundary claimed the later leader-last anchor")
        require(native.resources["sample_count"] == 0, "partial scope became a complete sample")

    native = snapshot(namespace, exits[0][0], before)
    capture(lambda: native.memory_or_confirmed_zombie(MEMBER, before, False, False, None))
    native.libproc.mode = exits[1][0]
    capture(lambda: native.memory_or_confirmed_zombie(MEMBER, before, False, True, True))
    history = native.resources["native_memory_exits"]
    require(history["observations"] == 2 and history["first"]["stage"] == "task_info" and
            history["last"]["stage"] == "rusage", "bounded first and last facts were replaced")
    native.libproc.after = None
    capture(lambda: native.memory_or_confirmed_zombie(MEMBER, before, False, False, None))
    require(history["observations"] == 3 and history["last"]["after_status"] is None and
            history["first"]["stage"] == "task_info", "hard failure lost first or final native facts")
    history["observations"] = namespace["U64_MAX"]
    capture(lambda: native.memory_or_confirmed_zombie(MEMBER, before, False, False, None))
    require(history["observations"] == namespace["U64_MAX"], "diagnostic count is unbounded")
    retained = json.dumps(history, separators=(",", ":"))
    native.libproc.pids = (LEADER,)
    native.libproc.calls.clear()
    require(native.observe(LEADER, False) == 0 and
            json.dumps(history, separators=(",", ":")) == retained and
            "task_info" not in native.libproc.calls and "rusage" not in native.libproc.calls,
            "membership-only error cleanup lost facts or added a resource query")
    encoded = json.dumps(history, separators=(",", ":"))
    for value in (LEADER, MEMBER, MOCK_UID, *MOCK_BIRTH, 16001, 17001):
        require(str(value) not in encoded, "raw native identity or timestamp escaped into evidence")
    require(len(encoded) < 8192 and set(history["first"]) == set(history["last"]) == FIELDS,
            "diagnostic history is not a closed bounded record")
    missing_cases(namespace)
    print(json.dumps({"schema": "mmmm-bootstrap-darwin-pure/1", "exit_source_role_cases": 6,
                      "strict_failure_cases": 4, "live_case": 1, "confirmation_cases": 4,
                      "complete_scope_case": 1, "anchor_order_cases": 4, "history_case": 1,
                      "error_cleanup_case": 1, "missing_pending_case": 1, "missing_rejection_cases": 13,
                      "latched_identity_cases": 9, "unattributed_memory_case": 1,
                      "missing_resolution_cases": 3, "missing_budget_cases": 4,
                      "native_execution": False},
                     separators=(",", ":")))


if __name__ == "__main__":
    run()
