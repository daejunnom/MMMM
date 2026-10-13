#!/usr/bin/env python3
"""Pinned JVM toolchain extraction inside an already owned Rust build scope.

This build-infrastructure helper never creates links or replaces a previous
extraction. Failed staging is retained for the managing runner to diagnose.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import unicodedata
import zipfile

ARCHIVE_LIMIT = 512 * 1024**2
ENTRY_LIMIT = 10_000
FILE_LIMIT = 256 * 1024**2
EXPANDED_LIMIT = 2 * 1024**3
TAR_STREAM_LIMIT = EXPANDED_LIMIT + 64 * 1024**2
CHUNK = 64 * 1024
LINK_DEPTH = 16
DOS_NAMES = {"CON", "PRN", "AUX", "NUL"} | {
    prefix + str(number) for prefix in ("COM", "LPT") for number in range(1, 10)
}


def fail(code):
    raise ValueError(code)


def physical_directory(path):
    path = Path(os.path.abspath(path))
    for entry in (path, *path.parents):
        info = entry.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) & 0x400
        ):
            fail("NON_PHYSICAL_DIRECTORY")
    return path


def safe_name(name, root):
    if not isinstance(name, str) or len(name) > 512 or "\\" in name:
        fail("INVALID_MEMBER_PATH")
    name = name.rstrip("/")
    parts = name.split("/")
    if not parts or len(parts) > 32 or parts[0] != root:
        fail("UNEXPECTED_ARCHIVE_ROOT")
    for part in parts:
        if not part or part in (".", "..") or part.endswith((".", " ")):
            fail("NON_PORTABLE_MEMBER_PATH")
        if any(ord(character) < 32 or character in ':<>"|?*' for character in part):
            fail("NON_PORTABLE_MEMBER_PATH")
        if part.split(".", 1)[0].upper() in DOS_NAMES:
            fail("RESERVED_MEMBER_PATH")
        lower = part.lower()
        if lower == ".env" or lower.startswith(".env.") or lower in (
            "credentials", "credentials.json", "service-account.json", "id_rsa", "id_ed25519"
        ) or lower.startswith(("id_rsa", "id_ed25519")):
            fail("SECRET_MEMBER_PATH")
        if lower.endswith(".json") and ("credential" in lower or "service-account" in lower or "service_account" in lower):
            fail("SECRET_MEMBER_PATH")
        if lower.endswith((".pem", ".key", ".p12", ".pfx")):
            fail("SECRET_MEMBER_PATH")
    return "/".join(parts)


def collision_key(name):
    return unicodedata.normalize("NFC", name).casefold()


class Extraction:
    def __init__(self, destination, root):
        self.destination = destination
        self.root = root
        self.members = {}
        self.names = {}
        self.directories = {}
        self.expanded = 0

    def register(self, name, kind, size, executable=False, target=None):
        name = safe_name(name, self.root)
        key = collision_key(name)
        if key in self.names:
            fail("DUPLICATE_OR_UNICODE_CASE_COLLISION")
        if len(self.members) >= ENTRY_LIMIT or not 0 <= size <= FILE_LIMIT:
            fail("MEMBER_BUDGET_EXCEEDED")
        for parent in PurePosixPath(name).parents:
            if str(parent) == ".":
                continue
            parent_name = str(parent)
            parent_key = collision_key(parent_name)
            if parent_key in self.names:
                existing = self.members[self.names[parent_key]]
                if existing["kind"] != "directory" or self.names[parent_key] != parent_name:
                    fail("MEMBER_ANCESTOR_COLLISION")
            else:
                # Implicit directories are also checked against later explicit names.
                previous = self.directories.get(parent_key)
                if previous is not None and previous != parent_name:
                    fail("MEMBER_ANCESTOR_UNICODE_CASE_COLLISION")
                self.directories[parent_key] = parent_name
        directory = self.directories.get(key)
        if directory is not None and (directory != name or kind != "directory"):
            fail("MEMBER_DIRECTORY_COLLISION")
        if kind != "directory" and any(entry.startswith(name + "/") for entry in self.members):
            fail("MEMBER_DIRECTORY_COLLISION")
        self.names[key] = name
        self.members[name] = dict(kind=kind, size=size, executable=executable, target=target)
        return name

    def directory(self, name):
        path = self.destination
        for part in PurePosixPath(name).parts:
            path = path / part
            path.mkdir(mode=0o700, exist_ok=True)
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or (
                getattr(info, "st_file_attributes", 0) & 0x400
            ):
                fail("NON_PHYSICAL_EXTRACTION_DIRECTORY")
            if os.name != "nt" and info.st_mode & 0o700 != 0o700:
                fail("EXTRACTION_OWNER_PERMISSIONS_INVALID")
        return path

    def write(self, name, source):
        member = self.members[name]
        path = self.destination / name
        self.directory(str(PurePosixPath(name).parent))
        physical_directory(path.parent)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        count = 0
        with os.fdopen(descriptor, "wb") as output:
            while True:
                chunk = source.read(CHUNK)
                if not chunk:
                    break
                count += len(chunk)
                self.expanded += len(chunk)
                if count > member["size"] or self.expanded > EXPANDED_LIMIT:
                    fail("EXPANDED_BUDGET_EXCEEDED")
                output.write(chunk)
            if count != member["size"]:
                fail("MEMBER_SIZE_MISMATCH")
            output.flush()
            os.fsync(output.fileno())
        if os.name != "nt":
            os.chmod(path, 0o700 if member["executable"] else 0o600, follow_symlinks=False)

    def link_target(self, name):
        target = self.members[name]["target"]
        if not target or len(target) > 512 or "\\" in target or target.startswith("/"):
            fail("INVALID_LINK_TARGET")
        parts = list(PurePosixPath(name).parent.parts)
        for part in target.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if len(parts) <= 1:
                    fail("LINK_ESCAPE")
                parts.pop()
            else:
                parts.append(part)
        resolved = safe_name("/".join(parts), self.root)
        if resolved not in self.members:
            fail("DANGLING_OR_CASE_CHANGED_LINK")
        return resolved

    def materialize_links(self):
        for name, member in self.members.items():
            if member["kind"] != "link":
                continue
            current, seen = name, set()
            for _ in range(LINK_DEPTH):
                if current in seen:
                    fail("LINK_CYCLE")
                seen.add(current)
                candidate = self.members[current]
                if candidate["kind"] == "regular":
                    member["size"] = candidate["size"]
                    member["executable"] = candidate["executable"]
                    with (self.destination / current).open("rb") as source:
                        self.write(name, source)
                    break
                if candidate["kind"] != "link":
                    fail("NON_REGULAR_LINK_TARGET")
                current = self.link_target(current)
            else:
                fail("LINK_DEPTH_EXCEEDED")


class BoundedTarStream:
    def __init__(self, stream):
        self.stream, self.count = stream, 0

    def read(self, size):
        if size < 0 or size > FILE_LIMIT:
            fail("TAR_READ_BUDGET_EXCEEDED")
        data = self.stream.read(size)
        self.count += len(data)
        if self.count > TAR_STREAM_LIMIT:
            fail("TAR_STREAM_BUDGET_EXCEEDED")
        return data


def extract_zip(source, extraction):
    # Bound the central directory before ZipFile allocates its member inventory.
    source.seek(0, os.SEEK_END)
    length = source.tell()
    tail_start = max(0, length - 65_557)
    source.seek(tail_start)
    tail = source.read(65_557)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        fail("MISSING_ZIP_DIRECTORY")
    values = struct.unpack_from("<4s4H2LH", tail, offset)
    if values[1] or values[2] or values[3] != values[4] or values[4] > ENTRY_LIMIT:
        fail("MULTIDISK_ZIP64_OR_ENTRY_BUDGET")
    if values[5] > 16 * 1024**2 or values[6] == 0xFFFFFFFF or values[6] + values[5] > length:
        fail("ZIP_DIRECTORY_BUDGET")
    absolute_eocd = tail_start + offset
    if absolute_eocd >= 20:
        source.seek(absolute_eocd - 20)
        if source.read(4) == b"PK\x06\x07":
            fail("ZIP64_LOCATOR_REJECTED")
    if offset + 22 + values[7] != len(tail):
        fail("ZIP_TRAILING_DATA")
    source.seek(0)
    with zipfile.ZipFile(source) as archive:
        if len(archive.infolist()) != values[4]:
            fail("ZIP_ENTRY_COUNT_MISMATCH")
        for entry in archive.infolist():
            if entry.orig_filename != entry.filename:
                fail("ZIP_TRUNCATED_MEMBER_PATH")
            mode = entry.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                fail("UNSUPPORTED_ZIP_MEMBER")
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK):
                fail("ZIP_SPECIAL_MEMBER")
            kind = "directory" if entry.is_dir() else "link" if file_type == stat.S_IFLNK else "regular"
            if (file_type == stat.S_IFDIR) != entry.is_dir() and file_type != 0:
                fail("ZIP_DIRECTORY_MODE_MISMATCH")
            target = None
            if kind == "link":
                if entry.file_size > 512:
                    fail("LINK_TARGET_BUDGET")
                target = archive.read(entry).decode("utf-8", "strict")
            name = extraction.register(entry.filename, kind, entry.file_size, bool(mode & 0o111), target)
            if kind == "directory":
                if entry.file_size != 0:
                    fail("NONEMPTY_DIRECTORY")
                extraction.directory(name)
            elif kind == "regular":
                with archive.open(entry, "r") as data:
                    extraction.write(name, data)


def extract_tar(source, extraction):
    source.seek(0)
    with gzip.GzipFile(fileobj=source, mode="rb") as compressed:
        bounded = BoundedTarStream(compressed)
        with tarfile.open(fileobj=bounded, mode="r|") as archive:
            for entry in archive:
                if entry.sparse is not None or entry.islnk() or not (entry.isdir() or entry.isfile() or entry.issym()):
                    fail("TAR_SPECIAL_SPARSE_OR_HARDLINK")
                kind = "directory" if entry.isdir() else "link" if entry.issym() else "regular"
                if kind != "regular" and entry.size != 0:
                    fail("NONEMPTY_TAR_DIRECTORY_OR_LINK")
                name = extraction.register(entry.name, kind, entry.size, bool(entry.mode & 0o111), entry.linkname)
                if kind == "directory":
                    extraction.directory(name)
                elif kind == "regular":
                    data = archive.extractfile(entry)
                    if data is None:
                        fail("MISSING_TAR_MEMBER_DATA")
                    with data:
                        extraction.write(name, data)
        # tar EOF may precede the gzip footer. Consume the bounded remainder to
        # verify the gzip CRC/length and reject truncated or inflated trailers.
        while bounded.read(CHUNK):
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--root", required=True)
    options = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", options.sha256):
        fail("INVALID_ARCHIVE_DIGEST")
    safe_name(options.root, options.root)
    parent = physical_directory(options.destination.parent)
    destination = parent / options.destination.name
    if destination.exists() or destination.is_symlink():
        fail("EXISTING_EXTRACTION_RETAINED")
    physical_directory(options.archive.parent)
    metadata = options.archive.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or (
        getattr(metadata, "st_file_attributes", 0) & 0x400
    ) or not 0 < metadata.st_size <= ARCHIVE_LIMIT:
        fail("INVALID_ARCHIVE_FILE")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(options.archive, flags), "rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (metadata.st_dev, metadata.st_ino, metadata.st_size):
            fail("ARCHIVE_IDENTITY_CHANGED")
        hasher, hashed_bytes = hashlib.sha256(), 0
        while chunk := source.read(CHUNK):
            hashed_bytes += len(chunk)
            if hashed_bytes > ARCHIVE_LIMIT:
                fail("ARCHIVE_BUDGET_EXCEEDED")
            hasher.update(chunk)
        if hashed_bytes != metadata.st_size:
            fail("ARCHIVE_SIZE_CHANGED")
        digest = hasher.hexdigest()
        if digest != options.sha256:
            fail("ARCHIVE_DIGEST_MISMATCH")
        destination.mkdir(mode=0o700)
        extraction = Extraction(destination, options.root)
        if options.archive.name.endswith(".zip"):
            extract_zip(source, extraction)
        elif options.archive.name.endswith(".tar.gz"):
            extract_tar(source, extraction)
        else:
            fail("UNSUPPORTED_ARCHIVE_FORMAT")
        extraction.materialize_links()
        expected_root = extraction.members.get(options.root)
        if expected_root is not None and expected_root["kind"] != "directory":
            fail("NON_DIRECTORY_ARCHIVE_ROOT")
        physical_directory(destination / options.root)
        final = os.fstat(source.fileno())
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns
        ):
            fail("ARCHIVE_CHANGED_DURING_EXTRACTION")
        print(json.dumps({"schema": "mmmm-jvm-extraction/1", "archive_sha256": digest,
                          "root": options.root, "members": len(extraction.members),
                          "expanded_bytes": extraction.expanded, "links_materialized": sum(
                              member["kind"] == "link" for member in extraction.members.values())},
                         separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never print private paths, archive contents, environment, or command arguments.
        code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[A-Z_]+", str(error)) else type(error).__name__
        print("JVM_ARCHIVE_FAILED:" + code, file=os.sys.stderr)
        raise SystemExit(1) from None
