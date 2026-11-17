"""Content-addressed, read-only object store for admitted upload bytes.

The store is the only place later stages read payloads from.  Admission copies
the caller-supplied path exactly once, hashing while copying, and then renames
the completed temporary file into an immutable, content-addressed slot.
Everything after admission refers to the object by ``content_id`` (the SHA-256
hex digest), never by the caller's path or display name.

Object names are derived from the digest and validated against a strict hex
pattern before any filesystem operation, so a user-supplied path can never be
turned into an object path or a deletion target.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import BinaryIO, Iterable

from .errors import ObjectIntegrityError, UploadTooLarge

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CHUNK = 1024 * 1024


class ObjectStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.tmp = self.root / "tmp"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.tmp.mkdir(parents=True, exist_ok=True)
        # Admission and collection must not interleave: a freshly admitted
        # object exists on disk before its reference is committed to the DB.
        self.lock = threading.RLock()

    # -- identity ---------------------------------------------------------
    @staticmethod
    def is_content_id(value: str) -> bool:
        return bool(_HEX64.match(value))

    def _path_for(self, content_id: str) -> Path:
        if not self.is_content_id(content_id):
            raise ValueError(f"invalid content id: {content_id!r}")
        return self.objects / content_id[:2] / content_id[2:]

    def path_for(self, content_id: str) -> Path:
        """Public accessor used by the scanner; validates the digest shape."""
        return self._path_for(content_id)

    # -- admission --------------------------------------------------------
    def admit_from_path(self, source: Path, max_bytes: int) -> tuple[str, int, bool]:
        """Copy ``source`` once into the store.

        Returns ``(content_id, size, created)``.  The caller's path is never
        recorded or reused: later stages only see the returned content id.
        """
        source = Path(source)
        digest = hashlib.sha256()
        size = 0
        with self.lock:
            fd, tmp_name = tempfile.mkstemp(dir=self.tmp, prefix="admit-")
            try:
                with os.fdopen(fd, "wb") as out:
                    with open(source, "rb") as src:
                        while True:
                            chunk = src.read(_CHUNK)
                            if not chunk:
                                break
                            size += len(chunk)
                            if size > max_bytes:
                                raise UploadTooLarge(size, max_bytes)
                            digest.update(chunk)
                            out.write(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                content_id = digest.hexdigest()
                target = self._path_for(content_id)
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    # Same bytes may already be stored for another upload.
                    # Verify the existing immutable object rather than trust
                    # the name.
                    self._verify_file(target, content_id, size)
                    os.unlink(tmp_name)
                    return content_id, size, False
                os.chmod(tmp_name, 0o444)
                os.replace(tmp_name, target)
                tmp_name = None
                return content_id, size, True
            finally:
                if tmp_name is not None:
                    try:
                        os.unlink(tmp_name)
                    except FileNotFoundError:
                        pass

    # -- reads ------------------------------------------------------------
    def read_bytes(self, content_id: str, expected_size: int | None = None) -> bytes:
        path = self._path_for(content_id)
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != content_id:
            raise ObjectIntegrityError(
                f"object {content_id} has digest {actual} (corrupted or swapped)"
            )
        if expected_size is not None and len(data) != expected_size:
            raise ObjectIntegrityError(
                f"object {content_id} has size {len(data)}, expected {expected_size}"
            )
        return data

    def open(self, content_id: str) -> BinaryIO:
        return self._path_for(content_id).open("rb")

    def verify(self, content_id: str, expected_size: int | None = None) -> None:
        path = self._path_for(content_id)
        self._verify_file(path, content_id, expected_size)

    def _verify_file(self, path: Path, content_id: str, expected_size: int | None) -> None:
        digest = hashlib.sha256()
        size = 0
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
        if digest.hexdigest() != content_id:
            raise ObjectIntegrityError(f"object {content_id} failed digest verification")
        if expected_size is not None and size != expected_size:
            raise ObjectIntegrityError(
                f"object {content_id} has size {size}, expected {expected_size}"
            )

    # -- maintenance ------------------------------------------------------
    def collect_garbage(self, referenced: Iterable[str]) -> list[str]:
        """Delete only service-created objects with no live reference.

        ``referenced`` comes from the database, not from user input.  Anything
        that does not look like one of our digest-named regular files is left
        alone.
        """
        referenced_set = set(referenced)
        removed: list[str] = []
        with self.lock:
            if not self.objects.exists():
                return removed
            for shard in sorted(self.objects.iterdir()):
                if not shard.is_dir() or shard.is_symlink():
                    continue
                for entry in sorted(shard.iterdir()):
                    name = shard.name + entry.name
                    if not self.is_content_id(name):
                        continue
                    if name in referenced_set:
                        continue
                    if entry.is_symlink() or not entry.is_file():
                        continue
                    try:
                        entry.unlink()
                    except FileNotFoundError:
                        continue
                    removed.append(name)
                try:
                    shard.rmdir()
                except OSError:
                    pass
        return removed
