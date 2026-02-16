"""Safe file I/O primitives with symlink protection and atomic writes.

Security rationale
------------------
All atomic-write paths in the codebase previously used deterministic ``.tmp``
suffixes next to the target file.  An attacker can pre-create a symlink at the
``.tmp`` path, causing the process to follow the symlink and overwrite an
arbitrary file.  This module replaces those patterns with:

* **Randomised temp names** via ``tempfile.mkstemp`` — no predictable paths.
* **Symlink pre-check** — rejects targets that are symlinks before writing.
* **``os.fsync``** — ensures data hits disk before ``os.replace``.
* **Restricted permissions** — files default to ``0o600``, directories to ``0o700``.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Union


class SecurityError(Exception):
    """Raised when a file I/O operation would be unsafe."""


def atomic_write_sync(
    target_path: Union[str, Path],
    data: Union[bytes, str],
    mode: int = 0o600,
) -> None:
    """Write *data* to *target_path* atomically with symlink protection.

    Security guarantees:

    1. Rejects symlink targets (prevents redirect-to-arbitrary-file attacks).
    2. Uses ``tempfile.mkstemp`` for a random temp name in the same directory
       — no predictable ``.tmp`` suffix an attacker can pre-create.
    3. Calls ``os.fsync`` before replacing — data is durable before visible.
    4. ``os.replace`` is an atomic rename on POSIX (and best-effort on Windows).
    5. Sets file permissions via ``os.chmod`` (POSIX only).
    6. Cleans up the temp file on any failure.

    Args:
        target_path: Destination path (will be created or overwritten).
        data: Content to write — ``str`` is encoded to UTF-8, ``bytes``
            written verbatim.
        mode: POSIX file permission bits (default ``0o600``).
    """
    target = Path(target_path)

    # Reject symlinks at the target path
    if target.is_symlink():
        link_target = os.readlink(str(target))
        raise SecurityError(
            f"Refusing to write to symlink: {target} -> {link_target}"
        )

    if isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = data

    fd: int | None = None
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=str(target.parent),
            prefix=f".{target.name}.",
            suffix=".tmp",
        )
        os.write(fd, raw)
        os.fsync(fd)
        os.close(fd)
        fd = None

        if sys.platform != "win32":
            os.chmod(tmp_path, mode)

        os.replace(tmp_path, str(target))
        tmp_path = None  # success — no cleanup needed
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def ensure_secure_dir(
    dir_path: Union[str, Path],
    mode: int = 0o700,
) -> None:
    """Create or validate a directory with restricted permissions.

    Security guarantees:

    1. Rejects symlinks — the directory path itself must not be a symlink.
    2. Creates the directory with the given mode if it doesn't exist.
    3. Fixes permissions on existing directories.

    Args:
        dir_path: Directory path to create or validate.
        mode: POSIX permission bits (default ``0o700``).

    Raises:
        SecurityError: If *dir_path* is a symlink.
    """
    d = Path(dir_path)
    if d.is_symlink():
        link_target = os.readlink(str(d))
        raise SecurityError(
            f"Refusing to use symlink directory: {d} -> {link_target}"
        )

    os.makedirs(str(d), mode=mode, exist_ok=True)

    # Fix permissions on pre-existing directories (POSIX only)
    if sys.platform != "win32":
        os.chmod(str(d), mode)
