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
        # Write loop: os.write() may produce short writes for large payloads
        total = 0
        while total < len(raw):
            written = os.write(fd, raw[total:])
            if written == 0:
                raise OSError("os.write returned 0 bytes")
            total += written
        os.fsync(fd)
        os.close(fd)
        fd = None

        if sys.platform != "win32":
            os.chmod(tmp_path, mode)

        os.replace(tmp_path, str(target))
        tmp_path = None  # success — no cleanup needed

        # Fsync parent directory so the rename is durable on POSIX
        try:
            dir_fd = os.open(str(target.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except (OSError, AttributeError):
            pass  # Best-effort — not all platforms support O_DIRECTORY
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def atomic_write_text_sync(
    target_path: Union[str, Path],
    text: str,
    mode: int = 0o600,
    encoding: str = "utf-8",
) -> None:
    """Convenience wrapper: encode *text* and write atomically.

    Same security guarantees as :func:`atomic_write_sync`.
    """
    atomic_write_sync(target_path, text.encode(encoding), mode)


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

    # Pre-check: reject symlinks before creating/opening
    if d.is_symlink():
        link_target = os.readlink(str(d))
        raise SecurityError(
            f"Refusing to use symlink directory: {d} -> {link_target}"
        )

    os.makedirs(str(d), mode=mode, exist_ok=True)

    # Fix permissions on pre-existing directories using fd-based approach
    # to close the TOCTOU gap between is_symlink() check and chmod().
    if sys.platform != "win32":
        try:
            dir_fd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchmod(dir_fd, mode)
            finally:
                os.close(dir_fd)
        except (OSError, AttributeError):
            # O_DIRECTORY, O_NOFOLLOW, or fchmod not available — fall back
            # but re-check symlink status first
            if d.is_symlink():
                raise SecurityError(
                    f"Refusing to use symlink directory: {d}"
                )
            os.chmod(str(d), mode)
