"""
Sanna ReceiptStore — SQLite persistence for reasoning receipts.

Stores receipts with indexed metadata for fleet-level governance queries.
Uses Python's built-in sqlite3 module with no external dependencies.
"""

import json
import logging
import os
import stat
import sqlite3
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("sanna.store")


_SCHEMA_VERSION = 1

_CREATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
    id              TEXT PRIMARY KEY,
    agent_id        TEXT,
    constitution_id TEXT,
    trace_id        TEXT,
    timestamp       TEXT,
    overall_status  TEXT,
    halt_event      INTEGER DEFAULT 0,
    check_statuses  TEXT,
    receipt_json    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_agent_id ON receipts(agent_id);
CREATE INDEX IF NOT EXISTS idx_receipts_constitution_id ON receipts(constitution_id);
CREATE INDEX IF NOT EXISTS idx_receipts_trace_id ON receipts(trace_id);
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
CREATE INDEX IF NOT EXISTS idx_receipts_overall_status ON receipts(overall_status);
CREATE INDEX IF NOT EXISTS idx_receipts_halt_event ON receipts(halt_event);
"""


def _extract_agent_id(receipt: dict) -> Optional[str]:
    """Extract agent_id from receipt's constitution_ref.document_id.

    The document_id format is "{agent_name}/{version}". Returns the agent_name
    portion, or None if no constitution_ref is present.
    """
    ref = receipt.get("constitution_ref")
    if not ref or not isinstance(ref, dict):
        return None
    doc_id = ref.get("document_id")
    if not doc_id or not isinstance(doc_id, str):
        return None
    parts = doc_id.split("/", 1)
    return parts[0] if parts[0] else None


def _extract_constitution_id(receipt: dict) -> Optional[str]:
    """Extract constitution_id from receipt's constitution_ref.document_id."""
    ref = receipt.get("constitution_ref")
    if not ref or not isinstance(ref, dict):
        return None
    doc_id = ref.get("document_id")
    if doc_id and isinstance(doc_id, str):
        return doc_id
    return None


def _extract_check_statuses(receipt: dict) -> str:
    """Extract check statuses as a JSON array of {check_id, status} dicts."""
    checks = receipt.get("checks")
    if not checks or not isinstance(checks, list):
        return "[]"
    statuses = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        check_id = check.get("check_id", "unknown")
        explicit_status = check.get("status")
        if explicit_status:
            status = explicit_status
        elif check.get("passed", False):
            status = "PASS"
        else:
            status = "FAIL"
        statuses.append({"check_id": check_id, "status": status})
    return json.dumps(statuses)


def _is_halt(receipt: dict) -> int:
    """Determine whether receipt represents a halt event. Returns 0 or 1."""
    halt = receipt.get("halt_event")
    if halt and isinstance(halt, dict) and halt.get("halted"):
        return 1
    return 0


class ReceiptStore:
    """SQLite-backed persistence for Sanna reasoning receipts.

    Usage::

        store = ReceiptStore()              # default: .sanna/receipts.db
        store = ReceiptStore("/tmp/my.db")  # custom path
        receipt_id = store.save(receipt)
        results = store.query(agent_id="my-agent", status="FAIL")
        store.close()

    Also works as a context manager::

        with ReceiptStore() as store:
            store.save(receipt)
    """

    def __init__(self, db_path: str = ".sanna/receipts.db"):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._closed = False

        from sanna.utils.safe_io import ensure_secure_dir

        db_dir = os.path.dirname(db_path)
        if db_dir:
            ensure_secure_dir(db_dir, 0o700)

        db_file = Path(db_path)
        self._secure_db_file(db_file)

        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.row_factory = sqlite3.Row

        # Harden WAL/SHM sidecar files after enabling WAL mode
        self._harden_wal_sidecars(db_path)

        try:
            self._init_schema()
        except Exception:
            self._conn.close()
            raise
        self._has_json1 = self._detect_json1()

    def _secure_db_file(self, db_file: Path) -> None:
        """Validate and harden a DB file (new or existing).

        For new files: creates with restricted permissions (0o600).
        For existing files: validates regular file, ownership, and
        enforces 0o600 permissions. Rejects symlinks via O_NOFOLLOW.
        """
        from sanna.utils.safe_io import SecurityError

        if db_file.exists():
            # Existing file — validate and harden
            if sys.platform == "win32":
                # Windows: limited validation — reject symlinks, chmod only
                if db_file.is_symlink():
                    raise SecurityError(
                        f"Cannot open {db_file}: is a symlink"
                    )
                try:
                    os.chmod(str(db_file), 0o600)
                except OSError as e:
                    logger.warning(
                        "Could not harden DB file permissions on Windows: %s", e,
                    )
            else:
                try:
                    fd = os.open(str(db_file), os.O_RDWR | os.O_NOFOLLOW)
                except OSError:
                    raise SecurityError(
                        f"Cannot open {db_file}: may be a symlink or inaccessible"
                    )
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode):
                        raise SecurityError(
                            f"{db_file} is not a regular file"
                        )
                    if st.st_uid != os.getuid():
                        raise SecurityError(
                            f"{db_file} is not owned by current user"
                        )
                    os.fchmod(fd, 0o600)
                finally:
                    os.close(fd)
        else:
            # New file — create with restricted permissions
            fd = os.open(str(db_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)

    def _harden_wal_sidecars(self, db_path: str) -> None:
        """Ensure WAL/SHM sidecar files have restricted permissions."""
        if sys.platform == "win32":
            return
        for suffix in ("-wal", "-shm"):
            sidecar = Path(db_path + suffix)
            if sidecar.exists():
                if sidecar.is_symlink():
                    logger.warning(
                        "Sidecar %s is a symlink — skipping permission hardening",
                        sidecar,
                    )
                    continue
                try:
                    os.chmod(str(sidecar), 0o600)
                except OSError as e:
                    logger.warning(
                        "Could not harden sidecar %s: %s", sidecar, e,
                    )

    def _detect_json1(self) -> bool:
        """Detect whether the SQLite build has JSON1 extension support."""
        try:
            self._conn.execute("SELECT json_extract('{}', '$')")
            return True
        except sqlite3.OperationalError:
            logger.warning(
                "SQLite JSON1 extension not available. "
                "Receipt querying will use basic filtering. "
                "For full query support, use a SQLite build with JSON1 enabled."
            )
            return False

    def _init_schema(self) -> None:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.executescript(_CREATE_SCHEMA)
            row = cursor.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is None:
                cursor.execute(
                    "INSERT INTO schema_version (version) VALUES (?)",
                    (_SCHEMA_VERSION,),
                )
            elif row["version"] != _SCHEMA_VERSION:
                found = row["version"]
                raise ValueError(
                    f"ReceiptStore schema version mismatch: expected "
                    f"{_SCHEMA_VERSION}, found {found}. Database may have "
                    f"been created by a different version of Sanna."
                )
            self._conn.commit()

    def save(self, receipt: dict) -> str:
        """Store a receipt and return its ID."""
        receipt_id = receipt.get("receipt_id")
        if not receipt_id or not isinstance(receipt_id, str):
            receipt_id = uuid.uuid4().hex[:16]

        agent_id = _extract_agent_id(receipt)
        constitution_id = _extract_constitution_id(receipt)
        trace_id = receipt.get("trace_id")
        timestamp = receipt.get("timestamp")
        overall_status = receipt.get("coherence_status")
        halt = _is_halt(receipt)
        check_statuses = _extract_check_statuses(receipt)
        receipt_json = json.dumps(receipt)

        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO receipts
                   (id, agent_id, constitution_id, trace_id, timestamp,
                    overall_status, halt_event, check_statuses, receipt_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    receipt_id,
                    agent_id,
                    constitution_id,
                    trace_id if isinstance(trace_id, str) else None,
                    timestamp if isinstance(timestamp, str) else None,
                    overall_status if isinstance(overall_status, str) else None,
                    halt,
                    check_statuses,
                    receipt_json,
                ),
            )
            self._conn.commit()

        return receipt_id

    def _build_where(self, filters: dict) -> tuple[str, list]:
        """Build WHERE clause and params from filter dict."""
        clauses: list[str] = []
        params: list[Any] = []

        if "agent_id" in filters:
            clauses.append("agent_id = ?")
            params.append(filters["agent_id"])

        if "constitution_id" in filters:
            clauses.append("constitution_id = ?")
            params.append(filters["constitution_id"])

        if "trace_id" in filters:
            clauses.append("trace_id = ?")
            params.append(filters["trace_id"])

        if "status" in filters:
            clauses.append("overall_status = ?")
            params.append(filters["status"])

        if "halt_event" in filters and filters["halt_event"]:
            clauses.append("halt_event = 1")

        if "check_status" in filters:
            if self._has_json1:
                clauses.append(
                    "EXISTS (SELECT 1 FROM json_each(check_statuses) "
                    "WHERE json_extract(value, '$.status') = ?)"
                )
                params.append(filters["check_status"])
            else:
                # Fallback: use LIKE on the JSON text column.
                # json.dumps produces compact format ("status": "X"),
                # so this pattern matches correctly.
                clauses.append("check_statuses LIKE ?")
                params.append(f'%"status": "{filters["check_status"]}"%')

        if "since" in filters:
            since = filters["since"]
            if isinstance(since, datetime):
                clauses.append("timestamp >= ?")
                params.append(since.isoformat())
            elif isinstance(since, str):
                clauses.append("timestamp >= ?")
                params.append(since)

        if "until" in filters:
            until = filters["until"]
            if isinstance(until, datetime):
                clauses.append("timestamp <= ?")
                params.append(until.isoformat())
            elif isinstance(until, str):
                clauses.append("timestamp <= ?")
                params.append(until)

        where = " AND ".join(clauses) if clauses else "1=1"
        return where, params

    def query(self, *, limit: int | None = None, offset: int = 0, **filters) -> list[dict]:
        """Query receipts with combinable filters.

        Keyword Args:
            agent_id, constitution_id, trace_id, status, halt_event,
            check_status, since, until, limit, offset.

        Note: offset is only applied when limit is also provided.

        Returns list of full receipt dicts, ordered by timestamp descending.
        """
        where, params = self._build_where(filters)
        sql = f"SELECT receipt_json FROM receipts WHERE {where} ORDER BY timestamp DESC"

        if limit is not None:
            # Defense in depth: clamp negative limits
            if limit < 0:
                limit = None
            else:
                sql += " LIMIT ? OFFSET ?"
                params.extend([limit, offset])

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        return [json.loads(row["receipt_json"]) for row in rows]

    def count(self, **filters) -> int:
        """Count receipts matching the given filters."""
        where, params = self._build_where(filters)
        sql = f"SELECT COUNT(*) as cnt FROM receipts WHERE {where}"

        with self._lock:
            row = self._conn.execute(sql, params).fetchone()

        return row["cnt"]

    def close(self) -> None:
        if not self._closed:
            self._conn.close()
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
