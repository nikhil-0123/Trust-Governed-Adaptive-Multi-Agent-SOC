import sqlite3
import json
import logging
import os
import re
import random
import email.utils
import threading
import time
try:
    import msvcrt
except ImportError:
    msvcrt = None
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, NamedTuple

class CheckpointResult(NamedTuple):
    busy: int
    log: int
    checkpointed: int

# Supported Phase 0 V1 Schema Specification
# Exact 7 columns, exact sequence order, declared types, notnull, defaults, and primary key
SUPPORTED_V1_COLUMN_SPECS = [
    {"name": "detection_event_id", "type": "TEXT", "notnull": 0, "dflt_value": None, "pk": 1},
    {"name": "event_data", "type": "TEXT", "notnull": 1, "dflt_value": None, "pk": 0},
    {"name": "status", "type": "TEXT", "notnull": 1, "dflt_value": None, "pk": 0},
    {"name": "created_at", "type": "TIMESTAMP", "notnull": 0, "dflt_value": "CURRENT_TIMESTAMP", "pk": 0},
    {"name": "attempts", "type": "INTEGER", "notnull": 0, "dflt_value": "0", "pk": 0},
    {"name": "last_attempt", "type": "TIMESTAMP", "notnull": 0, "dflt_value": None, "pk": 0},
    {"name": "last_error", "type": "TEXT", "notnull": 0, "dflt_value": None, "pk": 0},
]
EXPECTED_V1_COLUMNS = [c["name"] for c in SUPPORTED_V1_COLUMN_SPECS]

# Required V2 Schema Specification (exact 11 columns)
REQUIRED_V2_COLUMN_SPECS = [
    {"name": "detection_event_id", "type": "TEXT", "notnull": 0, "dflt_value": None, "pk": 1},
    {"name": "event_data", "type": "TEXT", "notnull": 1, "dflt_value": None, "pk": 0},
    {"name": "status", "type": "TEXT", "notnull": 1, "dflt_value": None, "pk": 0},
    {"name": "created_at", "type": "TEXT", "notnull": 1, "dflt_value": "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')", "pk": 0},
    {"name": "attempts", "type": "INTEGER", "notnull": 1, "dflt_value": "0", "pk": 0},
    {"name": "last_attempt", "type": "TEXT", "notnull": 0, "dflt_value": None, "pk": 0},
    {"name": "last_error", "type": "TEXT", "notnull": 0, "dflt_value": None, "pk": 0},
    {"name": "delivered_at", "type": "TEXT", "notnull": 0, "dflt_value": None, "pk": 0},
    {"name": "next_attempt_at", "type": "TEXT", "notnull": 0, "dflt_value": "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')", "pk": 0},
    {"name": "quarantined_at", "type": "TEXT", "notnull": 0, "dflt_value": None, "pk": 0},
    {"name": "quarantine_reason", "type": "TEXT", "notnull": 0, "dflt_value": None, "pk": 0},
]
REQUIRED_V2_COLUMNS = frozenset(c["name"] for c in REQUIRED_V2_COLUMN_SPECS)

CANONICAL_V2_TABLE_DDL = """
CREATE TABLE outbox (
    detection_event_id TEXT PRIMARY KEY,
    event_data TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'delivered', 'quarantined')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt TEXT,
    last_error TEXT,
    delivered_at TEXT,
    next_attempt_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    quarantined_at TEXT,
    quarantine_reason TEXT,
    CHECK (status != 'pending' OR next_attempt_at IS NOT NULL)
);
"""

REBUILD_V2_TABLE_DDL = """
CREATE TABLE outbox_v2 (
    detection_event_id TEXT PRIMARY KEY,
    event_data TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'delivered', 'quarantined')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt TEXT,
    last_error TEXT,
    delivered_at TEXT,
    next_attempt_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    quarantined_at TEXT,
    quarantine_reason TEXT,
    CHECK (status != 'pending' OR next_attempt_at IS NOT NULL)
);
"""

# Expected V2 Index Specifications with exact column order, uniqueness, partial flag, and complete predicate
EXPECTED_V2_INDEX_SPECS = {
    "idx_outbox_pending_attempt": {
        "columns": ["next_attempt_at", "created_at"],
        "unique": False,
        "partial": True,
        "exact_predicate": "status='pending'"
    },
    "idx_outbox_status_delivered": {
        "columns": ["status", "delivered_at"],
        "unique": False,
        "partial": True,
        "exact_predicate": "status='delivered'"
    },
    "idx_outbox_quarantine_created": {
        "columns": ["status", "quarantined_at"],
        "unique": False,
        "partial": True,
        "exact_predicate": "status='quarantined'"
    },
    "idx_outbox_created_at": {
        "columns": ["created_at"],
        "unique": False,
        "partial": False,
        "exact_predicate": None
    }
}

def normalize_predicate(ddl: str) -> str:
    """Extracts and normalizes the complete WHERE predicate from index DDL."""
    m = re.search(r'(?i)\bwhere\s+(.*)$', ddl.strip())
    if not m:
        return ""
    raw = m.group(1).strip()
    norm = re.sub(r'\s+', ' ', raw)
    if norm.endswith(';'):
        norm = norm[:-1].strip()
    if norm.startswith('(') and norm.endswith(')'):
        inner = norm[1:-1].strip()
        if '(' not in inner and ')' not in inner:
            norm = inner
    norm = re.sub(r'\s*=\s*', '=', norm)
    norm = norm.replace('"', "'")
    return norm.lower()

def extract_check_constraints(ddl: str) -> List[str]:
    """Extracts all CHECK constraint expressions handling nested parentheses."""
    checks = []
    for match in re.finditer(r'(?i)\bcheck\s*\(', ddl):
        start = match.end()
        depth = 1
        pos = start
        while pos < len(ddl) and depth > 0:
            if ddl[pos] == '(':
                depth += 1
            elif ddl[pos] == ')':
                depth -= 1
            pos += 1
        if depth == 0:
            checks.append(ddl[start:pos-1].strip())
    return checks

def normalize_check_expr(expr: str) -> str:
    """Normalizes a single CHECK expression for canonical comparison."""
    norm = re.sub(r'\s+', ' ', expr.strip())
    norm = norm.replace('"', "'")
    norm = re.sub(r'\s*([(),!=<>])\s*', r'\1', norm)
    norm = norm.replace('<>', '!=')
    if norm.startswith('(') and norm.endswith(')'):
        inner = norm[1:-1].strip()
        if '(' not in inner and ')' not in inner:
            norm = inner
    return norm.lower()

def is_valid_status_check_expr(raw: str) -> bool:
    """
    Validates that a CHECK expression is strictly equivalent to:
    status IN ('pending', 'delivered', 'quarantined')

    Verifies the complete parsed expression, including closing parenthesis
    and absence of appended operators (OR/AND), conditions, or extra/missing values.
    Preserves acceptance of valid status ordering, casing, and whitespace variants.
    """
    expr = raw.strip()
    if expr.endswith(';'):
        expr = expr[:-1].strip()

    # Strip outer balanced parentheses if the entire expression is wrapped
    while expr.startswith('(') and expr.endswith(')'):
        depth = 0
        encloses_all = True
        for i, ch in enumerate(expr):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0 and i < len(expr) - 1:
                    encloses_all = False
                    break
        if encloses_all and depth == 0:
            expr = expr[1:-1].strip()
        else:
            break

    # Strictly match: status IN (...) with no preceding or trailing tokens/operators
    # Disallow parentheses inside the IN (...) list to forbid subexpressions or bypass clauses
    m = re.match(r"(?i)^(?:status|\"status\"|`status`|\[status\])\s+in\s*\(\s*([^()]+?)\s*\)$", expr)
    if not m:
        return False

    inner = m.group(1).strip()
    raw_items = inner.split(',')
    parsed_items = []
    for item in raw_items:
        item = item.strip()
        item_m = re.match(r"^['\"]([a-zA-Z0-9_-]+)['\"]$", item)
        if not item_m:
            return False
        parsed_items.append(item_m.group(1).lower())

    if len(parsed_items) != 3:
        return False
    if set(parsed_items) != {'pending', 'delivered', 'quarantined'}:
        return False

    return True

def validate_v2_check_constraints(ddl: str):
    """
    Validates that the table DDL contains both required CHECK constraints:
    1. status IN ('pending', 'delivered', 'quarantined')
    2. status != 'pending' OR next_attempt_at IS NOT NULL
    """
    raw_checks = extract_check_constraints(ddl)
    has_status_check = False
    has_pending_schedule_check = False

    for raw in raw_checks:
        if is_valid_status_check_expr(raw):
            has_status_check = True

        norm = normalize_check_expr(raw)
        if norm in [
            "status!='pending' or next_attempt_at is not null",
            "(status!='pending' or next_attempt_at is not null)",
            "next_attempt_at is not null or status!='pending'",
            "(next_attempt_at is not null or status!='pending')"
        ]:
            has_pending_schedule_check = True

    if not has_status_check:
        raise RuntimeError("Table constraint corruption: Missing required CHECK constraint on 'status' values ('pending', 'delivered', 'quarantined').")
    if not has_pending_schedule_check:
        raise RuntimeError("Table constraint corruption: Missing required CHECK constraint '(status != 'pending' OR next_attempt_at IS NOT NULL)'.")

def sanitize_error_message(error: Any, max_length: int = 500) -> str:
    """
    Sanitizes raw error strings, HTTP error responses, exception objects, or HTML error pages
    before persistent storage in the outbox database.

    Protections:
    1. Authorization & Proxy-Authorization headers/assignments (colon or equals, with or without scheme, raw values with spaces).
    2. Cookie and Set-Cookie headers.
    3. URL user-info credentials (e.g. https://user:password@host).
    4. Standalone Bearer / Basic / Token scheme credentials.
    5. URL query parameters (raw, single-encoded, double-encoded) including api_key, token, access_token, refresh_token, etc.
    6. x-api-key headers and assignments.
    7. Key-value credential parameters (with quotes, spaces, or equals/colon delimiters).
    8. JSON Web Tokens (JWT Header.Payload.Signature).
    9. Strips HTML markup tags and collapses multiline whitespace.
    10. Fail-safe: Returns generic fallback string if parsing raises.
    11. Strictly bounds length to <= max_length (default 500).
    """
    if error is None:
        return ""

    try:
        if isinstance(error, bytes):
            try:
                text = error.decode('utf-8', errors='replace')
            except Exception:
                text = str(error)
        else:
            text = str(error)

        # 1. Authorization & Proxy-Authorization header/assignment variants
        text = re.sub(
            r'(?i)\b(authorization|proxy-authorization)\s*[:=]\s*(?:bearer\s+|basic\s+|token\s+)?([\'"][^\'"]*[\'"]|[^\r\n,;]+)',
            r'\1: [REDACTED]',
            text
        )

        # 2. Cookie and Set-Cookie headers (mask entire cookie string)
        text = re.sub(
            r'(?i)\b(cookie|set-cookie)\s*[:=]\s*([\'"][^\'"]*[\'"]|[^\r\n]+)',
            r'\1: [REDACTED]',
            text
        )

        # 3. URL user-info credentials: http(s)://username:password@host
        text = re.sub(
            r'(?i)\b([a-zA-Z][a-zA-Z0-9+\-.]*://[^:@\s]+):([^@\s]+)@',
            r'\1:[REDACTED]@',
            text
        )

        # 4. Standalone Bearer / Basic / Token scheme credentials
        text = re.sub(
            r'(?i)\b(bearer\s+|basic\s+|token\s+)(?![=:])([\'"][^\'"]*[\'"]|[a-zA-Z0-9_\-\.+=/]+)',
            r'\1[REDACTED]',
            text
        )

        # 5. URL query parameter credentials (including refresh_token)
        # 5a. Raw query strings (?key=val or &key=val)
        text = re.sub(
            r'(?i)([?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|auth|password|secret|client[_-]?secret)=)[^&#\s\'\"<>]+',
            r'\1[REDACTED]',
            text
        )
        # 5b. Single & Double URL-encoded query parameters (%3Fkey%3D... or %253Fkey%253D...)
        text = re.sub(
            r'(?i)((?:%3F|%26|%253F|%2526)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|auth|password|secret|client[_-]?secret)(?:%3D|%253D))[^&#\s\'\"<>]+',
            r'\1[REDACTED]',
            text
        )

        # 6. x-api-key and variants
        text = re.sub(
            r'(?i)\b(x-api-key)\s*[:=]\s*([\'"][^\'"]*[\'"]|[^\s,;]+)',
            r'\1:[REDACTED]',
            text
        )

        # 7. Key-value credential parameters (supporting quotes with spaces and unquoted strings)
        text = re.sub(
            r'(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|auth|password|passwd|pwd|secret|client[_-]?secret)\s*[:=]\s*([\'"][^\'"]*[\'"]|[^\s,;]+)',
            r'\1=[REDACTED]',
            text
        )

        # 8. JSON Web Tokens (JWT Header.Payload.Signature)
        text = re.sub(
            r'\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+',
            '[REDACTED_JWT]',
            text
        )

        # 9. Strip HTML error bodies
        text = re.sub(r'<[^>]+>', ' ', text)

        # 10. Collapse whitespace and normalize
        text = re.sub(r'\s+', ' ', text).strip()

        # 11. Enforce bounding ceiling
        return text[:max_length]

    except Exception:
        return "[SANITIZATION_FALLBACK] Error details could not be safely sanitized."

def compute_transient_backoff(attempt: int) -> float:
    """
    Computes retry backoff for transient network errors and HTTP 5xx responses.
    Base backoff: 2.0 * 2^(min(attempt - 1, 8))
    Jitter: Uniform(0.8, 1.2)
    Final delay: Strictly clamped to [1.0, 300.0] seconds AFTER jitter.
    """
    base = min(300.0, 2.0 * (2 ** min(max(attempt - 1, 0), 8)))
    jitter = random.uniform(0.8, 1.2)
    raw_delay = base * jitter
    return min(300.0, max(1.0, raw_delay))

def compute_auth_backoff(attempt: int) -> float:
    """
    Computes retry backoff for HTTP 401 / 403 responses.
    Base backoff: 30.0 * 2^(min(attempt - 1, 4))
    Jitter: Uniform(0.9, 1.1)
    Final delay: Strictly clamped to [1.0, 300.0] seconds AFTER jitter.
    """
    base = min(300.0, 30.0 * (2 ** min(max(attempt - 1, 0), 4)))
    jitter = random.uniform(0.9, 1.1)
    raw_delay = base * jitter
    return min(300.0, max(1.0, raw_delay))

def compute_rate_limit_backoff(retry_after_seconds: float = 30.0) -> float:
    """
    Computes retry backoff for HTTP 429 Too Many Requests.
    Jitter: Uniform(0.0, 2.0)
    Final delay: Strictly clamped to [1.0, 3600.0] seconds AFTER jitter.
    """
    raw_delay = retry_after_seconds + random.uniform(0.0, 2.0)
    return min(3600.0, max(1.0, raw_delay))

def parse_retry_after(header_val: Optional[str], default_seconds: float = 30.0) -> float:
    """
    Parses Retry-After header which can be delta-seconds or an HTTP-date.
    Clamps parsed seconds to [1.0, 3600.0].
    """
    if not header_val:
        return default_seconds
    header_str = str(header_val).strip()
    try:
        secs = float(header_str)
        return min(3600.0, max(1.0, secs))
    except ValueError:
        pass
    try:
        parsed_dt = email.utils.parsedate_to_datetime(header_str)
        diff = (parsed_dt - datetime.now(timezone.utc)).total_seconds()
        return min(3600.0, max(1.0, diff))
    except Exception:
        return default_seconds

def is_sqlite_busy_or_locked(err: Exception) -> bool:
    """
    Determines whether an OperationalError is caused by database lock contention,
    correctly masking SQLite extended error codes to extract the primary result code.
    """
    code = getattr(err, 'sqlite_errorcode', None)
    if code is not None and isinstance(code, int):
        primary_code = code & 0xFF
        busy_primary = getattr(sqlite3, 'SQLITE_BUSY', 5)
        locked_primary = getattr(sqlite3, 'SQLITE_LOCKED', 6)
        if primary_code in (busy_primary, locked_primary):
            return True

    # Compatibility fallback: string inspection
    err_msg = str(err).lower()
    return "busy" in err_msg or "locked" in err_msg

def canonicalize_db_path(path: str) -> str:
    """
    Produces a canonical, unambiguous, normalized database path on Windows.
    Applies os.path.abspath, os.path.realpath (symlink resolution), and os.path.normcase (case-folding).
    """
    if path == ":memory:":
        return ":memory:"
    abs_path = os.path.abspath(path)
    real_path = os.path.realpath(abs_path)
    return os.path.normcase(real_path)

class WindowsProcessLock:
    """
    Enforces process-level mutual exclusion for the outbox delivery worker on Windows.
    Uses msvcrt.locking with mode msvcrt.LK_NBLCK for non-blocking lock acquisition.
    """
    def __init__(self, lock_path: str, logger: Optional[logging.Logger] = None):
        self.lock_path = os.path.abspath(lock_path)
        self.logger = logger
        self._fd: Optional[int] = None

    def acquire(self) -> bool:
        if self._fd is not None:
            return False

        if msvcrt is None or not hasattr(msvcrt, "locking"):
            if self.logger:
                self.logger.error("Platform locking mechanism (msvcrt.locking) is unavailable. Failing closed.")
            return False

        os.makedirs(os.path.dirname(self.lock_path), exist_ok=True)
        fd = None
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            self._fd = fd
            return True
        except (OSError, IOError) as e:
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    pass
            if self.logger:
                self.logger.warning(f"Could not acquire outbox OS lock on {self.lock_path}: {e}")
            return False

    def release(self) -> None:
        if self._fd is not None:
            fd = self._fd
            self._fd = None
            if msvcrt is not None:
                try:
                    try:
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                finally:
                    try:
                        os.close(fd)
                    except Exception:
                        pass
            else:
                try:
                    os.close(fd)
                except Exception:
                    pass

    def __enter__(self):
        if not self.acquire():
            raise RuntimeError(f"Could not acquire OS lock on {self.lock_path}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

class OutboxLock:
    """
    Two-Tier Synchronization Guard:
    Tier 1 (Process-Local): Shared threading.Lock registry keyed by canonical db_path.
    Tier 2 (Cross-Process): Windows file locking via msvcrt.LK_NBLCK on canonical lock path.
    """
    _process_locks: Dict[str, threading.Lock] = {}
    _registry_lock = threading.Lock()

    def __init__(self, db_path: str, logger: Optional[logging.Logger] = None):
        self.canonical_db_path = canonicalize_db_path(db_path)
        self.canonical_lock_path = self.canonical_db_path + ".lock"
        self.logger = logger
        self._local_lock: Optional[threading.Lock] = None
        self._local_acquired = False
        self._os_lock = WindowsProcessLock(self.canonical_lock_path, logger=logger)
        self._os_acquired = False

    def acquire(self) -> bool:
        with self._registry_lock:
            if self.canonical_db_path not in self._process_locks:
                self._process_locks[self.canonical_db_path] = threading.Lock()
            self._local_lock = self._process_locks[self.canonical_db_path]

        self._local_acquired = self._local_lock.acquire(blocking=False)
        if not self._local_acquired:
            return False

        self._os_acquired = self._os_lock.acquire()
        if not self._os_acquired:
            self._local_lock.release()
            self._local_acquired = False
            return False

        return True

    def release(self) -> None:
        try:
            if self._os_acquired:
                self._os_lock.release()
        finally:
            self._os_acquired = False
            if self._local_acquired and self._local_lock is not None:
                try:
                    self._local_lock.release()
                except Exception:
                    pass
                self._local_acquired = False

    def __enter__(self):
        if not self.acquire():
            raise RuntimeError(f"Could not acquire outbox lock for: {self.canonical_db_path}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

class Outbox:
    VALID_STATUSES = frozenset({'pending', 'delivered', 'quarantined'})

    def __init__(
        self,
        db_path: str,
        logger: logging.Logger,
        busy_timeout_ms: int = 5000,
        synchronous_mode: str = "NORMAL",
        wal_autocheckpoint: int = 1000
    ):
        self.db_path = db_path
        self.logger = logger

        if not isinstance(busy_timeout_ms, int) or busy_timeout_ms < 1000:
            raise ValueError(f"busy_timeout_ms must be an integer >= 1000, got: {busy_timeout_ms}")
        self.busy_timeout_ms = busy_timeout_ms

        sync_upper = str(synchronous_mode).upper().strip()
        if sync_upper not in ("NORMAL", "FULL"):
            raise ValueError(f"synchronous_mode must be 'NORMAL' or 'FULL', got: {synchronous_mode}")
        self.synchronous_mode = sync_upper

        if not isinstance(wal_autocheckpoint, int) or wal_autocheckpoint < 10:
            raise ValueError(f"wal_autocheckpoint must be an integer >= 10, got: {wal_autocheckpoint}")
        self.wal_autocheckpoint = wal_autocheckpoint

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = None
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=float(self.busy_timeout_ms) / 1000.0,
                isolation_level=None
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute(f"PRAGMA synchronous = {self.synchronous_mode};")
            conn.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms};")
            conn.execute(f"PRAGMA wal_autocheckpoint = {self.wal_autocheckpoint};")
            conn.execute("PRAGMA temp_store = MEMORY;")
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn
        except Exception:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            raise

    def checkpoint(self, mode: str = "PASSIVE") -> CheckpointResult:
        """
        Executes a WAL checkpoint operation.
        Defaults to PASSIVE mode to avoid blocking concurrent readers/writers.
        Returns CheckpointResult(busy=..., log=..., checkpointed=...).
        """
        mode_upper = mode.upper().strip()
        if mode_upper not in ("PASSIVE", "FULL", "RESTART", "TRUNCATE"):
            raise ValueError(f"Invalid checkpoint mode: {mode}")

        conn = self._get_connection()
        try:
            cur = conn.execute(f"PRAGMA wal_checkpoint({mode_upper});")
            row = cur.fetchone()
            if row:
                busy, log, checkpointed = int(row[0]), int(row[1]), int(row[2])
            else:
                busy, log, checkpointed = 0, 0, 0
            return CheckpointResult(busy=busy, log=log, checkpointed=checkpointed)
        finally:
            conn.close()

    def _execute_transaction_with_retry(self, fn, max_retries: int = 5):
        """
        Executes a database transaction with bounded retry and backoff on BUSY/LOCKED contention.
        Wraps the operation in BEGIN IMMEDIATE ... COMMIT.
        Rolls back and closes connection before each retry attempt.
        """
        attempt = 0
        while True:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                result = fn(conn)
                conn.execute("COMMIT")
                return result
            except sqlite3.OperationalError as e:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None

                if is_sqlite_busy_or_locked(e) and attempt < max_retries:
                    attempt += 1
                    backoff = min(1.0, (0.05 * (2 ** (attempt - 1))) + random.uniform(0.01, 0.05))
                    if self.logger:
                        self.logger.warning(
                            f"Database busy or locked (attempt {attempt}/{max_retries}), retrying in {backoff:.3f}s: {e}"
                        )
                    time.sleep(backoff)
                    continue
                raise
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass

    def _init_db(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        conn = self._get_connection()
        try:
            self._validate_or_migrate_schema(conn)
        finally:
            conn.close()

    def _validate_or_migrate_schema(self, conn: sqlite3.Connection):
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'")
        has_migrations_tbl = cur.fetchone() is not None

        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='outbox'")
        has_outbox_tbl = cur.fetchone() is not None

        current_version = 0
        if has_migrations_tbl:
            self._validate_schema_migrations_table(conn)
            cur = conn.execute("SELECT MAX(version) FROM schema_migrations")
            row = cur.fetchone()
            if row and row[0] is not None:
                current_version = row[0]

        if current_version > 2:
            raise RuntimeError(
                f"Unsupported outbox schema version: {current_version}. "
                "Maximum supported version by this agent is 2. Please upgrade windows-telemetry."
            )

        if has_migrations_tbl and not has_outbox_tbl:
            raise RuntimeError(
                f"Schema corruption detected: schema_migrations indicates version {current_version} but 'outbox' table is missing."
            )

        if current_version == 2:
            self._validate_v2_integrity(conn)
            return

        # Handle database without schema_migrations or version < 2
        if not has_outbox_tbl:
            self._init_fresh_db(conn)
        else:
            # Table exists: validate complete V1 schema before executing migration DDL
            self._validate_v1_schema(conn)
            self._migrate_v1_to_v2(conn)

    def _validate_schema_migrations_table(self, conn: sqlite3.Connection):
        """Validates schema_migrations structure before trusting version records."""
        table_info = conn.execute("PRAGMA table_info(schema_migrations)").fetchall()
        cols = {r[1]: r for r in table_info}
        if "version" not in cols or "applied_at" not in cols or "description" not in cols:
            raise RuntimeError("Schema corruption: 'schema_migrations' table missing required columns.")
        if cols["version"][5] != 1:
            raise RuntimeError("Schema corruption: 'version' in 'schema_migrations' must be primary key.")

    def _validate_v1_schema(self, conn: sqlite3.Connection):
        """
        Validates the entire supported V1 schema:
        - Exact column names and order
        - Declared types
        - Primary-key definition
        - NOT NULL constraints
        - Defaults
        """
        table_info = conn.execute("PRAGMA table_info(outbox)").fetchall()
        if len(table_info) != len(SUPPORTED_V1_COLUMN_SPECS):
            raise RuntimeError(
                f"Unrecognized existing outbox schema: found {len(table_info)} columns, "
                f"expected {len(SUPPORTED_V1_COLUMN_SPECS)} supported V1 columns. "
                "Automatic migration aborted to prevent data loss."
            )

        for idx, (expected, actual) in enumerate(zip(SUPPORTED_V1_COLUMN_SPECS, table_info)):
            act_cid, act_name, act_type, act_notnull, act_dflt, act_pk = actual

            if act_name != expected["name"]:
                raise RuntimeError(
                    f"Unrecognized outbox schema: column {idx} named '{act_name}', expected '{expected['name']}'."
                )
            if act_type.upper() != expected["type"]:
                raise RuntimeError(
                    f"Unrecognized outbox schema: column '{act_name}' type is '{act_type}', expected '{expected['type']}'."
                )
            if act_notnull != expected["notnull"]:
                raise RuntimeError(
                    f"Unrecognized outbox schema: column '{act_name}' notnull is {act_notnull}, expected {expected['notnull']}."
                )
            if act_pk != expected["pk"]:
                raise RuntimeError(
                    f"Unrecognized outbox schema: column '{act_name}' pk is {act_pk}, expected {expected['pk']}."
                )
            if act_dflt != expected["dflt_value"]:
                raise RuntimeError(
                    f"Unrecognized outbox schema: column '{act_name}' default is '{act_dflt}', expected '{expected['dflt_value']}'."
                )

    def _validate_v2_integrity(self, conn: sqlite3.Connection):
        """
        Validates the complete required V2 schema, including exact column definitions,
        declared types, NOT NULL flags, defaults, primary keys, and complete index specifications.
        """
        table_info = conn.execute("PRAGMA table_info(outbox)").fetchall()
        actual_cols = {r[1]: r for r in table_info}
        missing_cols = REQUIRED_V2_COLUMNS - set(actual_cols.keys())
        if missing_cols:
            raise RuntimeError(f"Schema corruption: Version 2 outbox missing required columns: {sorted(missing_cols)}")

        if actual_cols.get("detection_event_id") and actual_cols["detection_event_id"][5] != 1:
            raise RuntimeError("Schema corruption: 'detection_event_id' must be primary key in Version 2.")

        if len(table_info) != len(REQUIRED_V2_COLUMN_SPECS):
            raise RuntimeError(
                f"Schema corruption: Version 2 outbox has {len(table_info)} columns, "
                f"expected {len(REQUIRED_V2_COLUMN_SPECS)} columns."
            )

        for idx, (expected, actual) in enumerate(zip(REQUIRED_V2_COLUMN_SPECS, table_info)):
            act_cid, act_name, act_type, act_notnull, act_dflt, act_pk = actual

            if act_name != expected["name"]:
                raise RuntimeError(
                    f"Schema corruption: column {idx} named '{act_name}', expected '{expected['name']}'."
                )
            if act_type.upper() != expected["type"]:
                raise RuntimeError(
                    f"Schema corruption: column '{act_name}' type is '{act_type}', expected '{expected['type']}'."
                )
            if act_notnull != expected["notnull"]:
                raise RuntimeError(
                    f"Schema corruption: column '{act_name}' notnull is {act_notnull}, expected {expected['notnull']}."
                )
            if act_pk != expected["pk"]:
                raise RuntimeError(
                    f"Schema corruption: column '{act_name}' pk is {act_pk}, expected {expected['pk']}."
                )
            if act_dflt != expected["dflt_value"]:
                raise RuntimeError(
                    f"Schema corruption: column '{act_name}' default is '{act_dflt}', expected '{expected['dflt_value']}'."
                )

        index_list = {r[1]: {"unique": bool(r[2]), "partial": bool(r[4])}
                      for r in conn.execute("PRAGMA index_list(outbox)").fetchall()}

        for idx_name, spec in EXPECTED_V2_INDEX_SPECS.items():
            if idx_name not in index_list:
                raise RuntimeError(f"Index corruption: Missing expected index '{idx_name}'")

            actual_meta = index_list[idx_name]
            if actual_meta["unique"] != spec["unique"]:
                raise RuntimeError(f"Index corruption on '{idx_name}': expected unique={spec['unique']}, found {actual_meta['unique']}")

            if actual_meta["partial"] != spec["partial"]:
                raise RuntimeError(f"Index corruption on '{idx_name}': expected partial={spec['partial']}, found {actual_meta['partial']}")

            info_rows = conn.execute(f"PRAGMA index_info({idx_name})").fetchall()
            actual_cols_order = [r[2] for r in sorted(info_rows, key=lambda x: x[0])]
            if actual_cols_order != spec["columns"]:
                raise RuntimeError(f"Index corruption on '{idx_name}': expected columns {spec['columns']}, found {actual_cols_order}")

            if spec["exact_predicate"]:
                cur = conn.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (idx_name,))
                sql_row = cur.fetchone()
                if not sql_row or not sql_row[0]:
                    raise RuntimeError(f"Index corruption on '{idx_name}': could not read index DDL from sqlite_master")
                pred = normalize_predicate(sql_row[0])
                if pred != spec["exact_predicate"]:
                    raise RuntimeError(
                        f"Index corruption on '{idx_name}': extracted predicate '{pred}' "
                        f"does not exactly match expected predicate '{spec['exact_predicate']}'."
                    )

        # Validate table-level CHECK constraints directly from table DDL
        cur = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='outbox'")
        tbl_row = cur.fetchone()
        if not tbl_row or not tbl_row[0]:
            raise RuntimeError("Schema corruption: could not read table DDL for 'outbox' from sqlite_master")
        validate_v2_check_constraints(tbl_row[0])

    def _init_fresh_db(self, conn: sqlite3.Connection):
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    description TEXT NOT NULL
                );
            """)
            conn.execute(CANONICAL_V2_TABLE_DDL)
            self._create_indexes(conn)
            conn.execute("""
                INSERT INTO schema_migrations (version, applied_at, description)
                VALUES (2, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), 'Initial canonical V2 outbox schema');
            """)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection):
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    description TEXT NOT NULL
                );
            """)

            # Create transitional table using canonical V2 structure and constraints
            conn.execute(REBUILD_V2_TABLE_DDL)

            # Copy and normalize data from outbox to outbox_v2
            conn.execute("""
                INSERT INTO outbox_v2 (
                    detection_event_id,
                    event_data,
                    status,
                    created_at,
                    attempts,
                    last_attempt,
                    last_error,
                    delivered_at,
                    next_attempt_at,
                    quarantined_at,
                    quarantine_reason
                )
                SELECT
                    detection_event_id,
                    event_data,
                    status,
                    COALESCE(
                        strftime('%Y-%m-%dT%H:%M:%SZ', created_at),
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    ),
                    MAX(0, CAST(COALESCE(attempts, 0) AS INTEGER)),
                    CASE
                        WHEN last_attempt IS NOT NULL THEN strftime('%Y-%m-%dT%H:%M:%SZ', last_attempt)
                        ELSE NULL
                    END,
                    last_error,
                    CASE
                        WHEN status = 'delivered' THEN strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                        ELSE NULL
                    END,
                    CASE
                        WHEN status = 'pending' THEN COALESCE(
                            strftime('%Y-%m-%dT%H:%M:%SZ', created_at),
                            strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                        )
                        ELSE NULL
                    END,
                    NULL,
                    NULL
                FROM outbox;
            """)

            # Atomic swap: drop old V1 table and rename rebuilt table to canonical outbox
            conn.execute("DROP TABLE outbox;")
            conn.execute("ALTER TABLE outbox_v2 RENAME TO outbox;")

            # Create canonical V2 indexes on rebuilt outbox
            self._create_indexes(conn)

            conn.execute("""
                INSERT INTO schema_migrations (version, applied_at, description)
                VALUES (2, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), 'Migrated V1 outbox to canonical V2 via transactional table rebuild');
            """)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def _create_indexes(self, conn: sqlite3.Connection):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_outbox_pending_attempt ON outbox (next_attempt_at, created_at) WHERE status = 'pending';")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_outbox_status_delivered ON outbox (status, delivered_at) WHERE status = 'delivered';")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_outbox_quarantine_created ON outbox (status, quarantined_at) WHERE status = 'quarantined';")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_outbox_created_at ON outbox (created_at);")

    def add_event(self, event: Dict[str, Any]):
        event_id = event.get("detection_event_id")
        if not event_id:
            raise ValueError("Event missing detection_event_id")

        def _op(conn: sqlite3.Connection):
            conn.execute('''
                INSERT OR IGNORE INTO outbox (detection_event_id, event_data, status)
                VALUES (?, ?, 'pending')
            ''', (event_id, json.dumps(event)))

        try:
            self._execute_transaction_with_retry(_op)
        except Exception as e:
            self.logger.error(f"Failed to add event {event_id} to outbox: {e}")
            raise

    def get_pending_events(self, limit: int = 50, eligible_only: bool = False, now_utc: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            if eligible_only:
                now_str = now_utc or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                cursor = conn.execute('''
                    SELECT detection_event_id, event_data, attempts, created_at, next_attempt_at FROM outbox
                    WHERE status = 'pending' AND next_attempt_at <= ?
                    ORDER BY next_attempt_at ASC, created_at ASC LIMIT ?
                ''', (now_str, limit))
            else:
                cursor = conn.execute('''
                    SELECT detection_event_id, event_data, attempts, created_at, next_attempt_at FROM outbox
                    WHERE status = 'pending'
                    ORDER BY created_at ASC LIMIT ?
                ''', (limit,))
            rows = [dict(row) for row in cursor.fetchall()]
            cursor.close()
            return rows
        finally:
            conn.close()

    def mark_delivered(self, event_id: str):
        def _op(conn: sqlite3.Connection):
            conn.execute('''
                UPDATE outbox SET
                    status = 'delivered',
                    last_attempt = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                    delivered_at = COALESCE(delivered_at, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                WHERE detection_event_id = ?
            ''', (event_id,))

        self._execute_transaction_with_retry(_op)

    def mark_failed(self, event_id: str, error: str, next_attempt_at: Optional[str] = None):
        sanitized_error = sanitize_error_message(error)

        def _op(conn: sqlite3.Connection):
            if next_attempt_at:
                conn.execute('''
                    UPDATE outbox SET
                        attempts = attempts + 1,
                        last_attempt = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                        last_error = ?,
                        next_attempt_at = ?
                    WHERE detection_event_id = ?
                ''', (sanitized_error, next_attempt_at, event_id))
            else:
                conn.execute('''
                    UPDATE outbox SET
                        attempts = attempts + 1,
                        last_attempt = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                        last_error = ?
                    WHERE detection_event_id = ?
                ''', (sanitized_error, event_id))

        self._execute_transaction_with_retry(_op)

    def mark_quarantined(self, event_id: str, reason: str, error: str = "", increment_attempts: bool = False):
        sanitized_error = sanitize_error_message(error)

        def _op(conn: sqlite3.Connection):
            if increment_attempts:
                conn.execute('''
                    UPDATE outbox SET
                        status = 'quarantined',
                        attempts = CASE WHEN status = 'quarantined' THEN attempts ELSE attempts + 1 END,
                        quarantined_at = COALESCE(quarantined_at, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                        quarantine_reason = ?,
                        last_error = ?,
                        last_attempt = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                        next_attempt_at = NULL
                    WHERE detection_event_id = ?
                ''', (reason, sanitized_error, event_id))
            else:
                conn.execute('''
                    UPDATE outbox SET
                        status = 'quarantined',
                        quarantined_at = COALESCE(quarantined_at, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                        quarantine_reason = ?,
                        last_error = ?,
                        last_attempt = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                        next_attempt_at = NULL
                    WHERE detection_event_id = ?
                ''', (reason, sanitized_error, event_id))

        self._execute_transaction_with_retry(_op)

    def get_quarantined_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.execute('''
                SELECT detection_event_id, event_data, status, created_at, attempts,
                       last_attempt, last_error, quarantined_at, quarantine_reason
                FROM outbox
                WHERE status = 'quarantined'
                ORDER BY quarantined_at ASC, created_at ASC LIMIT ?
            ''', (limit,))
            rows = [dict(row) for row in cursor.fetchall()]
            cursor.close()
            return rows
        finally:
            conn.close()

    def purge_delivered_events(self, retention_hours: int = 72, cutoff_time: Optional[str] = None) -> int:
        if cutoff_time is None:
            cutoff_dt = datetime.now(timezone.utc) - timedelta(hours=retention_hours)
            cutoff_time = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        def _op(conn: sqlite3.Connection):
            cur = conn.execute('''
                DELETE FROM outbox
                WHERE status = 'delivered'
                  AND delivered_at IS NOT NULL
                  AND delivered_at <= ?
            ''', (cutoff_time,))
            return cur.rowcount

        return self._execute_transaction_with_retry(_op)
