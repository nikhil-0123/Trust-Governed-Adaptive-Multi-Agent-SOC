"""
CheckpointManager: Channel-Specific Checkpoint and Epoch Store for TGAM-SOC
===========================================================================

Implements persistent, channel-specific epoch authority and crash-recoverable
checkpoint transitions for Windows Event Log channels.
Enforces channel-ownership boundaries, OS kernel-level concurrency locking,
fencing token verification, dual-file backup durability with 7-phase fsync,
and coordinated cross-store pending outbox notification ledger.
"""

import os
import json
import time
import uuid
import zlib
import socket
import logging
import hashlib
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, Callable, Union

try:
    import msvcrt
except ImportError:
    msvcrt = None

try:
    import fcntl
except ImportError:
    fcntl = None

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from canonical import validate_epoch, validate_record_id, canonicalize_tgam_rcc_v1


class CheckpointLockTimeout(Exception):
    """Raised when acquiring the channel-level filesystem kernel lock times out."""
    pass


def compute_checkpoint_crc32(state: Dict[str, Any]) -> str:
    """
    Computes deterministic CRC32 checksum over the canonical checkpoint fields using TGAM-RCC-v1.
    Canonical state fields included:
      - log_name (str)
      - epoch (int)
      - last_record_id (int)
      - applied_transitions (dict)
      - highest_applied_source_positions (dict)
      - watermark (dict)
      - pending_outbox_notifications (dict)
    """
    manifest = {
        "applied_transitions": state.get("applied_transitions", {}),
        "epoch": int(state.get("epoch", 1)),
        "highest_applied_source_positions": state.get("highest_applied_source_positions", {}),
        "last_record_id": int(state.get("last_record_id", 0)),
        "log_name": str(state.get("log_name", "")).strip(),
        "pending_outbox_notifications": state.get("pending_outbox_notifications", {}),
        "watermark": state.get("watermark", {}),
    }
    canonical_bytes = canonicalize_tgam_rcc_v1(manifest)
    crc = zlib.crc32(canonical_bytes) & 0xFFFFFFFF
    return f"{crc:08x}"


def _acquire_kernel_lock(fd: int) -> bool:
    """Acquires a non-blocking exclusive OS kernel-level byte/file lock on fd."""
    if msvcrt is not None and hasattr(msvcrt, "locking"):
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except (OSError, IOError, PermissionError):
            return False
    elif fcntl is not None and hasattr(fcntl, "flock"):
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (OSError, IOError):
            return False
    else:
        raise RuntimeError("No supported OS kernel file locking mechanism available (msvcrt or fcntl).")


def _release_kernel_lock(fd: int) -> None:
    """Releases the OS kernel-level byte/file lock on fd."""
    if msvcrt is not None and hasattr(msvcrt, "locking"):
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
    elif fcntl is not None and hasattr(fcntl, "flock"):
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception:
            pass


class CheckpointManager:
    """
    Manages channel-specific checkpoint state with atomic file operations,
    OS-level kernel concurrency locking, fencing token progression, dual-file
    backup durability, and coordinated transition ledger durability.
    """

    def __init__(
        self,
        checkpoint_dir: str,
        log_name: str,
        logger: logging.Logger,
        channel: Optional[str] = None,
    ):
        self.checkpoint_dir = checkpoint_dir
        self.logger = logger
        # Explicit channel binding
        self.channel = (channel or log_name).strip()
        self.log_name = self.channel

        safe_name = "".join([c if c.isalnum() else "_" for c in self.channel])
        self.checkpoint_file = os.path.join(checkpoint_dir, f"{safe_name}_checkpoint.json")
        self.bak_file = os.path.join(checkpoint_dir, f"{safe_name}_checkpoint.json.bak")
        self.lock_dir = os.path.join(checkpoint_dir, "locks")
        self.lock_file = os.path.join(self.lock_dir, f"checkpoint_{safe_name}.lock")
        self._lock_fd: Optional[int] = None
        self._lock_depth: int = 0
        self._current_lock_epoch: int = 0
        self._current_owner_uuid: Optional[str] = None
        self._thread_rlock = threading.RLock()

    def _ensure_dirs(self):
        os.makedirs(self.checkpoint_dir, exist_ok=True)
        os.makedirs(self.lock_dir, exist_ok=True)

    def _check_channel_authorization(self, target_channel: str):
        """Enforces that this instance cannot mutate a foreign channel's state."""
        if target_channel != self.channel:
            raise PermissionError(
                f"CheckpointManager for channel '{self.channel}' is unauthorized to mutate '{target_channel}'"
            )

    def _fsync_directory(self):
        """On POSIX systems, fsync the parent directory to commit directory entry changes."""
        if hasattr(os, "O_DIRECTORY"):
            try:
                dir_fd = os.open(self.checkpoint_dir, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except Exception:
                pass

    class _FileLockContext:
        def __init__(self, manager: "CheckpointManager", timeout: float = 10.0):
            self.manager = manager
            self.timeout = timeout
            self.acquired = False
            self.reentrant = False
            self.lock_epoch = 0
            self.owner_uuid = ""

        def __enter__(self):
            # Guard thread synchronization and reentrancy within the same process
            acquired_thread_lock = self.manager._thread_rlock.acquire(timeout=self.timeout)
            if not acquired_thread_lock:
                raise CheckpointLockTimeout(
                    f"Timed out acquiring thread lock for channel '{self.manager.channel}' after {self.timeout}s"
                )

            try:
                if self.manager._lock_depth > 0:
                    self.manager._lock_depth += 1
                    self.acquired = True
                    self.reentrant = True
                    self.lock_epoch = self.manager._current_lock_epoch
                    self.owner_uuid = self.manager._current_owner_uuid or ""
                    return self

                self.manager._ensure_dirs()
                start_time = time.time()
                poll_interval = 0.05

                while True:
                    fd = None
                    try:
                        fd = os.open(self.manager.lock_file, os.O_CREAT | os.O_RDWR)
                        if _acquire_kernel_lock(fd):
                            self.manager._lock_fd = fd
                            self.manager._lock_depth = 1

                            # Read previous metadata to increment lock_epoch monotonically
                            prev_epoch = 0
                            try:
                                os.lseek(fd, 0, os.SEEK_SET)
                                raw = os.read(fd, 4096)
                                if raw:
                                    meta = json.loads(raw.decode("utf-8"))
                                    prev_epoch = int(meta.get("lock_epoch", 0))
                            except Exception:
                                prev_epoch = 0

                            self.lock_epoch = prev_epoch + 1
                            self.owner_uuid = uuid.uuid4().hex
                            self.manager._current_lock_epoch = self.lock_epoch
                            self.manager._current_owner_uuid = self.owner_uuid

                            # Write structured lock ownership metadata
                            meta_record = {
                                "lock_epoch": self.lock_epoch,
                                "owner_uuid": self.owner_uuid,
                                "pid": os.getpid(),
                                "hostname": socket.gethostname(),
                                "channel": self.manager.channel,
                                "acquired_at": datetime.now(timezone.utc).isoformat(),
                            }
                            try:
                                os.ftruncate(fd, 0)
                                os.lseek(fd, 0, os.SEEK_SET)
                                os.write(fd, json.dumps(meta_record, indent=2).encode("utf-8"))
                                os.fsync(fd)
                            except Exception as e:
                                self.manager.logger.warning(
                                    f"Failed writing lock ownership metadata to {self.manager.lock_file}: {e}"
                                )

                            self.acquired = True
                            return self
                        else:
                            os.close(fd)
                            fd = None
                    except Exception:
                        if fd is not None:
                            try:
                                os.close(fd)
                            except Exception:
                                pass
                            fd = None

                    if time.time() - start_time > self.timeout:
                        raise CheckpointLockTimeout(
                            f"Timed out acquiring kernel lock on {self.manager.lock_file} after {self.timeout}s"
                        )
                    time.sleep(poll_interval)
            except Exception:
                self.manager._thread_rlock.release()
                raise

        def __exit__(self, exc_type, exc_val, exc_tb):
            if not self.acquired:
                return

            try:
                if self.reentrant:
                    self.manager._lock_depth -= 1
                    self.acquired = False
                    return

                self.manager._lock_depth -= 1
                if self.manager._lock_depth <= 0:
                    self.manager._lock_depth = 0
                    fd = self.manager._lock_fd
                    self.manager._lock_fd = None
                    self.manager._current_lock_epoch = 0
                    self.manager._current_owner_uuid = None

                    if fd is not None:
                        try:
                            _release_kernel_lock(fd)
                        finally:
                            try:
                                os.close(fd)
                            except Exception:
                                pass
                    self.acquired = False
            finally:
                self.manager._thread_rlock.release()

    def acquire_lock(self, timeout: float = 10.0):
        """Context manager to acquire channel-exclusive OS kernel-level lock."""
        return self._FileLockContext(self, timeout=timeout)

    def get_lock_epoch(self) -> int:
        """Returns the active lock epoch fencing token (0 if lock not currently held by this instance)."""
        return self._current_lock_epoch

    def get_lock_metadata(self) -> Optional[Dict[str, Any]]:
        """Reads structured lock ownership metadata."""
        if self._lock_fd is not None:
            try:
                os.lseek(self._lock_fd, 0, os.SEEK_SET)
                content = os.read(self._lock_fd, 4096)
                if content:
                    return json.loads(content.decode("utf-8"))
            except Exception:
                pass

        if not os.path.exists(self.lock_file):
            return None
        try:
            with open(self.lock_file, "r", encoding="utf-8") as f:
                content = f.read()
            if content.strip():
                return json.loads(content)
        except Exception:
            pass
        return None

    def _normalize_state_schema(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures all expected schema fields and migrations exist in state dict."""
        if "epoch" not in data:
            data["epoch"] = 1
        if "applied_transitions" not in data:
            data["applied_transitions"] = {}
        if "highest_applied_source_positions" not in data:
            data["highest_applied_source_positions"] = {}
        if "watermark" not in data:
            data["watermark"] = {
                "pruned_source_epochs": {},
                "last_compacted_at": datetime.now(timezone.utc).isoformat(),
                "total_compacted_count": 0,
            }
        else:
            if "pruned_source_epochs" not in data["watermark"]:
                data["watermark"]["pruned_source_epochs"] = {}
            if "total_compacted_count" not in data["watermark"]:
                data["watermark"]["total_compacted_count"] = 0
        if "pending_outbox_notifications" not in data:
            data["pending_outbox_notifications"] = {}
        return data

    def load_state(self) -> Dict[str, Any]:
        """
        Loads complete structured checkpoint dictionary with dual-file corruption recovery:
        1. If primary .json is valid, returns loaded state.
        2. If primary .json is corrupt or missing, attempts recovery from .bak.
        3. If both primary and .bak are corrupt, quarantines both to .corrupt.<timestamp>
           and raises RuntimeError("CHECKPOINT_UNRECOVERABLE: ...") (fail closed, never silently resets).
        """
        primary_exists = os.path.exists(self.checkpoint_file)
        bak_exists = os.path.exists(self.bak_file)

        # Clean initialization: neither exists
        if not primary_exists and not bak_exists:
            return {
                "log_name": self.channel,
                "epoch": 1,
                "last_record_id": 0,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "applied_transitions": {},
                "highest_applied_source_positions": {},
                "watermark": {
                    "pruned_source_epochs": {},
                    "last_compacted_at": datetime.now(timezone.utc).isoformat(),
                    "total_compacted_count": 0,
                },
                "pending_outbox_notifications": {},
            }

        # Try loading primary
        primary_data = None
        primary_corrupt = False
        primary_err = None

        if primary_exists:
            try:
                with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                    content = f.read()
                if not content.strip():
                    raise ValueError("Checkpoint file is empty (zero bytes)")
                data = json.loads(content)
                if not isinstance(data, dict):
                    raise ValueError("Checkpoint root is not a JSON object")
                if "crc32" in data:
                    expected_crc = data["crc32"]
                    actual_crc = compute_checkpoint_crc32(data)
                    if expected_crc != actual_crc:
                        raise ValueError(f"Primary checkpoint CRC32 mismatch: expected {expected_crc}, computed {actual_crc}")
                primary_data = data
            except Exception as e:
                primary_corrupt = True
                primary_err = e
                self.logger.warning(f"Primary checkpoint {self.checkpoint_file} is corrupt: {e}")

        # If primary is valid, return with schema normalization
        if primary_data is not None:
            return self._normalize_state_schema(primary_data)

        # Primary missing or corrupt: attempt recovery from backup
        bak_data = None
        bak_corrupt = False
        bak_err = None

        if bak_exists:
            try:
                with open(self.bak_file, "r", encoding="utf-8") as f_bak:
                    bak_content = f_bak.read()
                if not bak_content.strip():
                    raise ValueError("Backup checkpoint file is empty")
                b_data = json.loads(bak_content)
                if not isinstance(b_data, dict):
                    raise ValueError("Backup root is not a JSON object")
                if "crc32" in b_data:
                    expected_crc = b_data["crc32"]
                    actual_crc = compute_checkpoint_crc32(b_data)
                    if expected_crc != actual_crc:
                        raise ValueError(f"Backup checkpoint CRC32 mismatch: expected {expected_crc}, computed {actual_crc}")
                bak_data = b_data
            except Exception as e:
                bak_corrupt = True
                bak_err = e
                self.logger.warning(f"Backup checkpoint {self.bak_file} is corrupt: {e}")

        if bak_data is not None:
            # Successfully recovered from backup!
            self.logger.warning(
                f"Recovered checkpoint state for channel '{self.channel}' from backup {self.bak_file} "
                f"(primary error: {primary_err})"
            )
            normalized = self._normalize_state_schema(bak_data)
            # Restore primary file from backup
            try:
                self._write_state_atomic(normalized)
            except Exception as e:
                self.logger.error(f"Failed to restore primary checkpoint from backup: {e}")
            return normalized

        # DUAL CORRUPTION (or primary corrupt and backup missing / primary missing and backup corrupt)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        quarantine_paths = []

        if primary_exists and primary_corrupt:
            q_prim = f"{self.checkpoint_file}.corrupt.{ts}"
            try:
                os.replace(self.checkpoint_file, q_prim)
                quarantine_paths.append(q_prim)
            except Exception:
                pass

        if bak_exists and bak_corrupt:
            q_bak = f"{self.bak_file}.corrupt.{ts}"
            try:
                os.replace(self.bak_file, q_bak)
                quarantine_paths.append(q_bak)
            except Exception:
                pass

        err_msg = (
            f"CHECKPOINT_UNRECOVERABLE: Dual checkpoint corruption for channel '{self.channel}'. "
            f"Primary error: {primary_err}; Backup error: {bak_err}. "
            f"Quarantined: {quarantine_paths}. Ingestion halted."
        )
        self.logger.error(err_msg)
        raise RuntimeError(err_msg)

    def load_checkpoint(self) -> int:
        """Legacy-compatible accessor: returns the last_record_id integer (0 if none)."""
        return self.load_state().get("last_record_id", 0)

    def get_current_epoch(self) -> int:
        """Returns the authoritative channel epoch (>= 1)."""
        return self.load_state().get("epoch", 1)

    def is_transition_applied(self, transition_id: str) -> bool:
        """Checks if a transition_id is present in the durable applied_transitions ledger."""
        state = self.load_state()
        return transition_id in state.get("applied_transitions", {})

    @staticmethod
    def build_local_witness_id(channel: str, from_epoch: int, record_id: int, event_id: int) -> str:
        """Generates a deterministic local clear witness transition ID using canonical RCC-v1."""
        manifest = {
            "channel": str(channel).strip(),
            "event_id": int(event_id),
            "from_epoch": int(from_epoch),
            "identity_type": "local_clear_witness",
            "record_id": int(record_id),
        }
        return hashlib.sha256(canonicalize_tgam_rcc_v1(manifest)).hexdigest()

    def is_local_witness_replay(self, channel: str, record_id: int, event_id: int) -> bool:
        """
        Checks if an ingested clear event (1102 or 104) is a replay of the witness
        that transitioned this channel into its current epoch.
        Prevents duplicate epoch advancement across process restart while ensuring
        that a genuine clear event reusing the same record ID in a later epoch is accepted.
        """
        state = self.load_state()
        current_epoch = state.get("epoch", 1)
        if current_epoch <= 1:
            return False

        expected_from_epoch = current_epoch - 1
        expected_tid = self.build_local_witness_id(channel, expected_from_epoch, record_id, event_id)

        if expected_tid in state.get("applied_transitions", {}):
            return True

        last_wit = state.get("last_local_witness", {})
        if (
            last_wit.get("channel") == channel
            and last_wit.get("to_epoch") == current_epoch
            and last_wit.get("from_epoch") == expected_from_epoch
            and last_wit.get("record_id") == record_id
            and last_wit.get("event_id") == event_id
        ):
            return True

        return False

    def is_local_witness_applied(self, channel: str, record_id: int, event_id: int, from_epoch: Optional[int] = None) -> bool:
        """
        Checks if a local clear witness is recorded in applied_transitions or last_local_witness.
        If from_epoch is provided, matches exact transition edge.
        If from_epoch is omitted, matches witness for the current epoch boundary (current_epoch - 1).
        """
        state = self.load_state()
        current_epoch = state.get("epoch", 1)
        target_from_epoch = from_epoch if from_epoch is not None else (current_epoch - 1)

        expected_tid = self.build_local_witness_id(channel, target_from_epoch, record_id, event_id)
        if expected_tid in state.get("applied_transitions", {}):
            return True

        last_wit = state.get("last_local_witness", {})
        if (
            last_wit.get("channel") == channel
            and last_wit.get("from_epoch") == target_from_epoch
            and last_wit.get("record_id") == record_id
            and last_wit.get("event_id") == event_id
        ):
            return True

        return False

    @staticmethod
    def _make_source_key(source_agent_id: Optional[str], source_channel: str) -> str:
        agent = str(source_agent_id).strip() if source_agent_id else ""
        channel = str(source_channel).strip() if source_channel else ""
        if not agent or not channel:
            raise ValueError(f"Invalid source identity: source_agent_id='{source_agent_id}', source_channel='{source_channel}'")
        return f"{agent}:{channel}"

    def is_transition_retired(
        self,
        source_channel: Any,
        source_epoch: Optional[int] = None,
        transition_id: Optional[str] = None,
        source_agent_id: Optional[str] = None,
    ) -> bool:
        """
        Checks whether a transition has been retired by its (source_agent_id, source_channel) scoped watermark.
        Strictly source-scoped: NEVER compares source_epoch against target channel current_epoch.
        Missing or invalid source identity fails closed.
        """
        if not source_agent_id or not str(source_agent_id).strip():
            return False
        if not source_channel or not str(source_channel).strip():
            return False

        agent = str(source_agent_id).strip()
        s_chan = str(source_channel).strip()
        s_epoch = int(source_epoch if source_epoch is not None else 0)

        try:
            watermark_key = self._make_source_key(agent, s_chan)
        except ValueError:
            return False

        state = self.load_state()
        watermark = state.get("watermark", {})
        pruned_source_epochs = watermark.get("pruned_source_epochs", {})

        pruned_epoch = pruned_source_epochs.get(watermark_key, 0)
        if s_epoch <= pruned_epoch:
            return True

        return False

    def compact_ledger(
        self,
        source_agent_id: str,
        source_channel: str = "System",
        prune_source_epoch_threshold: Optional[int] = None,
    ) -> int:
        """
        Prunes entries from applied_transitions originating from (source_agent_id, source_channel)
        whose source_epoch <= prune_source_epoch_threshold.
        Requires explicit source_agent_id; missing or invalid source identity fails closed.
        Updates the (source_agent_id, source_channel) scoped retirement watermark atomically.
        Never conflates source epochs with target epochs, and never purges pending/unacknowledged transitions.
        """
        if not source_agent_id or not str(source_agent_id).strip():
            raise ValueError("Missing or invalid source_agent_id: explicit source_agent_id is required for compaction")
        if not source_channel or not str(source_channel).strip():
            raise ValueError("Missing or invalid source_channel: explicit source_channel is required for compaction")

        target_agent = str(source_agent_id).strip()
        s_chan_clean = str(source_channel).strip()
        threshold = int(prune_source_epoch_threshold if prune_source_epoch_threshold is not None else 0)
        watermark_key = self._make_source_key(target_agent, s_chan_clean)

        with self.acquire_lock():
            state = self.load_state()
            applied = state.get("applied_transitions", {})
            pruned_ids = []

            for tid, meta in applied.items():
                s_chan = meta.get("source_channel")
                entry_agent = str(meta.get("agent_id") or "").strip()
                s_epoch = meta.get("source_epoch") or meta.get("from_epoch", 0)
                if entry_agent == target_agent and s_chan == s_chan_clean and s_epoch <= threshold:
                    pruned_ids.append(tid)

            for tid in pruned_ids:
                del applied[tid]

            wm = state.setdefault("watermark", {})
            pruned_source_epochs = wm.setdefault("pruned_source_epochs", {})
            pruned_source_epochs[watermark_key] = max(
                pruned_source_epochs.get(watermark_key, 0), threshold
            )

            wm["last_compacted_at"] = datetime.now(timezone.utc).isoformat()
            wm["total_compacted_count"] = wm.get("total_compacted_count", 0) + len(pruned_ids)

            self._write_state_atomic(state)
            self.logger.info(
                f"Compacted ledger for channel {self.channel}: pruned {len(pruned_ids)} transitions "
                f"from source '{watermark_key}' up to source epoch {threshold}."
            )
            return len(pruned_ids)

    def check_source_transition_position(
        self,
        source_agent_id: str,
        source_channel: str,
        source_epoch: int,
        source_record_id: int,
        transition_id: str,
    ) -> Tuple[str, str]:
        """
        Evaluates an incoming transition's source position (source_epoch, source_record_id)
        against the highest applied source position for (source_agent_id, source_channel).

        Returns:
            Tuple[str, str]: (status, reason)
            status is one of:
                - "VALID": Position is strictly newer than highest applied position.
                - "SUPERSEDED": Position is strictly older than highest applied position.
                - "DUPLICATE": Position is equal and transition_id matches.
                - "CONFLICT": Position is equal but transition_id differs (quarantine).
        """
        agent = str(source_agent_id or "").strip()
        channel = str(source_channel).strip()
        if not agent or not channel:
            return "CONFLICT", f"Invalid source identity: agent='{agent}', channel='{channel}'"

        pos_key = f"{agent}:{channel}"
        state = self.load_state()
        highest_positions = state.get("highest_applied_source_positions", {})
        current = highest_positions.get(pos_key)

        if not current:
            return "VALID", "No prior transitions applied for this source identity"

        cur_epoch = current.get("source_epoch", 0)
        cur_rec = current.get("source_record_id", 0)
        cur_tid = current.get("transition_id")

        incoming_pos = (int(source_epoch), int(source_record_id))
        current_pos = (int(cur_epoch), int(cur_rec))

        if incoming_pos > current_pos:
            return "VALID", f"Position {incoming_pos} is newer than current position {current_pos}"
        elif incoming_pos < current_pos:
            return "SUPERSEDED", (
                f"Transition {transition_id} at source position {incoming_pos} is superseded "
                f"by already applied position {current_pos} (transition {cur_tid})"
            )
        else:
            if transition_id == cur_tid:
                return "DUPLICATE", f"Duplicate delivery of transition {transition_id} at position {incoming_pos}"
            else:
                return "CONFLICT", (
                    f"Conflict detected at position {incoming_pos}: incoming transition {transition_id} "
                    f"differs from applied transition {cur_tid}"
                )

    def _write_state_atomic(self, state: Dict[str, Any], fencing_token: Optional[int] = None):
        """
        Executes complete 7-phase fsync durability sequence with dual-file backup protocol:
        Phase 1: Write verified active state to .bak.tmp (if existing checkpoint is valid)
        Phase 2: Flush and fsync .bak.tmp
        Phase 3: Atomic replace .bak.tmp -> .bak
        Phase 4: Directory fsync (POSIX)
        Phase 5: Write target state to .tmp
        Phase 6: Flush and fsync .tmp
        Phase 7: Atomic replace .tmp -> .json (& directory fsync on POSIX)
        """
        self._ensure_dirs()
        if self._lock_depth == 0:
            with self.acquire_lock():
                return self._write_state_atomic(state, fencing_token=fencing_token)

        if fencing_token is not None and fencing_token != self._current_lock_epoch:
            raise PermissionError(
                f"Stale writer rejected: fencing token {fencing_token} does not match active lock epoch {self._current_lock_epoch}"
            )

        if self._current_lock_epoch > 0:
            state["last_lock_epoch"] = self._current_lock_epoch

        bak_temp_file = f"{self.bak_file}.tmp"
        primary_temp_file = f"{self.checkpoint_file}.tmp"

        # Phases 1-4: Dual-file backup protocol (backup active valid state)
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, "r", encoding="utf-8") as f_prev:
                    prev_content = f_prev.read()
                if prev_content.strip():
                    # Validate JSON and CRC before backing up
                    prev_data = json.loads(prev_content)
                    if isinstance(prev_data, dict):
                        if "crc32" in prev_data:
                            expected_prev_crc = prev_data["crc32"]
                            actual_prev_crc = compute_checkpoint_crc32(prev_data)
                            if expected_prev_crc != actual_prev_crc:
                                raise ValueError(f"Existing primary has invalid CRC32: {expected_prev_crc} != {actual_prev_crc}")
                        # Phase 1: Write to .bak.tmp
                        with open(bak_temp_file, "w", encoding="utf-8") as f_bak:
                            f_bak.write(prev_content)
                            # Phase 2: Flush & fsync .bak.tmp
                            f_bak.flush()
                            os.fsync(f_bak.fileno())
                        # Phase 3: Atomic rename .bak.tmp -> .bak
                        os.replace(bak_temp_file, self.bak_file)
                        # Phase 4: Directory fsync
                        self._fsync_directory()
            except Exception as e:
                self.logger.warning(f"Could not create checkpoint backup {self.bak_file}: {e}")
                if os.path.exists(bak_temp_file):
                    try:
                        os.remove(bak_temp_file)
                    except OSError:
                        pass

        # Phases 5-7: Primary state write
        try:
            # Deterministic CRC32 checksum computation over canonical fields
            state["crc32"] = compute_checkpoint_crc32(state)
            # Phase 5: Write to .tmp
            with open(primary_temp_file, "w", encoding="utf-8") as f_prim:
                json.dump(state, f_prim, indent=4)
                # Phase 6: Flush & fsync .tmp
                f_prim.flush()
                os.fsync(f_prim.fileno())
            # Phase 7: Atomic replace .tmp -> .json
            os.replace(primary_temp_file, self.checkpoint_file)
            # Directory fsync
            self._fsync_directory()
        except Exception as e:
            self.logger.error(f"Failed atomic write to {self.checkpoint_file}: {e}")
            if os.path.exists(primary_temp_file):
                try:
                    os.remove(primary_temp_file)
                except OSError:
                    pass
            raise

    def save_checkpoint(
        self,
        record_id: int,
        epoch: Optional[int] = None,
        target_channel: Optional[str] = None,
        fencing_token: Optional[int] = None,
    ):
        """
        Updates the channel checkpoint record ID (and optionally epoch) within channel boundary.
        Enforces fencing token if provided.
        """
        self._check_channel_authorization(target_channel or self.channel)
        valid_rec_id = validate_record_id(record_id)
        if epoch is not None:
            valid_epoch = validate_epoch(epoch)
        else:
            valid_epoch = None

        with self.acquire_lock():
            if fencing_token is not None and fencing_token != self._current_lock_epoch:
                raise PermissionError(
                    f"Stale writer rejected: fencing token {fencing_token} does not match active lock epoch {self._current_lock_epoch}"
                )
            state = self.load_state()
            state["last_record_id"] = valid_rec_id
            if valid_epoch is not None:
                state["epoch"] = valid_epoch
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._write_state_atomic(state, fencing_token=fencing_token)
            self.logger.debug(
                f"Checkpoint updated: channel={self.channel}, epoch={state['epoch']}, record_id={valid_rec_id}"
            )

    def advance_epoch(
        self,
        new_epoch: Optional[int] = None,
        reset_record_id: int = 0,
        transition_id: Optional[str] = None,
        transition_metadata: Optional[Dict[str, Any]] = None,
        target_channel: Optional[str] = None,
        pending_notification: Optional[Dict[str, Any]] = None,
        fencing_token: Optional[int] = None,
    ) -> int:
        """
        Advances the channel epoch, registers applied transition, and durably records
        any pending outbox notification in the exact same atomic transaction.
        Enforces fencing token if provided.
        """
        self._check_channel_authorization(target_channel or self.channel)
        valid_rec_id = validate_record_id(reset_record_id)

        with self.acquire_lock():
            if fencing_token is not None and fencing_token != self._current_lock_epoch:
                raise PermissionError(
                    f"Stale writer rejected: fencing token {fencing_token} does not match active lock epoch {self._current_lock_epoch}"
                )
            state = self.load_state()
            current_epoch = state.get("epoch", 1)

            if new_epoch is not None:
                next_epoch = validate_epoch(new_epoch)
                if next_epoch <= current_epoch:
                    raise ValueError(
                        f"Cannot advance epoch backward or equal: current={current_epoch}, requested={next_epoch}"
                    )
            else:
                next_epoch = current_epoch + 1

            state["epoch"] = next_epoch
            state["last_record_id"] = valid_rec_id
            state["updated_at"] = datetime.now(timezone.utc).isoformat()

            # Embed applied transition in the exact same atomic state commit
            if transition_id:
                applied = state.setdefault("applied_transitions", {})
                applied[transition_id] = {
                    "applied_in_target_epoch": next_epoch,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **(transition_metadata or {}),
                }

                # Update highest applied source position atomically with checkpoint advance
                if transition_metadata:
                    s_chan = transition_metadata.get("source_channel")
                    s_epoch = transition_metadata.get("source_epoch")
                    s_rec = transition_metadata.get("source_record_id")
                    s_agent = (transition_metadata.get("agent_id") or "AGT-WIN-01").strip()

                    if s_chan and s_epoch is not None and s_rec is not None:
                        pos_key = f"{s_agent}:{s_chan}"
                        highest_positions = state.setdefault("highest_applied_source_positions", {})
                        highest_positions[pos_key] = {
                            "source_epoch": int(s_epoch),
                            "source_record_id": int(s_rec),
                            "transition_id": str(transition_id),
                            "applied_in_target_epoch": next_epoch,
                            "applied_at": datetime.now(timezone.utc).isoformat(),
                        }

                if transition_metadata and transition_metadata.get("is_local_witness"):
                    state["last_local_witness"] = {
                        "transition_id": transition_id,
                        "channel": self.channel,
                        "record_id": transition_metadata.get("source_record_id"),
                        "event_id": transition_metadata.get("witness_event_id"),
                        "from_epoch": current_epoch,
                        "to_epoch": next_epoch,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

            # Embed pending outbox notification atomically in the same commit
            if pending_notification:
                notif_id = (
                    pending_notification.get("notification_id")
                    or pending_notification.get("detection_event_id")
                    or transition_id
                )
                if not notif_id:
                    notif_id = hashlib.sha256(canonicalize_tgam_rcc_v1(pending_notification)).hexdigest()

                pending = state.setdefault("pending_outbox_notifications", {})
                pending[str(notif_id)] = pending_notification
                self.logger.info(
                    f"Registered pending outbox notification '{notif_id}' atomically with epoch advance to {next_epoch}."
                )

            self._write_state_atomic(state, fencing_token=fencing_token)
            self.logger.info(
                f"Epoch advanced: channel={self.channel}, {current_epoch} -> {next_epoch}, "
                f"reset_record_id={valid_rec_id}, transition_id={transition_id}"
            )
            return next_epoch

    def add_pending_outbox_notification(
        self,
        notification_id: str,
        notification: Dict[str, Any],
        fencing_token: Optional[int] = None,
    ) -> None:
        """Durably registers a pending outbox notification in the checkpoint ledger."""
        if not notification_id or not str(notification_id).strip():
            raise ValueError("notification_id must be a non-empty string")
        with self.acquire_lock():
            if fencing_token is not None and fencing_token != self._current_lock_epoch:
                raise PermissionError(
                    f"Stale writer rejected: fencing token {fencing_token} does not match active lock epoch {self._current_lock_epoch}"
                )
            state = self.load_state()
            pending = state.setdefault("pending_outbox_notifications", {})
            pending[str(notification_id).strip()] = notification
            self._write_state_atomic(state, fencing_token=fencing_token)
            self.logger.info(f"Added pending outbox notification: {notification_id}")

    def get_pending_outbox_notifications(self) -> Dict[str, Dict[str, Any]]:
        """Returns all uncommitted pending outbox notifications."""
        state = self.load_state()
        return dict(state.get("pending_outbox_notifications", {}))

    def remove_pending_outbox_notification(
        self,
        notification_id: str,
        fencing_token: Optional[int] = None,
    ) -> bool:
        """Removes an acknowledged notification from the pending ledger."""
        notif_key = str(notification_id).strip()
        with self.acquire_lock():
            if fencing_token is not None and fencing_token != self._current_lock_epoch:
                raise PermissionError(
                    f"Stale writer rejected: fencing token {fencing_token} does not match active lock epoch {self._current_lock_epoch}"
                )
            state = self.load_state()
            pending = state.get("pending_outbox_notifications", {})
            if notif_key in pending:
                del pending[notif_key]
                self._write_state_atomic(state, fencing_token=fencing_token)
                self.logger.info(f"Removed acknowledged outbox notification: {notif_key}")
                return True
            return False

    def drain_pending_outbox_notifications(
        self,
        enqueue_handler: Union[Callable[[Dict[str, Any]], Any], Any] = None,
        detection_outbox: Any = None,
        transition_outbox: Any = None,
        fencing_token: Optional[int] = None,
    ) -> int:
        """
        Drains pending outbox notifications by dispatching each notification to its
        dedicated persistent outbox destination:
        - Detection notifications -> detection outbox (POST /api/v1/detection-events)
        - Channel transition notifications -> transition outbox (POST /api/v1/events/transition)
        Removes the pending marker from the checkpoint ledger only after confirmed durable insertion.
        Raises on handler failure, leaving unacknowledged notifications intact (fail-closed).
        """
        with self.acquire_lock():
            if fencing_token is not None and fencing_token != self._current_lock_epoch:
                raise PermissionError(
                    f"Stale writer rejected: fencing token {fencing_token} does not match active lock epoch {self._current_lock_epoch}"
                )
            state = self.load_state()
            pending = state.get("pending_outbox_notifications", {})
            if not pending:
                return 0

            drained = 0
            for notif_id in list(pending.keys()):
                notif_data = pending[notif_id]
                is_transition = (
                    "transition_id" in notif_data
                    or "target_epoch" in notif_data
                    or notif_data.get("type") in ("transition", "channel_transition", "epoch_advance", "gap_quarantine")
                    or notif_data.get("event_type") in ("channel_transition", "epoch_advance", "channel_gap_quarantine")
                    or ("detection_event_id" not in notif_data)
                )

                try:
                    if detection_outbox is not None and transition_outbox is not None:
                        if is_transition:
                            if hasattr(transition_outbox, "add_transition"):
                                transition_outbox.add_transition(notif_data)
                            elif hasattr(transition_outbox, "add_event"):
                                transition_outbox.add_event(notif_data)
                            elif callable(transition_outbox):
                                transition_outbox(notif_data)
                            else:
                                raise TypeError("transition_outbox must provide add_transition/add_event or be callable")
                        else:
                            if hasattr(detection_outbox, "add_event"):
                                detection_outbox.add_event(notif_data)
                            elif callable(detection_outbox):
                                detection_outbox(notif_data)
                            else:
                                raise TypeError("detection_outbox must provide add_event or be callable")
                    elif enqueue_handler is not None:
                        if is_transition and hasattr(enqueue_handler, "add_transition"):
                            enqueue_handler.add_transition(notif_data)
                        elif hasattr(enqueue_handler, "add_event"):
                            enqueue_handler.add_event(notif_data)
                        elif callable(enqueue_handler):
                            enqueue_handler(notif_data)
                        else:
                            raise TypeError("enqueue_handler must provide add_transition/add_event or be callable")
                    else:
                        raise ValueError("Either (detection_outbox, transition_outbox) or enqueue_handler must be provided")

                    del pending[notif_id]
                    drained += 1
                    # Persist removal immediately so completed dispatches are durable
                    self._write_state_atomic(state, fencing_token=fencing_token)
                except Exception as e:
                    self.logger.error(
                        f"Failed draining pending outbox notification '{notif_id}': {e}. "
                        "Preserving in checkpoint ledger for retry."
                    )
                    raise

            return drained
