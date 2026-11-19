"""
CheckpointManager: Channel-Specific Checkpoint and Epoch Store for TGAM-SOC
===========================================================================

Implements persistent, channel-specific epoch authority and crash-recoverable
checkpoint transitions for Windows Event Log channels.
Enforces channel-ownership boundaries and atomic state updates embedding
applied-transition deduplication markers.
"""

import os
import json
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from canonical import validate_epoch, validate_record_id


class CheckpointLockTimeout(Exception):
    """Raised when acquiring the channel-level filesystem lock times out."""
    pass


class CheckpointManager:
    """
    Manages channel-specific checkpoint state with atomic file operations,
    OS-level concurrency locking, and coordinated transition ledger durability.
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
        self.lock_dir = os.path.join(checkpoint_dir, "locks")
        self.lock_file = os.path.join(self.lock_dir, f"checkpoint_{safe_name}.lock")
        self._lock_fd = None

    def _ensure_dirs(self):
        os.makedirs(self.checkpoint_dir, exist_ok=True)
        os.makedirs(self.lock_dir, exist_ok=True)

    def _check_channel_authorization(self, target_channel: str):
        """Enforces that this instance cannot mutate a foreign channel's state."""
        if target_channel != self.channel:
            raise PermissionError(
                f"CheckpointManager for channel '{self.channel}' is unauthorized to mutate '{target_channel}'"
            )

    class _FileLockContext:
        def __init__(self, manager: "CheckpointManager", timeout: float = 10.0):
            self.manager = manager
            self.timeout = timeout
            self.acquired = False

        def __enter__(self):
            self.manager._ensure_dirs()
            start_time = time.time()
            while True:
                try:
                    # Use exclusive file creation as atomic mutex across threads & processes
                    self.manager._lock_fd = os.open(
                        self.manager.lock_file,
                        os.O_CREAT | os.O_EXCL | os.O_RDWR
                    )
                    self.acquired = True
                    return self
                except FileExistsError:
                    if time.time() - start_time > self.timeout:
                        # Clean up stale lock if older than 60s
                        try:
                            mtime = os.path.getmtime(self.manager.lock_file)
                            if time.time() - mtime > 60.0:
                                os.remove(self.manager.lock_file)
                                continue
                        except OSError:
                            pass
                        raise CheckpointLockTimeout(
                            f"Timed out acquiring lock on {self.manager.lock_file} after {self.timeout}s"
                        )
                    time.sleep(0.05)

        def __exit__(self, exc_type, exc_val, exc_tb):
            if self.acquired and self.manager._lock_fd is not None:
                try:
                    os.close(self.manager._lock_fd)
                except OSError:
                    pass
                self.manager._lock_fd = None
                try:
                    os.remove(self.manager.lock_file)
                except OSError:
                    pass
                self.acquired = False

    def acquire_lock(self, timeout: float = 10.0):
        """Context manager to acquire channel-exclusive OS lock."""
        return self._FileLockContext(self, timeout=timeout)

    def load_state(self) -> Dict[str, Any]:
        """Loads complete structured checkpoint dictionary, initializing defaults if absent."""
        if not os.path.exists(self.checkpoint_file):
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
            }
        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Ensure schema migration from flat V1 checkpoints
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
            return data
        except Exception as e:
            self.logger.error(f"Failed to read checkpoint file {self.checkpoint_file}: {e}")
            raise RuntimeError(f"Corrupted checkpoint file: {e}") from e

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
        import hashlib
        from canonical import canonicalize_tgam_rcc_v1
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
        agent = (source_agent_id or "AGT-WIN-01").strip()
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
            # incoming_pos == current_pos
            if transition_id == cur_tid:
                return "DUPLICATE", f"Duplicate delivery of transition {transition_id} at position {incoming_pos}"
            else:
                return "CONFLICT", (
                    f"Conflict detected at position {incoming_pos}: incoming transition {transition_id} "
                    f"differs from applied transition {cur_tid}"
                )

    def _write_state_atomic(self, state: Dict[str, Any]):
        """Writes state dictionary to disk atomically with sync/flush and rename."""
        self._ensure_dirs()
        temp_file = f"{self.checkpoint_file}.tmp"
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=4)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_file, self.checkpoint_file)
        except Exception as e:
            self.logger.error(f"Failed atomic write to {self.checkpoint_file}: {e}")
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass
            raise

    def save_checkpoint(
        self,
        record_id: int,
        epoch: Optional[int] = None,
        target_channel: Optional[str] = None,
    ):
        """
        Updates the channel checkpoint record ID (and optionally epoch) within channel boundary.
        """
        self._check_channel_authorization(target_channel or self.channel)
        valid_rec_id = validate_record_id(record_id)
        if epoch is not None:
            valid_epoch = validate_epoch(epoch)
        else:
            valid_epoch = None

        with self.acquire_lock():
            state = self.load_state()
            state["last_record_id"] = valid_rec_id
            if valid_epoch is not None:
                state["epoch"] = valid_epoch
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._write_state_atomic(state)
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
    ) -> int:
        """
        Advances the channel epoch and optionally registers the applied transition
        in the exact same atomic transaction.
        """
        self._check_channel_authorization(target_channel or self.channel)
        valid_rec_id = validate_record_id(reset_record_id)

        with self.acquire_lock():
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

            self._write_state_atomic(state)
            self.logger.info(
                f"Epoch advanced: channel={self.channel}, {current_epoch} -> {next_epoch}, "
                f"reset_record_id={valid_rec_id}, transition_id={transition_id}"
            )
            return next_epoch
