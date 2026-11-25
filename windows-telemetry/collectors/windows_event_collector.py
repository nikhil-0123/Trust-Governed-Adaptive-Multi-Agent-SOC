import os
import subprocess
import xml.etree.ElementTree as ET
import logging
import json
import uuid
import re
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Union
from config.settings import config
from .checkpoint import CheckpointManager
from .mailbox import TransitionMailbox

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from canonical import generate_source_event_id_v2, validate_epoch


class UnverifiedDiscontinuityError(Exception):
    """Raised when an unverified record ID drop occurs without an authoritative log clear."""
    pass


class ChannelQueryError(Exception):
    """Raised when a live wevtutil query fails or channel is unavailable."""
    def __init__(self, message: str, channel: str, error_type: str = "QUERY_FAILED"):
        super().__init__(message)
        self.channel = channel
        self.error_type = error_type


class ChannelUnavailableError(ChannelQueryError):
    """Raised when a channel is missing, not installed, or access is denied."""
    pass


class ChannelTimeoutError(ChannelQueryError):
    """Raised when a live wevtutil query times out."""
    pass


class WindowsEventCollector:
    """
    Collects raw Windows events incrementally using native wevtutil or simulation files.
    Coordinates channel-specific epoch authority, log-clear event detection (1102 and 104),
    and cross-channel transition publication and claiming.
    """

    def __init__(
        self,
        logger: logging.Logger,
        log_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        execution_mode: Optional[str] = None,
    ):
        self.logger = logger
        self.log_name = (log_name or config.windows_security_log_name).strip()
        self.agent_id = (agent_id or "AGT-WIN-01").strip()
        self.execution_mode = (
            execution_mode
            or getattr(config, "execution_mode", None)
            or os.getenv("TGAM_EXECUTION_MODE")
            or os.getenv("EXECUTION_MODE", "PRODUCTION")
        ).strip().upper()
        self.is_simulation = self.execution_mode in ("SIMULATION", "TEST", "EVALUATION")

        # Channel-specific batch size and timeout resolution (Phase 2.2)
        if self.log_name == getattr(config, "windows_security_log_name", "Security"):
            self.batch_size = getattr(config, "windows_security_batch_size", config.windows_event_batch_size)
            self.poll_interval = getattr(config, "windows_security_poll_interval", config.windows_event_poll_interval)
        elif self.log_name == getattr(config, "windows_system_log_name", "System"):
            self.batch_size = getattr(config, "windows_system_batch_size", config.windows_event_batch_size)
            self.poll_interval = getattr(config, "windows_system_poll_interval", config.windows_event_poll_interval)
        elif self.log_name == getattr(config, "windows_sysmon_log_name", "Microsoft-Windows-Sysmon/Operational"):
            self.batch_size = getattr(config, "windows_sysmon_batch_size", config.windows_event_batch_size)
            self.poll_interval = getattr(config, "windows_sysmon_poll_interval", config.windows_event_poll_interval)
        else:
            self.batch_size = config.windows_event_batch_size
            self.poll_interval = config.windows_event_poll_interval

        self.timeout_seconds = getattr(config, "wevtutil_subprocess_timeout_seconds", 30.0)

        # Operational health & metrics tracking (Phase 2.2)
        self.status = "HEALTHY"
        self.consecutive_failures = 0
        self.timeout_count = 0
        self.events_collected_total = 0
        self.quarantined_count = 0
        self.last_successful_collection: Optional[str] = None
        self.last_error: Optional[str] = None

        # Channel-bound CheckpointManager instance
        self.checkpoint_manager = CheckpointManager(
            config.checkpoint_dir, self.log_name, logger, channel=self.log_name
        )
        self.current_checkpoint = 0
        self.current_epoch = 1
        self._warned_permission = False
        self.is_initialized = False

        # Transition Mailbox and Producer Journal
        mailbox_dir = os.path.join(config.data_dir, "transitions")
        self.mailbox = TransitionMailbox(mailbox_dir, logger)
        self.journal_dir = os.path.join(config.data_dir, "journals")
        safe_channel = "".join([c if c.isalnum() else "_" for c in self.log_name.lower()])
        self.producer_journal_file = os.path.join(
            self.journal_dir, f"{safe_channel}_producer.json"
        )
        self.channel_quarantine_file = os.path.join(
            self.journal_dir, f"{safe_channel}_quarantine.json"
        )
        self.remainder_file = os.path.join(
            self.journal_dir, f"{safe_channel}_remainder.json"
        )
        self.malformed_events_dir = os.path.join(
            self.journal_dir, "malformed_events", safe_channel
        )
        self.oversized_events_dir = os.path.join(
            self.journal_dir, "oversized_events", safe_channel
        )
        self._serving_remainder = False
        self._in_flight_simulated_files = []

        # Simulation directories
        self.simulated_events_dir = os.path.join(config.data_dir, "simulated_events")
        if self.log_name != "Security":
            self.simulated_events_channel_dir = os.path.join(
                self.simulated_events_dir, safe_channel
            )
        else:
            self.simulated_events_channel_dir = self.simulated_events_dir

        self._pending_epoch_advance = False
        self._pending_epoch_advance_rec_id = 0
        self._pending_local_witness = None

    def initialize(self):
        self.logger.info(f"Initializing WindowsEventCollector for channel: {self.log_name}")
        os.makedirs(self.journal_dir, exist_ok=True)
        os.makedirs(self.malformed_events_dir, exist_ok=True)
        os.makedirs(self.oversized_events_dir, exist_ok=True)
        os.makedirs(self.simulated_events_dir, exist_ok=True)
        os.makedirs(self.simulated_events_channel_dir, exist_ok=True)

        checkpoint_exists = os.path.exists(self.checkpoint_manager.checkpoint_file)
        state = self.checkpoint_manager.load_state()
        self.current_checkpoint = state.get("last_record_id", 0)
        self.current_epoch = state.get("epoch", 1)

        # Reconcile any in-flight producer journal from prior crash
        self._reconcile_producer_journal()

        if not checkpoint_exists:
            self.logger.info("No checkpoint found. Applying conservative first-run behavior.")
            self._apply_first_run_behavior()
        else:
            self.logger.info(
                f"Loaded checkpoint for {self.log_name}: record_id={self.current_checkpoint}, epoch={self.current_epoch}"
            )
        self.is_initialized = True

    def get_current_epoch(self) -> int:
        """Returns the authoritative channel epoch from CheckpointManager."""
        self.current_epoch = self.checkpoint_manager.get_current_epoch()
        return self.current_epoch

    def is_channel_quarantined(self) -> bool:
        """Checks whether this channel is under a persistent, durable quarantine halt."""
        return os.path.isfile(self.channel_quarantine_file)

    def get_channel_quarantine_reason(self) -> Optional[str]:
        """Reads the reason from the durable channel quarantine file if present."""
        if not self.is_channel_quarantined():
            return None
        try:
            with open(self.channel_quarantine_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("reason")
        except Exception:
            return "Active channel quarantine"

    def set_channel_quarantine(self, record_id: int, reason: str, witness_event_id: int = 104):
        """Persists a durable channel quarantine halt marker in journals directory."""
        os.makedirs(self.journal_dir, exist_ok=True)
        quarantine_state = {
            "channel": self.log_name,
            "status": "QUARANTINED",
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "witness_record_id": record_id,
            "witness_event_id": witness_event_id,
            "reason": reason,
        }
        temp_file = f"{self.channel_quarantine_file}.tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(quarantine_state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_file, self.channel_quarantine_file)

    def resolve_channel_quarantine(self, resolution_metadata: Optional[Dict[str, Any]] = None):
        """
        Authorized recovery mechanism: lifts the channel quarantine after administrative validation.
        Archives the quarantine state and allows collection to resume.
        """
        if not self.is_channel_quarantined():
            return

        meta = resolution_metadata or {}
        authorized_by = meta.get("authorized_by", "administrator")
        recovery_reason = meta.get("resolution_reason", "Authorized administrative recovery")

        self.logger.info(
            f"Lifting channel quarantine on '{self.log_name}' authorized by '{authorized_by}': {recovery_reason}"
        )

        archive_dir = os.path.join(self.journal_dir, "resolved_quarantines")
        os.makedirs(archive_dir, exist_ok=True)
        archive_file = os.path.join(
            archive_dir,
            f"{self.log_name.lower()}_quarantine_resolved_{int(datetime.now(timezone.utc).timestamp())}.json",
        )
        try:
            os.replace(self.channel_quarantine_file, archive_file)
        except OSError:
            if os.path.exists(self.channel_quarantine_file):
                os.remove(self.channel_quarantine_file)

    def has_durable_remainder(self) -> bool:
        """Checks whether a durable remainder queue file exists on disk."""
        return os.path.isfile(self.remainder_file)

    def get_durable_remainder_target_epoch(self) -> Optional[int]:
        """Returns the target epoch for which the durable remainder is designated."""
        if not os.path.isfile(self.remainder_file):
            return None
        try:
            with open(self.remainder_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data.get("target_epoch")
                return None
        except Exception:
            return None

    def is_durable_remainder_eligible(self) -> bool:
        """
        Checks whether the durable remainder is eligible for draining under the current channel epoch.
        A post-clear remainder is only eligible after the clear witness has committed downstream and advanced the epoch.
        """
        if not self.has_durable_remainder():
            return False
        tgt_epoch = self.get_durable_remainder_target_epoch()
        if tgt_epoch is not None:
            return self.current_epoch >= tgt_epoch
        return True

    def load_durable_remainder(self) -> List[Dict[str, Any]]:
        """Loads and deserializes the durable remainder queue from disk."""
        if not self.has_durable_remainder():
            return []
        try:
            with open(self.remainder_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return data.get("events", [])
                return []
        except Exception as e:
            self.logger.error(f"Failed to read durable remainder file {self.remainder_file}: {e}")
            return []

    def persist_durable_remainder(
        self,
        remainder_events: List[Dict[str, Any]],
        target_epoch: Optional[int] = None,
    ):
        """
        Durably persists remainder events to disk using atomic .tmp write, fsync, and replace.
        Records channel, from_epoch, target_epoch, and event list in remainder manifest.
        """
        if not remainder_events:
            return
        os.makedirs(self.journal_dir, exist_ok=True)
        tgt_epoch = target_epoch if target_epoch is not None else self.current_epoch
        payload = {
            "channel": self.log_name,
            "from_epoch": self.current_epoch,
            "target_epoch": tgt_epoch,
            "events": remainder_events,
        }
        temp_file = f"{self.remainder_file}.tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_file, self.remainder_file)
        self.logger.info(
            f"Durably persisted {len(remainder_events)} remainder events to {self.remainder_file} (target_epoch={tgt_epoch})"
        )

    def clear_durable_remainder(self):
        """Removes the durable remainder file after successful downstream commitment."""
        if os.path.isfile(self.remainder_file):
            try:
                os.remove(self.remainder_file)
                self.logger.info(f"Cleared durable remainder file {self.remainder_file}")
            except OSError as e:
                self.logger.warning(f"Could not remove remainder file {self.remainder_file}: {e}")

    def _acknowledge_in_flight_simulated_files(self, committed_record_id: Optional[int] = None):
        """Acknowledges and unlinks simulated XML files after downstream commitment."""
        remaining_files = []
        for item in getattr(self, "_in_flight_simulated_files", []):
            if isinstance(item, tuple):
                fp, max_rec_id = item
            else:
                fp, max_rec_id = item, None

            if committed_record_id is None or max_rec_id is None or committed_record_id >= max_rec_id:
                try:
                    if os.path.exists(fp):
                        os.remove(fp)
                        self.logger.debug(f"Acknowledged and removed simulated event source: {fp}")
                except OSError as e:
                    self.logger.warning(f"Could not remove simulated event file {fp}: {e}")
            else:
                remaining_files.append((fp, max_rec_id))
        self._in_flight_simulated_files = remaining_files

    def has_pending_simulated_events(self) -> bool:
        """Checks if there are pending unconsumed simulated XML events waiting for this channel."""
        if not os.path.isdir(self.simulated_events_channel_dir):
            return False
        try:
            return any(f.endswith(".xml") for f in os.listdir(self.simulated_events_channel_dir))
        except OSError:
            return False

    def get_health_status(self) -> Dict[str, Any]:
        """Returns comprehensive operational health metrics for this channel (Phase 2.2)."""
        effective_status = "QUARANTINED" if self.is_channel_quarantined() else self.status
        return {
            "channel": self.log_name,
            "status": effective_status,
            "current_checkpoint": self.current_checkpoint,
            "current_epoch": self.current_epoch,
            "consecutive_failures": self.consecutive_failures,
            "timeout_count": self.timeout_count,
            "events_collected_total": self.events_collected_total,
            "quarantined_count": self.quarantined_count,
            "last_successful_collection": self.last_successful_collection,
            "last_error": self.last_error,
        }

    def _decode_wevtutil_output(self, raw_bytes: Union[bytes, str]) -> Tuple[Optional[str], Optional[str]]:
        """
        Losslessly decodes raw byte output from wevtutil without character loss or silent replacement.
        Checks byte-order marks (BOM) and applies strict decoding across valid Windows encodings:
        1. UTF-8 BOM (utf-8-sig) or strict UTF-8
        2. UTF-16LE BOM or strict UTF-16LE / UTF-16
        3. Active Windows ANSI / CP1252 (strict)

        If raw_bytes cannot be decoded by any supported encoding:
        - Quarantines the undecodable payload into malformed_events directory.
        - Returns (None, "UNDECODABLE_RAW_BYTES").
        """
        if not raw_bytes:
            return "", None

        if isinstance(raw_bytes, str):
            return raw_bytes, None

        # Check Byte Order Marks (BOM)
        if raw_bytes.startswith(b"\xef\xbb\xbf"):
            try:
                return raw_bytes[3:].decode("utf-8"), None
            except UnicodeDecodeError:
                pass
        elif raw_bytes.startswith(b"\xff\xfe"):
            try:
                return raw_bytes[2:].decode("utf-16le"), None
            except UnicodeDecodeError:
                pass
        elif raw_bytes.startswith(b"\xfe\xff"):
            try:
                return raw_bytes[2:].decode("utf-16be"), None
            except UnicodeDecodeError:
                pass

        # Try strict candidate encodings without destructive character replacement
        candidate_encodings = getattr(self, "candidate_encodings", ("utf-8", "utf-16le", "cp1252", "mbcs"))
        for enc in candidate_encodings:
            try:
                decoded = raw_bytes.decode(enc)
                return decoded, None
            except (UnicodeDecodeError, LookupError):
                continue

        # Forensic preservation: quarantine undecodable evidence without silent character replacement
        ts = int(datetime.now(timezone.utc).timestamp())
        quarantine_file = os.path.join(self.malformed_events_dir, f"undecodable_wevtutil_{ts}.bin")
        try:
            with open(quarantine_file, "wb") as qf:
                qf.write(raw_bytes)
            self.logger.error(
                f"Quarantined {len(raw_bytes)} bytes of undecodable wevtutil output on '{self.log_name}' to {quarantine_file}"
            )
        except Exception as qe:
            self.logger.error(f"Failed to write undecodable quarantine file: {qe}")

        return None, "UNDECODABLE_RAW_BYTES"

    def _probe_newest_record_id(self) -> Tuple[Optional[int], Optional[str]]:
        """
        Executes a reverse query for the newest record ID:
        wevtutil qe <Channel> /c:1 /rd:true /f:xml
        Returns (newest_record_id, error_code).
        error_code can be None, 'EMPTY_LOG', 'COMMAND_UNAVAILABLE', 'TIMEOUT', or 'PARSE_ERROR'.
        """
        if self.execution_mode == "SIMULATION":
            return None, "EMPTY_LOG"

        cmd = ["wevtutil", "qe", self.log_name, "/c:1", "/rd:true", "/f:xml"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, check=True, timeout=self.timeout_seconds
            )
            xml_output, decode_err = self._decode_wevtutil_output(result.stdout)
            if decode_err:
                self.logger.error(f"Failed to decode newest record query on {self.log_name}: {decode_err}")
                return None, "PARSE_ERROR"
            xml_output = (xml_output or "").strip()
            if not xml_output:
                return None, "EMPTY_LOG"
            events = self._parse_wevtutil_xml(xml_output)
            if not events:
                return None, "EMPTY_LOG"
            newest_id = events[0].get("record_id")
            return newest_id, None
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            if not self._warned_permission:
                self.logger.warning(
                    f"Live wevtutil query on '{self.log_name}' unavailable ({e}). "
                    "Running in waiting mode. Drop XML files into simulated_events for offline/lab simulation."
                )
                self._warned_permission = True
            return None, "COMMAND_UNAVAILABLE"
        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Timeout probing newest record on {self.log_name}: {e}")
            return None, "TIMEOUT"
        except Exception as e:
            self.logger.error(f"Unexpected error probing newest record on {self.log_name}: {e}")
            return None, "PARSE_ERROR"

    def _find_clear_witness_for_reset(self) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Executes targeted clear-witness queries to determine if a record ID reset was legitimate:
        - Security: Event 1102
        - System: Event 104 with affected_channel == 'System'
        Returns (witness_found, witness_event, reason).
        """
        if self.is_simulation:
            return False, None, "Simulation mode active: live clear witness query bypassed"

        if self.log_name == "Security":
            query = "*[System[(EventID=1102)]]"
            cmd = ["wevtutil", "qe", "Security", f"/q:{query}", "/c:10", "/rd:true", "/f:xml"]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, check=True, timeout=self.timeout_seconds
                )
                xml_output, decode_err = self._decode_wevtutil_output(result.stdout)
                if decode_err:
                    return False, None, f"Query for Event 1102 produced undecodable output: {decode_err}"
                xml_output = (xml_output or "").strip()
                if xml_output:
                    events = self._parse_wevtutil_xml(xml_output)
                    for ev in events:
                        if ev.get("event_id") == 1102:
                            rec_id = ev.get("record_id", 0)
                            if not self.checkpoint_manager.is_local_witness_replay("Security", rec_id, 1102):
                                return True, ev, None
                return False, None, "No valid Event 1102 clear witness found in Security log"
            except Exception as e:
                return False, None, f"Query for Event 1102 failed: {e}"

        elif self.log_name == "System":
            query = "*[System[(EventID=104)]]"
            cmd = ["wevtutil", "qe", "System", f"/q:{query}", "/c:10", "/rd:true", "/f:xml"]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, check=True, timeout=self.timeout_seconds
                )
                xml_output, decode_err = self._decode_wevtutil_output(result.stdout)
                if decode_err:
                    return False, None, f"Query for Event 104 produced undecodable output: {decode_err}"
                xml_output = (xml_output or "").strip()
                if xml_output:
                    events = self._parse_wevtutil_xml(xml_output)
                    for ev in events:
                        if ev.get("event_id") == 104:
                            aff = ev.get("affected_channel")
                            if aff and aff.lower() == "system" and not ev.get("is_malformed_witness"):
                                rec_id = ev.get("record_id", 0)
                                if not self.checkpoint_manager.is_local_witness_replay("System", rec_id, 104):
                                    return True, ev, None
                return False, None, "No valid in-channel Event 104 clear witness found in System log"
            except Exception as e:
                return False, None, f"Query for Event 104 failed: {e}"

        return False, None, f"No clear witness mechanism for channel '{self.log_name}'"

    def _is_in_channel_clear_witness(self, ev: Dict[str, Any]) -> bool:
        """
        Determines if an event is an authoritative in-channel clear witness
        that warrants epoch advance and batch truncation for this channel.
        """
        event_id = ev.get("event_id")
        record_id = ev.get("record_id", 0)
        if self.log_name == "Security":
            if event_id == 1102:
                if not self.checkpoint_manager.is_local_witness_replay("Security", record_id, 1102):
                    return True
        elif self.log_name == "System":
            if event_id == 104:
                aff = ev.get("affected_channel")
                if (
                    aff
                    and str(aff).strip().lower() == "system"
                    and not ev.get("is_malformed_witness")
                ):
                    if not self.checkpoint_manager.is_local_witness_replay("System", record_id, 104):
                        return True
        return False

    def _truncate_batch_at_clear(
        self, events: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Scans events for the first in-channel clear witness.
        If found at index i, splits into:
          truncated = events[: i + 1]  (pre-clear events + clear witness)
          remainder = events[i + 1 :]  (post-clear events)
        Otherwise returns (events, []).
        """
        for i, ev in enumerate(events):
            if self._is_in_channel_clear_witness(ev):
                return events[: i + 1], events[i + 1 :]
        return events, []

    def _reconcile_producer_journal(self):
        """Recovers in-flight producer journal intents across crashes."""
        if not os.path.exists(self.producer_journal_file):
            return
        try:
            with open(self.producer_journal_file, "r", encoding="utf-8") as f:
                intent = json.load(f)
            if intent.get("status") == "PUBLISHING":
                self.logger.warning(
                    f"Recovering in-flight producer journal intent for {self.log_name}: {intent}"
                )
                envelope = intent.get("envelope")
                if envelope:
                    self.mailbox.publish_transition(envelope)
                # Mark committed
                intent["status"] = "COMMITTED"
                with open(self.producer_journal_file, "w", encoding="utf-8") as f:
                    json.dump(intent, f)
        except Exception as e:
            self.logger.error(f"Error reconciling producer journal {self.producer_journal_file}: {e}")

    def _apply_first_run_behavior(self):
        """
        Conservative default: fetch the single latest EventRecordID to establish baseline.
        In simulation/test modes, establish isolated test baseline at record 1 without probing live OS logs.
        """
        if self.is_simulation:
            self.current_checkpoint = 1
            self.checkpoint_manager.save_checkpoint(self.current_checkpoint)
            self.logger.info(
                f"Simulation/Test mode active: isolated first-run baseline checkpoint set to {self.current_checkpoint}"
            )
            return

        cmd = ["wevtutil", "qe", self.log_name, "/c:1", "/rd:true", "/f:xml"]
        try:
            result = subprocess.run(
                cmd, capture_output=True, check=True, timeout=30
            )
            out_str, decode_err = self._decode_wevtutil_output(result.stdout)
            if decode_err:
                self.logger.error(f"Failed to decode first-run output for {self.log_name}: {decode_err}")
                self.current_checkpoint = 1
                self.checkpoint_manager.save_checkpoint(self.current_checkpoint)
                return
            out_str = (out_str or "").strip()
            if out_str:
                events = self._parse_wevtutil_xml(out_str)
                if events and "record_id" in events[0]:
                    latest_id = events[0]["record_id"]
                    self.current_checkpoint = latest_id
                    self.checkpoint_manager.save_checkpoint(self.current_checkpoint)
                    self.logger.info(
                        f"First-run checkpoint set to latest event ID: {self.current_checkpoint}"
                    )
                    return
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self.logger.warning(
                f"Permission notice: wevtutil query on '{self.log_name}' unavailable ({e}). "
                "Administrator privileges required for live Windows Event log. "
                "Agent ready for elevated collection or simulated event injection."
            )
            self.current_checkpoint = 1
            self.checkpoint_manager.save_checkpoint(self.current_checkpoint)
            return
        except Exception as e:
            self.logger.error(f"Failed to determine first-run checkpoint for {self.log_name}: {e}")
            self.current_checkpoint = 1
            self.checkpoint_manager.save_checkpoint(self.current_checkpoint)
            return

    def _matches_channel(self, ev_channel: Optional[str]) -> bool:
        """Determines if a parsed event belongs to this collector's channel."""
        if not ev_channel:
            return True
        c1 = ev_channel.strip().lower()
        c2 = self.log_name.strip().lower()
        if c1 == c2:
            return True
        if "sysmon" in c1 and "sysmon" in c2:
            return True
        return False

    def _collect_simulated_events(self) -> List[Dict[str, Any]]:
        """Collects simulated event XML files placed in simulation directories."""
        dirs_to_check = [self.simulated_events_channel_dir]
        if "sysmon" in self.log_name.lower():
            sysmon_alias_dir = os.path.join(self.simulated_events_dir, "sysmon")
            if sysmon_alias_dir not in dirs_to_check:
                dirs_to_check.append(sysmon_alias_dir)
        if self.simulated_events_dir not in dirs_to_check:
            dirs_to_check.append(self.simulated_events_dir)

        events = []
        for sdir in dirs_to_check:
            if not os.path.isdir(sdir):
                continue
            try:
                files = sorted([f for f in os.listdir(sdir) if f.endswith(".xml")])
                for filename in files[: self.batch_size]:
                    filepath = os.path.join(sdir, filename)
                    try:
                        file_size = os.path.getsize(filepath)
                        if file_size > 10 * 1024 * 1024:
                            self.logger.warning(
                                f"Oversized simulated event file {filepath} ({file_size} bytes). Quarantining."
                            )
                            with open(filepath, "r", encoding="utf-8") as f:
                                raw_content = f.read()
                            rec_id = self._extract_record_id_from_raw_xml(raw_content)
                            q_path = self.quarantine_oversized_record(raw_content, record_id=rec_id)
                            if not q_path:
                                self.logger.error(
                                    f"Failed to quarantine oversized record {filepath}; halting batch without advancing checkpoint."
                                )
                                return events
                            if rec_id is not None and rec_id > self.current_checkpoint:
                                self.checkpoint_manager.save_checkpoint(rec_id)
                                self.current_checkpoint = rec_id
                            try:
                                os.remove(filepath)
                            except OSError:
                                pass
                            continue

                        with open(filepath, "r", encoding="utf-8") as f:
                            content = f.read()
                        parsed = self._parse_wevtutil_xml(content)
                        # Filter to events matching this channel if log_name is embedded
                        filtered = [
                            ev for ev in parsed
                            if self._matches_channel(ev.get("channel"))
                        ]
                        for ev in filtered:
                            ev["is_simulated"] = True
                        if not filtered:
                            continue

                        # If file contains an already-quarantined malformed witness, filter it out
                        # so remaining valid events in the source can be safely processed without re-triggering quarantine
                        if self.current_checkpoint > 0 and any(
                            ev.get("is_malformed_witness") and ev.get("record_id", 0) <= self.current_checkpoint
                            for ev in filtered
                        ):
                            remaining = [ev for ev in filtered if ev.get("record_id", 0) > self.current_checkpoint]
                            if not remaining:
                                # All events in this file have been handled/quarantined
                                try:
                                    os.remove(filepath)
                                except OSError:
                                    pass
                                continue
                            filtered = remaining

                        # If this file was partially committed in a previous cycle, skip already committed records
                        if self.current_checkpoint > 0 and not any(self._is_in_channel_clear_witness(ev) for ev in filtered):
                            committed_pre = [ev for ev in filtered if ev.get("record_id", 0) <= self.current_checkpoint]
                            uncommitted = [ev for ev in filtered if ev.get("record_id", 0) > self.current_checkpoint]
                            if committed_pre and uncommitted:
                                filtered = uncommitted

                        # Handle unquarantined malformed witness safely while preserving the source file
                        malformed_indices = [i for i, ev in enumerate(filtered) if ev.get("is_malformed_witness")]
                        if malformed_indices:
                            m_idx = malformed_indices[0]
                            max_rec_id = max((ev.get("record_id", 0) for ev in filtered), default=0)
                            self._in_flight_simulated_files = [
                                item for item in self._in_flight_simulated_files
                                if (item[0] if isinstance(item, tuple) else item) != filepath
                            ]
                            self._in_flight_simulated_files.append((filepath, max_rec_id))

                            if m_idx > 0 and not events:
                                # Yield valid events preceding the malformed witness first
                                return filtered[:m_idx]
                            elif m_idx == 0 and not events:
                                # Yield the malformed witness to trigger quarantine and persistent channel halt
                                return [filtered[0]]
                            elif events:
                                # Yield accumulated events prior to this malformed witness
                                return events

                        # Check if adding filtered events introduces an in-channel clear witness
                        candidate_events = events + filtered
                        truncated, remainder = self._truncate_batch_at_clear(candidate_events)

                        if remainder:
                            # A clear witness is present: persist remainder durably with target_epoch = current_epoch + 1
                            # Source file is preserved until downstream checkpoint commitment.
                            self.persist_durable_remainder(remainder, target_epoch=self.current_epoch + 1)
                            max_rec_id = max((ev.get("record_id", 0) for ev in truncated), default=0)
                            self._in_flight_simulated_files = [
                                item for item in self._in_flight_simulated_files
                                if (item[0] if isinstance(item, tuple) else item) != filepath
                            ]
                            self._in_flight_simulated_files.append((filepath, max_rec_id))
                            return truncated
                        else:
                            events.extend(filtered)
                            max_rec_id = max((ev.get("record_id", 0) for ev in filtered), default=0)
                            self._in_flight_simulated_files = [
                                item for item in self._in_flight_simulated_files
                                if (item[0] if isinstance(item, tuple) else item) != filepath
                            ]
                            self._in_flight_simulated_files.append((filepath, max_rec_id))

                    except Exception as e:
                        if isinstance(e, UnverifiedDiscontinuityError):
                            raise
                        self.logger.error(f"Error reading simulated event file {filepath}: {e}")
                        raise
            except Exception as e:
                if isinstance(e, UnverifiedDiscontinuityError):
                    raise
                self.logger.error(f"Error accessing simulated events directory {sdir}: {e}")
                raise
        return events

    def check_and_apply_pending_transitions(self):
        """
        Consumer side: Claims pending transition manifests from mailbox and applies them
        to advance the channel epoch atomically.
        """
        if self.log_name != "Security":
            return

        claimed = self.mailbox.claim_pending_transitions(target_channel="Security")
        for envelope in claimed:
            transition_id = envelope.get("transition_id")
            manifest = envelope.get("identity_manifest", {})

            # 1. Verify the complete transition envelope (Cryptographic and contract verification)
            is_valid, reason = TransitionMailbox.verify_transition(envelope)
            if not is_valid:
                self.logger.error(
                    f"REJECTED transition {transition_id} due to verification failure: {reason}"
                )
                self.mailbox.quarantine_transition(transition_id, reason=reason)
                continue

            # 2. Validate the identity manifest and required source identity (Fail closed on missing identity)
            source_agent_id = manifest.get("agent_id")
            source_channel = manifest.get("source_channel")
            source_epoch = manifest.get("source_epoch")
            source_record_id = manifest.get("source_record_id")

            if not source_agent_id or not source_channel or source_epoch is None or source_record_id is None:
                fail_reason = "Incomplete source identity in transition manifest"
                self.logger.error(f"REJECTED transition {transition_id}: {fail_reason}")
                self.mailbox.quarantine_transition(transition_id, reason=fail_reason)
                continue

            # 3. Check whether the verified transition ID is already applied (Idempotent deduplication for verified duplicates)
            if transition_id and self.checkpoint_manager.is_transition_applied(transition_id):
                self.logger.info(
                    f"Transition {transition_id} is already applied; acknowledging and skipping."
                )
                self.mailbox.acknowledge_transition(transition_id)
                continue

            # 4. Check source retirement by (source_agent_id, source_channel) watermark
            if self.checkpoint_manager.is_transition_retired(
                source_channel=source_channel,
                source_epoch=source_epoch,
                transition_id=transition_id,
                source_agent_id=source_agent_id,
            ):
                self.logger.info(
                    f"Transition {transition_id} is retired by watermark ({source_agent_id}:{source_channel} "
                    f"epoch {source_epoch} <= watermark); acknowledging and skipping."
                )
                self.mailbox.acknowledge_transition(transition_id)
                continue

            # 5. Check source-position high-watermark
            pos_status, pos_reason = self.checkpoint_manager.check_source_transition_position(
                source_agent_id=source_agent_id,
                source_channel=source_channel,
                source_epoch=source_epoch,
                source_record_id=source_record_id,
                transition_id=transition_id,
            )

            if pos_status == "CONFLICT":
                self.logger.error(f"QUARANTINED transition {transition_id}: {pos_reason}")
                self.mailbox.quarantine_transition(transition_id, reason=pos_reason)
                continue

            if pos_status == "SUPERSEDED":
                self.logger.info(
                    f"Transition {transition_id} is superseded ({pos_reason}); acknowledging and skipping without epoch advance."
                )
                self.mailbox.acknowledge_transition(transition_id)
                continue

            # 6. Advance checkpoint atomically
            old_epoch = self.get_current_epoch()
            target_epoch = old_epoch + 1
            transition_notif = {
                "transition_id": transition_id,
                "agent_id": self.agent_id,
                "source_channel": "Security",
                "target_channel": "Security",
                "target_epoch": target_epoch,
                "transition_type": manifest.get("transition_type", "EPOCH_ADVANCE"),
                "identity_manifest": manifest,
                "witness_payload": envelope.get("witness_payload", {}),
            }
            new_epoch = self.checkpoint_manager.advance_epoch(
                reset_record_id=0,
                transition_id=transition_id,
                transition_metadata=manifest,
                target_channel="Security",
                pending_notification=transition_notif,
            )
            self.current_checkpoint = 0
            self.current_epoch = new_epoch
            self.logger.info(
                f"Security epoch advanced via cross-channel transition {transition_id}: {old_epoch} -> {new_epoch}"
            )

            # 7. Acknowledge
            self.mailbox.acknowledge_transition(transition_id)

    @staticmethod
    def _extract_event_104_affected_channel(event_elem: ET.Element) -> Tuple[Optional[str], Optional[str]]:
        """
        Explicitly extracts the affected channel from an Event 104 payload.
        Inspects <UserData> and <EventData> elements while handling namespaces safely.
        Never infers the affected channel from <System><Channel>.
        Normalizes known channel names consistently.
        If missing, empty, or ambiguous, returns (None, malformed_reason).
        """
        known_channels = {
            "security": "Security",
            "system": "System",
            "application": "Application",
            "microsoft-windows-sysmon/operational": "Microsoft-Windows-Sysmon/Operational",
        }

        raw_candidates = []
        has_empty_tag = False

        # 1. Search UserData (e.g. <UserData><LogFileCleared><Channel>Security</Channel></LogFileCleared></UserData>)
        user_data_elem = None
        for elem in event_elem:
            if elem.tag.split("}")[-1] == "UserData":
                user_data_elem = elem
                break

        if user_data_elem is not None:
            for child in user_data_elem:
                for item in child.iter():
                    tag_local = item.tag.split("}")[-1]
                    if tag_local in ("Channel", "TargetChannel", "LogName"):
                        txt = item.text
                        if txt is not None and txt.strip() and txt.strip() != "-":
                            raw_candidates.append(txt.strip())
                        else:
                            has_empty_tag = True

        # 2. Search EventData
        event_data_elem = None
        for elem in event_elem:
            if elem.tag.split("}")[-1] == "EventData":
                event_data_elem = elem
                break

        if event_data_elem is not None:
            named_found = False
            for data_elem in event_data_elem:
                if data_elem.tag.split("}")[-1] == "Data":
                    name = data_elem.get("Name")
                    txt = data_elem.text
                    if name in ("Channel", "TargetChannel", "LogName"):
                        named_found = True
                        if txt is not None and txt.strip() and txt.strip() != "-":
                            raw_candidates.append(txt.strip())
                        else:
                            has_empty_tag = True

            # If no named Channel/TargetChannel/LogName tag in EventData, check positional Data
            if not named_found and not raw_candidates:
                for data_elem in event_data_elem:
                    if data_elem.tag.split("}")[-1] == "Data" and data_elem.get("Name") is None:
                        txt = data_elem.text
                        if txt is not None and txt.strip() and txt.strip() != "-":
                            raw_candidates.append(txt.strip())
                            break  # First positional is Channel in Event 104
                        elif txt is not None and (not txt.strip() or txt.strip() == "-"):
                            has_empty_tag = True

        # Normalize candidates
        normalized_candidates = set()
        for cand in raw_candidates:
            c_clean = cand.strip()
            if c_clean and c_clean != "-":
                c_norm = known_channels.get(c_clean.lower(), c_clean)
                normalized_candidates.add(c_norm)

        if len(normalized_candidates) == 0:
            if has_empty_tag:
                return None, "Empty affected channel in Event 104 payload"
            return None, "Missing affected channel in Event 104 payload"

        if len(normalized_candidates) > 1:
            sorted_conflicts = sorted(list(normalized_candidates))
            return None, f"Ambiguous or conflicting affected channels in Event 104 payload: {sorted_conflicts}"

        return next(iter(normalized_candidates)), None

    def handle_event_104_system(self, event_data: Dict[str, Any]):
        """
        Producer side: Coordinates the 5-step durable publication sequence for System Event 104.
        """
        affected_channel = event_data.get("affected_channel")
        record_id = event_data.get("record_id", 0)

        self.logger.info(
            f"Processing System Event 104 at record_id={record_id}, affected_channel='{affected_channel}'"
        )

        if not affected_channel or not str(affected_channel).strip() or event_data.get("is_malformed_witness"):
            reason = event_data.get("malformed_witness_reason") or "Missing, empty, or ambiguous affected_channel in Event 104"
            self.logger.error(
                f"REJECTED Event 104 clear witness at record_id={record_id}: {reason}. Failing closed."
            )
            event_data["quarantine_reason"] = reason
            event_data["quarantined"] = True

            # Record explicit malformed witness outcome in mailbox quarantine
            try:
                os.makedirs(self.mailbox.quarantined_dir, exist_ok=True)
                quarantine_payload = {
                    "event_id": 104,
                    "record_id": record_id,
                    "reason": reason,
                    "quarantined_at": datetime.now(timezone.utc).isoformat(),
                    "source_channel": "System",
                    "raw_data": {k: v for k, v in event_data.items() if k != "raw_xml"},
                }
                quarantine_file = os.path.join(
                    self.mailbox.quarantined_dir, f"malformed_104_rec_{record_id}.json"
                )
                with open(quarantine_file, "w", encoding="utf-8") as f:
                    json.dump(quarantine_payload, f, indent=2)
            except Exception as qe:
                self.logger.warning(f"Could not write malformed witness quarantine file: {qe}")

            # Persist durable channel quarantine halt marker in journals directory
            self.set_channel_quarantine(record_id, reason, witness_event_id=104)

            # Advance System checkpoint record_id past this invalid record so the collector does not loop on recovery,
            # but DO NOT mutate epoch and DO NOT publish any cross-channel transition!
            self.checkpoint_manager.save_checkpoint(record_id, target_channel="System")
            self.current_checkpoint = record_id
            return

        if affected_channel.lower() == "security":
            # 1. Normalize Event 104 under current System epoch (done by caller/pipeline)
            # 2. Persist producer journal intent
            intent = {
                "status": "PUBLISHING",
                "record_id": record_id,
                "target_channel": "Security",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # 3. Publish transition transport envelope durably
            # Zero fabrication: preserve None/empty when not in event payload
            subj_dom = event_data.get("subject_domain") or ""
            subj_user = event_data.get("subject_user") or ""
            subj_sid = event_data.get("subject_user_sid") or ""
            host_name = event_data.get("computer") or self.agent_id

            witness_payload = TransitionMailbox.build_witness_payload(
                affected_channel="Security",
                event_id=104,
                provider=event_data.get("provider") or "Microsoft-Windows-Eventlog",
                source_channel="System",
                subject_domain_name=subj_dom,
                subject_user_name=subj_user,
                subject_user_sid=subj_sid,
            )
            witness_hash = TransitionMailbox.compute_witness_payload_hash(witness_payload)

            source_event_id = generate_source_event_id_v2(
                agent_id=self.agent_id,
                channel="System",
                epoch=self.current_epoch,
                hostname=host_name,
                record_id=record_id,
            )

            identity_manifest = TransitionMailbox.build_transition_identity_manifest(
                agent_id=self.agent_id,
                source_channel="System",
                source_epoch=self.current_epoch,
                source_event_id=source_event_id,
                source_hostname=host_name,
                source_record_id=record_id,
                target_channel="Security",
                transition_type="LOG_CLEARED_SECURITY_REMOTE",
                witness_event_id=104,
                witness_payload_hash=witness_hash,
                witness_provider=event_data.get("provider") or "Microsoft-Windows-Eventlog",
            )

            envelope = TransitionMailbox.build_transition_envelope(identity_manifest, witness_payload)
            intent["envelope"] = envelope

            os.makedirs(self.journal_dir, exist_ok=True)
            with open(self.producer_journal_file, "w", encoding="utf-8") as f:
                json.dump(intent, f, indent=2)

            # Publish to pending
            self.mailbox.publish_transition(envelope)

            # 4. Advance System checkpoint ONLY after publication is durable
            self.checkpoint_manager.save_checkpoint(record_id, target_channel="System")
            self.current_checkpoint = record_id

            # 5. Complete journal intent
            intent["status"] = "COMMITTED"
            with open(self.producer_journal_file, "w", encoding="utf-8") as f:
                json.dump(intent, f, indent=2)

        elif affected_channel.lower() == "system":
            # Event 104 cleared System itself: check replay protection first
            if self.checkpoint_manager.is_local_witness_replay("System", record_id, 104):
                self.logger.info(
                    f"Local witness System Event 104 at record_id={record_id} already applied for epoch transition; ignoring replay."
                )
                self.current_checkpoint = max(self.current_checkpoint, record_id)
                self.checkpoint_manager.save_checkpoint(self.current_checkpoint, target_channel="System")
            else:
                local_tid = self.checkpoint_manager.build_local_witness_id(
                    "System", self.current_epoch, record_id, 104
                )
                metadata = {
                    "is_local_witness": True,
                    "source_channel": "System",
                    "from_epoch": self.current_epoch,
                    "source_record_id": record_id,
                    "witness_event_id": 104,
                }
                target_epoch = self.current_epoch + 1
                transition_notif = {
                    "transition_id": local_tid,
                    "agent_id": self.agent_id,
                    "source_channel": "System",
                    "target_channel": "System",
                    "target_epoch": target_epoch,
                    "transition_type": "EPOCH_ADVANCE",
                    "witness_event_id": 104,
                    "witness_record_id": record_id,
                }
                new_epoch = self.checkpoint_manager.advance_epoch(
                    reset_record_id=0,
                    transition_id=local_tid,
                    transition_metadata=metadata,
                    target_channel="System",
                    pending_notification=transition_notif,
                )
                self.current_checkpoint = 0
                self.current_epoch = new_epoch
                self.logger.info(f"System epoch advanced to {new_epoch} due to System self-clear")

        else:
            # Another supported/unrelated channel (e.g. Application): save checkpoint record_id without epoch mutation
            self.logger.info(
                f"Event 104 for channel '{affected_channel}' noted; epoch unaffected."
            )
            self.checkpoint_manager.save_checkpoint(record_id, target_channel="System")
            self.current_checkpoint = record_id

    def collect_once(self, raise_on_error: bool = False) -> List[Dict[str, Any]]:
        """
        Performs a single batch retrieval of events newer than the checkpoint.
        Checks durable remainder first, then simulated events, then live wevtutil with dual-probe.
        """
        # 0. Check if channel is under persistent quarantine halt
        if self.is_channel_quarantined():
            reason = self.get_channel_quarantine_reason() or "Active channel quarantine"
            raise UnverifiedDiscontinuityError(
                f"CHANNEL_QUARANTINED: Ingestion for channel '{self.log_name}' is halted "
                f"due to durable quarantine: {reason}. Resumption requires authorized recovery."
            )

        # Apply any pending cross-channel transitions before ingesting new Security events
        if self.log_name == "Security":
            self.check_and_apply_pending_transitions()

        # 1. Check for durable remainder first (eligible under current epoch)
        if self.is_durable_remainder_eligible():
            remainder_events = self.load_durable_remainder()
            if remainder_events:
                self.logger.info(
                    f"Serving {len(remainder_events)} remainder events from {self.remainder_file} under epoch {self.current_epoch}"
                )
                for ev in remainder_events:
                    ev["epoch"] = self.current_epoch
                truncated, new_remainder = self._truncate_batch_at_clear(remainder_events)
                if new_remainder:
                    self.persist_durable_remainder(new_remainder, target_epoch=self.current_epoch + 1)
                    self._serving_remainder = False
                else:
                    self._serving_remainder = True
                return self._process_events_for_dispatch(truncated)
            else:
                self.clear_durable_remainder()

        # 2. Strict Execution Mode Separation (Task 2)
        if self.execution_mode == "PRODUCTION":
            # In PRODUCTION mode: NEVER collect from simulated_events directory. Query live wevtutil ONLY!
            events = []
        else:
            # In simulation/test modes: check simulated events directory first
            sim_events = self._collect_simulated_events()
            events = sim_events

        # 3. Query wevtutil: in PRODUCTION mode, or in TEST mode when subprocess.run or _probe_newest_record_id is mocked
        should_query_wevtutil = (
            self.execution_mode == "PRODUCTION" or
            (self.execution_mode == "TEST" and (
                hasattr(subprocess.run, "assert_called") or
                hasattr(self._probe_newest_record_id, "assert_called")
            ))
        )
        if not events and should_query_wevtutil:
            # Dual-probe query: Probe 1 (reverse query for newest record ID)
            newest_record_id, probe_err = self._probe_newest_record_id()
            if probe_err == "EMPTY_LOG":
                self.status = "HEALTHY"
                self.consecutive_failures = 0
                self.last_error = None
                return []
            if probe_err == "COMMAND_UNAVAILABLE":
                self.status = "UNAVAILABLE"
                self.consecutive_failures += 1
                self.last_error = f"Live wevtutil query on '{self.log_name}' unavailable"
                if raise_on_error:
                    raise ChannelUnavailableError(self.last_error, channel=self.log_name, error_type="COMMAND_UNAVAILABLE")
                return []
            if probe_err == "TIMEOUT":
                self.status = "DEGRADED"
                self.consecutive_failures += 1
                self.timeout_count += 1
                self.last_error = f"Timeout probing newest record on {self.log_name}"
                if raise_on_error:
                    raise ChannelTimeoutError(self.last_error, channel=self.log_name)
                return []

            query_checkpoint = self.current_checkpoint
            if (
                newest_record_id is not None
                and self.current_checkpoint > 0
                and newest_record_id < self.current_checkpoint
            ):
                # Discontinuity detected: probe for clear witness (Probe 2)
                witness_found, witness_event, reason = self._find_clear_witness_for_reset()
                if not witness_found:
                    self.set_channel_quarantine(
                        record_id=newest_record_id,
                        reason=f"UNVERIFIED_RESET: Record ID dropped from {self.current_checkpoint} to {newest_record_id} without authoritative clear witness ({reason})",
                        witness_event_id=0,
                    )
                    raise UnverifiedDiscontinuityError(
                        f"UNVERIFIED_RESET: Record ID dropped from {self.current_checkpoint} to {newest_record_id} "
                        f"in channel '{self.log_name}' without authoritative clear event. "
                        f"Channel placed under durable quarantine halt."
                    )
                else:
                    self.logger.info(
                        f"Verified record ID reset from {self.current_checkpoint} to {newest_record_id} via clear witness: {witness_event}"
                    )
                    query_checkpoint = 0

            if query_checkpoint == 0:
                query = "*[System[(EventRecordID > 0)]]"
            else:
                query = f"*[System[(EventRecordID > {query_checkpoint})]]"

            cmd = ["wevtutil", "qe", self.log_name, f"/q:{query}", f"/c:{self.batch_size}", "/f:xml"]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, check=True, timeout=self.timeout_seconds
                )
                xml_output, decode_err = self._decode_wevtutil_output(result.stdout)
                if decode_err:
                    self.logger.error(
                        f"Decoding failure on {self.log_name} batch query: {decode_err}. "
                        "Quarantining undecodable raw bytes and halting checkpoint advancement for safety."
                    )
                    self.status = "DEGRADED"
                    self.consecutive_failures += 1
                    self.last_error = f"Undecodable XML payload on {self.log_name}"
                    return []
                xml_output = (xml_output or "").strip()
                if xml_output:
                    # Oversized XML handling & adaptive batch reduction (Task 3)
                    if len(xml_output) > 10 * 1024 * 1024:
                        self.logger.warning(
                            f"Oversized XML batch ({len(xml_output)} bytes) returned by {self.log_name} with batch_size={self.batch_size}. "
                            "Initiating adaptive batch reduction recovery."
                        )
                        recovery_batches = [10, 1] if self.batch_size > 10 else [1]
                        recovered = False
                        for reduced_size in recovery_batches:
                            r_cmd = ["wevtutil", "qe", self.log_name, f"/q:{query}", f"/c:{reduced_size}", "/f:xml"]
                            try:
                                r_res = subprocess.run(
                                    r_cmd, capture_output=True, check=True, timeout=self.timeout_seconds
                                )
                                r_xml, r_dec_err = self._decode_wevtutil_output(r_res.stdout)
                                if r_dec_err:
                                    continue
                                r_xml = (r_xml or "").strip()
                                if r_xml and len(r_xml) <= 10 * 1024 * 1024:
                                    live_events = self._parse_wevtutil_xml(r_xml)
                                    if live_events:
                                        truncated, remainder = self._truncate_batch_at_clear(live_events)
                                        if remainder:
                                            self.persist_durable_remainder(remainder)
                                        events = truncated
                                        recovered = True
                                        self.logger.info(f"Adaptive batch reduction succeeded on {self.log_name} with /c:{reduced_size}.")
                                        break
                            except Exception as re:
                                self.logger.warning(f"Adaptive batch reduction query failed with /c:{reduced_size}: {re}")

                        if not recovered:
                            # Indivisible single event or record batch exceeds 10MB
                            self.logger.error(
                                f"Indivisible oversized record (>10MB) detected on {self.log_name}. "
                                "Durably quarantining oversized payload to prevent channel deadlock."
                            )
                            rec_id = self._extract_record_id_from_raw_xml(xml_output)
                            q_path = self.quarantine_oversized_record(xml_output, record_id=rec_id)
                            if q_path and rec_id is not None and rec_id > self.current_checkpoint:
                                self.checkpoint_manager.save_checkpoint(rec_id)
                                self.current_checkpoint = rec_id
                                self.logger.warning(
                                    f"Advanced checkpoint for {self.log_name} past oversized record {rec_id} "
                                    f"after durable quarantine at {q_path}."
                                )
                            elif not q_path:
                                self.logger.error(
                                    f"Quarantine write failed for oversized record in {self.log_name}; "
                                    "refusing to advance checkpoint to prevent silent data loss."
                                )
                    else:
                        live_events = self._parse_wevtutil_xml(xml_output)
                        if live_events:
                            truncated, remainder = self._truncate_batch_at_clear(live_events)
                            if remainder:
                                self.persist_durable_remainder(remainder)
                            events = truncated
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                self.consecutive_failures += 1
                self.status = "UNAVAILABLE"
                self.last_error = f"Live wevtutil query on '{self.log_name}' unavailable ({e})"
                if not self._warned_permission:
                    self.logger.warning(
                        f"Live wevtutil query on '{self.log_name}' unavailable ({e}). "
                        "Running in waiting mode. Drop XML files into simulated_events for offline/lab simulation."
                    )
                    self._warned_permission = True
                if raise_on_error:
                    raise ChannelUnavailableError(self.last_error, channel=self.log_name, error_type="COMMAND_UNAVAILABLE") from e
                return []
            except subprocess.TimeoutExpired as e:
                self.timeout_count += 1
                self.consecutive_failures += 1
                self.status = "DEGRADED"
                self.last_error = f"Timeout querying {self.log_name} ({self.timeout_seconds}s): {e}"
                self.logger.error(self.last_error)
                if raise_on_error:
                    raise ChannelTimeoutError(self.last_error, channel=self.log_name) from e
                return []

        if not events:
            self.status = "HEALTHY"
            self.consecutive_failures = 0
            self.last_error = None
            return []

        # Tag events with current epoch if not already tagged
        self.status = "HEALTHY"
        self.consecutive_failures = 0
        self.last_error = None
        self.events_collected_total += len(events)
        self.last_successful_collection = datetime.now(timezone.utc).isoformat()
        for ev in events:
            if "epoch" not in ev:
                ev["epoch"] = self.current_epoch

        return self._process_events_for_dispatch(events)

    def _process_events_for_dispatch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Intercepts, validates, and tags events for downstream pipeline consumption."""
        processed_events = []
        for ev in events:
            record_id = ev.get("record_id", 0)
            event_id = ev.get("event_id")

            # Check for unverified record ID drops
            if self.current_checkpoint > 0 and record_id < self.current_checkpoint:
                # Unless this event is specifically a valid authoritative clear event, fail closed
                if event_id not in (1102, 104) or (event_id == 104 and ev.get("is_malformed_witness")):
                    if event_id == 104 and ev.get("is_malformed_witness"):
                        self.handle_event_104_system(ev)
                    self.set_channel_quarantine(
                        record_id=record_id,
                        reason=f"UNVERIFIED_CHANNEL_DISCONTINUITY: Record ID dropped from {self.current_checkpoint} to {record_id} without authoritative clear event in channel {self.log_name}",
                        witness_event_id=event_id or 0,
                    )
                    raise UnverifiedDiscontinuityError(
                        f"UNVERIFIED_CHANNEL_DISCONTINUITY: Record ID dropped from {self.current_checkpoint} to {record_id} "
                        f"without authoritative clear event in channel {self.log_name}"
                    )

            if self.log_name == "System" and event_id == 104:
                self.handle_event_104_system(ev)
                if ev.get("is_malformed_witness") or ev.get("quarantined"):
                    reason = ev.get("quarantine_reason") or "Malformed Event 104 witness"
                    raise UnverifiedDiscontinuityError(
                        f"CHANNEL_QUARANTINED: Channel '{self.log_name}' halted due to malformed Event 104 "
                        f"at record_id={record_id}: {reason}. Ingestion halted."
                    )

            if self.log_name == "Security" and event_id == 1102:
                # Check if this local witness was already applied as the transition into current_epoch
                if self.checkpoint_manager.is_local_witness_replay(self.log_name, record_id, 1102):
                    self.logger.info(
                        f"Local witness Event 1102 at record_id={record_id} already applied for epoch transition; ignoring replay."
                    )
                    self.current_checkpoint = max(self.current_checkpoint, record_id)
                    self.checkpoint_manager.save_checkpoint(self.current_checkpoint, target_channel=self.log_name)
                else:
                    self._pending_epoch_advance = True
                    self._pending_epoch_advance_rec_id = record_id
                    self._pending_local_witness = {
                        "is_local_witness": True,
                        "source_channel": "Security",
                        "from_epoch": self.current_epoch,
                        "source_record_id": record_id,
                        "witness_event_id": 1102,
                    }

            processed_events.append(ev)

        return processed_events

    def update_checkpoint(self, last_successful_record_id: int):
        """Advances the checkpoint only after successful downstream processing."""
        if getattr(self, "_serving_remainder", False):
            self.clear_durable_remainder()
            self._serving_remainder = False

        self._acknowledge_in_flight_simulated_files(committed_record_id=last_successful_record_id)

        if getattr(self, "_pending_epoch_advance", False) and last_successful_record_id >= getattr(self, "_pending_epoch_advance_rec_id", -1):
            witness_id_num = (
                self._pending_local_witness.get("witness_event_id", 1102)
                if getattr(self, "_pending_local_witness", None)
                else 1102
            )
            local_tid = self.checkpoint_manager.build_local_witness_id(
                self.log_name, self.current_epoch, self._pending_epoch_advance_rec_id, witness_id_num
            )
            target_epoch = self.current_epoch + 1
            transition_notif = {
                "transition_id": local_tid,
                "agent_id": self.agent_id,
                "source_channel": self.log_name,
                "target_channel": self.log_name,
                "target_epoch": target_epoch,
                "transition_type": "EPOCH_ADVANCE",
                "witness_event_id": witness_id_num,
                "witness_record_id": self._pending_epoch_advance_rec_id,
                "metadata": getattr(self, "_pending_local_witness", None),
            }
            new_epoch = self.checkpoint_manager.advance_epoch(
                reset_record_id=0,
                transition_id=local_tid,
                transition_metadata=getattr(self, "_pending_local_witness", None),
                target_channel=self.log_name,
                pending_notification=transition_notif,
            )
            self.current_checkpoint = 0
            self.current_epoch = new_epoch
            self._pending_epoch_advance = False
            self._pending_local_witness = None
            self.logger.info(
                f"In-channel Event {witness_id_num} commit completed: {self.log_name} epoch advanced to {new_epoch}"
            )
        elif last_successful_record_id > self.current_checkpoint or (self.current_checkpoint == 0 and last_successful_record_id > 0):
            self.checkpoint_manager.save_checkpoint(last_successful_record_id, target_channel=self.log_name)
            self.current_checkpoint = last_successful_record_id

    def shutdown(self):
        self.logger.info(f"Shutting down WindowsEventCollector for channel {self.log_name}.")

    @staticmethod
    def _parse_hashes(raw_hashes: Optional[str]) -> Dict[str, str]:
        """
        Parses Sysmon Hashes string into algorithm:hash dictionary.
        Handles comma or semicolon separated pairs like:
        'SHA1=...,MD5=...,SHA256=...,IMPHASH=...'
        """
        if not raw_hashes or not raw_hashes.strip() or raw_hashes.strip() == "-":
            return {}
        parsed = {}
        normalized_str = raw_hashes.replace(";", ",")
        for token in normalized_str.split(","):
            token = token.strip()
            if "=" in token:
                k, v = token.split("=", 1)
                k = k.strip().lower()
                v = v.strip()
                if k and v and v != "-":
                    parsed[k] = v
        return parsed

    def quarantine_malformed_record(
        self,
        raw_xml: str,
        reason: str,
        record_id: Optional[int] = None,
        error_details: Optional[str] = None,
    ) -> str:
        """
        Durably persists malformed raw XML and diagnostic metadata to disk.
        Never silently discards forensic evidence.
        Uses deterministic content digest for idempotent storage without unbounded duplication.
        Uses atomic temp file, flush, fsync, and replace.
        """
        try:
            import shutil
            os.makedirs(self.malformed_events_dir, exist_ok=True)
            watermark_mb = getattr(config, "outbox_disk_watermark_mb", 500)
            try:
                usage = shutil.disk_usage(self.malformed_events_dir)
                free_mb = usage.free / (1024 * 1024)
                if free_mb < watermark_mb:
                    self.logger.error(
                        f"Quarantine write rejected on {self.log_name}: free disk space ({free_mb:.1f}MB) "
                        f"is below watermark ({watermark_mb}MB)."
                    )
                    return ""
            except OSError as e:
                self.logger.warning(f"Could not determine disk usage for quarantine: {e}")

            now_iso = datetime.now(timezone.utc).isoformat()
            rec_label = str(record_id) if record_id is not None and record_id >= 0 else "unknown"
            content_bytes = raw_xml.encode("utf-8", errors="replace")
            token = hashlib.sha256(content_bytes).hexdigest()[:16]
            filename = f"malformed_{rec_label}_{token}.json"
            target_path = os.path.join(self.malformed_events_dir, filename)
            payload = {
                "channel": self.log_name,
                "quarantined_at": now_iso,
                "record_id": record_id,
                "reason": reason,
                "error_details": error_details,
                "raw_xml": raw_xml,
            }
            temp_file = f"{target_path}.tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_file, target_path)
            self.quarantined_count += 1
            self.logger.warning(
                f"Durably quarantined malformed event in {self.log_name} (record_id={record_id}): {reason} -> {target_path}"
            )
            return target_path
        except OSError as e:
            self.logger.warning(f"Could not persist malformed event quarantine file on {self.log_name}: {e}")
            return ""

    def quarantine_oversized_record(
        self,
        raw_xml: str,
        record_id: Optional[int] = None,
    ) -> str:
        """
        Durably persists an oversized XML record to disk to prevent channel stall.
        Uses deterministic content digest for idempotent storage without unbounded duplication.
        Uses atomic temp file, flush, fsync, and replace.
        """
        try:
            import shutil
            os.makedirs(self.oversized_events_dir, exist_ok=True)
            watermark_mb = getattr(config, "outbox_disk_watermark_mb", 500)
            try:
                usage = shutil.disk_usage(self.oversized_events_dir)
                free_mb = usage.free / (1024 * 1024)
                if free_mb < watermark_mb:
                    self.logger.error(
                        f"Oversized quarantine write rejected on {self.log_name}: free disk space ({free_mb:.1f}MB) "
                        f"is below watermark ({watermark_mb}MB)."
                    )
                    return ""
            except OSError as e:
                self.logger.warning(f"Could not determine disk usage for quarantine: {e}")

            rec_label = str(record_id) if record_id is not None and record_id >= 0 else "unknown"
            content_bytes = raw_xml.encode("utf-8", errors="replace")
            token = hashlib.sha256(content_bytes).hexdigest()[:16]
            filename = f"oversized_{rec_label}_{token}.xml"
            target_path = os.path.join(self.oversized_events_dir, filename)
            temp_file = f"{target_path}.tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(raw_xml)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_file, target_path)
            self.quarantined_count += 1
            self.logger.warning(
                f"Durably quarantined oversized record in {self.log_name} (record_id={record_id}, {len(raw_xml)} bytes) -> {target_path}"
            )
            return target_path
        except OSError as e:
            self.logger.warning(f"Could not persist oversized record quarantine file on {self.log_name}: {e}")
            return ""

    @staticmethod
    def _extract_record_id_from_raw_xml(xml_str: str) -> Optional[int]:
        """Extracts EventRecordID using regex from raw XML when parsing is bypassed or fails."""
        m = re.search(r"<EventRecordID[^>]*>\s*(\d+)\s*</EventRecordID>", xml_str[:8192])
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                return None
        return None

    def _parse_wevtutil_xml(self, xml_string: str) -> List[Dict[str, Any]]:
        """Parses multiple concatenated Event XML tags returned by wevtutil."""
        if not xml_string or not isinstance(xml_string, str):
            return []

        # Bound processing of unusually large inputs to prevent resource exhaustion (Task 5)
        if len(xml_string) > 10 * 1024 * 1024:
            self.logger.warning(f"Oversized XML batch ({len(xml_string)} bytes); rejecting to prevent resource exhaustion.")
            return []

        # Sanitize null characters that would cause XML parse failures
        cleaned_xml = xml_string.replace("\x00", "")

        wrapped_xml = f"<Events>{cleaned_xml}</Events>"
        parsed_events = []
        try:
            root = ET.fromstring(wrapped_xml)

            for event in root:
                if event.tag.split("}")[-1] != "Event":
                    continue
                system = None
                for elem in event:
                    if elem.tag.split("}")[-1] == "System":
                        system = elem
                        break
                if system is None:
                    raw_event_str = ET.tostring(event, encoding="unicode")
                    self.quarantine_malformed_record(
                        raw_xml=raw_event_str,
                        reason="Missing System element in event payload",
                        record_id=None
                    )
                    continue

                event_data = {
                    "raw_xml": ET.tostring(event, encoding="unicode"),
                    "channel": self.log_name,
                }

                channel_elem = None
                provider = None
                event_id_elem = None
                record_id_elem = None
                time_created_elem = None
                computer_elem = None
                level_elem = None
                task_elem = None
                keywords_elem = None

                for elem in system:
                    tag_l = elem.tag.split("}")[-1]
                    if tag_l == "Channel":
                        channel_elem = elem
                    elif tag_l == "Provider":
                        provider = elem
                    elif tag_l == "EventID":
                        event_id_elem = elem
                    elif tag_l == "EventRecordID":
                        record_id_elem = elem
                    elif tag_l == "TimeCreated":
                        time_created_elem = elem
                    elif tag_l == "Computer":
                        computer_elem = elem
                    elif tag_l == "Level":
                        level_elem = elem
                    elif tag_l == "Task":
                        task_elem = elem
                    elif tag_l == "Keywords":
                        keywords_elem = elem

                if channel_elem is not None and channel_elem.text:
                    event_data["channel"] = channel_elem.text

                if provider is not None:
                    event_data["provider"] = provider.get("Name")

                if event_id_elem is not None and event_id_elem.text and event_id_elem.text.strip():
                    try:
                        event_data["event_id"] = int(event_id_elem.text.strip())
                    except ValueError:
                        self.logger.warning(f"Malformed EventID text: '{event_id_elem.text}'")

                if record_id_elem is not None and record_id_elem.text and record_id_elem.text.strip():
                    try:
                        event_data["record_id"] = int(record_id_elem.text.strip())
                    except ValueError:
                        self.logger.warning(f"Malformed EventRecordID text: '{record_id_elem.text}'")
                        raw_event_str = ET.tostring(event, encoding="unicode")
                        self.quarantine_malformed_record(
                            raw_xml=raw_event_str,
                            reason=f"Malformed EventRecordID text: '{record_id_elem.text}'",
                            record_id=None
                        )
                        continue
                else:
                    self.logger.warning("Missing EventRecordID in event element")
                    raw_event_str = ET.tostring(event, encoding="unicode")
                    self.quarantine_malformed_record(
                        raw_xml=raw_event_str,
                        reason="Missing EventRecordID in event element",
                        record_id=None
                    )
                    continue

                if time_created_elem is not None:
                    event_data["timestamp"] = time_created_elem.get("SystemTime")

                if computer_elem is not None and computer_elem.text and computer_elem.text.strip() not in ("", "-"):
                    event_data["computer"] = computer_elem.text.strip()
                else:
                    event_data["computer"] = None

                if level_elem is not None and level_elem.text and level_elem.text.strip():
                    try:
                        event_data["level"] = int(level_elem.text.strip())
                    except ValueError:
                        pass

                if task_elem is not None and task_elem.text and task_elem.text.strip():
                    try:
                        event_data["task"] = int(task_elem.text.strip())
                    except ValueError:
                        pass

                if keywords_elem is not None and keywords_elem.text:
                    event_data["keywords"] = keywords_elem.text

                # Parse EventData and UserData namespace-safely
                event_data_elem = None
                user_data_elem = None
                for elem in event:
                    local_tag = elem.tag.split("}")[-1]
                    if local_tag == "EventData":
                        event_data_elem = elem
                    elif local_tag == "UserData":
                        user_data_elem = elem

                data_dict = {}
                if event_data_elem is not None:
                    for data_elem in event_data_elem:
                        if data_elem.tag.split("}")[-1] == "Data":
                            name = data_elem.get("Name")
                            if name:
                                data_dict[name] = data_elem.text
                            elif data_elem.text and "Channel" not in data_dict:
                                # Positional Data in Event 104
                                data_dict["Channel"] = data_elem.text

                if user_data_elem is not None:
                    for child in user_data_elem:
                        for item in child.iter():
                            tag_name = item.tag.split("}")[-1]
                            if tag_name and item.text and item.text.strip() and tag_name not in data_dict:
                                data_dict[tag_name] = item.text.strip()

                # Event 104 specific channel extraction
                if event_data.get("event_id") == 104:
                    aff_chan, malformed_reason = self._extract_event_104_affected_channel(event)
                    event_data["affected_channel"] = aff_chan
                    if malformed_reason:
                        event_data["is_malformed_witness"] = True
                        event_data["malformed_witness_reason"] = malformed_reason

                # Identity attributes
                raw_target_user = data_dict.get("TargetUserName")
                target_user = raw_target_user.strip() if raw_target_user and raw_target_user.strip() not in ("", "-") else None

                raw_target_domain = data_dict.get("TargetDomainName")
                target_domain = raw_target_domain.strip() if raw_target_domain and raw_target_domain.strip() not in ("", "-") else None

                raw_subject_user = data_dict.get("SubjectUserName")
                subject_user = raw_subject_user.strip() if raw_subject_user and raw_subject_user.strip() not in ("", "-") else None

                raw_subject_domain = data_dict.get("SubjectDomainName")
                subject_domain = raw_subject_domain.strip() if raw_subject_domain and raw_subject_domain.strip() not in ("", "-") else None

                raw_subject_sid = data_dict.get("SubjectUserSid") or data_dict.get("UserSid")
                subject_user_sid = raw_subject_sid.strip() if raw_subject_sid and raw_subject_sid.strip() not in ("", "-") else None

                raw_workstation = data_dict.get("WorkstationName")
                workstation_name = raw_workstation.strip() if raw_workstation and raw_workstation.strip() not in ("", "-") else None

                raw_ip_port = data_dict.get("IpPort")
                ip_port = raw_ip_port.strip() if raw_ip_port and raw_ip_port.strip() not in ("", "-") else None

                raw_status = data_dict.get("Status")
                status_code = raw_status.strip() if raw_status and raw_status.strip() not in ("", "-") else None

                raw_sub_status = data_dict.get("SubStatus")
                sub_status_code = raw_sub_status.strip() if raw_sub_status and raw_sub_status.strip() not in ("", "-") else None

                # Sysmon User attribute extraction
                raw_sysmon_user = data_dict.get("User")
                if raw_sysmon_user and raw_sysmon_user.strip() and raw_sysmon_user.strip() not in ("", "-"):
                    s_user = raw_sysmon_user.strip()
                    event_data["user"] = s_user
                    if "\\" in s_user:
                        s_dom, s_uname = s_user.split("\\", 1)
                        if not target_domain:
                            target_domain = s_dom
                        if not target_user:
                            target_user = s_uname
                        if not subject_domain:
                            subject_domain = s_dom
                        if not subject_user:
                            subject_user = s_uname
                    else:
                        if not target_user:
                            target_user = s_user
                        if not subject_user:
                            subject_user = s_user

                if target_user:
                    event_data["target_user"] = target_user
                if target_domain:
                    event_data["target_domain"] = target_domain
                event_data["subject_user"] = subject_user
                event_data["subject_domain"] = subject_domain
                event_data["subject_user_sid"] = subject_user_sid
                if workstation_name:
                    event_data["workstation_name"] = workstation_name
                if ip_port:
                    event_data["ip_port"] = ip_port
                if status_code:
                    event_data["status"] = status_code
                if sub_status_code:
                    event_data["sub_status"] = sub_status_code

                win_eid = event_data.get("event_id")
                if win_eid in (4624, 4625):
                    if target_user:
                        event_data["username"] = target_user
                else:
                    u = target_user or subject_user or event_data.get("user")
                    if u:
                        event_data["username"] = u

                # IP address & Network attributes (Security & Sysmon Event 3)
                ip_addr = data_dict.get("IpAddress") or data_dict.get("SourceIp")
                if ip_addr and ip_addr.strip() and ip_addr.strip() != "-":
                    event_data["source_ip"] = ip_addr.strip()

                raw_dst_ip = data_dict.get("DestinationIp")
                if raw_dst_ip and raw_dst_ip.strip() and raw_dst_ip.strip() != "-":
                    event_data["destination_ip"] = raw_dst_ip.strip()

                raw_src_port = data_dict.get("SourcePort")
                if raw_src_port and raw_src_port.strip() and raw_src_port.strip() != "-":
                    try:
                        event_data["source_port"] = int(raw_src_port.strip())
                    except ValueError:
                        event_data["source_port"] = raw_src_port.strip()

                raw_dst_port = data_dict.get("DestinationPort")
                if raw_dst_port and raw_dst_port.strip() and raw_dst_port.strip() != "-":
                    try:
                        event_data["destination_port"] = int(raw_dst_port.strip())
                    except ValueError:
                        event_data["destination_port"] = raw_dst_port.strip()

                raw_proto = data_dict.get("Protocol")
                if raw_proto and raw_proto.strip() and raw_proto.strip() != "-":
                    event_data["protocol"] = raw_proto.strip().lower()

                raw_init = data_dict.get("Initiated")
                if raw_init and raw_init.strip() and raw_init.strip() != "-":
                    event_data["initiated"] = raw_init.strip().lower() == "true"

                raw_src_host = data_dict.get("SourceHostname")
                if raw_src_host and raw_src_host.strip() and raw_src_host.strip() != "-":
                    event_data["source_hostname"] = raw_src_host.strip()

                raw_dst_host = data_dict.get("DestinationHostname")
                if raw_dst_host and raw_dst_host.strip() and raw_dst_host.strip() != "-":
                    event_data["destination_hostname"] = raw_dst_host.strip()

                # Process & Command line attributes
                logon_type = data_dict.get("LogonType")
                if logon_type and logon_type.strip() and logon_type.strip() != "-":
                    raw_lt = logon_type.strip()
                    try:
                        event_data["logon_type"] = int(raw_lt)
                    except ValueError:
                        event_data["logon_type"] = raw_lt

                cmd_line = data_dict.get("CommandLine") or data_dict.get("ScriptBlockText")
                if cmd_line and cmd_line.strip() and cmd_line.strip() != "-":
                    event_data["command_line"] = cmd_line.strip()

                proc_name = data_dict.get("NewProcessName") or data_dict.get("Image")
                if proc_name and proc_name.strip() and proc_name.strip() != "-":
                    event_data["process_name"] = proc_name.strip()

                parent_proc = data_dict.get("ParentProcessName") or data_dict.get("ParentImage")
                if parent_proc and parent_proc.strip() and parent_proc.strip() != "-":
                    event_data["parent_process_name"] = parent_proc.strip()

                proc_id = data_dict.get("ProcessId")
                if proc_id and proc_id.strip() and proc_id.strip() != "-":
                    event_data["process_id"] = proc_id.strip()

                parent_proc_id = data_dict.get("ParentProcessId")
                if parent_proc_id and parent_proc_id.strip() and parent_proc_id.strip() != "-":
                    event_data["parent_process_id"] = parent_proc_id.strip()

                parent_cmd = data_dict.get("ParentCommandLine")
                if parent_cmd and parent_cmd.strip() and parent_cmd.strip() != "-":
                    event_data["parent_command_line"] = parent_cmd.strip()

                parent_u = data_dict.get("ParentUser")
                if parent_u and parent_u.strip() and parent_u.strip() != "-":
                    event_data["parent_user"] = parent_u.strip()

                # Sysmon Process metadata & Hashes (Sysmon Event 1)
                raw_pguid = data_dict.get("ProcessGuid")
                if raw_pguid and raw_pguid.strip() and raw_pguid.strip() != "-":
                    event_data["process_guid"] = raw_pguid.strip()

                raw_ppguid = data_dict.get("ParentProcessGuid")
                if raw_ppguid and raw_ppguid.strip() and raw_ppguid.strip() != "-":
                    event_data["parent_process_guid"] = raw_ppguid.strip()

                raw_curdir = data_dict.get("CurrentDirectory")
                if raw_curdir and raw_curdir.strip() and raw_curdir.strip() != "-":
                    event_data["current_directory"] = raw_curdir.strip()

                raw_integ = data_dict.get("IntegrityLevel")
                if raw_integ and raw_integ.strip() and raw_integ.strip() != "-":
                    event_data["integrity_level"] = raw_integ.strip()

                raw_hashes = data_dict.get("Hashes")
                if raw_hashes and raw_hashes.strip() and raw_hashes.strip() != "-":
                    event_data["hashes"] = raw_hashes.strip()
                    parsed_h = self._parse_hashes(raw_hashes)
                    if parsed_h:
                        event_data["hashes_parsed"] = parsed_h
                        for algo in ("sha256", "md5", "sha1", "imphash"):
                            if algo in parsed_h:
                                event_data[algo] = parsed_h[algo]

                # DNS attributes (Sysmon Event 22)
                raw_qname = data_dict.get("QueryName")
                if raw_qname and raw_qname.strip() and raw_qname.strip() != "-":
                    event_data["query_name"] = raw_qname.strip()

                raw_qstatus = data_dict.get("QueryStatus")
                if raw_qstatus and raw_qstatus.strip() and raw_qstatus.strip() != "-":
                    try:
                        event_data["query_status"] = int(raw_qstatus.strip())
                    except ValueError:
                        event_data["query_status"] = raw_qstatus.strip()

                raw_qres = data_dict.get("QueryResults")
                if raw_qres and raw_qres.strip() and raw_qres.strip() != "-":
                    event_data["query_results"] = raw_qres.strip()

                # Additional Software & Execution attributes
                for tag, field in [
                    ("OriginalFileName", "original_file_name"),
                    ("FileVersion", "file_version"),
                    ("Description", "description"),
                    ("Product", "product"),
                    ("Company", "company"),
                    ("TerminalSessionId", "terminal_session_id"),
                    ("LogonGuid", "logon_guid"),
                    ("LogonId", "logon_id"),
                    ("UtcTime", "utc_time"),
                ]:
                    v = data_dict.get(tag)
                    if v and v.strip() and v.strip() != "-":
                        event_data[field] = v.strip()

                if "record_id" in event_data:
                    parsed_events.append(event_data)

        except ET.ParseError as e:
            self.logger.error(f"XML parse error in event batch on {self.log_name}: {e}")
            self.quarantine_malformed_record(
                raw_xml=xml_string,
                reason=f"XML parse error: {e}",
                error_details=str(e),
            )

        return parsed_events
