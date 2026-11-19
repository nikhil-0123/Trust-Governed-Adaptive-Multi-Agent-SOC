import os
import subprocess
import xml.etree.ElementTree as ET
import logging
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from config.settings import config
from .checkpoint import CheckpointManager
from .mailbox import TransitionMailbox

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from canonical import generate_source_event_id_v2, validate_epoch


class UnverifiedDiscontinuityError(Exception):
    """Raised when an unverified record ID drop occurs without an authoritative log clear."""
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
    ):
        self.logger = logger
        self.log_name = (log_name or config.windows_security_log_name).strip()
        self.agent_id = (agent_id or "AGT-WIN-01").strip()
        self.batch_size = config.windows_event_batch_size

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
        """
        cmd = ["wevtutil", "qe", self.log_name, "/c:1", "/rd:true", "/f:xml"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
            if result.stdout.strip():
                events = self._parse_wevtutil_xml(result.stdout)
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
                        with open(filepath, "r", encoding="utf-8") as f:
                            content = f.read()
                        parsed = self._parse_wevtutil_xml(content)
                        # Filter to events matching this channel if log_name is embedded
                        filtered = [
                            ev for ev in parsed
                            if self._matches_channel(ev.get("channel"))
                        ]
                        if filtered:
                            events.extend(filtered)
                            os.remove(filepath)
                    except Exception as e:
                        self.logger.error(f"Error reading simulated event file {filepath}: {e}")
            except Exception as e:
                self.logger.error(f"Error accessing simulated events directory {sdir}: {e}")
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
            new_epoch = self.checkpoint_manager.advance_epoch(
                reset_record_id=0,
                transition_id=transition_id,
                transition_metadata=manifest,
                target_channel="Security",
            )
            self.current_checkpoint = 0
            self.current_epoch = new_epoch
            self.logger.info(
                f"Security epoch advanced via cross-channel transition {transition_id}: {old_epoch} -> {new_epoch}"
            )

            # 7. Acknowledge
            self.mailbox.acknowledge_transition(transition_id)

    def handle_event_104_system(self, event_data: Dict[str, Any]):
        """
        Producer side: Coordinates the 5-step durable publication sequence for System Event 104.
        """
        affected_channel = event_data.get("affected_channel") or "Security"
        record_id = event_data["record_id"]

        self.logger.info(
            f"Processing System Event 104 at record_id={record_id}, affected_channel='{affected_channel}'"
        )

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
            witness_payload = TransitionMailbox.build_witness_payload(
                affected_channel="Security",
                event_id=104,
                provider=event_data.get("provider", "Microsoft-Windows-Eventlog"),
                source_channel="System",
                subject_domain_name=event_data.get("subject_domain") or event_data.get("computer", "WORKSTATION-01"),
                subject_user_name=event_data.get("subject_user", "SYSTEM"),
                subject_user_sid=event_data.get("subject_user_sid", "S-1-5-18"),
            )
            witness_hash = TransitionMailbox.compute_witness_payload_hash(witness_payload)

            source_event_id = generate_source_event_id_v2(
                agent_id=self.agent_id,
                channel="System",
                epoch=self.current_epoch,
                hostname=event_data.get("computer", "WORKSTATION-01"),
                record_id=record_id,
            )

            identity_manifest = TransitionMailbox.build_transition_identity_manifest(
                agent_id=self.agent_id,
                source_channel="System",
                source_epoch=self.current_epoch,
                source_event_id=source_event_id,
                source_hostname=event_data.get("computer", "WORKSTATION-01"),
                source_record_id=record_id,
                target_channel="Security",
                transition_type="LOG_CLEARED_SECURITY_REMOTE",
                witness_event_id=104,
                witness_payload_hash=witness_hash,
                witness_provider=event_data.get("provider", "Microsoft-Windows-Eventlog"),
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
                new_epoch = self.checkpoint_manager.advance_epoch(
                    reset_record_id=0,
                    transition_id=local_tid,
                    transition_metadata=metadata,
                    target_channel="System",
                )
                self.current_checkpoint = 0
                self.current_epoch = new_epoch
                self.logger.info(f"System epoch advanced to {new_epoch} due to System self-clear")

        else:
            # Unrelated channel (e.g. Application): save checkpoint record_id without epoch mutation
            self.logger.info(
                f"Event 104 for unrelated channel '{affected_channel}' ignored; epoch unaffected."
            )
            self.checkpoint_manager.save_checkpoint(record_id, target_channel="System")
            self.current_checkpoint = record_id

    def collect_once(self) -> List[Dict[str, Any]]:
        """
        Performs a single batch retrieval of events newer than the checkpoint.
        Checks simulated event queue first, then queries live wevtutil.
        """
        # Apply any pending cross-channel transitions before ingesting new Security events
        if self.log_name == "Security":
            self.check_and_apply_pending_transitions()

        # 1. Check for simulated events
        sim_events = self._collect_simulated_events()
        events = sim_events

        # 2. Query live wevtutil if no simulated events
        if not events:
            if self.current_checkpoint == 0:
                query = "*[System[(EventRecordID > 0)]]"
            else:
                query = f"*[System[(EventRecordID > {self.current_checkpoint})]]"

            cmd = ["wevtutil", "qe", self.log_name, f"/q:{query}", f"/c:{self.batch_size}", "/f:xml"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
                xml_output = result.stdout.strip()
                if xml_output:
                    events = self._parse_wevtutil_xml(xml_output)
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                if not self._warned_permission:
                    self.logger.warning(
                        f"Live wevtutil query on '{self.log_name}' unavailable ({e}). "
                        "Running in waiting mode. Drop XML files into simulated_events for offline/lab simulation."
                    )
                    self._warned_permission = True
                return []
            except subprocess.TimeoutExpired as e:
                self.logger.error(f"Timeout querying {self.log_name}: {e}")
                raise RuntimeError(f"wevtutil timeout: {e}") from e

        if not events:
            return []

        # Intercept and validate events
        processed_events = []
        for ev in events:
            record_id = ev.get("record_id", 0)
            event_id = ev.get("event_id")

            # Check for unverified record ID drops
            if self.current_checkpoint > 0 and record_id < self.current_checkpoint:
                # Unless this event is specifically Event 1102 or Event 104, fail closed
                if event_id not in (1102, 104):
                    raise UnverifiedDiscontinuityError(
                        f"UNVERIFIED_CHANNEL_DISCONTINUITY: Record ID dropped from {self.current_checkpoint} to {record_id} "
                        f"without authoritative clear event in channel {self.log_name}"
                    )

            if self.log_name == "System" and event_id == 104:
                self.handle_event_104_system(ev)

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
        if self._pending_epoch_advance and last_successful_record_id >= self._pending_epoch_advance_rec_id:
            # Advance epoch after Event 1102 is fully committed downstream
            local_tid = self.checkpoint_manager.build_local_witness_id(
                self.log_name, self.current_epoch, self._pending_epoch_advance_rec_id, 1102
            )
            new_epoch = self.checkpoint_manager.advance_epoch(
                reset_record_id=0,
                transition_id=local_tid,
                transition_metadata=getattr(self, "_pending_local_witness", None),
                target_channel=self.log_name,
            )
            self.current_checkpoint = 0
            self.current_epoch = new_epoch
            self._pending_epoch_advance = False
            self._pending_local_witness = None
            self.logger.info(
                f"In-channel Event 1102 commit completed: {self.log_name} epoch advanced to {new_epoch}"
            )
        elif last_successful_record_id > self.current_checkpoint:
            self.checkpoint_manager.save_checkpoint(last_successful_record_id, target_channel=self.log_name)
            self.current_checkpoint = last_successful_record_id

    def shutdown(self):
        self.logger.info(f"Shutting down WindowsEventCollector for channel {self.log_name}.")

    @staticmethod
    def _parse_hashes(raw_hashes: Optional[str]) -> Dict[str, str]:
        """
        Parses Sysmon Hashes string into algorithm:hash dictionary.
        Handles comma or comma-space separated pairs like:
        'SHA1=...,MD5=...,SHA256=...,IMPHASH=...'
        """
        if not raw_hashes or not raw_hashes.strip() or raw_hashes.strip() == "-":
            return {}
        parsed = {}
        for token in raw_hashes.split(","):
            token = token.strip()
            if "=" in token:
                k, v = token.split("=", 1)
                k = k.strip().lower()
                v = v.strip()
                if k and v and v != "-":
                    parsed[k] = v
        return parsed

    def _parse_wevtutil_xml(self, xml_string: str) -> List[Dict[str, Any]]:
        """Parses multiple concatenated Event XML tags returned by wevtutil."""
        wrapped_xml = f"<Events>{xml_string}</Events>"
        parsed_events = []
        try:
            root = ET.fromstring(wrapped_xml)
            namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"

            for event in root.findall(f"{namespace}Event"):
                system = event.find(f"{namespace}System")
                if system is None:
                    continue

                event_data = {
                    "raw_xml": ET.tostring(event, encoding="unicode"),
                    "channel": self.log_name,
                }

                channel_elem = system.find(f"{namespace}Channel")
                if channel_elem is not None and channel_elem.text:
                    event_data["channel"] = channel_elem.text

                provider = system.find(f"{namespace}Provider")
                if provider is not None:
                    event_data["provider"] = provider.get("Name")

                event_id_elem = system.find(f"{namespace}EventID")
                if event_id_elem is not None and event_id_elem.text:
                    event_data["event_id"] = int(event_id_elem.text)

                record_id_elem = system.find(f"{namespace}EventRecordID")
                if record_id_elem is not None and record_id_elem.text:
                    event_data["record_id"] = int(record_id_elem.text)

                time_created_elem = system.find(f"{namespace}TimeCreated")
                if time_created_elem is not None:
                    event_data["timestamp"] = time_created_elem.get("SystemTime")

                computer_elem = system.find(f"{namespace}Computer")
                if computer_elem is not None:
                    event_data["computer"] = computer_elem.text

                level_elem = system.find(f"{namespace}Level")
                if level_elem is not None and level_elem.text:
                    event_data["level"] = int(level_elem.text)

                task_elem = system.find(f"{namespace}Task")
                if task_elem is not None and task_elem.text:
                    event_data["task"] = int(task_elem.text)

                keywords_elem = system.find(f"{namespace}Keywords")
                if keywords_elem is not None and keywords_elem.text:
                    event_data["keywords"] = keywords_elem.text

                # Parse EventData and UserData
                event_data_elem = event.find(f"{namespace}EventData")
                data_dict = {}
                if event_data_elem is not None:
                    for data_elem in event_data_elem.findall(f"{namespace}Data"):
                        name = data_elem.get("Name")
                        if name:
                            data_dict[name] = data_elem.text
                        elif data_elem.text and "Channel" not in data_dict:
                            # Positional Data in Event 104
                            data_dict["Channel"] = data_elem.text

                user_data_elem = event.find(f"{namespace}UserData")
                if user_data_elem is not None:
                    for child in user_data_elem:
                        for item in child:
                            tag_name = item.tag.split("}")[-1]
                            if tag_name and item.text:
                                data_dict[tag_name] = item.text

                # Event 104 specific channel extraction
                if event_data.get("event_id") == 104:
                    aff_chan = (
                        data_dict.get("Channel")
                        or data_dict.get("TargetChannel")
                        or data_dict.get("LogName")
                        or "Security"
                    )
                    event_data["affected_channel"] = aff_chan.strip()

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
                if subject_user:
                    event_data["subject_user"] = subject_user
                if subject_domain:
                    event_data["subject_domain"] = subject_domain
                if subject_user_sid:
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
            self.logger.error(f"XML parse error in event batch: {e}")

        return parsed_events
