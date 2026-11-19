"""
TransitionMailbox: Cross-Channel Log-Clear Transition Mailbox for TGAM-SOC
==========================================================================

Implements durable, crash-safe publication, claiming, verification, and
acknowledgment of cross-channel log-clear transition manifests across Windows Event channels.
Adheres strictly to the WP-1E Revision 16 + Final Addendum transition contract.
"""

import os
import json
import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from canonical import (
    canonicalize_tgam_rcc_v1,
    build_source_identity_manifest_v2,
    generate_source_event_id_v2,
    validate_epoch,
    validate_record_id,
    TGAMCanonicalizationError,
)


class TransitionVerificationError(Exception):
    """Raised when a transition manifest fails cryptographic or contract verification."""
    pass


class TransitionMailbox:
    """
    Manages filesystem-based transition envelopes in:
      <mailbox_dir>/pending/       (published by producer, awaiting claim)
      <mailbox_dir>/in_progress/   (claimed by consumer, awaiting atomic checkpoint commit)
      <mailbox_dir>/acknowledged/  (durable acknowledgment archive)
    """

    def __init__(self, mailbox_dir: str, logger: logging.Logger):
        self.mailbox_dir = mailbox_dir
        self.logger = logger
        self.pending_dir = os.path.join(mailbox_dir, "pending")
        self.in_progress_dir = os.path.join(mailbox_dir, "in_progress")
        self.acknowledged_dir = os.path.join(mailbox_dir, "acknowledged")
        self.quarantined_dir = os.path.join(mailbox_dir, "quarantined")

    def _ensure_dirs(self):
        try:
            os.makedirs(self.pending_dir, exist_ok=True)
            os.makedirs(self.in_progress_dir, exist_ok=True)
            os.makedirs(self.acknowledged_dir, exist_ok=True)
            os.makedirs(self.quarantined_dir, exist_ok=True)
        except OSError as e:
            self.logger.debug(f"Could not ensure mailbox dirs: {e}")

    @staticmethod
    def build_witness_payload(
        affected_channel: str,
        event_id: int,
        provider: str,
        source_channel: str,
        subject_domain_name: str,
        subject_user_name: str,
        subject_user_sid: str,
    ) -> Dict[str, Any]:
        """Builds the canonical Event 104 witness evidence payload dictionary."""
        return {
            "affected_channel": str(affected_channel).strip(),
            "event_id": int(event_id),
            "provider": str(provider).strip(),
            "source_channel": str(source_channel).strip(),
            "subject_domain_name": str(subject_domain_name).strip(),
            "subject_user_name": str(subject_user_name).strip(),
            "subject_user_sid": str(subject_user_sid).strip(),
        }

    @staticmethod
    def compute_witness_payload_hash(witness_payload: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 digest of canonicalized witness payload using TGAM-RCC-v1."""
        canon_bytes = canonicalize_tgam_rcc_v1(witness_payload)
        return hashlib.sha256(canon_bytes).hexdigest()

    @staticmethod
    def build_transition_identity_manifest(
        agent_id: str,
        source_channel: str,
        source_epoch: int,
        source_event_id: str,
        source_hostname: str,
        source_record_id: int,
        target_channel: str,
        transition_type: str,
        witness_event_id: int,
        witness_payload_hash: str,
        witness_provider: str,
    ) -> Dict[str, Any]:
        """Builds the immutable transition identity manifest (pre-hash object)."""
        valid_epoch = validate_epoch(source_epoch)
        valid_rec_id = validate_record_id(source_record_id)

        return {
            "agent_id": str(agent_id).strip(),
            "identity_type": "transition",
            "schema_version": "1.0",
            "source_channel": str(source_channel).strip(),
            "source_epoch": valid_epoch,
            "source_event_id": str(source_event_id).strip(),
            "source_hostname": str(source_hostname).strip(),
            "source_record_id": valid_rec_id,
            "target_channel": str(target_channel).strip(),
            "transition_type": str(transition_type).strip(),
            "witness_event_id": int(witness_event_id),
            "witness_payload_hash": str(witness_payload_hash).strip(),
            "witness_provider": str(witness_provider).strip(),
        }

    @staticmethod
    def compute_transition_id(identity_manifest: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 digest of canonicalized identity manifest using TGAM-RCC-v1."""
        canon_bytes = canonicalize_tgam_rcc_v1(identity_manifest)
        return hashlib.sha256(canon_bytes).hexdigest()

    @classmethod
    def build_transition_envelope(
        cls,
        identity_manifest: Dict[str, Any],
        witness_payload: Dict[str, Any],
        created_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Builds complete transport envelope embedding transition_id, identity_manifest, and witness_payload."""
        transition_id = cls.compute_transition_id(identity_manifest)
        ts = created_at or datetime.now(timezone.utc).isoformat()
        return {
            "transition_id": transition_id,
            "created_at": ts,
            "identity_manifest": identity_manifest,
            "witness_payload": witness_payload,
        }

    def publish_transition(self, envelope: Dict[str, Any]) -> str:
        """
        Durably publishes transition transport envelope to pending/ directory using atomic write + fsync.
        Returns the transition_id.
        """
        transition_id = envelope.get("transition_id")
        if not transition_id:
            transition_id = self.compute_transition_id(envelope["identity_manifest"])
            envelope["transition_id"] = transition_id

        target_file = os.path.join(self.pending_dir, f"{transition_id}.json")
        temp_file = f"{target_file}.tmp"

        self._ensure_dirs()
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(envelope, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_file, target_file)
            self.logger.info(f"Published transition envelope {transition_id} to {target_file}")
            return transition_id
        except Exception as e:
            self.logger.error(f"Failed to publish transition envelope {transition_id}: {e}")
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass
            raise

    def claim_pending_transitions(
        self, target_channel: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Atomically claims all pending transition envelopes matching target_channel.
        Moves them from pending/ to in_progress/ and returns sorted by (source_epoch, source_record_id).
        """
        self._ensure_dirs()
        claimed: List[Dict[str, Any]] = []

        # List files in pending
        try:
            files = sorted([f for f in os.listdir(self.pending_dir) if f.endswith(".json")])
        except OSError as e:
            self.logger.error(f"Failed to list pending transitions: {e}")
            return []

        for filename in files:
            src_path = os.path.join(self.pending_dir, filename)
            dst_path = os.path.join(self.in_progress_dir, filename)
            try:
                with open(src_path, "r", encoding="utf-8") as f:
                    envelope = json.load(f)

                manifest = envelope.get("identity_manifest", {})
                if target_channel and manifest.get("target_channel") != target_channel:
                    continue

                # Atomically move from pending to in_progress
                os.replace(src_path, dst_path)
                claimed.append(envelope)
            except Exception as e:
                self.logger.error(f"Failed to claim transition {filename}: {e}")

        # Also inspect in_progress for any transitions from prior crash recovery
        try:
            ip_files = sorted([f for f in os.listdir(self.in_progress_dir) if f.endswith(".json")])
            claimed_ids = {e.get("transition_id") for e in claimed}
            for filename in ip_files:
                ip_path = os.path.join(self.in_progress_dir, filename)
                try:
                    with open(ip_path, "r", encoding="utf-8") as f:
                        env = json.load(f)
                    tid = env.get("transition_id")
                    if tid and tid not in claimed_ids:
                        manifest = env.get("identity_manifest", {})
                        if not target_channel or manifest.get("target_channel") == target_channel:
                            claimed.append(env)
                            claimed_ids.add(tid)
                except Exception as e:
                    self.logger.error(f"Failed to read in-progress transition {filename}: {e}")
        except OSError as e:
            self.logger.error(f"Failed to check in-progress directory: {e}")

        # Sort by (source_epoch, source_record_id)
        claimed.sort(
            key=lambda e: (
                e.get("identity_manifest", {}).get("source_epoch", 0),
                e.get("identity_manifest", {}).get("source_record_id", 0),
            )
        )
        return claimed

    @classmethod
    def verify_transition(cls, envelope: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Executes four-step cryptographic and contract verification of a transition envelope:
        1. transition_id matches SHA-256 of canonicalized identity_manifest.
        2. witness_payload_hash matches SHA-256 of canonicalized witness_payload.
        3. witness_payload.affected_channel matches identity_manifest.target_channel.
        4. Reconstituted V2 source identity manifest SHA-256 matches identity_manifest.source_event_id.
        """
        try:
            tid = envelope.get("transition_id")
            manifest = envelope.get("identity_manifest")
            witness = envelope.get("witness_payload")

            if not tid or not manifest or not witness:
                return False, "Missing required envelope components (transition_id, identity_manifest, witness_payload)"

            # 1. Transition ID check
            expected_tid = cls.compute_transition_id(manifest)
            if tid != expected_tid:
                return False, f"transition_id mismatch: expected {expected_tid}, got {tid}"

            # 2. Witness payload hash check
            expected_w_hash = cls.compute_witness_payload_hash(witness)
            manifest_w_hash = manifest.get("witness_payload_hash")
            if manifest_w_hash != expected_w_hash:
                return False, f"witness_payload_hash mismatch: expected {expected_w_hash}, got {manifest_w_hash}"

            # 3. Affected channel vs Target channel check
            affected = witness.get("affected_channel")
            target = manifest.get("target_channel")
            if affected != target:
                return False, f"Channel mismatch: witness affected_channel '{affected}' != target_channel '{target}'"

            # 4. Reconstruct V2 source identity manifest and verify source_event_id
            reconstructed_source_manifest = build_source_identity_manifest_v2(
                agent_id=manifest["agent_id"],
                channel=manifest["source_channel"],
                epoch=manifest["source_epoch"],
                hostname=manifest["source_hostname"],
                record_id=manifest["source_record_id"],
            )
            expected_source_event_id = hashlib.sha256(
                canonicalize_tgam_rcc_v1(reconstructed_source_manifest)
            ).hexdigest()

            if manifest.get("source_event_id") != expected_source_event_id:
                return (
                    False,
                    f"source_event_id verification failed: expected {expected_source_event_id}, got {manifest.get('source_event_id')}",
                )

            return True, "Verification successful"

        except Exception as e:
            return False, f"Verification raised exception: {e}"

    def acknowledge_transition(self, transition_id: str):
        """
        Archives or removes an applied transition from in_progress/ after checkpoint commitment.
        """
        src = os.path.join(self.in_progress_dir, f"{transition_id}.json")
        dst = os.path.join(self.acknowledged_dir, f"{transition_id}.json")

        if os.path.exists(src):
            try:
                os.replace(src, dst)
                self.logger.debug(f"Acknowledged transition {transition_id}")
            except Exception as e:
                self.logger.error(f"Failed to move acknowledged transition {transition_id}: {e}")
                try:
                    os.remove(src)
                except OSError:
                    pass

    def quarantine_transition(self, transition_id: str, reason: str = ""):
        """
        Quarantines an invalid or conflicting transition envelope into quarantined/ directory.
        Removes it from in_progress/ or pending/ without acknowledging it as valid.
        """
        self._ensure_dirs()
        src = os.path.join(self.in_progress_dir, f"{transition_id}.json")
        if not os.path.exists(src):
            src = os.path.join(self.pending_dir, f"{transition_id}.json")

        dst = os.path.join(self.quarantined_dir, f"{transition_id}.json")

        if os.path.exists(src):
            try:
                os.replace(src, dst)
                self.logger.warning(f"Quarantined transition {transition_id}: {reason}")
            except Exception as e:
                self.logger.error(f"Failed to quarantine transition {transition_id}: {e}")
                try:
                    os.remove(src)
                except OSError:
                    pass
