import os
import tempfile
import shutil
import logging
import json
import pytest
from collectors.checkpoint import CheckpointManager
from collectors.mailbox import TransitionMailbox
from collectors.windows_event_collector import WindowsEventCollector, UnverifiedDiscontinuityError
from canonical import (
    canonicalize_tgam_rcc_v1,
    generate_source_event_id_v2,
    build_source_identity_manifest_v2,
)

logger = logging.getLogger("test_checkpoint_recovery")


@pytest.fixture
def test_env():
    temp_dir = tempfile.mkdtemp()
    checkpoint_dir = os.path.join(temp_dir, "checkpoints")
    data_dir = os.path.join(temp_dir, "data")
    outbox_db_path = os.path.join(temp_dir, "outbox.db")
    detection_dir = os.path.join(temp_dir, "detections")
    os.makedirs(checkpoint_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(detection_dir, exist_ok=True)

    from config.settings import config
    orig_chk = config._checkpoint_dir
    orig_data = config.data_dir
    orig_outbox = config._outbox_db_path
    orig_detection = config._detection_output_dir

    config.checkpoint_dir = checkpoint_dir
    config.data_dir = data_dir
    config.outbox_db_path = outbox_db_path
    config.detection_output_dir = detection_dir

    try:
        yield {
            "root": temp_dir,
            "checkpoint_dir": checkpoint_dir,
            "data_dir": data_dir,
            "outbox_db_path": outbox_db_path,
            "detection_dir": detection_dir,
        }
    finally:
        config._checkpoint_dir = orig_chk
        config.data_dir = orig_data
        config._outbox_db_path = orig_outbox
        config._detection_output_dir = orig_detection
        shutil.rmtree(temp_dir, ignore_errors=True)


class TestCheckpointRecoveryWP1E2:
    def test_security_in_channel_clear_event_1102(self, test_env):
        """
        Event 1102 in Security channel:
        - Normalized under Epoch 1.
        - After downstream commit, Security epoch advances (1 -> 2) and record ID resets to 0.
        - System channel remains in Epoch 1.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        sys_collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
        sys_collector.initialize()

        assert sec_collector.get_current_epoch() == 1
        assert sys_collector.get_current_epoch() == 1

        # Ingest normal event
        sec_collector.update_checkpoint(500)
        assert sec_collector.current_checkpoint == 500

        # Simulate Event 1102 XML
        raw_1102 = {
            "record_id": 501,
            "event_id": 1102,
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "computer": "WORKSTATION-01",
            "timestamp": "2026-11-10T12:00:00Z",
            "subject_user": "SYSTEM",
        }

        # Drop into simulation queue
        sim_file = os.path.join(sec_collector.simulated_events_channel_dir, "event_1102.xml")
        xml_content = f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>1102</EventID>
                <EventRecordID>501</EventRecordID>
                <Channel>Security</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-10T12:00:00Z"/>
            </System>
            <EventData>
                <Data Name="SubjectUserName">SYSTEM</Data>
            </EventData>
        </Event>"""
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_content)

        batch = sec_collector.collect_once()
        assert len(batch) == 1
        assert batch[0]["event_id"] == 1102
        assert batch[0]["record_id"] == 501
        # Before update_checkpoint, epoch is still 1
        assert sec_collector.get_current_epoch() == 1

        # Commit downstream processing of Event 1102
        sec_collector.update_checkpoint(501)
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.current_checkpoint == 0
        # System epoch remains 1
        assert sys_collector.get_current_epoch() == 1

    def test_system_cross_channel_clear_event_104_for_security(self, test_env):
        """
        Event 104 in System channel for Security:
        - System collector normalizes under System epoch 2.
        - System collector durably publishes transition manifest to mailbox.
        - System checkpoint advances to record_id 45020 under System epoch 2.
        - Security consumer claims manifest, verifies it, advances Security epoch to 2, resets record_id to 0.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        sys_collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
        sys_collector.initialize()
        # Set System to epoch 2
        sys_collector.checkpoint_manager.save_checkpoint(45019, epoch=2)
        sys_collector.current_checkpoint = 45019
        sys_collector.current_epoch = 2

        # Simulate System Event 104 clearing Security
        xml_104 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Eventlog"/>
                <EventID>104</EventID>
                <EventRecordID>45020</EventRecordID>
                <Channel>System</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-10T12:00:00Z"/>
            </System>
            <EventData>
                <Data Name="Channel">Security</Data>
                <Data Name="SubjectUserName">SYSTEM</Data>
                <Data Name="SubjectDomainName">WORKSTATION-01</Data>
                <Data Name="SubjectUserSid">S-1-5-18</Data>
            </EventData>
        </Event>"""
        sim_file = os.path.join(sys_collector.simulated_events_channel_dir, "event_104.xml")
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_104)

        sys_batch = sys_collector.collect_once()
        assert len(sys_batch) == 1
        assert sys_batch[0]["event_id"] == 104
        assert sys_batch[0]["affected_channel"] == "Security"

        # System checkpoint advanced record_id, epoch remains 2
        assert sys_collector.current_checkpoint == 45020
        assert sys_collector.get_current_epoch() == 2

        # Verify envelope exists in pending mailbox
        pending_files = os.listdir(sys_collector.mailbox.pending_dir)
        assert len(pending_files) == 1
        expected_tid = "374c2fd35d27e045cd646c0472cd7a3422161b6dc7812dc3d564a2404f40be44"
        assert pending_files[0] == f"{expected_tid}.json"

        # Security collector runs collect_once / check_and_apply_pending_transitions
        assert sec_collector.get_current_epoch() == 1
        sec_collector.check_and_apply_pending_transitions()

        # Security epoch must now be 2, record ID 0, and transition marked applied
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.current_checkpoint == 0
        assert sec_collector.checkpoint_manager.is_transition_applied(expected_tid)

        # Mailbox pending should now be empty; acknowledged should contain the envelope
        assert len(os.listdir(sec_collector.mailbox.pending_dir)) == 0
        assert os.path.exists(os.path.join(sec_collector.mailbox.acknowledged_dir, f"{expected_tid}.json"))

    def test_system_self_clear_event_104_for_system(self, test_env):
        """
        Event 104 with affected_channel == 'System':
        - System epoch advances (1 -> 2), record_id resets to 0.
        - Security epoch remains untouched.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        sys_collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
        sys_collector.initialize()

        sys_collector.update_checkpoint(100)
        assert sys_collector.current_checkpoint == 100

        xml_104_sys = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Eventlog"/>
                <EventID>104</EventID>
                <EventRecordID>101</EventRecordID>
                <Channel>System</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-10T12:00:00Z"/>
            </System>
            <EventData>
                <Data Name="Channel">System</Data>
                <Data Name="SubjectUserName">SYSTEM</Data>
            </EventData>
        </Event>"""
        sim_file = os.path.join(sys_collector.simulated_events_channel_dir, "event_104_sys.xml")
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_104_sys)

        sys_collector.collect_once()
        assert sys_collector.get_current_epoch() == 2
        assert sys_collector.current_checkpoint == 0
        assert sec_collector.get_current_epoch() == 1

    def test_unrelated_channel_clear_event_104_ignored(self, test_env):
        """
        Event 104 with affected_channel == 'Application':
        - Does not advance Security or System epoch.
        """
        sys_collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
        sys_collector.initialize()

        xml_104_app = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Eventlog"/>
                <EventID>104</EventID>
                <EventRecordID>200</EventRecordID>
                <Channel>System</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-10T12:00:00Z"/>
            </System>
            <EventData>
                <Data Name="Channel">Application</Data>
                <Data Name="SubjectUserName">SYSTEM</Data>
            </EventData>
        </Event>"""
        sim_file = os.path.join(sys_collector.simulated_events_channel_dir, "event_104_app.xml")
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_104_app)

        sys_collector.collect_once()
        assert sys_collector.get_current_epoch() == 1
        assert sys_collector.current_checkpoint == 200

    def test_verified_test_vectors_reconstitution(self):
        """
        Verifies exact test vector matching for witness payload hash,
        V2 source identity, and transition ID.
        """
        witness = TransitionMailbox.build_witness_payload(
            affected_channel="Security",
            event_id=104,
            provider="Microsoft-Windows-Eventlog",
            source_channel="System",
            subject_domain_name="WORKSTATION-01",
            subject_user_name="SYSTEM",
            subject_user_sid="S-1-5-18",
        )
        w_hash = TransitionMailbox.compute_witness_payload_hash(witness)
        assert w_hash == "52e591b636c98902c162e1982d84d38845ab47d78c63cf89d3dce1436e5f9935"

        source_event_id = generate_source_event_id_v2(
            agent_id="AGT-WIN-01",
            channel="System",
            epoch=2,
            hostname="WORKSTATION-01",
            record_id=45020,
        )
        assert source_event_id == "d40a7ee1bf8c5d8299f0ea1bb67a404ae7918e5232c2c8795d43f5dc44d94182"

        manifest = TransitionMailbox.build_transition_identity_manifest(
            agent_id="AGT-WIN-01",
            source_channel="System",
            source_epoch=2,
            source_event_id=source_event_id,
            source_hostname="WORKSTATION-01",
            source_record_id=45020,
            target_channel="Security",
            transition_type="LOG_CLEARED_SECURITY_REMOTE",
            witness_event_id=104,
            witness_payload_hash=w_hash,
            witness_provider="Microsoft-Windows-Eventlog",
        )
        t_id = TransitionMailbox.compute_transition_id(manifest)
        assert t_id == "374c2fd35d27e045cd646c0472cd7a3422161b6dc7812dc3d564a2404f40be44"

        envelope = TransitionMailbox.build_transition_envelope(manifest, witness)
        valid, msg = TransitionMailbox.verify_transition(envelope)
        assert valid, f"Verification failed: {msg}"

    def test_tampered_transition_manifest_rejections(self):
        """Verifies that any tampering with transition manifest or payload is rejected."""
        witness = TransitionMailbox.build_witness_payload(
            affected_channel="Security",
            event_id=104,
            provider="Microsoft-Windows-Eventlog",
            source_channel="System",
            subject_domain_name="WORKSTATION-01",
            subject_user_name="SYSTEM",
            subject_user_sid="S-1-5-18",
        )
        manifest = TransitionMailbox.build_transition_identity_manifest(
            agent_id="AGT-WIN-01",
            source_channel="System",
            source_epoch=2,
            source_event_id="d40a7ee1bf8c5d8299f0ea1bb67a404ae7918e5232c2c8795d43f5dc44d94182",
            source_hostname="WORKSTATION-01",
            source_record_id=45020,
            target_channel="Security",
            transition_type="LOG_CLEARED_SECURITY_REMOTE",
            witness_event_id=104,
            witness_payload_hash=TransitionMailbox.compute_witness_payload_hash(witness),
            witness_provider="Microsoft-Windows-Eventlog",
        )

        # 1. Tampered transition_id
        env_bad_id = TransitionMailbox.build_transition_envelope(manifest, witness)
        env_bad_id["transition_id"] = "bad" * 16
        valid, _ = TransitionMailbox.verify_transition(env_bad_id)
        assert not valid

        # 2. Tampered witness payload
        witness_tampered = dict(witness)
        witness_tampered["subject_user_name"] = "ATTACKER"
        env_bad_w = TransitionMailbox.build_transition_envelope(manifest, witness_tampered)
        valid, _ = TransitionMailbox.verify_transition(env_bad_w)
        assert not valid

        # 3. Channel mismatch (affected != target)
        witness_app = dict(witness)
        witness_app["affected_channel"] = "Application"
        env_bad_chan = TransitionMailbox.build_transition_envelope(manifest, witness_app)
        valid, _ = TransitionMailbox.verify_transition(env_bad_chan)
        assert not valid

        # 4. Tampered source hostname in manifest (fails V2 source ID reconstitution)
        manifest_tampered_host = dict(manifest)
        manifest_tampered_host["source_hostname"] = "ROGUE-PC"
        env_bad_host = TransitionMailbox.build_transition_envelope(manifest_tampered_host, witness)
        valid, _ = TransitionMailbox.verify_transition(env_bad_host)
        assert not valid

    def test_duplicate_transition_delivery_is_idempotent(self, test_env):
        """
        Replaying an identical transition twice must be an idempotent no-op.
        The epoch must advance exactly once.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        assert sec_collector.get_current_epoch() == 1

        t_id = "374c2fd35d27e045cd646c0472cd7a3422161b6dc7812dc3d564a2404f40be44"
        envelope = {
            "transition_id": t_id,
            "identity_manifest": {
                "agent_id": "AGT-WIN-01",
                "identity_type": "transition",
                "schema_version": "1.0",
                "source_channel": "System",
                "source_epoch": 2,
                "source_event_id": "d40a7ee1bf8c5d8299f0ea1bb67a404ae7918e5232c2c8795d43f5dc44d94182",
                "source_hostname": "WORKSTATION-01",
                "source_record_id": 45020,
                "target_channel": "Security",
                "transition_type": "LOG_CLEARED_SECURITY_REMOTE",
                "witness_event_id": 104,
                "witness_payload_hash": "52e591b636c98902c162e1982d84d38845ab47d78c63cf89d3dce1436e5f9935",
                "witness_provider": "Microsoft-Windows-Eventlog",
            },
            "witness_payload": {
                "affected_channel": "Security",
                "event_id": 104,
                "provider": "Microsoft-Windows-Eventlog",
                "source_channel": "System",
                "subject_domain_name": "WORKSTATION-01",
                "subject_user_name": "SYSTEM",
                "subject_user_sid": "S-1-5-18",
            },
        }

        # First delivery
        sec_collector.mailbox.publish_transition(envelope)
        sec_collector.check_and_apply_pending_transitions()
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.checkpoint_manager.is_transition_applied(t_id)

        # Second delivery (replay identical envelope)
        sec_collector.mailbox.publish_transition(envelope)
        sec_collector.check_and_apply_pending_transitions()
        # Epoch must still be 2 (NOT 3)
        assert sec_collector.get_current_epoch() == 2

    def test_unverified_discontinuity_fails_closed(self, test_env):
        """
        Record ID drops without an authoritative clear event:
        Raises UnverifiedDiscontinuityError (fails closed).
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        sec_collector.update_checkpoint(500)

        # Drop simulated event with record_id=50 (drop from 500) with event_id=4625 (NOT 1102)
        xml_drop = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>4625</EventID>
                <EventRecordID>50</EventRecordID>
                <Channel>Security</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-10T12:00:00Z"/>
            </System>
            <EventData>
                <Data Name="TargetUserName">Alice</Data>
            </EventData>
        </Event>"""
        sim_file = os.path.join(sec_collector.simulated_events_channel_dir, "event_drop.xml")
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_drop)

        with pytest.raises(UnverifiedDiscontinuityError, match="UNVERIFIED_CHANNEL_DISCONTINUITY"):
            sec_collector.collect_once()

    def test_crash_recovery_journal_intent_replay(self, test_env):
        """
        Crash recovery: in-flight producer journal with status='PUBLISHING'
        is automatically reconciled and re-published on collector initialization.
        """
        sys_collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")

        envelope = {
            "transition_id": "374c2fd35d27e045cd646c0472cd7a3422161b6dc7812dc3d564a2404f40be44",
            "identity_manifest": {
                "agent_id": "AGT-WIN-01",
                "identity_type": "transition",
                "schema_version": "1.0",
                "source_channel": "System",
                "source_epoch": 2,
                "source_event_id": "d40a7ee1bf8c5d8299f0ea1bb67a404ae7918e5232c2c8795d43f5dc44d94182",
                "source_hostname": "WORKSTATION-01",
                "source_record_id": 45020,
                "target_channel": "Security",
                "transition_type": "LOG_CLEARED_SECURITY_REMOTE",
                "witness_event_id": 104,
                "witness_payload_hash": "52e591b636c98902c162e1982d84d38845ab47d78c63cf89d3dce1436e5f9935",
                "witness_provider": "Microsoft-Windows-Eventlog",
            },
            "witness_payload": {
                "affected_channel": "Security",
                "event_id": 104,
                "provider": "Microsoft-Windows-Eventlog",
                "source_channel": "System",
                "subject_domain_name": "WORKSTATION-01",
                "subject_user_name": "SYSTEM",
                "subject_user_sid": "S-1-5-18",
            },
        }

        # Write simulated interrupted journal
        os.makedirs(sys_collector.journal_dir, exist_ok=True)
        with open(sys_collector.producer_journal_file, "w", encoding="utf-8") as f:
            json.dump({
                "status": "PUBLISHING",
                "record_id": 45020,
                "target_channel": "Security",
                "envelope": envelope,
            }, f)

        # Pending mailbox does not have it yet
        assert not os.path.exists(sys_collector.mailbox.pending_dir) or len(os.listdir(sys_collector.mailbox.pending_dir)) == 0

        # Initialize should reconcile and publish
        sys_collector.initialize()
        assert len(os.listdir(sys_collector.mailbox.pending_dir)) == 1

    def test_checkpoint_and_ledger_atomic_coordination(self, test_env):
        """
        Coordinates checkpoint advancement and applied-transitions ledger in a single atomic commit.
        """
        cm = CheckpointManager(test_env["checkpoint_dir"], "Security", logger)
        t_id = "test_trans_id_123"

        # Advance epoch with transition
        cm.advance_epoch(reset_record_id=0, transition_id=t_id, transition_metadata={"note": "test"})

        # Read raw json to ensure both epoch and applied_transitions are present in the exact same file
        with open(cm.checkpoint_file, "r", encoding="utf-8") as f:
            state = json.load(f)

        assert state["epoch"] == 2
        assert state["last_record_id"] == 0
        assert t_id in state["applied_transitions"]
        assert state["applied_transitions"][t_id]["applied_in_target_epoch"] == 2

    def test_crash_recovery_at_claim_boundary_in_progress(self, test_env):
        """
        Scenario 5: Crash after transition is claimed into in_progress/ but before checkpoint commit.
        On restart/recovery, the in-progress envelope is re-read, verified, and applied.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        assert sec_collector.get_current_epoch() == 1

        t_id = "374c2fd35d27e045cd646c0472cd7a3422161b6dc7812dc3d564a2404f40be44"
        envelope = {
            "transition_id": t_id,
            "identity_manifest": {
                "agent_id": "AGT-WIN-01",
                "identity_type": "transition",
                "schema_version": "1.0",
                "source_channel": "System",
                "source_epoch": 2,
                "source_event_id": "d40a7ee1bf8c5d8299f0ea1bb67a404ae7918e5232c2c8795d43f5dc44d94182",
                "source_hostname": "WORKSTATION-01",
                "source_record_id": 45020,
                "target_channel": "Security",
                "transition_type": "LOG_CLEARED_SECURITY_REMOTE",
                "witness_event_id": 104,
                "witness_payload_hash": "52e591b636c98902c162e1982d84d38845ab47d78c63cf89d3dce1436e5f9935",
                "witness_provider": "Microsoft-Windows-Eventlog",
            },
            "witness_payload": {
                "affected_channel": "Security",
                "event_id": 104,
                "provider": "Microsoft-Windows-Eventlog",
                "source_channel": "System",
                "subject_domain_name": "WORKSTATION-01",
                "subject_user_name": "SYSTEM",
                "subject_user_sid": "S-1-5-18",
            },
        }

        # Simulate crash halfway: envelope is already in in_progress/ directory
        sec_collector.mailbox._ensure_dirs()
        in_prog_file = os.path.join(sec_collector.mailbox.in_progress_dir, f"{t_id}.json")
        with open(in_prog_file, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)

        # On restart / recovery pass:
        sec_collector.check_and_apply_pending_transitions()
        # Epoch must have safely advanced from 1 to 2
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.checkpoint_manager.is_transition_applied(t_id)
        # Envelope must now be archived in acknowledged/ and removed from in_progress/
        assert not os.path.exists(in_prog_file)
        assert os.path.exists(os.path.join(sec_collector.mailbox.acknowledged_dir, f"{t_id}.json"))

    def test_crash_recovery_after_checkpoint_commit_before_ack(self, test_env):
        """
        Scenario 6: Crash after checkpoint advancement commits atomically with transition marker,
        but before the mailbox envelope is moved to acknowledged/.
        On restart, the collector detects transition is already applied, archives it, and does not re-advance.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()

        t_id = "374c2fd35d27e045cd646c0472cd7a3422161b6dc7812dc3d564a2404f40be44"
        envelope = {
            "transition_id": t_id,
            "identity_manifest": {
                "agent_id": "AGT-WIN-01",
                "identity_type": "transition",
                "schema_version": "1.0",
                "source_channel": "System",
                "source_epoch": 2,
                "source_event_id": "d40a7ee1bf8c5d8299f0ea1bb67a404ae7918e5232c2c8795d43f5dc44d94182",
                "source_hostname": "WORKSTATION-01",
                "source_record_id": 45020,
                "target_channel": "Security",
                "transition_type": "LOG_CLEARED_SECURITY_REMOTE",
                "witness_event_id": 104,
                "witness_payload_hash": "52e591b636c98902c162e1982d84d38845ab47d78c63cf89d3dce1436e5f9935",
                "witness_provider": "Microsoft-Windows-Eventlog",
            },
            "witness_payload": {
                "affected_channel": "Security",
                "event_id": 104,
                "provider": "Microsoft-Windows-Eventlog",
                "source_channel": "System",
                "subject_domain_name": "WORKSTATION-01",
                "subject_user_name": "SYSTEM",
                "subject_user_sid": "S-1-5-18",
            },
        }

        # Step 1: Advance epoch with transition ID committed
        sec_collector.checkpoint_manager.advance_epoch(reset_record_id=0, transition_id=t_id, target_channel="Security")
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.checkpoint_manager.is_transition_applied(t_id)

        # Step 2: Simulate crash state where envelope remained in in_progress/
        sec_collector.mailbox._ensure_dirs()
        in_prog_file = os.path.join(sec_collector.mailbox.in_progress_dir, f"{t_id}.json")
        with open(in_prog_file, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)

        # Step 3: Run check_and_apply_pending_transitions on recovery
        sec_collector.check_and_apply_pending_transitions()

        # Epoch must remain 2 (NO duplicate epoch advance)
        assert sec_collector.get_current_epoch() == 2
        # File should be safely moved to acknowledged/
        assert not os.path.exists(in_prog_file)
        assert os.path.exists(os.path.join(sec_collector.mailbox.acknowledged_dir, f"{t_id}.json"))

    def test_out_of_order_transition_delivery(self, test_env):
        """
        Scenario 8: Out-of-order transition delivery.
        1. Envelopes in mailbox are claimed and ordered strictly by (source_epoch, source_record_id).
        2. If a delayed transition from an earlier source epoch arrives after a newer epoch transition
           has already advanced the channel, the older transition is rejected as retired.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        assert sec_collector.get_current_epoch() == 1

        # Build Envelope 1 (epoch 2, record 100)
        w1 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid1 = generate_source_event_id_v2("AGT-WIN-01", "System", 2, "WORKSTATION-01", 100)
        m1 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 2, sid1, "WORKSTATION-01", 100, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w1), "Microsoft-Windows-Eventlog"
        )
        env1 = TransitionMailbox.build_transition_envelope(m1, w1)

        # Build Envelope 2 (epoch 3, record 200)
        w2 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid2 = generate_source_event_id_v2("AGT-WIN-01", "System", 3, "WORKSTATION-01", 200)
        m2 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 3, sid2, "WORKSTATION-01", 200, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w2), "Microsoft-Windows-Eventlog"
        )
        env2 = TransitionMailbox.build_transition_envelope(m2, w2)

        # Publish out of order: Envelope 2 first, Envelope 1 second
        sec_collector.mailbox.publish_transition(env2)
        sec_collector.mailbox.publish_transition(env1)

        # Claiming pending transitions must return them in ascending (source_epoch, source_record_id) order
        claimed = sec_collector.mailbox.claim_pending_transitions(target_channel="Security")
        assert len(claimed) == 2
        assert claimed[0]["identity_manifest"]["source_epoch"] == 2
        assert claimed[1]["identity_manifest"]["source_epoch"] == 3

        # Apply claimed transitions
        sec_collector.check_and_apply_pending_transitions()
        assert sec_collector.get_current_epoch() == 3

        # Demonstrate late older transition arriving in subsequent batch:
        # Build Envelope 0 (epoch 1, record 50)
        w0 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid0 = generate_source_event_id_v2("AGT-WIN-01", "System", 1, "WORKSTATION-01", 50)
        m0 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 1, sid0, "WORKSTATION-01", 50, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w0), "Microsoft-Windows-Eventlog"
        )
        env0 = TransitionMailbox.build_transition_envelope(m0, w0)

        sec_collector.mailbox.publish_transition(env0)
        sec_collector.check_and_apply_pending_transitions()

        # Security epoch must remain 3 (superseded transition does not advance target epoch)
        assert sec_collector.get_current_epoch() == 3
        assert os.path.exists(os.path.join(sec_collector.mailbox.acknowledged_dir, f"{env0['transition_id']}.json"))

    def test_retired_transition_rejection_after_ledger_compaction(self, test_env):
        """
        Scenario 10: Delayed retired-transition rejection after ledger compaction.
        A transition whose entry was pruned from applied_transitions is rejected
        by the compaction watermark and does not trigger duplicate epoch advancement.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        assert sec_collector.get_current_epoch() == 1

        w = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid = generate_source_event_id_v2("AGT-WIN-01", "System", 2, "WORKSTATION-01", 45020)
        m = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 2, sid, "WORKSTATION-01", 45020, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w), "Microsoft-Windows-Eventlog"
        )
        env = TransitionMailbox.build_transition_envelope(m, w)
        t_id = env["transition_id"]

        # Step 1: Apply transition to advance to epoch 2
        sec_collector.mailbox.publish_transition(env)
        sec_collector.check_and_apply_pending_transitions()
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.checkpoint_manager.is_transition_applied(t_id)

        # Step 2: Advance epoch to 3 (simulating normal system progression)
        sec_collector.checkpoint_manager.advance_epoch(reset_record_id=0, target_channel="Security")
        assert sec_collector.get_current_epoch() == 3

        # Step 3: Compact ledger up to epoch 2
        pruned = sec_collector.checkpoint_manager.compact_ledger(
            source_agent_id="AGT-WIN-01", source_channel="System", prune_source_epoch_threshold=2
        )
        assert pruned == 1
        assert not sec_collector.checkpoint_manager.is_transition_applied(t_id)

        # Verify watermark
        state = sec_collector.checkpoint_manager.load_state()
        assert state["watermark"]["pruned_source_epochs"]["AGT-WIN-01:System"] == 2

        # Step 4: Replay the retired envelope from epoch 2
        sec_collector.mailbox.publish_transition(env)
        assert sec_collector.checkpoint_manager.is_transition_retired("System", 2, t_id, source_agent_id="AGT-WIN-01")
        sec_collector.check_and_apply_pending_transitions()

        # Security epoch must remain 3 (NOT advance to 4)
        assert sec_collector.get_current_epoch() == 3

    def test_local_witness_event_1102_replay_protection_on_restart(self, test_env):
        """
        Gap 1: Event 1102 replay protection across process restarts.
        After advancing epoch and resetting checkpoint to 0, restarting the collector
        and re-reading Event 1102 must NOT trigger a second epoch advance.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        assert sec_collector.get_current_epoch() == 1

        # Simulate Event 1102 at record 501
        xml_1102 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>1102</EventID>
                <EventRecordID>501</EventRecordID>
                <Channel>Security</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-10T12:00:00Z"/>
            </System>
            <EventData><Data Name="SubjectUserName">SYSTEM</Data></EventData>
        </Event>"""
        sim_file = os.path.join(sec_collector.simulated_events_channel_dir, "event_1102.xml")
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_1102)

        batch = sec_collector.collect_once()
        assert len(batch) == 1
        assert batch[0]["event_id"] == 1102

        # Commit downstream: epoch advances to 2, checkpoint resets to 0
        sec_collector.update_checkpoint(501)
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.current_checkpoint == 0
        assert sec_collector.checkpoint_manager.is_local_witness_applied("Security", 501, 1102)

        # SIMULATE PROCESS RESTART: Create a brand new collector instance
        restarted_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        restarted_collector.initialize()
        assert restarted_collector.get_current_epoch() == 2
        assert restarted_collector.current_checkpoint == 0

        # Feed the exact same Event 1102 at record 501 again
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_1102)

        # collect_once should detect local witness was already applied and not set pending epoch advance
        restarted_batch = restarted_collector.collect_once()
        assert len(restarted_batch) == 1
        assert not restarted_collector._pending_epoch_advance

        # Even if update_checkpoint is called, epoch remains 2 (does NOT advance to 3)
        restarted_collector.update_checkpoint(501)
        assert restarted_collector.get_current_epoch() == 2

    def test_local_witness_event_104_system_replay_protection_on_restart(self, test_env):
        """
        Gap 1: System self-clear Event 104 replay protection across process restarts.
        After advancing System epoch and resetting checkpoint to 0, restarting and re-reading
        Event 104 must NOT advance the System epoch again.
        """
        sys_collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
        sys_collector.initialize()
        assert sys_collector.get_current_epoch() == 1

        xml_104 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Eventlog"/>
                <EventID>104</EventID>
                <EventRecordID>101</EventRecordID>
                <Channel>System</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-10T12:00:00Z"/>
            </System>
            <EventData>
                <Data Name="Channel">System</Data>
                <Data Name="SubjectUserName">SYSTEM</Data>
            </EventData>
        </Event>"""
        sim_file = os.path.join(sys_collector.simulated_events_channel_dir, "event_104_sys.xml")
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_104)

        sys_collector.collect_once()
        assert sys_collector.get_current_epoch() == 2
        assert sys_collector.current_checkpoint == 0
        assert sys_collector.checkpoint_manager.is_local_witness_applied("System", 101, 104)

        # SIMULATE PROCESS RESTART
        restarted_sys = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
        restarted_sys.initialize()
        assert restarted_sys.get_current_epoch() == 2
        assert restarted_sys.current_checkpoint == 0

        # Feed the exact same Event 104 again
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_104)

        restarted_sys.collect_once()
        # Epoch must remain 2 (does NOT advance to 3)
        assert restarted_sys.get_current_epoch() == 2

    def test_event_1102_outbox_failure_boundary_does_not_advance_checkpoint(self, test_env):
        """
        Gap 3: Outbox failure injection during Event 1102 processing.
        When outbox.add_event() raises an exception while processing Event 1102,
        the batch halts immediately, update_checkpoint is not called, and the
        checkpoint and Security epoch do NOT advance prematurely.
        """
        from pipeline import WindowsDetectionPipeline
        from unittest.mock import patch

        pipeline = WindowsDetectionPipeline(logger)
        sec_collector = pipeline.collector
        sec_collector.initialize()
        sec_collector.checkpoint_manager.save_checkpoint(500)
        sec_collector.current_checkpoint = 500
        assert sec_collector.get_current_epoch() == 1
        assert sec_collector.current_checkpoint == 500

        xml_1102 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>1102</EventID>
                <EventRecordID>501</EventRecordID>
                <Channel>Security</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-10T12:00:00Z"/>
            </System>
            <EventData><Data Name="SubjectUserName">SYSTEM</Data></EventData>
        </Event>"""
        sim_file = os.path.join(sec_collector.simulated_events_channel_dir, "event_1102_fail.xml")
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_1102)

        from detection.rules import DetectionResult

        mock_detection = DetectionResult(
            detected=True,
            detection_type="windows_log_cleared",
            confidence=1.0,
            severity="critical",
            detector_name="log_clear_rule",
            source_event_id="501",
            evidence={"action": "Security Log Cleared"},
        )

        # Inject failure into outbox.add_event while processing Event 1102 detection
        with patch.object(pipeline.engine, "process_event", return_value=[mock_detection]):
            with patch.object(pipeline.outbox, "add_event", side_effect=IOError("Simulated outbox disk failure")):
                pipeline.process_batch()

        # Checkpoint and epoch must NOT have advanced
        assert sec_collector.get_current_epoch() == 1
        assert sec_collector.current_checkpoint == 500
        assert not sec_collector.checkpoint_manager.is_local_witness_applied("Security", 501, 1102)

        # Now simulate recovery / next batch where outbox succeeds
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_1102)

        with patch.object(pipeline.engine, "process_event", return_value=[mock_detection]):
            pipeline.process_batch()
        # Now processing succeeds: epoch advances to 2, checkpoint resets to 0
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.current_checkpoint == 0
        assert sec_collector.checkpoint_manager.is_local_witness_applied("Security", 501, 1102)

    def test_system_epoch_1_to_security_epoch_4_accepted(self, test_env):
        """
        Required Test 1: System epoch 1 to Security epoch 4: valid transition is accepted.
        Verifies that a valid System-to-Security transition is NOT discarded when
        System epoch is numerically lower than Security epoch.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        sys_collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
        sys_collector.initialize()

        # Set Security to Epoch 4, checkpoint 1000
        sec_collector.checkpoint_manager.save_checkpoint(1000, epoch=4)
        sec_collector.current_checkpoint = 1000
        sec_collector.current_epoch = 4
        assert sec_collector.get_current_epoch() == 4

        # System is at Epoch 1
        assert sys_collector.get_current_epoch() == 1

        # System records Event 104 clearing Security at System record 45020 under System epoch 1
        w = TransitionMailbox.build_witness_payload(
            affected_channel="Security",
            event_id=104,
            provider="Microsoft-Windows-Eventlog",
            source_channel="System",
            subject_domain_name="WORKSTATION-01",
            subject_user_name="SYSTEM",
            subject_user_sid="S-1-5-18",
        )
        sid = generate_source_event_id_v2("AGT-WIN-01", "System", 1, "WORKSTATION-01", 45020)
        m = TransitionMailbox.build_transition_identity_manifest(
            agent_id="AGT-WIN-01",
            source_channel="System",
            source_epoch=1,
            source_event_id=sid,
            source_hostname="WORKSTATION-01",
            source_record_id=45020,
            target_channel="Security",
            transition_type="LOG_CLEARED_SECURITY_REMOTE",
            witness_event_id=104,
            witness_payload_hash=TransitionMailbox.compute_witness_payload_hash(w),
            witness_provider="Microsoft-Windows-Eventlog",
        )
        env = TransitionMailbox.build_transition_envelope(m, w)
        tid = env["transition_id"]

        sec_collector.mailbox.publish_transition(env)

        # Security claims and processes pending transition
        sec_collector.check_and_apply_pending_transitions()

        # Security epoch must advance from 4 to 5, reset checkpoint to 0
        assert sec_collector.get_current_epoch() == 5
        assert sec_collector.current_checkpoint == 0
        assert sec_collector.checkpoint_manager.is_transition_applied(tid)

    def test_retired_system_transition_rejected_after_compaction_and_restart(self, test_env):
        """
        Required Test 2: Retired System transition is rejected after compaction and restart.
        Ensures genuinely retired System transitions remain rejected even after the
        original applied_transitions entry has been pruned from disk.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()

        w = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid = generate_source_event_id_v2("AGT-WIN-01", "System", 1, "WORKSTATION-01", 100)
        m = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 1, sid, "WORKSTATION-01", 100, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w), "Microsoft-Windows-Eventlog"
        )
        env = TransitionMailbox.build_transition_envelope(m, w)
        tid = env["transition_id"]

        # Apply transition: advances Security 1 -> 2
        sec_collector.mailbox.publish_transition(env)
        sec_collector.check_and_apply_pending_transitions()
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.checkpoint_manager.is_transition_applied(tid)

        # Compact ledger for System source channel up to source epoch 1
        pruned = sec_collector.checkpoint_manager.compact_ledger(
            source_agent_id="AGT-WIN-01", source_channel="System", prune_source_epoch_threshold=1
        )
        assert pruned == 1
        assert not sec_collector.checkpoint_manager.is_transition_applied(tid)

        # Restart Security collector
        restarted_sec = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        restarted_sec.initialize()
        assert restarted_sec.get_current_epoch() == 2

        # Replay the retired envelope from System epoch 1
        restarted_sec.mailbox.publish_transition(env)
        assert restarted_sec.checkpoint_manager.is_transition_retired("System", 1, tid, source_agent_id="AGT-WIN-01")

        # Check and apply should reject and acknowledge without advancing epoch
        restarted_sec.check_and_apply_pending_transitions()
        assert restarted_sec.get_current_epoch() == 2

    def test_security_local_witness_replay_rejected_in_original_epoch_boundary(self, test_env):
        """
        Required Test 3: Security local witness replay is rejected in its original epoch boundary.
        Event 1102 at record 501 transitions epoch 1 -> 2. Re-ingesting record 501 in epoch 2
        is detected as a replay of the transition edge (from_epoch=1, to_epoch=2) and rejected.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        assert sec_collector.get_current_epoch() == 1

        xml_1102 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>1102</EventID>
                <EventRecordID>501</EventRecordID>
                <Channel>Security</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-10T12:00:00Z"/>
            </System>
            <EventData><Data Name="SubjectUserName">SYSTEM</Data></EventData>
        </Event>"""
        sim_file = os.path.join(sec_collector.simulated_events_channel_dir, "event_1102.xml")
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_1102)

        sec_collector.collect_once()
        sec_collector.update_checkpoint(501)
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.current_checkpoint == 0

        # Restart collector
        restarted = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        restarted.initialize()
        assert restarted.get_current_epoch() == 2

        # Re-read the exact same Event 1102 at record 501
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_1102)

        restarted.collect_once()
        assert not restarted._pending_epoch_advance
        restarted.update_checkpoint(501)
        assert restarted.get_current_epoch() == 2

    def test_genuine_later_security_clear_reusing_record_id_accepted(self, test_env):
        """
        Required Test 4: A genuine later Security clear reusing the same record ID is accepted.
        Verifies that an old witness from epoch 1 (record 501) does NOT suppress a genuine
        new clear event in epoch 3 that happens to reuse record ID 501.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()

        # Step 1: Clear in Epoch 1 at record 501 -> advances to Epoch 2
        sec_collector.collect_once()
        sec_collector._pending_epoch_advance = True
        sec_collector._pending_epoch_advance_rec_id = 501
        sec_collector._pending_local_witness = {
            "is_local_witness": True,
            "source_channel": "Security",
            "from_epoch": 1,
            "source_record_id": 501,
            "witness_event_id": 1102,
        }
        sec_collector.update_checkpoint(501)
        assert sec_collector.get_current_epoch() == 2

        # Step 2: Normal operation in Epoch 2, then clear at record 800 -> advances to Epoch 3
        sec_collector._pending_epoch_advance = True
        sec_collector._pending_epoch_advance_rec_id = 800
        sec_collector._pending_local_witness = {
            "is_local_witness": True,
            "source_channel": "Security",
            "from_epoch": 2,
            "source_record_id": 800,
            "witness_event_id": 1102,
        }
        sec_collector.update_checkpoint(800)
        assert sec_collector.get_current_epoch() == 3

        # Step 3: In Epoch 3, a genuine new clear occurs at record 501 (reused record ID)
        assert not sec_collector.checkpoint_manager.is_local_witness_replay("Security", 501, 1102)

        xml_1102 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>1102</EventID>
                <EventRecordID>501</EventRecordID>
                <Channel>Security</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-11T12:00:00Z"/>
            </System>
            <EventData><Data Name="SubjectUserName">SYSTEM</Data></EventData>
        </Event>"""
        sim_file = os.path.join(sec_collector.simulated_events_channel_dir, "event_1102_reuse.xml")
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_1102)

        sec_collector.collect_once()
        assert sec_collector._pending_epoch_advance
        assert sec_collector._pending_epoch_advance_rec_id == 501

        # Commit downstream: must advance from 3 to 4!
        sec_collector.update_checkpoint(501)
        assert sec_collector.get_current_epoch() == 4
        assert sec_collector.current_checkpoint == 0

    def test_system_event_104_replay_and_reuse(self, test_env):
        """
        Required Test 5: Equivalent replay and reuse tests for System Event 104.
        1. Event 104 at record 101 advances System epoch 1 -> 2.
        2. On restart, re-ingesting record 101 is detected as replay and rejected.
        3. System advances to epoch 3.
        4. In epoch 3, a genuine clear reusing record ID 101 is accepted (advances 3 -> 4).
        """
        sys_collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
        sys_collector.initialize()
        assert sys_collector.get_current_epoch() == 1

        xml_104 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Eventlog"/>
                <EventID>104</EventID>
                <EventRecordID>101</EventRecordID>
                <Channel>System</Channel>
                <Computer>WORKSTATION-01</Computer>
                <TimeCreated SystemTime="2026-11-10T12:00:00Z"/>
            </System>
            <EventData><Data Name="Channel">System</Data><Data Name="SubjectUserName">SYSTEM</Data></EventData>
        </Event>"""
        sim_file = os.path.join(sys_collector.simulated_events_channel_dir, "event_104_sys.xml")
        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_104)

        # Ingestion 1: advances 1 -> 2
        sys_collector.collect_once()
        assert sys_collector.get_current_epoch() == 2
        assert sys_collector.current_checkpoint == 0

        # Restart: replay check ignores duplicate
        restarted_sys = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
        restarted_sys.initialize()
        assert restarted_sys.get_current_epoch() == 2

        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_104)

        restarted_sys.collect_once()
        assert restarted_sys.get_current_epoch() == 2

        # Advance System to Epoch 3 via normal clear
        restarted_sys.checkpoint_manager.advance_epoch(reset_record_id=0, target_channel="System")
        assert restarted_sys.get_current_epoch() == 3

        # In Epoch 3, new Event 104 arrives reusing record ID 101
        assert not restarted_sys.checkpoint_manager.is_local_witness_replay("System", 101, 104)

        with open(sim_file, "w", encoding="utf-8") as f:
            f.write(xml_104)

        restarted_sys.collect_once()
        # Must advance 3 -> 4!
        assert restarted_sys.get_current_epoch() == 4

    def test_pending_and_unacknowledged_transitions_survive_compaction(self, test_env):
        """
        Required Test 6: Pending and unacknowledged transitions survive compaction.
        Compaction strictly operates on applied_transitions inside checkpoint.json;
        pending and in_progress mailbox envelopes are never purged.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()

        w = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid = generate_source_event_id_v2("AGT-WIN-01", "System", 1, "WORKSTATION-01", 100)
        m = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 1, sid, "WORKSTATION-01", 100, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w), "Microsoft-Windows-Eventlog"
        )
        env = TransitionMailbox.build_transition_envelope(m, w)
        tid = env["transition_id"]

        # Publish to pending
        sec_collector.mailbox.publish_transition(env)
        pending_path = os.path.join(sec_collector.mailbox.pending_dir, f"{tid}.json")
        assert os.path.exists(pending_path)

        # Run compaction on checkpoint
        sec_collector.checkpoint_manager.compact_ledger(
            source_agent_id="AGT-WIN-01", source_channel="System", prune_source_epoch_threshold=10
        )

        # Pending envelope MUST survive!
        assert os.path.exists(pending_path)

        # Move to in_progress (simulate claimed but unacknowledged)
        claimed = sec_collector.mailbox.claim_pending_transitions(target_channel="Security")
        assert len(claimed) == 1
        in_prog_path = os.path.join(sec_collector.mailbox.in_progress_dir, f"{tid}.json")
        assert os.path.exists(in_prog_path)

        # Run compaction again
        sec_collector.checkpoint_manager.compact_ledger(
            source_agent_id="AGT-WIN-01", source_channel="System", prune_source_epoch_threshold=10
        )

        # In-progress envelope MUST survive!
        assert os.path.exists(in_prog_path)

    def test_no_cross_channel_epoch_comparison_in_retirement_logic(self, test_env):
        """
        Required Test 7: No cross-channel epoch comparison occurs in retirement logic.
        Validates that is_transition_retired evaluates purely against source-channel
        scoped watermarks, completely independent of the target checkpoint's epoch.
        """
        cm = CheckpointManager(test_env["checkpoint_dir"], "Security", logger)

        # Manually set Security target epoch to 100
        cm.save_checkpoint(0, epoch=100)
        assert cm.get_current_epoch() == 100

        # System source epoch = 1 is NOT retired simply because 1 < 100!
        assert not cm.is_transition_retired(source_channel="System", source_epoch=1, source_agent_id="AGT-WIN-01")

        # Set Security target epoch to 10
        cm.save_checkpoint(0, epoch=10)
        assert cm.get_current_epoch() == 10

        # System source epoch = 50 is NOT retired simply because 50 > 10!
        assert not cm.is_transition_retired(source_channel="System", source_epoch=50, source_agent_id="AGT-WIN-01")

        # Now set an explicit source watermark for System at 50
        cm.compact_ledger(source_agent_id="AGT-WIN-01", source_channel="System", prune_source_epoch_threshold=50)

        # Exactly 50 is retired
        assert cm.is_transition_retired(source_channel="System", source_epoch=50, source_agent_id="AGT-WIN-01")
        # 49 is retired
        assert cm.is_transition_retired(source_channel="System", source_epoch=49, source_agent_id="AGT-WIN-01")
        # 51 is NOT retired
        assert not cm.is_transition_retired(source_channel="System", source_epoch=51, source_agent_id="AGT-WIN-01")

        # Unrelated channel (e.g. Application) has independent watermark (defaults to 0)
        assert not cm.is_transition_retired(source_channel="Application", source_epoch=50, source_agent_id="AGT-WIN-01")

    def test_forged_envelope_with_invalid_hash_never_acknowledged_as_retired(self, test_env):
        """
        Defect 1 Test: Submit a forged envelope with an invalid witness hash and an old source epoch.
        Confirm it is quarantined/rejected and NEVER acknowledged as a valid retired transition.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()

        # Compact ledger up to System epoch 2 so that epoch 1 would be considered retired if valid
        sec_collector.checkpoint_manager.compact_ledger(
            source_channel="System", prune_source_epoch_threshold=2, source_agent_id="AGT-WIN-01"
        )
        assert sec_collector.checkpoint_manager.is_transition_retired(
            source_channel="System", source_epoch=1, source_agent_id="AGT-WIN-01"
        )

        # Create a forged envelope with an invalid witness payload hash
        w = TransitionMailbox.build_witness_payload(
            "Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18"
        )
        sid = generate_source_event_id_v2("AGT-WIN-01", "System", 1, "WORKSTATION-01", 100)
        m = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 1, sid, "WORKSTATION-01", 100, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, "0000000000000000000000000000000000000000000000000000000000000000",
            "Microsoft-Windows-Eventlog"
        )
        forged_env = TransitionMailbox.build_transition_envelope(m, w)
        t_id = forged_env["transition_id"]

        sec_collector.mailbox.publish_transition(forged_env)
        sec_collector.check_and_apply_pending_transitions()

        # The forged envelope must NEVER be in acknowledged/
        ack_file = os.path.join(sec_collector.mailbox.acknowledged_dir, f"{t_id}.json")
        assert not os.path.exists(ack_file), "Forged envelope was erroneously acknowledged!"

        # The forged envelope MUST be in quarantined/
        quar_file = os.path.join(sec_collector.mailbox.quarantined_dir, f"{t_id}.json")
        assert os.path.exists(quar_file), "Forged envelope was not quarantined!"

        # Security epoch must remain 1
        assert sec_collector.get_current_epoch() == 1

    def test_source_agent_watermark_isolation_and_restart(self, test_env):
        """
        Defect 2 Test: Source-agent watermark isolation.
        - Compact AGT-WIN-01 System transitions through epoch 2.
        - Confirm AGT-WIN-01 epoch 2 is retired.
        - Confirm AGT-WIN-02 epoch 1 remains valid.
        - Restart and verify both results remain correct.
        """
        cm = CheckpointManager(test_env["checkpoint_dir"], "Security", logger)

        # Compact AGT-WIN-01 System transitions through epoch 2
        cm.compact_ledger(source_channel="System", prune_source_epoch_threshold=2, source_agent_id="AGT-WIN-01")

        # Confirm AGT-WIN-01 epoch 2 is retired
        assert cm.is_transition_retired(source_channel="System", source_epoch=2, source_agent_id="AGT-WIN-01")
        assert cm.is_transition_retired(source_channel="System", source_epoch=1, source_agent_id="AGT-WIN-01")

        # Confirm AGT-WIN-02 epoch 1 remains valid (NOT retired!)
        assert not cm.is_transition_retired(source_channel="System", source_epoch=1, source_agent_id="AGT-WIN-02")
        assert not cm.is_transition_retired(source_channel="System", source_epoch=2, source_agent_id="AGT-WIN-02")

        # Missing / invalid source identity fails closed
        assert not cm.is_transition_retired(source_channel="System", source_epoch=1, source_agent_id="")
        assert not cm.is_transition_retired(source_channel="", source_epoch=1, source_agent_id="AGT-WIN-01")

        # Simulate Restart: Re-instantiate CheckpointManager from disk
        restarted_cm = CheckpointManager(test_env["checkpoint_dir"], "Security", logger)

        # Confirm both results remain correct after restart
        assert restarted_cm.is_transition_retired(source_channel="System", source_epoch=2, source_agent_id="AGT-WIN-01")
        assert not restarted_cm.is_transition_retired(source_channel="System", source_epoch=1, source_agent_id="AGT-WIN-02")

    def test_late_transition_protection_newer_epoch_then_older_epoch(self, test_env):
        """
        Defect 3 Test 1: Newer source epoch applied, then older source epoch arrives.
        Superseded transition must be acknowledged/archived without advancing target epoch.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        assert sec_collector.get_current_epoch() == 1

        # Apply Transition from System epoch 3, record 200
        w2 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid2 = generate_source_event_id_v2("AGT-WIN-01", "System", 3, "WORKSTATION-01", 200)
        m2 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 3, sid2, "WORKSTATION-01", 200, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w2), "Microsoft-Windows-Eventlog"
        )
        env2 = TransitionMailbox.build_transition_envelope(m2, w2)
        sec_collector.mailbox.publish_transition(env2)
        sec_collector.check_and_apply_pending_transitions()
        assert sec_collector.get_current_epoch() == 2

        # Older transition from System epoch 2, record 100 arrives
        w1 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid1 = generate_source_event_id_v2("AGT-WIN-01", "System", 2, "WORKSTATION-01", 100)
        m1 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 2, sid1, "WORKSTATION-01", 100, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w1), "Microsoft-Windows-Eventlog"
        )
        env1 = TransitionMailbox.build_transition_envelope(m1, w1)
        sec_collector.mailbox.publish_transition(env1)
        sec_collector.check_and_apply_pending_transitions()

        # Security epoch must remain 2 (did NOT advance to 3)
        assert sec_collector.get_current_epoch() == 2
        # Superseded envelope is archived in acknowledged/
        assert os.path.exists(os.path.join(sec_collector.mailbox.acknowledged_dir, f"{env1['transition_id']}.json"))

    def test_late_transition_protection_newer_record_then_older_record_same_epoch(self, test_env):
        """
        Defect 3 Test 2: Newer record ID applied, then older record ID arrives within the same source epoch.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        assert sec_collector.get_current_epoch() == 1

        # Apply Transition from System epoch 2, record 200
        w2 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid2 = generate_source_event_id_v2("AGT-WIN-01", "System", 2, "WORKSTATION-01", 200)
        m2 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 2, sid2, "WORKSTATION-01", 200, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w2), "Microsoft-Windows-Eventlog"
        )
        env2 = TransitionMailbox.build_transition_envelope(m2, w2)
        sec_collector.mailbox.publish_transition(env2)
        sec_collector.check_and_apply_pending_transitions()
        assert sec_collector.get_current_epoch() == 2

        # Older record ID 150 within the same System epoch 2 arrives
        w1 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid1 = generate_source_event_id_v2("AGT-WIN-01", "System", 2, "WORKSTATION-01", 150)
        m1 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 2, sid1, "WORKSTATION-01", 150, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w1), "Microsoft-Windows-Eventlog"
        )
        env1 = TransitionMailbox.build_transition_envelope(m1, w1)
        sec_collector.mailbox.publish_transition(env1)
        sec_collector.check_and_apply_pending_transitions()

        # Security epoch must remain 2 (did NOT advance to 3)
        assert sec_collector.get_current_epoch() == 2
        assert os.path.exists(os.path.join(sec_collector.mailbox.acknowledged_dir, f"{env1['transition_id']}.json"))

    def test_late_transition_equal_position_conflict_quarantined(self, test_env):
        """
        Defect 3 Test 3: Equal source position with a different transition ID — quarantine as a conflict.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()

        # Apply original Transition from System epoch 2, record 200
        w1 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid1 = generate_source_event_id_v2("AGT-WIN-01", "System", 2, "WORKSTATION-01", 200)
        m1 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 2, sid1, "WORKSTATION-01", 200, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w1), "Microsoft-Windows-Eventlog"
        )
        env1 = TransitionMailbox.build_transition_envelope(m1, w1)
        sec_collector.mailbox.publish_transition(env1)
        sec_collector.check_and_apply_pending_transitions()
        assert sec_collector.get_current_epoch() == 2

        # Create conflicting transition with the exact same (source_epoch=2, source_record_id=200),
        # but differing witness payload which yields a different transition ID!
        w2 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "ALT_USER", "S-1-5-21-999")
        m2 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 2, sid1, "WORKSTATION-01", 200, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w2), "Microsoft-Windows-Eventlog"
        )
        env2 = TransitionMailbox.build_transition_envelope(m2, w2)
        assert env2["transition_id"] != env1["transition_id"]

        # Publish conflicting transition
        sec_collector.mailbox.publish_transition(env2)
        sec_collector.check_and_apply_pending_transitions()

        # Conflicting envelope must be QUARANTINED, NOT acknowledged
        quar_file = os.path.join(sec_collector.mailbox.quarantined_dir, f"{env2['transition_id']}.json")
        ack_file = os.path.join(sec_collector.mailbox.acknowledged_dir, f"{env2['transition_id']}.json")
        assert os.path.exists(quar_file), "Conflicting transition was not quarantined!"
        assert not os.path.exists(ack_file), "Conflicting transition was erroneously acknowledged!"
        assert sec_collector.get_current_epoch() == 2

    def test_late_transition_protection_after_restart(self, test_env):
        """
        Defect 3 Test 4: Restart followed by late older transition delivery.
        High-watermark must be restored from disk and protect against late transitions across process restart.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()

        # Apply Transition 2 (System epoch 4, record 500)
        w = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid = generate_source_event_id_v2("AGT-WIN-01", "System", 4, "WORKSTATION-01", 500)
        m = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 4, sid, "WORKSTATION-01", 500, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w), "Microsoft-Windows-Eventlog"
        )
        env = TransitionMailbox.build_transition_envelope(m, w)
        sec_collector.mailbox.publish_transition(env)
        sec_collector.check_and_apply_pending_transitions()
        assert sec_collector.get_current_epoch() == 2

        # Simulate Restart: Re-instantiate collector and checkpoint manager
        restarted_sec = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        restarted_sec.initialize()
        assert restarted_sec.get_current_epoch() == 2

        # Deliver late older transition from System epoch 3, record 400
        w_late = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid_late = generate_source_event_id_v2("AGT-WIN-01", "System", 3, "WORKSTATION-01", 400)
        m_late = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 3, sid_late, "WORKSTATION-01", 400, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w_late), "Microsoft-Windows-Eventlog"
        )
        env_late = TransitionMailbox.build_transition_envelope(m_late, w_late)
        restarted_sec.mailbox.publish_transition(env_late)
        restarted_sec.check_and_apply_pending_transitions()

        # Epoch must remain 2 (did not advance to 3)
        assert restarted_sec.get_current_epoch() == 2
        assert os.path.exists(os.path.join(restarted_sec.mailbox.acknowledged_dir, f"{env_late['transition_id']}.json"))

    def test_independent_source_agents_maintain_independent_high_watermarks(self, test_env):
        """
        Defect 3 Test 5: Independent source agents maintain independent high-watermarks.
        AGT-WIN-01 reaching (epoch 5, record 1000) does NOT supersede AGT-WIN-02 at (epoch 2, record 100).
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()

        # AGT-WIN-01 publishes Transition at (System epoch 5, record 1000)
        w1 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18")
        sid1 = generate_source_event_id_v2("AGT-WIN-01", "System", 5, "WORKSTATION-01", 1000)
        m1 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 5, sid1, "WORKSTATION-01", 1000, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w1), "Microsoft-Windows-Eventlog"
        )
        env1 = TransitionMailbox.build_transition_envelope(m1, w1)
        sec_collector.mailbox.publish_transition(env1)
        sec_collector.check_and_apply_pending_transitions()
        assert sec_collector.get_current_epoch() == 2

        # AGT-WIN-02 publishes Transition at (System epoch 2, record 100)
        w2 = TransitionMailbox.build_witness_payload("Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-02", "SYSTEM", "S-1-5-18")
        sid2 = generate_source_event_id_v2("AGT-WIN-02", "System", 2, "WORKSTATION-02", 100)
        m2 = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-02", "System", 2, sid2, "WORKSTATION-02", 100, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w2), "Microsoft-Windows-Eventlog"
        )
        env2 = TransitionMailbox.build_transition_envelope(m2, w2)
        sec_collector.mailbox.publish_transition(env2)
        sec_collector.check_and_apply_pending_transitions()

        # Both transitions must be accepted; Security epoch advances to 3
        assert sec_collector.get_current_epoch() == 3
        assert sec_collector.checkpoint_manager.is_transition_applied(env1["transition_id"])
        assert sec_collector.checkpoint_manager.is_transition_applied(env2["transition_id"])

    def test_reused_applied_transition_id_with_invalid_witness_hash_is_quarantined(self, test_env):
        """
        Regression Test: Verification Ordering.
        - Apply a valid transition.
        - Submit a modified envelope reusing its transition ID but containing an invalid witness hash.
        - Assert that the modified envelope is quarantined and never acknowledged.
        - Preserve normal duplicate delivery behavior for an unchanged, valid envelope.
        """
        sec_collector = WindowsEventCollector(logger, log_name="Security", agent_id="AGT-WIN-01")
        sec_collector.initialize()
        assert sec_collector.get_current_epoch() == 1

        # 1. Apply a valid transition
        w = TransitionMailbox.build_witness_payload(
            "Security", 104, "Microsoft-Windows-Eventlog", "System", "WORKSTATION-01", "SYSTEM", "S-1-5-18"
        )
        sid = generate_source_event_id_v2("AGT-WIN-01", "System", 2, "WORKSTATION-01", 100)
        m = TransitionMailbox.build_transition_identity_manifest(
            "AGT-WIN-01", "System", 2, sid, "WORKSTATION-01", 100, "Security", "LOG_CLEARED_SECURITY_REMOTE",
            104, TransitionMailbox.compute_witness_payload_hash(w), "Microsoft-Windows-Eventlog"
        )
        valid_env = TransitionMailbox.build_transition_envelope(m, w)
        t_id = valid_env["transition_id"]

        sec_collector.mailbox.publish_transition(valid_env)
        sec_collector.check_and_apply_pending_transitions()

        # Target epoch advances to 2, transition is applied
        assert sec_collector.get_current_epoch() == 2
        assert sec_collector.checkpoint_manager.is_transition_applied(t_id)
        assert os.path.exists(os.path.join(sec_collector.mailbox.acknowledged_dir, f"{t_id}.json"))

        # 2. Normal duplicate delivery behavior for an unchanged, valid envelope
        # Clean acknowledged file to verify duplicate delivery re-acknowledges it
        os.remove(os.path.join(sec_collector.mailbox.acknowledged_dir, f"{t_id}.json"))
        sec_collector.mailbox.publish_transition(valid_env)
        sec_collector.check_and_apply_pending_transitions()

        # Epoch remains 2, valid envelope re-acknowledged
        assert sec_collector.get_current_epoch() == 2
        assert os.path.exists(os.path.join(sec_collector.mailbox.acknowledged_dir, f"{t_id}.json"))

        # 3. Submit a modified envelope reusing transition_id but containing an invalid witness hash
        os.remove(os.path.join(sec_collector.mailbox.acknowledged_dir, f"{t_id}.json"))
        tampered_env = {
            "transition_id": t_id,
            "created_at": valid_env["created_at"],
            "identity_manifest": m,
            "witness_payload": {
                **w,
                "subject_user_name": "TAMPERED_ATTACKER",
            },
        }

        sec_collector.mailbox.publish_transition(tampered_env)
        sec_collector.check_and_apply_pending_transitions()

        # The modified envelope MUST be quarantined and NEVER acknowledged
        quar_file = os.path.join(sec_collector.mailbox.quarantined_dir, f"{t_id}.json")
        ack_file = os.path.join(sec_collector.mailbox.acknowledged_dir, f"{t_id}.json")
        assert os.path.exists(quar_file), "Modified envelope was not quarantined!"
        assert not os.path.exists(ack_file), "Modified envelope was erroneously acknowledged!"
        assert sec_collector.get_current_epoch() == 2
