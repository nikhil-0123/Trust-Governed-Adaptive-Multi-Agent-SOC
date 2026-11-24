import os
import tempfile
import shutil
import json
import unittest
import logging
from unittest.mock import patch, MagicMock
from config.settings import config
from collectors.windows_event_collector import WindowsEventCollector, UnverifiedDiscontinuityError

class TestWindowsEventCollector(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("TestLogger")
        self.collector = WindowsEventCollector(self.logger)

    def test_parse_xml(self):
        mock_xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
    <EventID>4624</EventID>
    <EventRecordID>12345</EventRecordID>
    <TimeCreated SystemTime='2023-10-03T15:00:00.000000000Z'/>
    <Computer>TEST-PC</Computer>
  </System>
</Event>"""
        events = self.collector._parse_wevtutil_xml(mock_xml)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["record_id"], 12345)
        self.assertEqual(events[0]["event_id"], 4624)
        self.assertEqual(events[0]["provider"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(events[0]["computer"], "TEST-PC")
        self.assertEqual(events[0]["timestamp"], "2023-10-03T15:00:00.000000000Z")

    def test_malformed_xml_handling(self):
        mock_xml = "<Event><System><unclosed>"
        events = self.collector._parse_wevtutil_xml(mock_xml)
        self.assertEqual(len(events), 0) # Should fail safely and return empty list

    def test_parse_xml_with_event_data_4625(self):
        sample_4625_xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4625</EventID>
    <EventRecordID>998811</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Computer>WIN-EMP-01</Computer>
    <Level>0</Level>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>-</Data>
    <Data Name='TargetUserName'>corp_admin</Data>
    <Data Name='IpAddress'>10.0.5.99</Data>
    <Data Name='IpPort'>49822</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='Status'>0xc000006d</Data>
  </EventData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(sample_4625_xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["record_id"], 998811)
        self.assertEqual(ev["event_id"], 4625)
        self.assertEqual(ev["username"], "corp_admin")
        self.assertEqual(ev["source_ip"], "10.0.5.99")
        self.assertEqual(ev["logon_type"], 3)

    def test_parse_xml_event_data_hyphen_dash_safe_handling(self):
        sample_hyphen_xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4625</EventID>
    <EventRecordID>998812</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:01.000000000Z'/>
    <Computer>WIN-EMP-01</Computer>
    <Level>0</Level>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>-</Data>
    <Data Name='TargetUserName'>-</Data>
    <Data Name='IpAddress'>-</Data>
    <Data Name='LogonType'>-</Data>
  </EventData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(sample_hyphen_xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["record_id"], 998812)
        self.assertEqual(ev["event_id"], 4625)
        self.assertNotIn("username", ev)
        self.assertNotIn("source_ip", ev)
        self.assertNotIn("logon_type", ev)

    def test_event_104_targeting_security(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>5001</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Channel>System</Channel>
    <Computer>WIN-PC</Computer>
  </System>
  <UserData>
    <LogFileCleared>
      <SubjectUserName>admin</SubjectUserName>
      <SubjectDomainName>CORP</SubjectDomainName>
      <SubjectUserSid>S-1-5-21-1234</SubjectUserSid>
      <Channel>Security</Channel>
    </LogFileCleared>
  </UserData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_id"], 104)
        self.assertEqual(ev["channel"], "System")
        self.assertEqual(ev["affected_channel"], "Security")
        self.assertFalse(ev.get("is_malformed_witness", False))
        self.assertEqual(ev["subject_user"], "admin")
        self.assertEqual(ev["subject_domain"], "CORP")
        self.assertEqual(ev["subject_user_sid"], "S-1-5-21-1234")

    def test_event_104_targeting_system(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>5002</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Channel>System</Channel>
    <Computer>WIN-PC</Computer>
  </System>
  <UserData>
    <LogFileCleared>
      <SubjectUserName>admin</SubjectUserName>
      <SubjectDomainName>CORP</SubjectDomainName>
      <SubjectUserSid>S-1-5-21-1234</SubjectUserSid>
      <Channel>System</Channel>
    </LogFileCleared>
  </UserData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_id"], 104)
        self.assertEqual(ev["channel"], "System")
        self.assertEqual(ev["affected_channel"], "System")
        self.assertFalse(ev.get("is_malformed_witness", False))

    def test_event_104_targeting_another_supported_channel(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>5003</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Channel>System</Channel>
    <Computer>WIN-PC</Computer>
  </System>
  <UserData>
    <LogFileCleared>
      <SubjectUserName>admin</SubjectUserName>
      <SubjectDomainName>CORP</SubjectDomainName>
      <SubjectUserSid>S-1-5-21-1234</SubjectUserSid>
      <Channel>Application</Channel>
    </LogFileCleared>
  </UserData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_id"], 104)
        self.assertEqual(ev["channel"], "System")
        self.assertEqual(ev["affected_channel"], "Application")
        self.assertFalse(ev.get("is_malformed_witness", False))

    def test_event_104_missing_affected_channel(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>5004</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Channel>System</Channel>
    <Computer>WIN-PC</Computer>
  </System>
  <UserData>
    <LogFileCleared>
      <SubjectUserName>admin</SubjectUserName>
    </LogFileCleared>
  </UserData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_id"], 104)
        self.assertIsNone(ev["affected_channel"])
        self.assertTrue(ev["is_malformed_witness"])
        self.assertIn("Missing affected channel", ev["malformed_witness_reason"])
        self.assertNotEqual(ev["affected_channel"], "Security")
        self.assertNotEqual(ev["affected_channel"], "System")

    def test_event_104_empty_affected_channel(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>5005</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Channel>System</Channel>
    <Computer>WIN-PC</Computer>
  </System>
  <UserData>
    <LogFileCleared>
      <Channel>  -  </Channel>
    </LogFileCleared>
  </UserData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_id"], 104)
        self.assertIsNone(ev["affected_channel"])
        self.assertTrue(ev["is_malformed_witness"])
        self.assertIn("Empty affected channel", ev["malformed_witness_reason"])

    def test_event_104_conflicting_or_ambiguous_channel_representations(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>5006</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Channel>System</Channel>
    <Computer>WIN-PC</Computer>
  </System>
  <UserData>
    <LogFileCleared>
      <Channel>Security</Channel>
    </LogFileCleared>
  </UserData>
  <EventData>
    <Data Name='Channel'>System</Data>
  </EventData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_id"], 104)
        self.assertIsNone(ev["affected_channel"])
        self.assertTrue(ev["is_malformed_witness"])
        self.assertIn("Ambiguous or conflicting", ev["malformed_witness_reason"])

    def test_event_104_namespaced_xml_parsing(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>5007</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Channel>System</Channel>
    <Computer>WIN-PC</Computer>
  </System>
  <UserData xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>
    <LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>
      <Channel>Security</Channel>
      <SubjectUserName>alice</SubjectUserName>
      <SubjectDomainName>DOMAIN</SubjectDomainName>
      <SubjectUserSid>S-1-5-21-999</SubjectUserSid>
    </LogFileCleared>
  </UserData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_id"], 104)
        self.assertEqual(ev["affected_channel"], "Security")
        self.assertFalse(ev.get("is_malformed_witness", False))
        self.assertEqual(ev["subject_user"], "alice")
        self.assertEqual(ev["subject_domain"], "DOMAIN")
        self.assertEqual(ev["subject_user_sid"], "S-1-5-21-999")

    def test_missing_subject_username_remains_none(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4624</EventID>
    <EventRecordID>5008</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Computer>WIN-PC</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>-</Data>
    <Data Name='TargetUserName'>bob</Data>
  </EventData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertIsNone(ev.get("subject_user"))
        self.assertNotEqual(ev.get("subject_user"), "SYSTEM")

    def test_missing_subject_user_sid_remains_none(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4624</EventID>
    <EventRecordID>5009</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Computer>WIN-PC</Computer>
  </System>
  <EventData>
    <Data Name='SubjectUserSid'>-</Data>
    <Data Name='TargetUserName'>bob</Data>
  </EventData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertIsNone(ev.get("subject_user_sid"))
        self.assertNotEqual(ev.get("subject_user_sid"), "S-1-5-18")

    def test_missing_subject_domain_name_remains_none(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4624</EventID>
    <EventRecordID>5010</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Computer>WIN-PC</Computer>
  </System>
  <EventData>
    <Data Name='SubjectDomainName'>-</Data>
    <Data Name='TargetUserName'>bob</Data>
  </EventData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertIsNone(ev.get("subject_domain"))
        self.assertNotEqual(ev.get("subject_domain"), "WORKSTATION-01")

    def test_no_fabricated_system_or_workstation_identity(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>5011</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Channel>System</Channel>
  </System>
  <UserData>
    <LogFileCleared>
      <Channel>Security</Channel>
    </LogFileCleared>
  </UserData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertIsNone(ev["subject_user"])
        self.assertIsNone(ev["subject_domain"])
        self.assertIsNone(ev["subject_user_sid"])
        self.assertIsNone(ev["computer"])
        all_values = [str(v) for k, v in ev.items() if k != "raw_xml" and v is not None]
        for val in all_values:
            self.assertNotIn("SYSTEM", val)
            self.assertNotIn("S-1-5-18", val)
            self.assertNotIn("WORKSTATION-01", val)

    def test_existing_event_1102_behavior_remains_correct(self):
        xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>1102</EventID>
    <EventRecordID>11020</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Channel>Security</Channel>
    <Computer>SEC-PC</Computer>
  </System>
  <UserData>
    <LogFileCleared>
      <SubjectUserSid>S-1-5-21-500</SubjectUserSid>
      <SubjectUserName>sec_admin</SubjectUserName>
      <SubjectDomainName>CORP</SubjectDomainName>
      <SubjectLogonId>0x12345</SubjectLogonId>
    </LogFileCleared>
  </UserData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml)
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_id"], 1102)
        self.assertEqual(ev["record_id"], 11020)
        self.assertEqual(ev["channel"], "Security")
        self.assertEqual(ev["subject_user"], "sec_admin")
        self.assertEqual(ev["subject_domain"], "CORP")
        self.assertEqual(ev["subject_user_sid"], "S-1-5-21-500")
        self.assertEqual(ev["username"], "sec_admin")
        self.assertEqual(ev["computer"], "SEC-PC")

    def test_invalid_witnesses_do_not_cause_unauthorized_epoch_transition(self):
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)

        try:
            logger = logging.getLogger("TestWitnessEpoch")
            system_collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
            system_collector.initialize()
            system_collector.current_checkpoint = 100
            system_collector.current_epoch = 1

            # 1. Provide malformed Event 104 with missing affected channel
            malformed_event = {
                "event_id": 104,
                "record_id": 105,
                "channel": "System",
                "affected_channel": None,
                "is_malformed_witness": True,
                "malformed_witness_reason": "Missing affected channel in Event 104 payload",
            }

            system_collector.handle_event_104_system(malformed_event)

            # Assert epoch did not mutate
            self.assertEqual(system_collector.current_epoch, 1)
            # Assert checkpoint moved to prevent looping
            self.assertEqual(system_collector.current_checkpoint, 105)
            # Assert event is quarantined
            self.assertTrue(malformed_event.get("quarantined"))
            self.assertEqual(malformed_event.get("quarantine_reason"), "Missing affected channel in Event 104 payload")

            # Assert no transition files were published to pending/
            if os.path.exists(system_collector.mailbox.pending_dir):
                pending_files = os.listdir(system_collector.mailbox.pending_dir)
                self.assertEqual(len(pending_files), 0)

            # Assert quarantine record was written
            quarantine_files = os.listdir(system_collector.mailbox.quarantined_dir)
            self.assertEqual(len(quarantine_files), 1)

            # 2. Assert unverified drop on malformed witness in collect_once raises UnverifiedDiscontinuityError
            sim_dir = system_collector.simulated_events_channel_dir
            os.makedirs(sim_dir, exist_ok=True)
            malformed_drop_xml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>50</EventRecordID>
    <TimeCreated SystemTime='2026-10-12T15:00:00.000000000Z'/>
    <Channel>System</Channel>
  </System>
  <UserData>
    <LogFileCleared>
    </LogFileCleared>
  </UserData>
</Event>"""
            with open(os.path.join(sim_dir, "event_104_drop.xml"), "w", encoding="utf-8") as f:
                f.write(malformed_drop_xml)

            # Current checkpoint is 105, incoming record is 50 -> must raise UnverifiedDiscontinuityError
            with self.assertRaises(UnverifiedDiscontinuityError):
                system_collector.collect_once()

            # Epoch still must not have advanced
            self.assertEqual(system_collector.current_epoch, 1)

        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_persistent_malformed_witness_halt_and_recovery(self):
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)

        try:
            logger = logging.getLogger("TestPersistentHalt")
            collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
            collector.initialize()
            collector.current_checkpoint = 100

            sim_dir = collector.simulated_events_channel_dir
            os.makedirs(sim_dir, exist_ok=True)

            # Malformed Event 104 (rec 105) followed by ordinary Event 7036 (rec 106)
            xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>105</EventRecordID>
    <Channel>System</Channel>
  </System>
  <UserData><LogFileCleared></LogFileCleared></UserData>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Service Control Manager'/>
    <EventID>7036</EventID>
    <EventRecordID>106</EventRecordID>
    <Channel>System</Channel>
  </System>
  <EventData><Data Name='param1'>Windows Update</Data></EventData>
</Event>"""

            with open(os.path.join(sim_dir, "batch.xml"), "w", encoding="utf-8") as f:
                f.write(xml)

            # 1. First collection must halt and raise UnverifiedDiscontinuityError
            with self.assertRaises(UnverifiedDiscontinuityError):
                collector.collect_once()

            # 2. Malformed witness is durably quarantined
            self.assertTrue(collector.is_channel_quarantined())
            quar_file = os.path.join(collector.mailbox.quarantined_dir, "malformed_104_rec_105.json")
            self.assertTrue(os.path.exists(quar_file))

            # CRITICAL CHECK: batch.xml MUST NOT be deleted merely because record 105 was malformed!
            # Event 106 is a valid event in the source file that must be preserved!
            self.assertTrue(os.path.exists(os.path.join(sim_dir, "batch.xml")))

            # 3. Calling collect_once() again must NOT silently resume ingestion
            with open(os.path.join(sim_dir, "next_event.xml"), "w", encoding="utf-8") as f:
                f.write("""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Service Control Manager'/>
    <EventID>7036</EventID>
    <EventRecordID>107</EventRecordID>
    <Channel>System</Channel>
  </System>
  <EventData><Data Name='param1'>Print Spooler</Data></EventData>
</Event>""")

            with self.assertRaises(UnverifiedDiscontinuityError):
                collector.collect_once()

            # 4. Restarting the collector with same data directory must NOT bypass quarantine
            restarted_collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
            restarted_collector.initialize()
            self.assertTrue(restarted_collector.is_channel_quarantined())

            with self.assertRaises(UnverifiedDiscontinuityError):
                restarted_collector.collect_once()

            # 5. Authorized recovery lifts quarantine and permits resumption
            restarted_collector.resolve_channel_quarantine({
                "authorized_by": "sec_admin",
                "resolution_reason": "Verified administrative recovery of clear witness gap",
            })
            self.assertFalse(restarted_collector.is_channel_quarantined())

            # Resumed collection safely processes remaining valid event from batch.xml (record 106)
            # and subsequent events (record 107) without data loss
            events = restarted_collector.collect_once()
            self.assertEqual(len(events), 2)
            self.assertEqual([e["record_id"] for e in events], [106, 107])
            self.assertEqual(events[0]["event_id"], 7036)
            self.assertEqual(events[1]["event_id"], 7036)

            # Downstream commits checkpoint to 107
            restarted_collector.update_checkpoint(107)
            self.assertFalse(os.path.exists(os.path.join(sim_dir, "batch.xml")))
            self.assertFalse(os.path.exists(os.path.join(sim_dir, "next_event.xml")))

        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_zero_fabrication_witness_payload(self):
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)

        try:
            logger = logging.getLogger("TestWitnessZeroFab")
            collector = WindowsEventCollector(logger, log_name="System", agent_id="AGT-WIN-01")
            collector.initialize()

            # Event 104 with missing actor fields and missing Computer
            xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>5050</EventRecordID>
    <Channel>System</Channel>
  </System>
  <UserData>
    <LogFileCleared>
      <Channel>Security</Channel>
    </LogFileCleared>
  </UserData>
</Event>"""
            events = collector._parse_wevtutil_xml(xml)
            self.assertEqual(len(events), 1)
            ev = events[0]
            self.assertIsNone(ev["subject_user"])
            self.assertIsNone(ev["subject_domain"])
            self.assertIsNone(ev["subject_user_sid"])
            self.assertIsNone(ev["computer"])

            collector.handle_event_104_system(ev)

            # Inspect published envelope
            pending_files = os.listdir(collector.mailbox.pending_dir)
            self.assertEqual(len(pending_files), 1)
            with open(os.path.join(collector.mailbox.pending_dir, pending_files[0]), "r", encoding="utf-8") as f:
                envelope = json.load(f)

            witness_payload = envelope["witness_payload"]
            self.assertEqual(witness_payload["affected_channel"], "Security")
            self.assertEqual(witness_payload["event_id"], 104)
            self.assertEqual(witness_payload["source_channel"], "System")
            self.assertEqual(witness_payload["subject_user_name"], "")
            self.assertEqual(witness_payload["subject_domain_name"], "")
            self.assertEqual(witness_payload["subject_user_sid"], "")

            # Verify no synthetic identities were fabricated
            for k, val in witness_payload.items():
                self.assertNotIn("SYSTEM", str(val))
                self.assertNotIn("S-1-5-18", str(val))
                self.assertNotIn("WORKSTATION-01", str(val))

            manifest = envelope["identity_manifest"]
            self.assertEqual(manifest["source_hostname"], collector.agent_id)
            self.assertNotEqual(manifest["source_hostname"], "WORKSTATION-01")

            # Direct unit test of TransitionMailbox.build_witness_payload with empty actor strings
            from collectors.mailbox import TransitionMailbox
            direct_wp = TransitionMailbox.build_witness_payload(
                affected_channel="Security",
                event_id=104,
                provider="Microsoft-Windows-Eventlog",
                source_channel="System",
                subject_domain_name="",
                subject_user_name="",
                subject_user_sid="",
            )
            self.assertEqual(direct_wp["subject_user_name"], "")
            self.assertEqual(direct_wp["subject_domain_name"], "")
            self.assertEqual(direct_wp["subject_user_sid"], "")
            self.assertNotIn("SYSTEM", direct_wp.values())
            self.assertNotIn("S-1-5-18", direct_wp.values())
            self.assertNotIn("WORKSTATION-01", direct_wp.values())

        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_01_checkpoint_50000_with_newest_record_id_3(self):
        """Test 1: Checkpoint 50,000 with newest record ID 3 triggers reset probe."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            collector.initialize()
            collector.current_checkpoint = 50000

            with patch.object(collector, "_probe_newest_record_id", return_value=(3, None)) as mock_probe, \
                 patch.object(collector, "_find_clear_witness_for_reset", return_value=(False, None, "No witness")) as mock_find:
                with self.assertRaises(UnverifiedDiscontinuityError):
                    collector.collect_once()

                mock_probe.assert_called_once()
                mock_find.assert_called_once()
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_02_valid_event_1102_discovered_after_security_record_reset(self):
        """Test 2: Valid Event 1102 discovered after Security record reset resets query and advances epoch."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            collector.initialize()
            collector.current_checkpoint = 50000

            live_batch = [
                {"event_id": 1102, "record_id": 1, "channel": "Security"},
                {"event_id": 4624, "record_id": 2, "channel": "Security"},
                {"event_id": 4624, "record_id": 3, "channel": "Security"},
            ]

            with patch.object(collector, "_probe_newest_record_id", return_value=(3, None)), \
                 patch.object(collector, "_find_clear_witness_for_reset", return_value=(True, live_batch[0], None)), \
                 patch("subprocess.run") as mock_sub, \
                 patch.object(collector, "_parse_wevtutil_xml", return_value=live_batch):
                mock_sub.return_value = MagicMock(stdout="<Events></Events>", returncode=0)

                events = collector.collect_once()
                # Batch is truncated at Event 1102!
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["event_id"], 1102)
                self.assertEqual(events[0]["record_id"], 1)

                # Post-clear remainder is persisted durably
                self.assertTrue(collector.has_durable_remainder())
                remainder = collector.load_durable_remainder()
                self.assertEqual(len(remainder), 2)
                self.assertEqual([r["record_id"] for r in remainder], [2, 3])

                # Commit Event 1102 downstream
                collector.update_checkpoint(1)
                self.assertEqual(collector.get_current_epoch(), 2)
                self.assertEqual(collector.current_checkpoint, 0)

                # Subsequent cycle serves remainder under Epoch 2
                rem_events = collector.collect_once()
                self.assertEqual(len(rem_events), 2)
                self.assertEqual(rem_events[0]["epoch"], 2)
                self.assertEqual(rem_events[1]["epoch"], 2)

                # Completing remainder commits checkpoint 3 and clears remainder file
                collector.update_checkpoint(3)
                self.assertFalse(collector.has_durable_remainder())
                self.assertEqual(collector.current_checkpoint, 3)
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_03_valid_event_104_targeting_system(self):
        """Test 3: Valid Event 104 targeting System allows verified reset for System channel."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="System", agent_id="AGT-WIN-01")
            collector.initialize()
            collector.current_checkpoint = 50000

            live_batch = [
                {"event_id": 104, "record_id": 1, "channel": "System", "affected_channel": "System"},
                {"event_id": 7036, "record_id": 2, "channel": "System"},
                {"event_id": 7036, "record_id": 3, "channel": "System"},
            ]

            with patch.object(collector, "_probe_newest_record_id", return_value=(3, None)), \
                 patch.object(collector, "_find_clear_witness_for_reset", return_value=(True, live_batch[0], None)), \
                 patch("subprocess.run") as mock_sub, \
                 patch.object(collector, "_parse_wevtutil_xml", return_value=live_batch):
                mock_sub.return_value = MagicMock(stdout="<Events></Events>", returncode=0)

                events = collector.collect_once()
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["event_id"], 104)
                self.assertEqual(events[0]["affected_channel"], "System")

                # System epoch advanced due to self-clear
                self.assertEqual(collector.get_current_epoch(), 2)
                self.assertTrue(collector.has_durable_remainder())
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_04_reset_without_valid_clear_witness(self):
        """Test 4: Reset without a valid clear witness fails closed and durably quarantines channel."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            collector.initialize()
            collector.current_checkpoint = 50000

            with patch.object(collector, "_probe_newest_record_id", return_value=(3, None)), \
                 patch.object(collector, "_find_clear_witness_for_reset", return_value=(False, None, "No witness")):
                with self.assertRaises(UnverifiedDiscontinuityError):
                    collector.collect_once()

                # Channel is persistently quarantined
                self.assertTrue(collector.is_channel_quarantined())
                reason = collector.get_channel_quarantine_reason()
                self.assertIn("UNVERIFIED_RESET", reason)

                # Subsequent call also halts due to quarantine
                with self.assertRaises(UnverifiedDiscontinuityError):
                    collector.collect_once()
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_05_empty_event_log(self):
        """Test 5: Empty event log handled cleanly without error or quarantine."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            collector.initialize()
            collector.current_checkpoint = 100

            with patch.object(collector, "_probe_newest_record_id", return_value=(None, "EMPTY_LOG")):
                events = collector.collect_once()
                self.assertEqual(len(events), 0)
                self.assertEqual(collector.current_checkpoint, 100)
                self.assertFalse(collector.is_channel_quarantined())
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_06_mixed_preclear_clearwitness_postclear_batch(self):
        """Test 6: Mixed pre-clear, clear-witness and post-clear batch is truncated atomically."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            collector.initialize()

            batch = [
                {"event_id": 4624, "record_id": 500, "channel": "Security"},
                {"event_id": 4624, "record_id": 501, "channel": "Security"},
                {"event_id": 1102, "record_id": 502, "channel": "Security"},
                {"event_id": 4624, "record_id": 1, "channel": "Security"},
                {"event_id": 4624, "record_id": 2, "channel": "Security"},
            ]
            truncated, remainder = collector._truncate_batch_at_clear(batch)
            self.assertEqual(len(truncated), 3)
            self.assertEqual([e["record_id"] for e in truncated], [500, 501, 502])
            self.assertEqual(len(remainder), 2)
            self.assertEqual([e["record_id"] for e in remainder], [1, 2])

            collector.persist_durable_remainder(remainder)
            self.assertTrue(collector.has_durable_remainder())
            loaded = collector.load_durable_remainder()
            self.assertEqual(len(loaded), 2)
            self.assertEqual([e["record_id"] for e in loaded], [1, 2])
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_07_preclear_detections_retain_old_epoch(self):
        """Test 7: Pre-clear detections retain the old epoch during pipeline processing."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        orig_outbox = config.outbox_db_path
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        config._outbox_db_path = os.path.join(temp_dir, "outbox.db")
        config.detection_output_dir = os.path.join(temp_dir, "detections")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        os.makedirs(config.detection_output_dir, exist_ok=True)
        try:
            from pipeline import WindowsDetectionPipeline
            pipeline = WindowsDetectionPipeline(self.logger)
            collector = pipeline.collector
            collector.initialize()
            self.assertEqual(collector.get_current_epoch(), 1)

            # Stage simulated XML with pre-clear, clear witness, and post-clear
            sim_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4625</EventID>
    <EventRecordID>500</EventRecordID>
    <Channel>Security</Channel>
    <TimeCreated SystemTime='2026-11-10T12:00:00Z'/>
  </System>
  <EventData>
    <Data Name='TargetUserName'>corp_admin</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='Status'>0xc000006d</Data>
    <Data Name='CommandLine'>wevtutil.exe cl security</Data>
  </EventData>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>1102</EventID>
    <EventRecordID>501</EventRecordID>
    <Channel>Security</Channel>
    <TimeCreated SystemTime='2026-11-10T12:01:00Z'/>
  </System>
  <UserData><LogFileCleared><SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4625</EventID>
    <EventRecordID>1</EventRecordID>
    <Channel>Security</Channel>
    <TimeCreated SystemTime='2026-11-10T12:02:00Z'/>
  </System>
  <EventData>
    <Data Name='TargetUserName'>corp_admin</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='Status'>0xc000006d</Data>
    <Data Name='CommandLine'>wevtutil.exe cl security</Data>
  </EventData>
</Event>"""
            sim_file = os.path.join(collector.simulated_events_channel_dir, "batch.xml")
            with open(sim_file, "w", encoding="utf-8") as f:
                f.write(sim_xml)

            # Process cycle 1 with normalize spy
            with patch.object(pipeline.normalizer, "normalize", wraps=pipeline.normalizer.normalize) as mock_norm:
                pipeline._process_channel_batch(collector, "Security")

                # Checkpoint updated to Event 1102, epoch advanced to 2
                self.assertEqual(collector.get_current_epoch(), 2)
                self.assertTrue(collector.has_durable_remainder())

                # All events processed in cycle 1 must have epoch == 1
                self.assertTrue(len(mock_norm.call_args_list) >= 2)
                for call in mock_norm.call_args_list:
                    self.assertEqual(call.kwargs["epoch"], 1)
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            config._outbox_db_path = orig_outbox
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_08_postclear_remainder_uses_new_epoch(self):
        """Test 8: Post-clear remainder uses the new epoch on subsequent collection cycle."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        orig_outbox = config.outbox_db_path
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        config._outbox_db_path = os.path.join(temp_dir, "outbox.db")
        config.detection_output_dir = os.path.join(temp_dir, "detections")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        os.makedirs(config.detection_output_dir, exist_ok=True)
        try:
            from pipeline import WindowsDetectionPipeline
            pipeline = WindowsDetectionPipeline(self.logger)
            collector = pipeline.collector
            collector.initialize()

            # Persist a remainder event under Epoch 2
            remainder_event = {
                "event_id": 4625,
                "record_id": 1,
                "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "computer": "WORKSTATION-01",
                "timestamp": "2026-11-10T12:02:00Z",
                "target_user": "corp_admin",
                "logon_type": 3,
                "status": "0xc000006d",
                "command_line": "wevtutil.exe cl security",
            }
            collector.persist_durable_remainder([remainder_event])
            # Advance collector to epoch 2
            collector.current_epoch = 2
            collector.checkpoint_manager.advance_epoch(new_epoch=2, reset_record_id=0, transition_id="tid-test-08", target_channel="Security")
            self.assertEqual(collector.get_current_epoch(), 2)

            # Cycle 2 processes remainder with normalize spy
            with patch.object(pipeline.normalizer, "normalize", wraps=pipeline.normalizer.normalize) as mock_norm:
                pipeline._process_channel_batch(collector, "Security")

                # Remainder cleared, checkpoint updated
                self.assertFalse(collector.has_durable_remainder())
                self.assertEqual(collector.current_checkpoint, 1)

                # Remainder event in cycle 2 must have epoch == 2
                self.assertEqual(len(mock_norm.call_args_list), 1)
                self.assertEqual(mock_norm.call_args_list[0].kwargs["epoch"], 2)
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            config._outbox_db_path = orig_outbox
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_09_simulation_remainder_survives_source_processing(self):
        """Test 9: Simulation remainder survives source file deletion and is safely persisted."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            collector.initialize()

            sim_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4624</EventID>
    <EventRecordID>500</EventRecordID>
    <Channel>Security</Channel>
  </System>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>1102</EventID>
    <EventRecordID>501</EventRecordID>
    <Channel>Security</Channel>
  </System>
  <UserData><LogFileCleared><SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4624</EventID>
    <EventRecordID>1</EventRecordID>
    <Channel>Security</Channel>
  </System>
</Event>"""
            sim_file = os.path.join(collector.simulated_events_channel_dir, "source.xml")
            with open(sim_file, "w", encoding="utf-8") as f:
                f.write(sim_xml)

            events = collector.collect_once()
            self.assertEqual(len(events), 2)
            self.assertEqual([e["record_id"] for e in events], [500, 501])

            # Source file MUST be preserved until downstream checkpoint commitment
            self.assertTrue(os.path.exists(sim_file))
            self.assertTrue(collector.has_durable_remainder())
            rem = collector.load_durable_remainder()
            self.assertEqual(len(rem), 1)
            self.assertEqual(rem[0]["record_id"], 1)

            # Downstream commits Event 1102
            collector.update_checkpoint(501)
            # Source file is now acknowledged and removed
            self.assertFalse(os.path.exists(sim_file))
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_10_crash_during_remainder_persistence(self):
        """Test 10: Crash during remainder persistence preserves source file intact."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            collector.initialize()

            sim_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>1102</EventID>
    <EventRecordID>501</EventRecordID>
    <Channel>Security</Channel>
  </System>
  <UserData><LogFileCleared><SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4624</EventID>
    <EventRecordID>1</EventRecordID>
    <Channel>Security</Channel>
  </System>
</Event>"""
            sim_file = os.path.join(collector.simulated_events_channel_dir, "crash_source.xml")
            with open(sim_file, "w", encoding="utf-8") as f:
                f.write(sim_xml)

            with patch.object(collector, "persist_durable_remainder", side_effect=OSError("Simulated disk error during fsync")):
                with self.assertRaises(OSError):
                    collector.collect_once()

            # Source file was NOT deleted
            self.assertTrue(os.path.exists(sim_file))
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_11_restart_with_existing_durable_remainder(self):
        """Test 11: Restart with an existing durable remainder immediately recovers remainder."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector1 = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            collector1.initialize()
            remainder_data = [
                {"event_id": 4624, "record_id": 1, "channel": "Security"},
                {"event_id": 4624, "record_id": 2, "channel": "Security"},
            ]
            collector1.persist_durable_remainder(remainder_data)

            # New collector instance simulating clean restart
            restarted = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            restarted.initialize()
            self.assertTrue(restarted.has_durable_remainder())

            batch = restarted.collect_once()
            self.assertEqual(len(batch), 2)
            self.assertEqual([e["record_id"] for e in batch], [1, 2])
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_12_no_duplicate_or_lost_events_after_remainder_recovery(self):
        """Test 12: No duplicate or lost events after remainder recovery across cycle boundaries."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            collector.initialize()

            sim_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>100</EventRecordID><Channel>Security</Channel></System>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>1102</EventID><EventRecordID>101</EventRecordID><Channel>Security</Channel></System>
  <UserData><LogFileCleared><SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>1</EventRecordID><Channel>Security</Channel></System>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>2</EventRecordID><Channel>Security</Channel></System>
</Event>"""
            sim_file = os.path.join(collector.simulated_events_channel_dir, "batch.xml")
            with open(sim_file, "w", encoding="utf-8") as f:
                f.write(sim_xml)

            # Cycle 1
            batch1 = collector.collect_once()
            self.assertEqual([e["record_id"] for e in batch1], [100, 101])
            collector.update_checkpoint(101)

            # Restart collector
            restarted = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            restarted.initialize()

            # Cycle 2
            batch2 = restarted.collect_once()
            self.assertEqual([e["record_id"] for e in batch2], [1, 2])
            restarted.update_checkpoint(2)

            # Cycle 3
            batch3 = restarted.collect_once()
            self.assertEqual(len(batch3), 0)

            # Total collected records
            all_collected = [e["record_id"] for e in batch1] + [e["record_id"] for e in batch2]
            self.assertEqual(all_collected, [100, 101, 1, 2])
            self.assertEqual(len(set(all_collected)), 4)  # No duplicates, no losses
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_13_existing_phase1_malformed_witness_quarantine_effective(self):
        """Test 13: Existing Phase 1 malformed-witness quarantine remains effective."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="System", agent_id="AGT-WIN-01")
            collector.initialize()
            collector.current_checkpoint = 100

            # Malformed Event 104 with missing affected channel
            sim_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>105</EventRecordID>
    <Channel>System</Channel>
  </System>
  <UserData><LogFileCleared></LogFileCleared></UserData>
</Event>"""
            sim_file = os.path.join(collector.simulated_events_channel_dir, "bad_104.xml")
            with open(sim_file, "w", encoding="utf-8") as f:
                f.write(sim_xml)

            with self.assertRaises(UnverifiedDiscontinuityError):
                collector.collect_once()

            self.assertTrue(collector.is_channel_quarantined())
            self.assertIn("Missing affected channel", collector.get_channel_quarantine_reason())

            # Resumption blocked until resolved
            with self.assertRaises(UnverifiedDiscontinuityError):
                collector.collect_once()

            collector.resolve_channel_quarantine({"authorized_by": "admin", "resolution_reason": "ok"})
            self.assertFalse(collector.is_channel_quarantined())
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_14_crash_recovery_preserves_source_and_recovers_all_events(self):
        """Test 14: Crash before downstream commitment preserves source XML and recovers all events across epochs."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            collector.initialize()
            self.assertEqual(collector.get_current_epoch(), 1)

            sim_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>500</EventRecordID><Channel>Security</Channel></System>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>1102</EventID><EventRecordID>501</EventRecordID><Channel>Security</Channel></System>
  <UserData><LogFileCleared><SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>1</EventRecordID><Channel>Security</Channel></System>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>2</EventRecordID><Channel>Security</Channel></System>
</Event>"""
            sim_file = os.path.join(collector.simulated_events_channel_dir, "batch.xml")
            with open(sim_file, "w", encoding="utf-8") as f:
                f.write(sim_xml)

            # 1. Collector collects first batch
            batch1 = collector.collect_once()
            self.assertEqual([e["record_id"] for e in batch1], [500, 501])
            self.assertEqual([e["epoch"] for e in batch1], [1, 1])

            # Remainder is persisted durably
            self.assertTrue(collector.has_durable_remainder())
            rem = collector.load_durable_remainder()
            self.assertEqual([r["record_id"] for r in rem], [1, 2])

            # CRITICAL CHECK: Source XML MUST NOT be deleted before downstream commitment
            self.assertTrue(os.path.exists(sim_file))

            # 2. Simulate process termination / crash BEFORE downstream checkpoint commitment
            # update_checkpoint() is NOT called! Drop collector instance.
            del collector

            # 3. Reinstantiate the collector (process restart simulation)
            restarted = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
            restarted.initialize()

            # Epoch is still 1 because update_checkpoint was not called
            self.assertEqual(restarted.get_current_epoch(), 1)
            # Source file is still present
            self.assertTrue(os.path.exists(sim_file))

            # Remainder exists on disk, but is NOT eligible yet because target_epoch is 2 and current_epoch is 1
            self.assertFalse(restarted.is_durable_remainder_eligible())

            # 4. Ingestion recovers the pre-clear batch and clear witness under Epoch 1
            recovered_batch1 = restarted.collect_once()
            self.assertEqual([e["record_id"] for e in recovered_batch1], [500, 501])
            self.assertEqual([e["epoch"] for e in recovered_batch1], [1, 1])

            # Source file is still preserved before downstream commitment
            self.assertTrue(os.path.exists(sim_file))

            # 5. Downstream pipeline now successfully processes batch and commits Event 1102
            restarted.update_checkpoint(501)

            # Epoch advanced to 2, and source file is now safely unlinked
            self.assertEqual(restarted.get_current_epoch(), 2)
            self.assertFalse(os.path.exists(sim_file))

            # Now remainder is eligible under Epoch 2
            self.assertTrue(restarted.is_durable_remainder_eligible())

            # 6. Next collection cycle recovers post-clear remainder under Epoch 2
            recovered_batch2 = restarted.collect_once()
            self.assertEqual([e["record_id"] for e in recovered_batch2], [1, 2])
            self.assertEqual([e["epoch"] for e in recovered_batch2], [2, 2])

            # Downstream commits remainder
            restarted.update_checkpoint(2)
            self.assertFalse(restarted.has_durable_remainder())
            self.assertEqual(restarted.current_checkpoint, 2)

            # Verify no event is silently discarded, all 4 events processed across correct epochs
            all_recovered = [e["record_id"] for e in recovered_batch1] + [e["record_id"] for e in recovered_batch2]
            self.assertEqual(all_recovered, [500, 501, 1, 2])
            self.assertEqual(len(set(all_recovered)), 4)
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase2_15_malformed_witness_preserves_surrounding_valid_events(self):
        """Test 15: XML source file with valid events preceding and following malformed witness is fully preserved."""
        temp_dir = tempfile.mkdtemp()
        orig_chk = config._checkpoint_dir
        orig_data = config.data_dir
        config.checkpoint_dir = os.path.join(temp_dir, "checkpoints")
        config.data_dir = os.path.join(temp_dir, "data")
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        os.makedirs(config.data_dir, exist_ok=True)
        try:
            collector = WindowsEventCollector(self.logger, log_name="System", agent_id="AGT-WIN-01")
            collector.initialize()
            collector.current_checkpoint = 100

            # Multi-event XML: Event 7036 (rec 104), malformed Event 104 (rec 105), Event 7036 (rec 106)
            sim_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Service Control Manager'/>
    <EventID>7036</EventID>
    <EventRecordID>104</EventRecordID>
    <Channel>System</Channel>
  </System>
  <EventData><Data Name='param1'>DHCP Client</Data></EventData>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Eventlog'/>
    <EventID>104</EventID>
    <EventRecordID>105</EventRecordID>
    <Channel>System</Channel>
  </System>
  <UserData><LogFileCleared></LogFileCleared></UserData>
</Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Service Control Manager'/>
    <EventID>7036</EventID>
    <EventRecordID>106</EventRecordID>
    <Channel>System</Channel>
  </System>
  <EventData><Data Name='param1'>DNS Client</Data></EventData>
</Event>"""
            sim_file = os.path.join(collector.simulated_events_channel_dir, "mixed_batch.xml")
            with open(sim_file, "w", encoding="utf-8") as f:
                f.write(sim_xml)

            # Cycle 1: Yields valid event(s) preceding the malformed witness (record 104)
            batch1 = collector.collect_once()
            self.assertEqual(len(batch1), 1)
            self.assertEqual(batch1[0]["record_id"], 104)
            # Source file MUST be preserved on disk!
            self.assertTrue(os.path.exists(sim_file))

            # Downstream pipeline commits record 104
            collector.update_checkpoint(104)
            self.assertEqual(collector.current_checkpoint, 104)
            # Source file is STILL preserved because records 105 and 106 have not yet been completed
            self.assertTrue(os.path.exists(sim_file))

            # Cycle 2: Evaluates malformed witness (record 105) and halts
            with self.assertRaises(UnverifiedDiscontinuityError):
                collector.collect_once()

            # Malformed witness is quarantined, channel is halted
            self.assertTrue(collector.is_channel_quarantined())
            quar_file = os.path.join(collector.mailbox.quarantined_dir, "malformed_104_rec_105.json")
            self.assertTrue(os.path.exists(quar_file))
            # Source file MUST STILL be preserved on disk!
            self.assertTrue(os.path.exists(sim_file))

            # Checkpoint was advanced past malformed record 105 to mark it handled
            self.assertEqual(collector.current_checkpoint, 105)

            # Repeated call fails closed while quarantined
            with self.assertRaises(UnverifiedDiscontinuityError):
                collector.collect_once()

            # Authorized recovery lifts quarantine
            collector.resolve_channel_quarantine({"authorized_by": "sec_admin", "resolution_reason": "Recovery"})
            self.assertFalse(collector.is_channel_quarantined())

            # Cycle 3: Resumed collection processes the remaining event following the malformed witness (record 106)
            batch3 = collector.collect_once()
            self.assertEqual(len(batch3), 1)
            self.assertEqual(batch3[0]["record_id"], 106)
            self.assertEqual(batch3[0]["event_id"], 7036)
            # Source file preserved until downstream commitment
            self.assertTrue(os.path.exists(sim_file))

            # Downstream commits record 106
            collector.update_checkpoint(106)
            self.assertEqual(collector.current_checkpoint, 106)
            # Now that ALL events (104, 105, 106) have been safely handled, source file is unlinked!
            self.assertFalse(os.path.exists(sim_file))
        finally:
            config._checkpoint_dir = orig_chk
            config.data_dir = orig_data
            shutil.rmtree(temp_dir, ignore_errors=True)
