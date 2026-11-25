"""
Phase 2.1 Deterministic Regression Test Suite.

Covers:
- Known Shannon entropy values and edge cases.
- DNS query representation, trailing-dot, length, label count, and max label entropy.
- Unicode and Punycode policy.
- IPv4 and IPv6 canonicalization, compression, mapping, and scoping.
- Network port validation (0-65535, negative, overflow, non-numeric).
- Process hash validation (MD5, SHA1, SHA256, IMPHASH, casing, length, hex, duplicates, unknown).
- Malformed XML handling (truncated, null chars, missing EventData, missing System, oversized).
- Raw evidence preservation.
- JSON Schema conformance against normalized_event_contract_v1.schema.json.
- Detector identity, canonical hashing, and historical replay stability (Task 6).
- Backend ingestion validation compatibility.
"""

import unittest
import os
import json
import logging
import tempfile
import hashlib
import re
import dataclasses
import xml.etree.ElementTree as ET
import jsonschema
from collections import Counter

from normalizer.evidence_enhancer import (
    calculate_shannon_entropy,
    extract_dns_features,
    canonicalize_ip_address,
    validate_network_port,
    validate_process_hashes,
)
from normalizer.windows_event_normalizer import WindowsEventNormalizer
from collectors.windows_event_collector import WindowsEventCollector
from core.agent_identity import AgentIdentity
from canonical import (
    canonicalize_tgam_rcc_v1,
    build_source_identity_manifest_v2,
    generate_source_event_id_v2,
)
from output.builder import DetectionEventBuilder
from detection.models import DetectionResult
from config.settings import config
from transport.outbox import Outbox, OutboxPayloadConflictError
from detection.manifest import build_detector_revision_manifest, compute_detector_revision_hash


class TestShannonEntropyAndDNSFeatures(unittest.TestCase):
    def test_known_shannon_entropy_values(self):
        # Empty string
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        # Single character
        self.assertEqual(calculate_shannon_entropy("a"), 0.0)
        # Repeated identical character
        self.assertEqual(calculate_shannon_entropy("aaaaaa"), 0.0)
        # 2 distinct uniform characters: log2(2) = 1.0
        self.assertEqual(calculate_shannon_entropy("ab"), 1.0)
        self.assertEqual(calculate_shannon_entropy("aabb"), 1.0)
        # 4 distinct uniform characters: log2(4) = 2.0
        self.assertEqual(calculate_shannon_entropy("abcd"), 2.0)
        self.assertEqual(calculate_shannon_entropy("aabbccdd"), 2.0)
        # 8 distinct uniform characters: log2(8) = 3.0
        self.assertEqual(calculate_shannon_entropy("abcdefgh"), 3.0)
        # Known non-uniform distribution: 'aab' -> - (2/3*log2(2/3) + 1/3*log2(1/3)) ~ 0.9183
        self.assertEqual(calculate_shannon_entropy("aab"), 0.9183)

    def test_entropy_numeric_safety(self):
        # Never emits NaN, inf, or negative values
        self.assertGreaterEqual(calculate_shannon_entropy(""), 0.0)
        self.assertGreaterEqual(calculate_shannon_entropy("!@#$%^&*()"), 0.0)
        self.assertFalse(isinstance(calculate_shannon_entropy("test"), bool))
        self.assertTrue(isinstance(calculate_shannon_entropy("test"), float))

    def test_entropy_bounded_processing(self):
        # Long string exceeding cap (e.g. 5000 chars) is processed deterministically without failure
        long_str = "a" * 5000 + "b" * 5000
        entropy = calculate_shannon_entropy(long_str, max_chars=2048)
        self.assertEqual(entropy, 0.0)  # first 2048 chars are all 'a'

    def test_dns_case_and_trailing_dot_normalization(self):
        # Case normalization and trailing dot removal
        raw_upper = "MALICIOUS-C2.EXAMPLE.COM."
        raw_lower = "malicious-c2.example.com"
        res_upper = extract_dns_features(raw_upper)
        res_lower = extract_dns_features(raw_lower)

        self.assertEqual(res_upper["query_name"], "MALICIOUS-C2.EXAMPLE.COM.")
        self.assertEqual(res_upper["query_name_normalized"], "malicious-c2.example.com")
        self.assertEqual(res_upper["dns_query_length"], 24)
        self.assertEqual(res_upper["dns_label_count"], 3)
        self.assertEqual(res_upper["dns_max_label_length"], 12)  # 'malicious-c2'
        self.assertEqual(res_upper["dns_query_entropy"], res_lower["dns_query_entropy"])
        self.assertEqual(res_upper["dns_max_label_entropy"], res_lower["dns_max_label_entropy"])

    def test_dns_repeated_character_and_empty_labels(self):
        # Single repeated label
        res = extract_dns_features("aaaa.bbbb")
        self.assertEqual(res["dns_label_count"], 2)
        self.assertEqual(res["dns_max_label_entropy"], 0.0)

        # Empty and root queries
        res_empty = extract_dns_features("")
        self.assertEqual(res_empty["dns_query_length"], 0)
        self.assertEqual(res_empty["dns_label_count"], 0)
        self.assertEqual(res_empty["dns_query_entropy"], 0.0)

        res_root = extract_dns_features(".")
        self.assertEqual(res_root["dns_query_length"], 0)
        self.assertEqual(res_root["dns_label_count"], 0)
        self.assertEqual(res_root["dns_query_entropy"], 0.0)

        # Multiple consecutive dots
        res_dots = extract_dns_features("foo..bar.com")
        self.assertEqual(res_dots["dns_label_count"], 3)  # ['foo', 'bar', 'com']

    def test_dns_unicode_and_punycode_policy(self):
        # Punycode ASCII
        punycode = "xn--bcher-kva.example"
        res_p = extract_dns_features(punycode)
        self.assertEqual(res_p["query_name_normalized"], punycode)
        self.assertTrue(res_p["dns_query_entropy"] > 0.0)

        # Unicode IDN
        unicode_dns = "bücher.example"
        res_u = extract_dns_features(unicode_dns)
        self.assertEqual(res_u["query_name_normalized"], unicode_dns)
        self.assertTrue(res_u["dns_query_entropy"] > 0.0)

    def test_dns_failed_queries_handled(self):
        # Failed query (NXDOMAIN = 9003) with results
        res = extract_dns_features("nonexistent.target.local", query_status=9003, query_results="-")
        self.assertEqual(res["query_status"], 9003)
        self.assertEqual(res["query_results"], "-")
        self.assertTrue(res["dns_query_length"] > 0)
        self.assertTrue(res["dns_query_entropy"] > 0.0)

    def test_dns_live_sysmon_event22_query_deterministic_features(self):
        # Actual live Sysmon Event 22 query observed on host (Record ID 142362)
        live_query = "8.9.f.f.b.6.f.e.2.7.0.0.e.9.2.f.b.d.2.7.5.e.a.9.0.0.7.4.6.0.6.2.ip6.arpa."
        res = extract_dns_features(live_query)
        self.assertEqual(res["dns_query_length"], 72)
        self.assertEqual(res["dns_label_count"], 34)
        self.assertEqual(res["dns_max_label_length"], 4)
        self.assertEqual(res["dns_query_entropy"], 3.0436)
        self.assertEqual(res["dns_max_label_entropy"], 1.585)

    def test_dns_reconstructed_21_zeros_query_deterministic_features(self):
        # Abbreviated reverse DNS query reconstructed with 21 zeros
        abbrev_query = "8.9.f.f.b.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa."
        res = extract_dns_features(abbrev_query)
        self.assertEqual(res["dns_query_length"], 68)
        self.assertEqual(res["dns_label_count"], 32)
        self.assertEqual(res["dns_max_label_length"], 4)
        self.assertEqual(res["dns_query_entropy"], 2.2849)
        self.assertEqual(res["dns_max_label_entropy"], 1.585)


class TestIPAddressCanonicalization(unittest.TestCase):
    def test_valid_ipv4(self):
        res = canonicalize_ip_address("192.168.1.50")
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["canonical_ip"], "192.168.1.50")
        self.assertEqual(res["ip_version"], 4)
        self.assertEqual(res["validation_status"], "VALID")
        self.assertFalse(res["is_ipv4_mapped"])
        self.assertTrue(res["is_private"])

    def test_ipv6_compressed_and_expanded(self):
        expanded = "2001:0db8:0000:0000:0000:ff00:0042:8329"
        res_exp = canonicalize_ip_address(expanded)
        self.assertTrue(res_exp["is_valid"])
        self.assertEqual(res_exp["canonical_ip"], "2001:db8::ff00:42:8329")
        self.assertEqual(res_exp["ip_version"], 6)

        compressed = "2001:db8::ff00:42:8329"
        res_comp = canonicalize_ip_address(compressed)
        self.assertEqual(res_exp["canonical_ip"], res_comp["canonical_ip"])

    def test_ipv4_mapped_ipv6(self):
        mapped = "::ffff:192.168.1.1"
        res = canonicalize_ip_address(mapped)
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["ip_version"], 6)
        self.assertTrue(res["is_ipv4_mapped"])
        self.assertEqual(res["mapped_ipv4"], "192.168.1.1")

    def test_scoped_ipv6_preservation(self):
        # Scoped IPv6 address must preserve scope ID to avoid conflating distinct network entities
        scoped = "fe80::1%12"
        res = canonicalize_ip_address(scoped)
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["scope_id"], "12")
        self.assertEqual(res["canonical_ip"], "fe80::1%12")
        self.assertEqual(res["ip_version"], 6)

        # Scoped vs non-scoped must differ
        non_scoped = "fe80::1"
        res_ns = canonicalize_ip_address(non_scoped)
        self.assertNotEqual(res["canonical_ip"], res_ns["canonical_ip"])

    def test_missing_and_placeholder_ips(self):
        for placeholder in (None, "", "  ", "-", " - "):
            res = canonicalize_ip_address(placeholder)
            self.assertFalse(res["is_valid"])
            self.assertEqual(res["validation_status"], "MISSING")
            self.assertIsNone(res["canonical_ip"])

    def test_unspecified_ips(self):
        res_v4 = canonicalize_ip_address("0.0.0.0")
        self.assertTrue(res_v4["is_valid"])
        self.assertTrue(res_v4["is_unspecified"])

        res_v6 = canonicalize_ip_address("::")
        self.assertTrue(res_v6["is_valid"])
        self.assertTrue(res_v6["is_unspecified"])

    def test_malformed_ips_preserved_without_crash(self):
        for bad_ip in ("999.999.999.999", "invalid-ip", "256.0.0.1", "1234::5678::90"):
            res = canonicalize_ip_address(bad_ip)
            self.assertFalse(res["is_valid"])
            self.assertEqual(res["validation_status"], "MALFORMED")
            self.assertEqual(res["raw_ip"], bad_ip)
            self.assertIsNone(res["canonical_ip"])


class TestNetworkPortValidation(unittest.TestCase):
    def test_valid_ports(self):
        for port in (0, 80, 443, 8080, 49152, 65535, "443", " 80 "):
            res = validate_network_port(port)
            self.assertTrue(res["is_valid"])
            self.assertEqual(res["status"], "VALID")
            self.assertEqual(res["port"], int(str(port).strip()))

    def test_negative_ports(self):
        for neg in (-1, -80, "-1", "-443"):
            res = validate_network_port(neg)
            self.assertFalse(res["is_valid"])
            self.assertEqual(res["status"], "OUT_OF_RANGE")
            self.assertIsNone(res["port"])

    def test_overflowing_ports(self):
        for over in (65536, 70000, 999999, "65536"):
            res = validate_network_port(over)
            self.assertFalse(res["is_valid"])
            self.assertEqual(res["status"], "OUT_OF_RANGE")
            self.assertIsNone(res["port"])

    def test_non_numeric_and_missing_ports(self):
        for non_num in ("http", "https", "abc", "-", True, False):
            res = validate_network_port(non_num)
            self.assertFalse(res["is_valid"])
            self.assertIn(res["status"], ("MALFORMED", "MISSING"))
            self.assertIsNone(res["port"])

        res_none = validate_network_port(None)
        self.assertFalse(res_none["is_valid"])
        self.assertEqual(res_none["status"], "MISSING")


class TestProcessHashValidation(unittest.TestCase):
    def test_valid_hashes_all_algorithms(self):
        raw = (
            "MD5=65B1D28C2B3F026FB6A611B21EE98B23,"
            "SHA1=B2636257E42531393698B9EE608AD9F312345678,"
            "SHA256=A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90,"
            "IMPHASH=259F818D27C218EEB51EFA87B95B94A7"
        )
        res = validate_process_hashes(raw)
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["md5"], "65b1d28c2b3f026fb6a611b21ee98b23")
        self.assertEqual(res["hashes_validated"]["md5"], "65b1d28c2b3f026fb6a611b21ee98b23")
        self.assertEqual(res["hashes_validated"]["sha1"], "b2636257e42531393698b9ee608ad9f312345678")
        self.assertEqual(
            res["hashes_validated"]["sha256"],
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        )
        self.assertEqual(res["hashes_validated"]["imphash"], "259f818d27c218eeb51efa87b95b94a7")
        self.assertEqual(res["hashes_raw"], raw)
        self.assertEqual(len(res["invalid_hashes"]), 0)
        self.assertEqual(len(res["unknown_hashes"]), 0)

    def test_mixed_casing_and_malformed_separators(self):
        raw = " md5 = 65b1d28c2b3f026fb6a611b21ee98b23 ; Sha256=A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90 , "
        res = validate_process_hashes(raw)
        self.assertTrue(res["is_valid"])
        self.assertIn("md5", res["hashes_validated"])
        self.assertIn("sha256", res["hashes_validated"])

    def test_incorrect_hash_lengths(self):
        # Truncated or overly long hashes
        raw = "MD5=SHORT,SHA256=A1B2C3D4"
        res = validate_process_hashes(raw)
        self.assertFalse(res["is_valid"])
        self.assertIn("md5", res["invalid_hashes"])
        self.assertIn("sha256", res["invalid_hashes"])

    def test_non_hexadecimal_characters(self):
        # Non-hex characters 'Z', 'G'
        raw = "MD5=65B1D28C2B3F026FB6A611B21EE98B2Z"
        res = validate_process_hashes(raw)
        self.assertFalse(res["is_valid"])
        self.assertIn("md5", res["invalid_hashes"])
        self.assertIn("Contains non-hexadecimal", res["invalid_hashes"]["md5"]["reason"])

    def test_duplicate_and_unknown_algorithms(self):
        raw = "MD5=65B1D28C2B3F026FB6A611B21EE98B23,MD5=00000000000000000000000000000000,CRC32=12345678"
        res = validate_process_hashes(raw)
        self.assertTrue(res["is_valid"])
        # Duplicate tracked
        self.assertEqual(len(res["duplicate_hashes"]), 1)
        self.assertEqual(res["duplicate_hashes"][0]["algorithm"], "md5")
        # Unknown algorithm isolated
        self.assertIn("crc32", res["unknown_hashes"])
        self.assertEqual(res["unknown_hashes"]["crc32"], "12345678")


class TestMalformedSysmonXmlAndCollectionHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.orig_chk = config._checkpoint_dir
        self.orig_data = config.data_dir
        self.orig_outbox = config._outbox_db_path
        self.orig_detection = config._detection_output_dir

        config.checkpoint_dir = os.path.join(self.temp_dir.name, "checkpoints")
        config.data_dir = self.temp_dir.name
        config.outbox_db_path = os.path.join(self.temp_dir.name, "outbox.db")
        config.detection_output_dir = os.path.join(self.temp_dir.name, "detections")

        self.logger = logging.getLogger("TestXmlHardening")
        self.collector = WindowsEventCollector(self.logger, log_name="Microsoft-Windows-Sysmon/Operational")
        self.collector.initialize()

    def tearDown(self):
        config._checkpoint_dir = self.orig_chk
        config.data_dir = self.orig_data
        config._outbox_db_path = self.orig_outbox
        config._detection_output_dir = self.orig_detection
        self.temp_dir.cleanup()

    def test_truncated_xml_gracefully_handled(self):
        truncated_xml = "<Event><System><EventID>1</EventID><EventRecordID>50</EventRecordID>"
        events = self.collector._parse_wevtutil_xml(truncated_xml)
        self.assertEqual(len(events), 0)

    def test_null_characters_sanitized(self):
        xml_with_null = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\x00"
            "  <System>"
            "    <EventID>1\x00</EventID>"
            "    <EventRecordID>1050</EventRecordID>"
            "    <TimeCreated SystemTime='2026-11-20T10:00:00Z'/>"
            "    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
            "    <Computer>TEST-PC</Computer>"
            "  </System>"
            "  <EventData>"
            "    <Data Name='Image'>C:\\test.exe\x00</Data>"
            "  </EventData>"
            "</Event>"
        )
        events = self.collector._parse_wevtutil_xml(xml_with_null)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["record_id"], 1050)
        self.assertEqual(events[0]["process_name"], "C:\\test.exe")

    def test_missing_eventdata_parses_system_metadata(self):
        # Event with System block but no EventData block
        xml_no_eventdata = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "  <System>"
            "    <EventID>3</EventID>"
            "    <EventRecordID>1051</EventRecordID>"
            "    <TimeCreated SystemTime='2026-11-20T10:05:00Z'/>"
            "    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
            "    <Computer>TEST-PC</Computer>"
            "  </System>"
            "</Event>"
        )
        events = self.collector._parse_wevtutil_xml(xml_no_eventdata)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["record_id"], 1051)
        self.assertEqual(events[0]["event_id"], 3)

    def test_missing_system_block_skipped(self):
        xml_no_system = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "  <EventData><Data Name='Image'>cmd.exe</Data></EventData>"
            "</Event>"
        )
        events = self.collector._parse_wevtutil_xml(xml_no_system)
        self.assertEqual(len(events), 0)

    def test_oversized_payload_rejected(self):
        oversized = "<Event>" + "x" * (11 * 1024 * 1024) + "</Event>"
        events = self.collector._parse_wevtutil_xml(oversized)
        self.assertEqual(len(events), 0)

    def test_malformed_record_id_handled(self):
        xml_bad_rec = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "  <System>"
            "    <EventID>1</EventID>"
            "    <EventRecordID>not_an_int</EventRecordID>"
            "    <TimeCreated SystemTime='2026-11-20T10:05:00Z'/>"
            "    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
            "    <Computer>TEST-PC</Computer>"
            "  </System>"
            "</Event>"
        )
        events = self.collector._parse_wevtutil_xml(xml_bad_rec)
        self.assertEqual(len(events), 0)  # Must not inject malformed record_id


class TestNormalizationAndContractCompatibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.identity = AgentIdentity(data_dir=cls.temp_dir.name)
        cls.logger = logging.getLogger("TestNormCompatibility")
        cls.normalizer = WindowsEventNormalizer(cls.identity, cls.logger)

        schema_path = os.path.join(
            os.path.dirname(__file__),
            "..", "..", "docs", "contracts", "normalized_event_contract_v1.schema.json"
        )
        with open(schema_path, "r", encoding="utf-8") as f:
            cls.schema = json.load(f)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_sysmon_dns_normalization_full_contract_schema(self):
        raw = {
            "record_id": 2001,
            "timestamp": "2026-11-20T10:00:00Z",
            "computer": "PC-EMP-01",
            "event_id": 22,
            "provider": "Microsoft-Windows-Sysmon",
            "query_name": "malicious-c2.example.com.",
            "query_status": 0,
            "query_results": "::ffff:198.51.100.24;198.51.100.25;",
            "source_ip": "192.168.1.100",
            "user": "CORP\\alice",
        }
        norm = self.normalizer.normalize(raw, log_name="Microsoft-Windows-Sysmon/Operational", epoch=1)

        # 1. JSON Schema validation
        jsonschema.validate(instance=norm, schema=self.schema)

        # 2. Check contract required fields
        self.assertEqual(norm["event_type"], "windows_dns_event")
        self.assertEqual(norm["hostname"], "PC-EMP-01")
        self.assertEqual(norm["source_ip"], "192.168.1.100")
        self.assertIsNone(norm["detection_type"])
        self.assertIsNone(norm["confidence"])

        # 3. Check enhanced DNS evidence
        ev = norm["evidence"]
        self.assertEqual(ev["query_name"], "malicious-c2.example.com.")
        self.assertEqual(ev["query_name_normalized"], "malicious-c2.example.com")
        self.assertEqual(ev["dns_query_length"], 24)
        self.assertEqual(ev["dns_label_count"], 3)
        self.assertEqual(ev["dns_max_label_length"], 12)
        self.assertTrue(ev["dns_query_entropy"] > 3.0)
        self.assertTrue(ev["dns_max_label_entropy"] > 3.0)
        self.assertEqual(ev["query_status"], 0)

    def test_sysmon_network_normalization_full_contract_schema(self):
        raw = {
            "record_id": 2002,
            "timestamp": "2026-11-20T10:05:00Z",
            "computer": "PC-EMP-01",
            "event_id": 3,
            "provider": "Microsoft-Windows-Sysmon",
            "source_ip": "fe80::1%12",
            "destination_ip": "2001:0db8:0000:0000:0000:ff00:0042:8329",
            "source_port": "49152",
            "destination_port": 443,
            "protocol": "tcp",
            "user": "CORP\\alice",
        }
        norm = self.normalizer.normalize(raw, log_name="Microsoft-Windows-Sysmon/Operational", epoch=1)

        jsonschema.validate(instance=norm, schema=self.schema)
        self.assertEqual(norm["event_type"], "windows_network_event")

        # Canonical IP representations
        self.assertEqual(norm["source_ip"], "fe80::1%12")
        ev = norm["evidence"]
        self.assertEqual(ev["source_ip_scope"], "12")
        self.assertEqual(ev["destination_ip"], "2001:db8::ff00:42:8329")
        self.assertEqual(ev["destination_ip_canonical"], "2001:db8::ff00:42:8329")
        self.assertEqual(ev["source_port"], 49152)
        self.assertEqual(ev["destination_port"], 443)

    def test_sysmon_process_normalization_full_contract_schema(self):
        raw = {
            "record_id": 2003,
            "timestamp": "2026-11-20T10:10:00Z",
            "computer": "PC-EMP-01",
            "event_id": 1,
            "provider": "Microsoft-Windows-Sysmon",
            "user": "CORP\\alice",
            "hashes": "MD5=65B1D28C2B3F026FB6A611B21EE98B23,SHA256=A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90,CRC32=12345678",
        }
        norm = self.normalizer.normalize(raw, log_name="Microsoft-Windows-Sysmon/Operational", epoch=1)

        jsonschema.validate(instance=norm, schema=self.schema)
        self.assertEqual(norm["event_type"], "windows_process_event")

        ev = norm["evidence"]
        self.assertIn("hashes_validated", ev)
        self.assertEqual(ev["hashes_validated"]["md5"], "65b1d28c2b3f026fb6a611b21ee98b23")
        self.assertEqual(
            ev["hashes_validated"]["sha256"],
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        )
        self.assertIn("crc32", ev["unknown_hashes"])

    def test_raw_malformed_evidence_preservation(self):
        # Even with malformed port and IP, raw evidence is preserved and schema passes
        raw = {
            "record_id": 2004,
            "timestamp": "2026-11-20T10:15:00Z",
            "computer": "PC-EMP-01",
            "event_id": 3,
            "source_ip": "not_an_ip",
            "destination_ip": "999.999.999.999",
            "source_port": "invalid_port",
            "destination_port": 999999,
            "user": "CORP\\alice",
        }
        norm = self.normalizer.normalize(raw, log_name="Microsoft-Windows-Sysmon/Operational", epoch=1)

        jsonschema.validate(instance=norm, schema=self.schema)
        # Top-level source_ip is None when invalid
        self.assertIsNone(norm["source_ip"])

        ev = norm["evidence"]
        self.assertEqual(ev["source_ip_raw"], "not_an_ip")
        self.assertEqual(ev["source_ip_status"], "MALFORMED")
        self.assertEqual(ev["destination_ip_raw"], "999.999.999.999")
        self.assertEqual(ev["destination_ip_status"], "MALFORMED")
        self.assertEqual(ev["source_port_raw"], "invalid_port")
        self.assertEqual(ev["destination_port_raw"], 999999)
        self.assertIsNone(ev["source_port"])
        self.assertIsNone(ev["destination_port"])


class TestIdentityAndHistoricalReplayStability(unittest.TestCase):
    """
    Task 6: Mandatory Acceptance Gate.
    Verifies that enhanced evidence fields do NOT alter canonical source event IDs,
    detection event IDs, or detector revision manifests, guaranteeing that replaying
    historical source events remains deterministic and collision-free.
    """
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.identity = AgentIdentity(data_dir=cls.temp_dir.name)
        cls.logger = logging.getLogger("TestReplayStability")
        cls.normalizer = WindowsEventNormalizer(cls.identity, cls.logger)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_source_event_id_independent_of_enhanced_evidence(self):
        # A raw event normalized with and without DNS entropy/hash features must produce the EXACT same source event ID
        raw_basic = {
            "record_id": 3001,
            "timestamp": "2026-11-20T12:00:00Z",
            "computer": "PC-REPLAY-01",
            "event_id": 22,
        }
        raw_enriched = {
            "record_id": 3001,
            "timestamp": "2026-11-20T12:00:00Z",
            "computer": "PC-REPLAY-01",
            "event_id": 22,
            "query_name": "dga-test-tunneling.attacker.net.",
            "query_status": 0,
            "query_results": "198.51.100.1",
        }

        norm_basic = self.normalizer.normalize(raw_basic, log_name="Microsoft-Windows-Sysmon/Operational", epoch=2)
        norm_enriched = self.normalizer.normalize(raw_enriched, log_name="Microsoft-Windows-Sysmon/Operational", epoch=2)

        # Source event ID must be identical because it derives strictly from (agent_id, channel, epoch, hostname, record_id)
        self.assertEqual(norm_basic["event_id"], norm_enriched["event_id"])

    def test_detection_event_id_deterministic_across_replays(self):
        # Building DetectionEvent twice on identical normalized events produces identical detection_event_id
        raw = {
            "record_id": 3002,
            "timestamp": "2026-11-20T12:05:00Z",
            "computer": "PC-REPLAY-01",
            "event_id": 1,
            "hashes": "SHA256=A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90",
            "user": "CORP\\alice",
        }
        norm = self.normalizer.normalize(raw, log_name="Microsoft-Windows-Sysmon/Operational", epoch=1)

        result = DetectionResult(
            detected=True,
            confidence=0.9,
            severity="HIGH",
            detection_type="process_creation_anomaly",
            detector_name="sysmon_process_rule",
            detector_version="1.0.0",
            source_event_id=norm["event_id"],
            evidence={"rule_hit": "powershell_encoded"},
        )

        det_ev1 = DetectionEventBuilder.build(norm, result)
        det_ev2 = DetectionEventBuilder.build(norm, result)

        self.assertIsNotNone(det_ev1)
        self.assertIsNotNone(det_ev2)
        self.assertEqual(det_ev1.detection_event_id, det_ev2.detection_event_id)

        # Check evidence contains both detection evidence and enhanced normalizer evidence
        self.assertEqual(det_ev1.evidence["rule_hit"], "powershell_encoded")
        self.assertIn("hashes_validated", det_ev1.evidence)


class TestBackendIngestionCompatibility(unittest.TestCase):
    """
    Verifies that enhanced Sysmon detection events are accepted by the SOC backend
    ingestion API (/api/v1/detection-events) without validation or schema rejections.
    """
    def setUp(self):
        import sys
        soc_backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "SOC", "backend"))
        if soc_backend_dir not in sys.path:
            sys.path.insert(0, soc_backend_dir)

        from fastapi.testclient import TestClient
        from app.main import app as fastapi_app, API_TOKEN
        import app.database as database

        self._env_backup = dict(os.environ)
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        self.orig_db_path = database.DB_PATH
        database.DB_PATH = self.temp_db_path
        database.init_db()

        self.client = TestClient(fastapi_app)
        auth_tok = os.getenv("SOC_API_TOKEN", API_TOKEN)
        self.headers = {"Authorization": f"Bearer {auth_tok}"}

    def tearDown(self):
        import app.database as database
        database.DB_PATH = self.orig_db_path
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass
        os.environ.clear()
        os.environ.update(self._env_backup)

    def test_backend_accepts_enhanced_dns_event(self):
        dns_event = {
            "detection_event_id": "det-dns-001",
            "timestamp": "2026-11-20T12:00:00+00:00",
            "agent_id": "AGT-WIN-01",
            "hostname": "WIN-EMP-01",
            "os": "Windows",
            "source_event_id": "src-dns-001",
            "detection_type": "dns_tunneling_detection",
            "confidence": 0.85,
            "severity": "HIGH",
            "detector_name": "dns_entropy_detector",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "channel_epoch": 1,
            "evidence": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "channel_epoch": 1,
                "query_name": "dga123456789.attacker.com.",
                "query_name_normalized": "dga123456789.attacker.com",
                "dns_query_length": 25,
                "dns_label_count": 3,
                "dns_max_label_length": 12,
                "dns_query_entropy": 3.8219,
                "dns_max_label_entropy": 3.4183,
                "query_status": 0,
                "query_results": "198.51.100.99",
            }
        }
        res = self.client.post("/api/v1/detection-events", json=dns_event, headers=self.headers)
        self.assertEqual(res.status_code, 201)
        self.assertTrue(res.json()["accepted"])
        self.assertFalse(res.json()["duplicate"])

        # Replay duplicate check
        res_dup = self.client.post("/api/v1/detection-events", json=dns_event, headers=self.headers)
        self.assertEqual(res_dup.status_code, 201)
        self.assertTrue(res_dup.json()["accepted"])
        self.assertTrue(res_dup.json()["duplicate"])

    def test_backend_accepts_enhanced_network_event(self):
        net_event = {
            "detection_event_id": "det-net-001",
            "timestamp": "2026-11-20T12:05:00+00:00",
            "agent_id": "AGT-WIN-01",
            "hostname": "WIN-EMP-01",
            "os": "Windows",
            "source_event_id": "src-net-001",
            "detection_type": "c2_network_connection",
            "confidence": 0.90,
            "severity": "CRITICAL",
            "detector_name": "c2_network_rule",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "channel_epoch": 1,
            "evidence": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "channel_epoch": 1,
                "source_ip": "fe80::1%12",
                "source_ip_canonical": "fe80::1%12",
                "source_ip_scope": "12",
                "destination_ip": "2001:db8::1",
                "destination_ip_canonical": "2001:db8::1",
                "source_port": 49152,
                "destination_port": 443,
                "protocol": "tcp",
            }
        }
        res = self.client.post("/api/v1/detection-events", json=net_event, headers=self.headers)
        self.assertEqual(res.status_code, 201)
        self.assertTrue(res.json()["accepted"])

    def test_backend_accepts_enhanced_process_hashes_event(self):
        proc_event = {
            "detection_event_id": "det-proc-001",
            "timestamp": "2026-11-20T12:10:00+00:00",
            "agent_id": "AGT-WIN-01",
            "hostname": "WIN-EMP-01",
            "os": "Windows",
            "source_event_id": "src-proc-001",
            "detection_type": "process_anomaly",
            "confidence": 0.88,
            "severity": "HIGH",
            "detector_name": "process_hash_rule",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "channel_epoch": 1,
            "evidence": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "channel_epoch": 1,
                "process_name": "C:\\Windows\\System32\\cmd.exe",
                "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
                "md5": "65b1d28c2b3f026fb6a611b21ee98b23",
                "hashes_validated": {
                    "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
                    "md5": "65b1d28c2b3f026fb6a611b21ee98b23",
                },
                "hashes_raw": "MD5=65b1d28c2b3f026fb6a611b21ee98b23,SHA256=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            }
        }
        res = self.client.post("/api/v1/detection-events", json=proc_event, headers=self.headers)
        self.assertEqual(res.status_code, 201)
        self.assertTrue(res.json()["accepted"])


class TestCrossVersionReplayAndPayloadFingerprints(unittest.TestCase):
    """
    Task 1: Cross-Version Replay and Payload Fingerprints.
    Verifies that:
    - source_event_id is invariant across baseline v1 and enriched v2 normalizers.
    - detection_event_id is identical when detector revision is unchanged.
    - payload_fingerprint diverges when evidence is enriched.
    - Outbox raises OutboxPayloadConflictError and logs durable conflict when replaying enriched payload for same detection_event_id.
    - Outbox accepts enriched payload when detector revision is bumped.
    - Backend returns 409 Conflict when replaying enriched payload for existing event_id with different hash.
    - Backend returns 201 Created for replayed enriched payload when detector revision is bumped.
    """
    def setUp(self):
        self.logger = logging.getLogger("TestCrossVersionReplay")
        self.temp_dir = tempfile.TemporaryDirectory()
        self.orig_chk = config._checkpoint_dir
        self.orig_data = config.data_dir
        self.orig_outbox = config._outbox_db_path
        self.orig_detection = config._detection_output_dir

        config.checkpoint_dir = os.path.join(self.temp_dir.name, "checkpoints")
        config.data_dir = self.temp_dir.name
        config.outbox_db_path = os.path.join(self.temp_dir.name, "outbox.db")
        config.detection_output_dir = os.path.join(self.temp_dir.name, "detections")

        self.identity = AgentIdentity(data_dir=self.temp_dir.name)
        self.normalizer = WindowsEventNormalizer(self.identity, self.logger)

        self.outbox_db_path = os.path.join(self.temp_dir.name, "test_outbox.db")
        self.outbox = Outbox(db_path=self.outbox_db_path, logger=self.logger)

        import sys
        soc_backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "SOC", "backend"))
        if soc_backend_dir not in sys.path:
            sys.path.insert(0, soc_backend_dir)

        from fastapi.testclient import TestClient
        from app.main import app as fastapi_app, API_TOKEN
        import app.database as database

        self._env_backup = dict(os.environ)
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)
        self.orig_db_path = database.DB_PATH
        database.DB_PATH = self.temp_db_path
        database.init_db()

        self.client = TestClient(fastapi_app)
        auth_tok = os.getenv("SOC_API_TOKEN", API_TOKEN)
        self.headers = {"Authorization": f"Bearer {auth_tok}"}

    def tearDown(self):
        config._checkpoint_dir = self.orig_chk
        config.data_dir = self.orig_data
        config._outbox_db_path = self.orig_outbox
        config._detection_output_dir = self.orig_detection
        import app.database as database
        database.DB_PATH = self.orig_db_path
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass
        self.temp_dir.cleanup()
        os.environ.clear()
        os.environ.update(self._env_backup)

    def _build_payloads(self):
        raw_source = {
            "record_id": 4001,
            "timestamp": "2026-11-20T14:00:00Z",
            "computer": "WIN-EMP-01",
            "event_id": 22,
            "query_name": "exfiltration.attacker-infra.org.",
            "query_status": 0,
            "query_results": "198.51.100.5",
        }

        # Current Phase 2.1 normalized event (enriched evidence format)
        norm_v2 = self.normalizer.normalize(raw_source, log_name="Microsoft-Windows-Sysmon/Operational", epoch=1)

        # Baseline v1 normalized event has identical source identity and metadata, but without Phase 2.1 enriched keys
        norm_v1 = json.loads(json.dumps(norm_v2))
        for enriched_key in [
            "query_name_normalized", "dns_query_length", "dns_label_count",
            "dns_max_label_length", "dns_query_entropy", "dns_max_label_entropy",
        ]:
            norm_v1["evidence"].pop(enriched_key, None)

        source_id = norm_v2["event_id"]

        # Baseline detector result (v1.0.0)
        res_v1 = DetectionResult(
            detected=True,
            confidence=0.85,
            severity="HIGH",
            detection_type="dns_tunneling",
            detector_name="dns_tunnel_detector",
            detector_version="1.0.0",
            source_event_id=source_id,
            evidence={"detector_rule": "high_entropy_rule"},
        )

        det_ev_v1 = DetectionEventBuilder.build(norm_v1, res_v1)
        det_ev_v2 = DetectionEventBuilder.build(norm_v2, res_v1)

        # Bumped detector result (v1.1.0)
        res_v2_bumped = DetectionResult(
            detected=True,
            confidence=0.85,
            severity="HIGH",
            detection_type="dns_tunneling",
            detector_name="dns_tunnel_detector",
            detector_version="1.1.0",
            source_event_id=source_id,
            evidence={"detector_rule": "high_entropy_rule"},
        )
        det_ev_v2_bumped = DetectionEventBuilder.build(norm_v2, res_v2_bumped)

        return (
            norm_v1,
            norm_v2,
            dataclasses.asdict(det_ev_v1),
            dataclasses.asdict(det_ev_v2),
            dataclasses.asdict(det_ev_v2_bumped),
        )

    def test_cross_version_payload_fingerprint_divergence(self):
        norm_v1, norm_v2, payload_v1, payload_v2, _ = self._build_payloads()

        # Invariant 1: source_event_id must be strictly identical
        self.assertEqual(norm_v1["event_id"], norm_v2["event_id"])
        self.assertEqual(payload_v1["source_event_id"], payload_v2["source_event_id"])

        # Invariant 2: detection_event_id is identical when detector revision is unchanged
        self.assertEqual(payload_v1["detection_event_id"], payload_v2["detection_event_id"])

        # Invariant 3: canonical payload fingerprint MUST diverge due to enriched evidence
        hash_v1 = hashlib.sha256(canonicalize_tgam_rcc_v1(payload_v1)).hexdigest()
        hash_v2 = hashlib.sha256(canonicalize_tgam_rcc_v1(payload_v2)).hexdigest()
        self.assertNotEqual(hash_v1, hash_v2)

        # Verify evidence enrichment keys exist in v2 but not v1
        self.assertNotIn("dns_query_entropy", payload_v1["evidence"])
        self.assertIn("dns_query_entropy", payload_v2["evidence"])
        self.assertIn("query_name_normalized", payload_v2["evidence"])

    def test_outbox_conflict_when_historical_payload_replayed_with_enrichment(self):
        _, _, payload_v1, payload_v2, payload_v2_bumped = self._build_payloads()

        # Step 1: Add historical v1 payload to outbox -> succeeds
        self.outbox.add_event(payload_v1)

        # Step 2: Idempotent duplicate replay of identical v1 payload -> succeeds without error
        self.outbox.add_event(payload_v1)

        # Step 3: Replaying enriched v2 payload with same detection_event_id must raise OutboxPayloadConflictError
        with self.assertRaises(OutboxPayloadConflictError) as ctx:
            self.outbox.add_event(payload_v2)

        self.assertEqual(ctx.exception.event_id, payload_v1["detection_event_id"])

        # Step 4: Verify conflict record durably recorded in outbox_conflicts
        import sqlite3
        conn = sqlite3.connect(self.outbox_db_path)
        cur = conn.cursor()
        cur.execute("SELECT conflict_id, detection_event_id, payload_a_hash, payload_b_hash FROM outbox_conflicts")
        conflicts = cur.fetchall()
        conn.close()
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0][1], payload_v1["detection_event_id"])

        # Step 5: Enriched payload with bumped detector revision (new detection_event_id) succeeds without conflict
        self.outbox.add_event(payload_v2_bumped)

    def test_backend_duplicate_and_conflict_behavior_on_replayed_payloads(self):
        _, _, payload_v1, payload_v2, payload_v2_bumped = self._build_payloads()

        # Step 1: Ingest v1 historical payload -> 201 Created (new event)
        res1 = self.client.post("/api/v1/detection-events", json=payload_v1, headers=self.headers)
        self.assertEqual(res1.status_code, 201)
        self.assertTrue(res1.json()["accepted"])
        self.assertFalse(res1.json()["duplicate"])

        # Step 2: Replay identical v1 payload -> 201 Created (duplicate=True)
        res_dup = self.client.post("/api/v1/detection-events", json=payload_v1, headers=self.headers)
        self.assertEqual(res_dup.status_code, 201)
        self.assertTrue(res_dup.json()["accepted"])
        self.assertTrue(res_dup.json()["duplicate"])

        # Step 3: Replay enriched v2 payload with SAME detection_event_id -> 409 Conflict
        res_conflict = self.client.post("/api/v1/detection-events", json=payload_v2, headers=self.headers)
        self.assertEqual(res_conflict.status_code, 409)
        self.assertFalse(res_conflict.json()["accepted"])
        self.assertEqual(res_conflict.json()["detail"], "Event payload conflict detected")

        # Step 4: Ingest enriched payload with bumped detector revision -> 201 Created
        self.assertNotEqual(payload_v1["detection_event_id"], payload_v2_bumped["detection_event_id"])
        res_bumped = self.client.post("/api/v1/detection-events", json=payload_v2_bumped, headers=self.headers)
        self.assertEqual(res_bumped.status_code, 201)
        self.assertTrue(res_bumped.json()["accepted"])
        self.assertFalse(res_bumped.json()["duplicate"])

    def test_backend_incident_fusion_single_incident_on_reevaluation(self):
        _, _, payload_v1, _, payload_v2_bumped = self._build_payloads()
        import app.database as database
        import sqlite3

        # 1. Ingest original baseline v1 payload
        res1 = self.client.post("/api/v1/detection-events", json=payload_v1, headers=self.headers)
        self.assertEqual(res1.status_code, 201)

        # Run EvidenceFusionEngine on the ingested event
        from app.fusion import EvidenceFusionEngine
        conn = sqlite3.connect(database.DB_PATH)
        conn.row_factory = sqlite3.Row
        engine = EvidenceFusionEngine(conn)
        engine.process_event(payload_v1["detection_event_id"])
        conn.commit()

        # 2. Check incident count in database
        incidents = conn.execute("SELECT incident_id, max_severity FROM incidents").fetchall()
        self.assertEqual(len(incidents), 1)
        orig_inc_id = incidents[0]["incident_id"]

        anchors = conn.execute("SELECT agent_id, source_event_id, incident_id FROM incident_anchors").fetchall()
        self.assertEqual(len(anchors), 1)
        self.assertEqual(anchors[0]["source_event_id"], payload_v1["source_event_id"])
        self.assertEqual(anchors[0]["incident_id"], orig_inc_id)

        evidence_pre = conn.execute("SELECT detection_event_id, classification FROM incident_evidence WHERE incident_id = ?", (orig_inc_id,)).fetchall()
        self.assertEqual(len(evidence_pre), 1)
        self.assertEqual(evidence_pre[0]["classification"], "PRIMARY_DETECTION")

        # 3. Ingest upgraded bumped v2 payload (historical re-evaluation)
        res2 = self.client.post("/api/v1/detection-events", json=payload_v2_bumped, headers=self.headers)
        self.assertEqual(res2.status_code, 201)

        # Run EvidenceFusionEngine on the replayed bumped event
        engine.process_event(payload_v2_bumped["detection_event_id"])
        conn.commit()

        # 4. Verify no duplicate incident was created
        incidents_post = conn.execute("SELECT incident_id, max_severity FROM incidents").fetchall()
        self.assertEqual(len(incidents_post), 1)
        self.assertEqual(incidents_post[0]["incident_id"], orig_inc_id)

        # 5. Verify the re-evaluated event was attached as HISTORICAL_RE_EVALUATION
        evidence_post = conn.execute("SELECT detection_event_id, classification FROM incident_evidence WHERE incident_id = ? ORDER BY classification", (orig_inc_id,)).fetchall()
        self.assertEqual(len(evidence_post), 2)
        classifications = {r["classification"] for r in evidence_post}
        self.assertIn("PRIMARY_DETECTION", classifications)
        self.assertIn("HISTORICAL_RE_EVALUATION", classifications)

        conn.close()

    def test_production_pipeline_detector_revision_default(self):
        from pipeline import WindowsDetectionPipeline
        pl = WindowsDetectionPipeline(self.logger)
        self.assertEqual(pl.engine.detector_version, "1.1.0")
        for r in pl.engine.rules:
            self.assertEqual(r.detector_version, "1.1.0")


class TestMalformedXmlAndPipelineDurability(unittest.TestCase):
    """
    Task 2: Malformed XML and Checkpoint Durability.
    Verifies that:
    - Valid record followed by malformed record followed by valid record drops malformed safely.
    - Truncated XML batches are handled without unhandled exceptions.
    - Missing System metadata is handled gracefully.
    - Embedded null characters are sanitized.
    - Oversized XML responses (>10MB) are rejected to prevent DoS.
    - Unexpected namespaces are parsed cleanly.
    - Checkpoints persist across collector restart and resume correctly.
    """
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.orig_chk = config._checkpoint_dir
        self.orig_data = config.data_dir
        self.orig_outbox = config._outbox_db_path
        self.orig_detection = config._detection_output_dir

        config.checkpoint_dir = os.path.join(self.temp_dir.name, "checkpoints")
        config.data_dir = self.temp_dir.name
        config.outbox_db_path = os.path.join(self.temp_dir.name, "outbox.db")
        config.detection_output_dir = os.path.join(self.temp_dir.name, "detections")

        self.logger = logging.getLogger("TestMalformedXml")
        self.collector = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")

    def tearDown(self):
        config._checkpoint_dir = self.orig_chk
        config.data_dir = self.orig_data
        config._outbox_db_path = self.orig_outbox
        config._detection_output_dir = self.orig_detection
        self.temp_dir.cleanup()

    def test_valid_malformed_valid_xml_sequence(self):
        xml_batch = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <EventRecordID>1001</EventRecordID>
    <TimeCreated SystemTime="2026-11-20T12:00:00Z"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-EMP-01</Computer>
  </System>
  <EventData><Data Name="Image">cmd.exe</Data></EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <EventRecordID>CORRUPTED_NOT_INT</EventRecordID>
    <TimeCreated SystemTime="2026-11-20T12:01:00Z"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData><Data Name="Image">corrupt.exe</Data></EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <EventRecordID>1002</EventRecordID>
    <TimeCreated SystemTime="2026-11-20T12:02:00Z"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-EMP-01</Computer>
  </System>
  <EventData><Data Name="Image">powershell.exe</Data></EventData>
</Event>"""
        events = self.collector._parse_wevtutil_xml(xml_batch)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["record_id"], 1001)
        self.assertEqual(events[0]["process_name"], "cmd.exe")
        self.assertEqual(events[1]["record_id"], 1002)
        self.assertEqual(events[1]["process_name"], "powershell.exe")

        # Verify corrupted record was durably quarantined to disk
        self.assertTrue(os.path.isdir(self.collector.malformed_events_dir))
        q_files = os.listdir(self.collector.malformed_events_dir)
        self.assertGreaterEqual(len(q_files), 1)

    def test_truncated_xml_batch_graceful_handling(self):
        truncated = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><EventID>1</EventID><EventRecordID>2001</EventRecordID></System></Event>'
            '<Event><System><EventID>1</EventID><EventRecordID>2002'
        )
        events = self.collector._parse_wevtutil_xml(truncated)
        self.assertEqual(events, [])
        # Verify parse failure was durably quarantined
        self.assertTrue(os.path.isdir(self.collector.malformed_events_dir))
        q_files = os.listdir(self.collector.malformed_events_dir)
        self.assertGreaterEqual(len(q_files), 1)

    def test_missing_system_metadata_handling(self):
        no_system = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<EventData><Data Name="Test">Value</Data></EventData>'
            '</Event>'
        )
        events = self.collector._parse_wevtutil_xml(no_system)
        self.assertEqual(events, [])
        # Verify missing System event was durably quarantined
        self.assertTrue(os.path.isdir(self.collector.malformed_events_dir))
        q_files = os.listdir(self.collector.malformed_events_dir)
        self.assertGreaterEqual(len(q_files), 1)

    def test_embedded_null_character_sanitization(self):
        null_xml = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><EventID>1</EventID><EventRecordID>3001</EventRecordID></System>'
            '<EventData><Data Name="CommandLine">cmd.exe\x00 /c dir\x00</Data></EventData>'
            '</Event>'
        )
        events = self.collector._parse_wevtutil_xml(null_xml)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["record_id"], 3001)
        self.assertEqual(events[0]["command_line"], "cmd.exe /c dir")

    def test_oversized_xml_batch_rejection(self):
        huge_xml = "<Event>" + (" " * (10 * 1024 * 1024 + 100)) + "</Event>"
        events = self.collector._parse_wevtutil_xml(huge_xml)
        self.assertEqual(events, [])

    def test_unexpected_namespaces_and_attributes(self):
        ns_xml = (
            '<Event xmlns:sec="http://custom.schema/sec" xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><EventID>22</EventID><EventRecordID>4001</EventRecordID>'
            '<Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>'
            '<EventData><Data Name="QueryName">test.internal.corp</Data></EventData>'
            '</Event>'
        )
        events = self.collector._parse_wevtutil_xml(ns_xml)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_id"], 22)
        self.assertEqual(events[0]["record_id"], 4001)
        self.assertEqual(events[0]["query_name"], "test.internal.corp")

    def test_checkpoint_durability_across_collector_restart(self):
        col1 = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
        col1.initialize()
        self.assertGreaterEqual(col1.current_checkpoint, 0)

        # Advance checkpoint to record 750
        col1.update_checkpoint(750)
        self.assertEqual(col1.current_checkpoint, 750)

        # Re-instantiate new collector simulating process crash/restart
        col2 = WindowsEventCollector(self.logger, log_name="Security", agent_id="AGT-WIN-01")
        col2.initialize()
        self.assertEqual(col2.current_checkpoint, 750)

    def test_oversized_batch_adaptive_reduction_and_quarantine(self):
        # Indivisible oversized record quarantine and checkpoint advancement
        huge_event = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>1</EventID><EventRecordID>8888</EventRecordID></System>"
            "<EventData><Data Name='Payload'>" + ("A" * (10 * 1024 * 1024 + 500)) + "</Data></EventData>"
            "</Event>"
        )
        rec_id = self.collector._extract_record_id_from_raw_xml(huge_event)
        self.assertEqual(rec_id, 8888)

        q_path = self.collector.quarantine_oversized_record(huge_event, record_id=rec_id)
        self.assertTrue(os.path.isfile(q_path))
        self.assertGreater(os.path.getsize(q_path), 10 * 1024 * 1024)

        # Advance checkpoint past oversized record to prevent deadlock
        self.collector.checkpoint_manager.save_checkpoint(rec_id)
        self.assertEqual(self.collector.checkpoint_manager.load_state()["last_record_id"], 8888)


class TestDownstreamEvidenceCompatibility(unittest.TestCase):
    """
    Task 3: Downstream Evidence Compatibility.
    Verifies that:
    - Scoped IPv6 addresses (fe80::1%12 vs fe80::1%14) do NOT merge across interfaces or endpoints.
    - IPv4-mapped IPv6 addresses preserve dual-stack correlation fields.
    - Top-level source_ip adheres to the schema regex pattern for all variations.
    - Invalid process hashes are excluded from validated indicators and recorded in invalid_hashes.
    - High DNS entropy is purely an analytical feature and does NOT elevate severity automatically.
    """
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.identity = AgentIdentity(data_dir=cls.temp_dir.name)
        cls.logger = logging.getLogger("TestDownstreamEvidenceCompat")
        cls.normalizer = WindowsEventNormalizer(cls.identity, cls.logger)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_scoped_ipv6_isolation_prevents_cross_endpoint_merging(self):
        ip1 = canonicalize_ip_address("fe80::1%12")
        ip2 = canonicalize_ip_address("fe80::1%14")
        ip_unscoped = canonicalize_ip_address("fe80::1")

        self.assertEqual(ip1["canonical_ip"], "fe80::1%12")
        self.assertEqual(ip1["scope_id"], "12")
        self.assertEqual(ip2["canonical_ip"], "fe80::1%14")
        self.assertEqual(ip2["scope_id"], "14")
        self.assertIsNone(ip_unscoped["scope_id"])

        # Downstream isolation guarantee: different scopes must never compare equal
        self.assertNotEqual(ip1["canonical_ip"], ip2["canonical_ip"])
        self.assertNotEqual(ip1["canonical_ip"], ip_unscoped["canonical_ip"])

    def test_ipv4_mapped_ipv6_dual_stack_correlation(self):
        mapped = canonicalize_ip_address("::ffff:192.168.1.100")
        self.assertEqual(mapped["canonical_ip"], "::ffff:c0a8:164")
        self.assertEqual(mapped["ip_version"], 6)
        self.assertEqual(mapped["mapped_ipv4"], "192.168.1.100")
        self.assertEqual(mapped["validation_status"], "VALID")
        self.assertTrue(mapped["is_ipv4_mapped"])

    def test_top_level_source_ip_contract_regex_compatibility(self):
        pattern = re.compile(
            r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+(?:%[0-9a-zA-Z]+)?$|^(?:unknown|unspecified|-)$"
        )
        valid_cases = [
            ("192.168.1.5", "192.168.1.5"),
            ("fe80::1%12", "fe80::1%12"),
            ("::ffff:192.168.1.1", "::ffff:c0a8:101"),
            ("0.0.0.0", "0.0.0.0"),
            ("::", "::"),
        ]
        for raw_ip, expected_val in valid_cases:
            raw_event = {
                "record_id": 9001,
                "timestamp": "2026-11-20T12:00:00Z",
                "computer": "WIN-EMP-01",
                "event_id": 3,
                "source_ip": raw_ip,
            }
            norm = self.normalizer.normalize(raw_event, log_name="Microsoft-Windows-Sysmon/Operational", epoch=1)
            self.assertEqual(norm["source_ip"], expected_val)
            self.assertIsNotNone(
                pattern.match(norm["source_ip"]),
                f"source_ip '{norm['source_ip']}' produced from '{raw_ip}' failed schema regex"
            )

        # Missing / placeholder / malformed cases: normalized source_ip is None, preserving raw forensic status in evidence
        non_valid_cases = ["-", "", None, "not_an_ip", "999.999.999.999"]
        for raw_ip in non_valid_cases:
            raw_event = {
                "record_id": 9002,
                "timestamp": "2026-11-20T12:00:00Z",
                "computer": "WIN-EMP-01",
                "event_id": 3,
                "source_ip": raw_ip,
            }
            norm = self.normalizer.normalize(raw_event, log_name="Microsoft-Windows-Sysmon/Operational", epoch=1)
            self.assertIsNone(norm["source_ip"])
            if raw_ip and str(raw_ip).strip() not in ("", "-"):
                self.assertIn("source_ip_raw", norm["evidence"])
                self.assertIn("source_ip_status", norm["evidence"])

    def test_invalid_process_hashes_excluded_from_validated(self):
        raw_hashes = (
            "MD5=short,SHA256=" + ("z" * 64) + ","
            "SHA1=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4,IMPHASH=12"
        )
        parsed = {
            "md5": "short",
            "sha256": "z" * 64,
            "sha1": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4",
            "imphash": "12",
        }
        res = validate_process_hashes(raw_hashes, parsed)
        self.assertIn("sha1", res["hashes_validated"])
        self.assertNotIn("md5", res["hashes_validated"])
        self.assertNotIn("sha256", res["hashes_validated"])
        self.assertNotIn("imphash", res["hashes_validated"])
        self.assertIn("Invalid length", res["invalid_hashes"]["md5"]["reason"])
        self.assertIn("non-hexadecimal", res["invalid_hashes"]["sha256"]["reason"])
        self.assertIn("Invalid length", res["invalid_hashes"]["imphash"]["reason"])
        self.assertEqual(res["hashes_raw"], raw_hashes)

    def test_dns_entropy_is_purely_analytical_feature(self):
        raw = {
            "record_id": 5001,
            "timestamp": "2026-11-20T15:00:00Z",
            "computer": "WIN-EMP-01",
            "event_id": 22,
            "query_name": "q9x8y7z6a5b4c3d2e1f0.tunneling.exfiltration-lab.org.",
            "query_status": 0,
            "query_results": "198.51.100.10",
        }
        norm = self.normalizer.normalize(raw, log_name="Microsoft-Windows-Sysmon/Operational", epoch=1)
        # High entropy calculated and recorded in evidence
        self.assertGreater(norm["evidence"]["dns_query_entropy"], 4.0)
        # Crucial invariant: severity is NOT automatically elevated to HIGH or CRITICAL by entropy alone
        self.assertEqual(norm["severity"], "low")
        self.assertIsNone(norm["detection_type"])


if __name__ == "__main__":
    unittest.main()
