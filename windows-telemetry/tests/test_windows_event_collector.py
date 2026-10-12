import unittest
import logging
from collectors.windows_event_collector import WindowsEventCollector

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
