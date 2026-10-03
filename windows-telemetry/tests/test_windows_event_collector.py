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
