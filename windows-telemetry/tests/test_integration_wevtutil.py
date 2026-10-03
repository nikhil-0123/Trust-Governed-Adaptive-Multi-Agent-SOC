import unittest
import platform
import subprocess
import logging
import tempfile
import shutil
from config.settings import config
from collectors.windows_event_collector import WindowsEventCollector

class TestWevtutilIntegration(unittest.TestCase):
    def test_wevtutil_access(self):
        if platform.system() != "Windows":
            self.skipTest("Integration test requires Windows")
            
        logger = logging.getLogger("TestLogger")
        collector = WindowsEventCollector(logger)
        
        # Override to test Application log since Security requires Admin sometimes
        collector.log_name = "Application"
        
        try:
            cmd = ["wevtutil", "qe", collector.log_name, "/c:1", "/rd:true", "/f:xml"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if result.stdout.strip():
                events = collector._parse_wevtutil_xml(result.stdout)
                self.assertTrue(len(events) <= 1)
                if len(events) == 1:
                    self.assertIn("record_id", events[0])
                    self.assertIn("timestamp", events[0])
        except subprocess.CalledProcessError as e:
            self.skipTest(f"Failed to query Application log. Permission issue? Stderr: {e.stderr}")

    def test_security_log_access(self):
        if platform.system() != "Windows":
            self.skipTest("Integration test requires Windows")
        
        try:
            cmd = ["wevtutil", "qe", "Security", "/c:1", "/rd:true", "/f:xml"]
            subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            self.skipTest(f"Insufficient permissions to read Security log. Run as Administrator. Stderr: {e.stderr}")
