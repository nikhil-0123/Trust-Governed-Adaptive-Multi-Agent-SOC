import unittest
import tempfile
import shutil
import time
from core.agent_identity import AgentIdentity
from core.health import HealthMonitor

class TestHealthMonitor(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.agent = AgentIdentity(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_get_status(self):
        start_time = time.time() - 10 # Pretend it ran for 10 seconds
        monitor = HealthMonitor(self.agent, "1.0.0", start_time)
        status = monitor.get_status()
        
        self.assertEqual(status["status"], "healthy")
        self.assertEqual(status["agent_id"], self.agent.agent_id)
        self.assertEqual(status["hostname"], self.agent.get_hostname())
        self.assertEqual(status["os"], self.agent.get_os())
        self.assertEqual(status["version"], "1.0.0")
        self.assertTrue(status["uptime_seconds"] >= 10.0)
