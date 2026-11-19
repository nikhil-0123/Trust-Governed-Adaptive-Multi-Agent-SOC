import unittest
import os
import tempfile
import shutil
from core.agent_identity import AgentIdentity

class TestAgentIdentity(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_identity_persistence(self):
        agent1 = AgentIdentity(self.test_dir)
        id1 = agent1.agent_id
        self.assertTrue(id1)
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "agent_identity.json")))

        # Reload the identity from the same directory to ensure it reads from disk
        agent2 = AgentIdentity(self.test_dir)
        self.assertEqual(id1, agent2.agent_id)

    def test_get_hostname(self):
        agent = AgentIdentity(self.test_dir)
        hostname = agent.get_hostname()
        self.assertTrue(isinstance(hostname, str))
        self.assertTrue(len(hostname) > 0)

    def test_get_os(self):
        agent = AgentIdentity(self.test_dir)
        os_name = agent.get_os()
        self.assertTrue(isinstance(os_name, str))
        self.assertTrue(len(os_name) > 0)
