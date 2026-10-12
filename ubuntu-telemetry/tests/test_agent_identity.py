import unittest
import os
import shutil
import tempfile
import json
from core.agent_identity import AgentIdentity

class TestAgentIdentity(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_identity_persistence(self):
        id_1 = AgentIdentity(self.test_dir)
        id_val_1 = id_1.agent_id
        self.assertTrue(bool(id_val_1))

        # Reinstantiate and verify persistence
        id_2 = AgentIdentity(self.test_dir)
        self.assertEqual(id_1.agent_id, id_2.agent_id)

    def test_corrupted_identity_file_recovers(self):
        identity_file = os.path.join(self.test_dir, "agent_identity.json")
        with open(identity_file, "w", encoding="utf-8") as f:
            f.write("{invalid-json")

        identity = AgentIdentity(self.test_dir)
        self.assertTrue(bool(identity.agent_id))

    def test_get_os_and_hostname(self):
        identity = AgentIdentity(self.test_dir)
        self.assertEqual(identity.get_os(), "Linux")
        self.assertTrue(len(identity.get_hostname()) > 0)
        self.assertTrue(len(identity.get_platform_info()) > 0)

if __name__ == "__main__":
    unittest.main()
