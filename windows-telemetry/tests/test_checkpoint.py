import unittest
import os
import tempfile
import shutil
import logging
from collectors.checkpoint import CheckpointManager

class TestCheckpointManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.logger = logging.getLogger("TestLogger")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_checkpoint_lifecycle(self):
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        self.assertEqual(cm.load_checkpoint(), 0)
        
        cm.save_checkpoint(100)
        self.assertEqual(cm.load_checkpoint(), 100)
        
        cm.save_checkpoint(250)
        self.assertEqual(cm.load_checkpoint(), 250)

    def test_corrupted_checkpoint(self):
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        cm.save_checkpoint(100)
        
        # Corrupt it
        with open(cm.checkpoint_file, "w", encoding="utf-8") as f:
            f.write("{invalid_json:")
            
        # Should fail safely and raise RuntimeError
        with self.assertRaises(RuntimeError):
            cm.load_checkpoint()
