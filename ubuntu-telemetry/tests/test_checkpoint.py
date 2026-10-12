import unittest
import os
import shutil
import tempfile
import logging
from core.checkpoint import CheckpointManager

class TestCheckpointManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.logger = logging.getLogger("TestCheckpoint")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_checkpoint_lifecycle(self):
        mgr = CheckpointManager(self.test_dir, "test_log", self.logger)
        init_state = mgr.load_checkpoint()
        self.assertEqual(init_state["last_offset"], 0)
        self.assertEqual(init_state["last_record_id"], 0)

        mgr.save_checkpoint(offset=1024, inode=9999, record_id=50)

        loaded = mgr.load_checkpoint()
        self.assertEqual(loaded["last_offset"], 1024)
        self.assertEqual(loaded["last_inode"], 9999)
        self.assertEqual(loaded["last_record_id"], 50)

    def test_corrupted_checkpoint_raises_runtime_error(self):
        mgr = CheckpointManager(self.test_dir, "test_log", self.logger)
        with open(mgr.checkpoint_file, "w", encoding="utf-8") as f:
            f.write("corrupted-not-json")

        with self.assertRaises(RuntimeError):
            mgr.load_checkpoint()

    def test_rotation_detection(self):
        # 1. Inode changed -> rotated
        self.assertTrue(CheckpointManager.is_rotated(current_inode=1002, current_size=500, saved_inode=1001, saved_offset=200))

        # 2. Size smaller than offset -> truncated/rotated
        self.assertTrue(CheckpointManager.is_rotated(current_inode=1001, current_size=100, saved_inode=1001, saved_offset=500))

        # 3. Normal progression -> not rotated
        self.assertFalse(CheckpointManager.is_rotated(current_inode=1001, current_size=800, saved_inode=1001, saved_offset=500))

if __name__ == "__main__":
    unittest.main()
