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

    def test_channel_boundary_permission_enforcement(self):
        """CheckpointManager for Security cannot mutate System and vice versa."""
        cm_sec = CheckpointManager(self.test_dir, "Security", self.logger)
        with self.assertRaises(PermissionError):
            cm_sec.save_checkpoint(100, target_channel="System")
            
        with self.assertRaises(PermissionError):
            cm_sec.advance_epoch(new_epoch=2, target_channel="System")

    def test_epoch_advancement_and_atomic_transition_registration(self):
        """Epoch advances monotonically and embeds transition marker in the same atomic commit."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        self.assertEqual(cm.get_current_epoch(), 1)
        self.assertEqual(cm.load_checkpoint(), 0)
        
        cm.save_checkpoint(500)
        self.assertEqual(cm.load_checkpoint(), 500)
        
        t_id = "374c2fd35d27e045cd646c0472cd7a3422161b6dc7812dc3d564a2404f40be44"
        self.assertFalse(cm.is_transition_applied(t_id))
        
        new_epoch = cm.advance_epoch(
            reset_record_id=0,
            transition_id=t_id,
            transition_metadata={"source_channel": "System", "source_epoch": 2}
        )
        self.assertEqual(new_epoch, 2)
        self.assertEqual(cm.get_current_epoch(), 2)
        self.assertEqual(cm.load_checkpoint(), 0)
        self.assertTrue(cm.is_transition_applied(t_id))
        
        # Backward epoch advancement must raise ValueError
        with self.assertRaises(ValueError):
            cm.advance_epoch(new_epoch=1)

    def test_legacy_v1_checkpoint_migration(self):
        """Legacy flat checkpoint without epoch or applied_transitions defaults safely."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        # Write flat legacy format
        with open(cm.checkpoint_file, "w", encoding="utf-8") as f:
            f.write('{"log_name": "Security", "last_record_id": 45000}')
            
        self.assertEqual(cm.load_checkpoint(), 45000)
        self.assertEqual(cm.get_current_epoch(), 1)
        self.assertFalse(cm.is_transition_applied("dummy_id"))

    def test_ledger_compaction_and_watermark_progression(self):
        """Applied transitions are pruned up to source-channel threshold and watermark updates atomically."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        # Advance to epoch 2 with transition 1
        cm.advance_epoch(reset_record_id=0, transition_id="t1", transition_metadata={"agent_id": "AGT-WIN-01", "source_channel": "System", "source_epoch": 1, "source_record_id": 100})
        # Advance to epoch 3 with transition 2
        cm.advance_epoch(reset_record_id=0, transition_id="t2", transition_metadata={"agent_id": "AGT-WIN-01", "source_channel": "System", "source_epoch": 2, "source_record_id": 200})
        self.assertEqual(cm.get_current_epoch(), 3)
        self.assertTrue(cm.is_transition_applied("t1"))
        self.assertTrue(cm.is_transition_applied("t2"))

        # Missing or invalid source_agent_id must fail closed
        with self.assertRaises(ValueError):
            cm.compact_ledger(source_agent_id="", source_channel="System", prune_source_epoch_threshold=1)

        # Compact up to System source epoch 1 with explicit source_agent_id
        pruned = cm.compact_ledger(source_agent_id="AGT-WIN-01", source_channel="System", prune_source_epoch_threshold=1)
        self.assertEqual(pruned, 1)
        self.assertFalse(cm.is_transition_applied("t1"))
        self.assertTrue(cm.is_transition_applied("t2"))

        state = cm.load_state()
        self.assertEqual(state["watermark"]["pruned_source_epochs"]["AGT-WIN-01:System"], 1)
        self.assertEqual(state["watermark"]["total_compacted_count"], 1)
        self.assertTrue(cm.is_transition_retired("System", 1, source_agent_id="AGT-WIN-01"))
        self.assertFalse(cm.is_transition_retired("System", 2, source_agent_id="AGT-WIN-01"))
        # Missing source_agent_id fails closed (returns False)
        self.assertFalse(cm.is_transition_retired("System", 1, source_agent_id=""))

    def test_local_witness_tracking_and_deduplication(self):
        """Local witness clear events are registered atomically and detected."""
        cm = CheckpointManager(self.test_dir, "Security", self.logger)
        self.assertFalse(cm.is_local_witness_replay("Security", 501, 1102))

        local_id = cm.build_local_witness_id("Security", from_epoch=1, record_id=501, event_id=1102)
        meta = {
            "is_local_witness": True,
            "source_channel": "Security",
            "from_epoch": 1,
            "source_record_id": 501,
            "witness_event_id": 1102,
        }
        cm.advance_epoch(reset_record_id=0, transition_id=local_id, transition_metadata=meta)
        self.assertEqual(cm.get_current_epoch(), 2)
        self.assertTrue(cm.is_local_witness_replay("Security", 501, 1102))
        # Different record ID is not applied
        self.assertFalse(cm.is_local_witness_replay("Security", 502, 1102))
