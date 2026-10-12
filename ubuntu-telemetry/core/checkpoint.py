import os
import json
import logging
from typing import Dict, Any

class CheckpointManager:
    """
    Manages safe, persistent checkpoints for Ubuntu log collection.
    Tracks byte offset, inode (for rotation detection), and processed record count.
    """
    def __init__(self, checkpoint_dir: str, log_identifier: str, logger: logging.Logger):
        self.checkpoint_dir = checkpoint_dir
        self.log_identifier = log_identifier
        self.logger = logger
        safe_name = "".join([c if c.isalnum() else "_" for c in log_identifier])
        self.checkpoint_file = os.path.join(checkpoint_dir, f"{safe_name}_checkpoint.json")

    def load_checkpoint(self) -> Dict[str, Any]:
        """Loads the last checkpoint state. Returns default dictionary if none exists."""
        default_state = {
            "log_identifier": self.log_identifier,
            "last_offset": 0,
            "last_inode": 0,
            "last_record_id": 0
        }
        if not os.path.exists(self.checkpoint_file):
            return default_state

        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {
                    "log_identifier": data.get("log_identifier", self.log_identifier),
                    "last_offset": int(data.get("last_offset", 0)),
                    "last_inode": int(data.get("last_inode", 0)),
                    "last_record_id": int(data.get("last_record_id", 0))
                }
        except Exception as e:
            self.logger.error(f"Failed to read checkpoint file {self.checkpoint_file}: {e}")
            raise RuntimeError(f"Corrupted checkpoint file: {e}")

    def save_checkpoint(self, offset: int, inode: int = 0, record_id: int = 0):
        """Safely saves the checkpoint using atomic replacement."""
        os.makedirs(self.checkpoint_dir, exist_ok=True)
        temp_file = f"{self.checkpoint_file}.tmp"
        payload = {
            "log_identifier": self.log_identifier,
            "last_offset": offset,
            "last_inode": inode,
            "last_record_id": record_id
        }
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=4)
            os.replace(temp_file, self.checkpoint_file)
            self.logger.debug(f"Checkpoint updated for {self.log_identifier}: offset={offset}, record_id={record_id}")
        except Exception as e:
            self.logger.error(f"Failed to save checkpoint to {self.checkpoint_file}: {e}")
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except OSError:
                    pass
            raise

    @staticmethod
    def is_rotated(current_inode: int, current_size: int, saved_inode: int, saved_offset: int) -> bool:
        """
        Determines whether the log file has been rotated:
        1. If inodes are known (> 0) and differ, the file was rotated.
        2. If the current file size is strictly less than the saved offset, the file was truncated/recreated.
        """
        if current_inode > 0 and saved_inode > 0 and current_inode != saved_inode:
            return True
        if current_size < saved_offset:
            return True
        return False
