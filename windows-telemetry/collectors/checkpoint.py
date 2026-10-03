import os
import json
import logging

class CheckpointManager:
    def __init__(self, checkpoint_dir: str, log_name: str, logger: logging.Logger):
        self.checkpoint_dir = checkpoint_dir
        self.log_name = log_name
        self.logger = logger
        safe_name = "".join([c if c.isalnum() else "_" for c in log_name])
        self.checkpoint_file = os.path.join(checkpoint_dir, f"{safe_name}_checkpoint.json")

    def load_checkpoint(self) -> int:
        """Loads the last successfully processed record ID. Returns 0 if none exists."""
        if not os.path.exists(self.checkpoint_file):
            return 0
        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("last_record_id", 0)
        except Exception as e:
            self.logger.error(f"Failed to read checkpoint file {self.checkpoint_file}: {e}")
            raise RuntimeError(f"Corrupted checkpoint file: {e}")

    def save_checkpoint(self, record_id: int):
        """Safely saves the checkpoint using a temporary file replacement to prevent corruption."""
        os.makedirs(self.checkpoint_dir, exist_ok=True)
        temp_file = f"{self.checkpoint_file}.tmp"
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump({"log_name": self.log_name, "last_record_id": record_id}, f, indent=4)
            os.replace(temp_file, self.checkpoint_file)
            self.logger.debug(f"Checkpoint updated to {record_id} for {self.log_name}")
        except Exception as e:
            self.logger.error(f"Failed to save checkpoint to {self.checkpoint_file}: {e}")
            if os.path.exists(temp_file):
                os.remove(temp_file)
            raise
