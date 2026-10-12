import os
import json
import logging
from dataclasses import asdict
from typing import Optional
from .models import DetectionEvent

class DetectionEventWriter:
    """
    Appends generated DetectionEvents to a local JSONL file for local audit and persistence.
    """
    def __init__(self, output_dir: str, logger: Optional[logging.Logger] = None):
        self.output_dir = output_dir
        self.logger = logger or logging.getLogger("DetectionEventWriter")
        os.makedirs(self.output_dir, exist_ok=True)
        self.file_path = os.path.join(self.output_dir, "detections.jsonl")

    def write(self, detection_event: DetectionEvent):
        try:
            line = json.dumps(asdict(detection_event)) + "\n"
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(line)
            self.logger.debug(f"Wrote detection event {detection_event.detection_event_id} to {self.file_path}")
        except Exception as e:
            self.logger.error(f"Failed to write detection event to {self.file_path}: {e}")
            raise
