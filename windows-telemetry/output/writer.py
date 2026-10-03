import json
import os
import dataclasses
import logging
from .models import DetectionEvent

class DetectionEventWriter:
    def __init__(self, output_dir: str, logger: logging.Logger):
        self.output_dir = output_dir
        self.logger = logger
        self.output_file = os.path.join(self.output_dir, "detections.jsonl")
        
    def write(self, event: DetectionEvent):
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            event_dict = dataclasses.asdict(event)
            json_str = json.dumps(event_dict, ensure_ascii=False)
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write(json_str + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write DetectionEvent to {self.output_file}: {e}")
            raise RuntimeError(f"Output writer failure: {e}")
