import logging
from config.settings import config
from normalizer.windows_event_normalizer import WindowsEventNormalizer
from detection.detector import DetectionEngine
from output.builder import DetectionEventBuilder
from output.writer import DetectionEventWriter
from core.agent_identity import AgentIdentity
from collectors.windows_event_collector import WindowsEventCollector

class WindowsDetectionPipeline:
    """
    Orchestrates the local endpoint pipeline:
    Collect -> Normalize -> Detect -> Build -> Write -> Checkpoint.
    """
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.identity = AgentIdentity(config.data_dir)
        self.normalizer = WindowsEventNormalizer(self.identity, logger)
        self.engine = DetectionEngine(logger)
        self.writer = DetectionEventWriter(config.detection_output_dir, logger)
        self.collector = WindowsEventCollector(logger)
        
    def initialize(self):
        self.collector.initialize()
        
    def process_batch(self):
        raw_events = self.collector.collect_once()
        if not raw_events:
            return
            
        last_successful_record_id = -1
        
        for raw_event in raw_events:
            record_id = raw_event.get("record_id", -1)
            try:
                # 1. Normalize
                normalized_event = self.normalizer.normalize(raw_event)
                
                # 2. Detect
                results = self.engine.process_event(normalized_event)
                
                # 3. Build & Write
                for result in results:
                    detection_event = DetectionEventBuilder.build(normalized_event, result)
                    if detection_event:
                        self.writer.write(detection_event)
                        
                # 4. Checkpoint success marking
                last_successful_record_id = record_id
                
            except Exception as e:
                # Pipeline processing failure (normalization, infrastructure, or logic).
                # Must NOT advance checkpoint past this failed event.
                self.logger.error(f"Pipeline processing failed on record {record_id}, halting batch. Error: {e}")
                break
                
        # Advance the collector checkpoint only up to the last successful record
        if last_successful_record_id > 0:
            self.collector.update_checkpoint(last_successful_record_id)
            
    def shutdown(self):
        self.collector.shutdown()
