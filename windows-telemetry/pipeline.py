import logging
from config.settings import config
from normalizer.windows_event_normalizer import WindowsEventNormalizer
from detection.detector import DetectionEngine
from output.builder import DetectionEventBuilder
from output.writer import DetectionEventWriter
from core.agent_identity import AgentIdentity
from collectors.windows_event_collector import WindowsEventCollector
from transport.outbox import Outbox
from transport.client import TransportClient
from transport.delivery import DeliveryManager
from transport.filter import ImportantEventFilter
from transport.worker import DeliveryWorker
import dataclasses

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
        
        self.outbox = Outbox(config.outbox_db_path, logger)
        self.client = TransportClient(config.soc_api_url, config.soc_api_token, logger)
        self.delivery_manager = DeliveryManager(self.outbox, self.client, logger)
        # Daemon delivery worker
        self.delivery_worker = DeliveryWorker(self.delivery_manager, logger, poll_interval=1.0)

    def initialize(self):
        self.collector.initialize()
        self.delivery_worker.start()
        
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
                        # 3a. Write to local JSONL (Step 5)
                        self.writer.write(detection_event)
                        # 3b. Important Event Filter before local outbox for Central SOC (Step 6)
                        event_dict = dataclasses.asdict(detection_event)
                        if ImportantEventFilter.should_forward(event_dict):
                            self.outbox.add_event(event_dict)
                        
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
        self.delivery_worker.stop()
        self.collector.shutdown()
