import logging
import dataclasses
from typing import Optional

from config.settings import config
from core.agent_identity import AgentIdentity
from collectors.auth_log_collector import AuthLogCollector
from normalizer.ubuntu_event_normalizer import UbuntuEventNormalizer
from detection.detector import DetectionEngine
from output.builder import DetectionEventBuilder
from output.writer import DetectionEventWriter
from transport.outbox import Outbox
from transport.client import TransportClient
from transport.delivery import DeliveryManager
from transport.filter import ImportantEventFilter
from transport.worker import DeliveryWorker
from transport.heartbeat import HeartbeatWorker

class UbuntuDetectionPipeline:
    """
    Orchestrates the local Ubuntu endpoint security pipeline:
    Collect (auth.log) -> Normalize -> Detect -> Build -> Write -> Outbox -> Checkpoint.
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("UbuntuDetectionPipeline")
        self.identity = AgentIdentity(config.data_dir)
        self.normalizer = UbuntuEventNormalizer(self.identity, self.logger)
        self.engine = DetectionEngine(self.logger)
        self.writer = DetectionEventWriter(config.detection_output_dir, self.logger)
        self.collector = AuthLogCollector(config.auth_log_path, self.logger)

        self.outbox = Outbox(config.outbox_db_path, self.logger)
        self.client = TransportClient(config.soc_api_url, config.soc_api_token, self.logger)
        self.delivery_manager = DeliveryManager(self.outbox, self.client, self.logger)
        self.delivery_worker = DeliveryWorker(self.delivery_manager, self.logger, poll_interval=1.0)
        self.heartbeat_worker = HeartbeatWorker(
            agent_id=self.identity.agent_id,
            os_type="linux",
            soc_api_url=config.soc_api_url,
            api_token=config.soc_api_token,
            logger=self.logger,
            capabilities=["AuthLog_SSH"],
            heartbeat_interval=15.0
        )

    def initialize(self):
        """Initializes collectors and starts the background delivery worker."""
        self.collector.initialize()
        self.delivery_worker.start()
        self.heartbeat_worker.start()

    def process_batch(self):
        """Processes a single batch of log events through the pipeline."""
        raw_events = self.collector.collect_once()
        if not raw_events:
            return

        last_successful_record_id = -1
        last_successful_offset = -1

        for raw_event in raw_events:
            record_id = raw_event.get("record_id", -1)
            byte_offset = raw_event.get("byte_offset", -1)

            try:
                # 1. Normalize
                normalized_event = self.normalizer.normalize(raw_event)

                # 2. Local Detection
                results = self.engine.process_event(normalized_event)

                # 3. Build & Write
                for result in results:
                    detection_event = DetectionEventBuilder.build(normalized_event, result)
                    if detection_event:
                        # 3a. Write to local JSONL log
                        self.writer.write(detection_event)

                        # 3b. Important Event Filter before queueing to outbox for Central SOC
                        event_dict = dataclasses.asdict(detection_event)
                        if ImportantEventFilter.should_forward(event_dict):
                            self.outbox.add_event(event_dict)

                # 4. Success marker
                last_successful_record_id = record_id
                last_successful_offset = byte_offset

            except Exception as e:
                self.logger.error(f"Pipeline processing failed on record {record_id}, halting batch. Error: {e}")
                break

        # Advance checkpoint only up to the last successful record
        if last_successful_record_id > 0 and last_successful_offset > 0:
            self.collector.update_checkpoint(last_successful_record_id, last_successful_offset)

    def shutdown(self):
        """Gracefully terminates background delivery worker and flushes pending outbox events."""
        try:
            self.delivery_manager.process_outbox()
        except Exception:
            pass
        self.delivery_worker.stop()
        self.heartbeat_worker.stop()
