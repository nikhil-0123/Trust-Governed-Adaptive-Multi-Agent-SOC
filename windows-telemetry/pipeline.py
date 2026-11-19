import logging
from typing import List, Optional, Dict, Any
from config.settings import config
from normalizer.windows_event_normalizer import WindowsEventNormalizer
from detection.detector import DetectionEngine
from output.builder import DetectionEventBuilder
from output.writer import DetectionEventWriter
from core.agent_identity import AgentIdentity
from collectors.windows_event_collector import WindowsEventCollector
from transport.outbox import Outbox, OutboxPayloadConflictError
from transport.client import TransportClient
from transport.delivery import DeliveryManager
from transport.filter import ImportantEventFilter
from transport.worker import DeliveryWorker
from transport.heartbeat import HeartbeatWorker
import dataclasses

class WindowsDetectionPipeline:
    """
    Orchestrates the local endpoint pipeline:
    Collect -> Normalize -> Detect -> Build -> Write -> Checkpoint.
    Supports multichannel collection across Windows Security and Sysmon operational logs.
    """
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.identity = AgentIdentity(config.data_dir)
        self.normalizer = WindowsEventNormalizer(self.identity, logger)
        self.engine = DetectionEngine(logger)
        self.writer = DetectionEventWriter(config.detection_output_dir, logger)
        
        # Primary Security Collector (retains self.collector for backward compatibility)
        self.collector = WindowsEventCollector(
            logger, log_name=config.windows_security_log_name, agent_id=self.identity.agent_id
        )
        self.security_collector = self.collector

        # Multichannel Sysmon Collector
        self.sysmon_collector = None
        if config.enable_sysmon_collection:
            self.sysmon_collector = WindowsEventCollector(
                logger, log_name=config.windows_sysmon_log_name, agent_id=self.identity.agent_id
            )

        self.outbox = Outbox(
            config.outbox_db_path,
            logger,
            busy_timeout_ms=config.outbox_busy_timeout_ms,
            synchronous_mode=config.outbox_synchronous_mode,
            wal_autocheckpoint=config.outbox_wal_autocheckpoint
        )
        self.client = TransportClient(config.soc_api_url, config.soc_api_token, logger)
        self.delivery_manager = DeliveryManager(self.outbox, self.client, logger)
        # Daemon delivery worker
        self.delivery_worker = DeliveryWorker(self.delivery_manager, logger, poll_interval=1.0)
        # Daemon heartbeat worker - initialized with effective capabilities
        self.heartbeat_worker = HeartbeatWorker(
            agent_id=self.identity.agent_id,
            os_type="windows",
            soc_api_url=config.soc_api_url,
            api_token=config.soc_api_token,
            logger=logger,
            capabilities=self.get_effective_capabilities(),
            heartbeat_interval=15.0
        )

    def get_effective_capabilities(self) -> List[str]:
        """
        Computes the effective capability list based on configured and initialized collectors.

        Security capabilities ('EventLog_4625', 'EventLog_4688') and mitigation actions
        ('BLOCK_SOURCE', 'KILL_PROCESS', 'ISOLATE_HOST', 'DISABLE_ACCOUNT') are base endpoint capabilities.

        Sysmon capabilities ('Sysmon_Event1', 'Sysmon_Event3', 'Sysmon_Event22') are reported
        ONLY when Sysmon collection is enabled in settings AND the Sysmon collector has
        initialized successfully.

        Note: Reporting Sysmon capabilities indicates that the local collector is configured
        and initialized; it does not assert verified live service status of the Windows Sysmon driver.
        """
        caps = ["EventLog_4625", "EventLog_4688"]

        if (
            config.enable_sysmon_collection
            and self.sysmon_collector is not None
            and getattr(self.sysmon_collector, "is_initialized", False)
        ):
            caps.extend(["Sysmon_Event1", "Sysmon_Event3", "Sysmon_Event22"])

        caps.extend(["BLOCK_SOURCE", "KILL_PROCESS", "ISOLATE_HOST", "DISABLE_ACCOUNT"])

        seen = set()
        return [c for c in caps if not (c in seen or seen.add(c))]

    def refresh_capabilities(self) -> List[str]:
        """
        Re-evaluates effective capabilities based on current collector states
        and updates the heartbeat worker.
        """
        effective = self.get_effective_capabilities()
        if hasattr(self, "heartbeat_worker") and self.heartbeat_worker:
            self.heartbeat_worker.update_capabilities(effective)
        return effective

    def initialize(self):
        config.ensure_directories()
        self.collector.initialize()
        if self.sysmon_collector:
            try:
                self.sysmon_collector.initialize()
                self.logger.info("Sysmon collector initialized; reporting configured Sysmon capabilities.")
            except Exception as e:
                self.logger.warning(f"Sysmon collector initialization bypassed: {e}")
                self.sysmon_collector.is_initialized = False

        self.refresh_capabilities()
        self.delivery_worker.start()
        self.heartbeat_worker.start()

    def _process_channel_batch(self, collector, channel_name: str):
        if collector is None:
            return

        raw_events = collector.collect_once()
        if not raw_events:
            return

        last_successful_record_id = -1
        current_epoch = getattr(collector, "current_epoch", None)
        channel_log_name = getattr(collector, "log_name", channel_name)

        for raw_event in raw_events:
            record_id = raw_event.get("record_id", -1)
            try:
                # 1. Normalize with authoritative channel epoch and log_name
                normalized_event = self.normalizer.normalize(
                    raw_event, log_name=channel_log_name, epoch=current_epoch
                )

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
                            try:
                                self.outbox.add_event(event_dict)
                            except OutboxPayloadConflictError as ce:
                                self.logger.error(
                                    f"Outbox payload conflict on record {record_id} ({channel_name}): "
                                    f"event_id={ce.event_id}, conflict_id={ce.conflict_id}, "
                                    f"existing_hash={ce.existing_hash}, incoming_hash={ce.incoming_hash}"
                                )

                # 4. Checkpoint success marking
                last_successful_record_id = record_id

            except Exception as e:
                # Pipeline processing failure (normalization, infrastructure, or logic).
                # Must NOT advance checkpoint past this failed event.
                self.logger.error(f"Pipeline processing failed on {channel_name} record {record_id}, halting batch. Error: {e}")
                break

        # Advance the collector checkpoint only up to the last successful record
        if last_successful_record_id > 0:
            collector.update_checkpoint(last_successful_record_id)

    def process_batch(self):
        # 1. Process Security events (primary collector, always executed)
        self._process_channel_batch(self.collector, "Security")

        # 2. Process Sysmon events (only when initialized)
        if self.sysmon_collector and getattr(self.sysmon_collector, "is_initialized", False):
            try:
                channel_name = getattr(self.sysmon_collector, "log_name", "Sysmon")
                self._process_channel_batch(self.sysmon_collector, channel_name)
            except Exception as e:
                self.logger.error(f"Sysmon batch processing error: {e}")

    def shutdown(self):
        """Gracefully terminates delivery worker and flushes pending outbox events."""
        try:
            self.delivery_manager.process_outbox()
        except Exception:
            pass
        self.delivery_worker.stop()
        self.heartbeat_worker.stop()
        if hasattr(self.collector, "shutdown"):
            self.collector.shutdown()
        if self.sysmon_collector and hasattr(self.sysmon_collector, "shutdown"):
            self.sysmon_collector.shutdown()
