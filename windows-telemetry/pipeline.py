import logging
from typing import List, Optional, Dict, Any
from config.settings import config
from normalizer.windows_event_normalizer import WindowsEventNormalizer
from detection.detector import DetectionEngine
from output.builder import DetectionEventBuilder
from output.writer import DetectionEventWriter
from core.agent_identity import AgentIdentity
from collectors.windows_event_collector import WindowsEventCollector
from transport.outbox import Outbox, OutboxPayloadConflictError, TransitionOutbox
from transport.client import TransportClient, TransitionTransportClient
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
    def __init__(self, logger: logging.Logger, execution_mode: Optional[str] = None):
        self.logger = logger
        self.execution_mode = (execution_mode or getattr(config, "execution_mode", "PRODUCTION")).upper().strip()
        self.identity = AgentIdentity(config.data_dir)
        self.normalizer = WindowsEventNormalizer(self.identity, logger)
        self.engine = DetectionEngine(logger)
        writer_filename = "detections_eval.jsonl" if self.execution_mode == "EVALUATION" else "detections.jsonl"
        self.writer = DetectionEventWriter(config.detection_output_dir, logger, filename=writer_filename)
        
        # Primary Security Collector (retains self.collector for backward compatibility)
        self.collector = WindowsEventCollector(
            logger, log_name=config.windows_security_log_name, agent_id=self.identity.agent_id
        )
        self.security_collector = self.collector

        # Multichannel System Collector
        self.system_collector = None
        if config.enable_system_collection:
            self.system_collector = WindowsEventCollector(
                logger, log_name=config.windows_system_log_name, agent_id=self.identity.agent_id
            )

        # Multichannel Sysmon Collector
        self.sysmon_collector = None
        if config.enable_sysmon_collection:
            self.sysmon_collector = WindowsEventCollector(
                logger, log_name=config.windows_sysmon_log_name, agent_id=self.identity.agent_id
            )

        mode_str = getattr(config, "outbox_auto_vacuum_mode", "NONE")
        auto_vac_mode_int = 1 if mode_str == "FULL" else (2 if mode_str == "INCREMENTAL" else 0)

        self.outbox = Outbox(
            config.outbox_db_path,
            logger,
            busy_timeout_ms=config.outbox_busy_timeout_ms,
            synchronous_mode=config.outbox_synchronous_mode,
            wal_autocheckpoint=config.outbox_wal_autocheckpoint,
            initial_auto_vacuum_mode=auto_vac_mode_int
        )
        self.transition_outbox = TransitionOutbox(
            config.outbox_db_path,
            logger,
            busy_timeout_ms=config.outbox_busy_timeout_ms,
            synchronous_mode=config.outbox_synchronous_mode,
            wal_autocheckpoint=config.outbox_wal_autocheckpoint
        )
        self.backpressure_enabled = getattr(config, "outbox_backpressure_enabled", True)
        self.max_pending_records = getattr(config, "outbox_max_pending_records", 50000)
        self.disk_watermark_mb = getattr(config, "outbox_disk_watermark_mb", 500)
        self.client = TransportClient(config.soc_api_url, config.soc_api_token, logger)
        self.transition_client = None
        if getattr(config, "soc_agent_api_token", None):
            try:
                self.transition_client = TransitionTransportClient(
                    config.soc_transition_api_url,
                    config.soc_agent_api_token,
                    logger,
                    agent_id=getattr(config, "agent_id", None) or self.identity.agent_id
                )
            except Exception as ce:
                self.logger.warning(f"Failed to initialize TransitionTransportClient: {ce}")
        else:
            self.logger.warning("SOC_AGENT_API_TOKEN is not configured; transition transport client is uninitialized.")
        self.delivery_manager = DeliveryManager(
            self.outbox,
            self.client,
            logger,
            retention_hours=config.outbox_retention_hours,
            purge_interval_seconds=config.outbox_purge_interval_seconds,
            vacuum_freelist_threshold=config.outbox_vacuum_freelist_threshold,
            vacuum_min_interval_seconds=config.outbox_vacuum_min_interval_seconds,
            vacuum_enabled=config.outbox_vacuum_enabled,
            transition_outbox=self.transition_outbox,
            transition_client=self.transition_client
        )
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
            config.enable_system_collection
            and self.system_collector is not None
            and getattr(self.system_collector, "is_initialized", False)
        ):
            caps.append("EventLog_104")

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
        if self.system_collector:
            try:
                self.system_collector.initialize()
                self.logger.info("System collector initialized successfully.")
            except Exception as e:
                self.logger.warning(f"System collector initialization bypassed: {e}")
                self.system_collector.is_initialized = False

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

            # Check backpressure before ingesting into outbox if enabled
            if self.execution_mode != "EVALUATION" and getattr(self, "backpressure_enabled", True):
                if self.outbox and hasattr(self.outbox, "check_backpressure"):
                    bp = self.outbox.check_backpressure(
                        max_pending=getattr(self, "max_pending_records", 50000),
                        disk_watermark_mb=getattr(self, "disk_watermark_mb", 500)
                    )
                    if bp.get("active"):
                        self.logger.warning(
                            f"Outbox backpressure active for {channel_name} on record {record_id} "
                            f"(reasons: {bp.get('reasons')}, pending: {bp.get('pending_count')}, free_disk: {bp.get('free_disk_mb')}MB). "
                            "Pausing batch ingestion; checkpoint preserved."
                        )
                        break

            try:
                # 1. Normalize with authoritative channel epoch and log_name
                event_epoch = raw_event["epoch"] if "epoch" in raw_event else current_epoch
                normalized_event = self.normalizer.normalize(
                    raw_event, log_name=channel_log_name, epoch=event_epoch
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
                        # Benchmark / Replay isolation: EVALUATION mode bypasses Outbox queue
                        if self.execution_mode != "EVALUATION":
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

    def _drain_all_checkpoint_notifications(self):
        """
        Coordinates draining of pending outbox notifications across all active collectors
        into their respective persistent outboxes (detection outbox vs transition outbox).
        """
        collectors = [self.collector]
        if self.system_collector and getattr(self.system_collector, "is_initialized", False):
            collectors.append(self.system_collector)
        if self.sysmon_collector and getattr(self.sysmon_collector, "is_initialized", False):
            collectors.append(self.sysmon_collector)

        for col in collectors:
            if col and hasattr(col, "checkpoint_manager") and col.checkpoint_manager:
                try:
                    col.checkpoint_manager.drain_pending_outbox_notifications(
                        detection_outbox=self.outbox,
                        transition_outbox=self.transition_outbox,
                    )
                except Exception as e:
                    self.logger.error(
                        f"Error draining checkpoint notifications for {getattr(col, 'log_name', 'unknown')}: {e}"
                    )

    def process_batch(self):
        # 1. Process System events first so cross-channel clear witnesses (Event 104) publish transitions
        if self.system_collector and getattr(self.system_collector, "is_initialized", False):
            try:
                channel_name = getattr(self.system_collector, "log_name", "System")
                self._process_channel_batch(self.system_collector, channel_name)
            except Exception as e:
                self.logger.error(f"System batch processing error: {e}")

        # 2. Process Security events second (claims pending transitions before collecting)
        self._process_channel_batch(self.collector, "Security")

        # 3. Process Sysmon events third (only when initialized)
        if self.sysmon_collector and getattr(self.sysmon_collector, "is_initialized", False):
            try:
                channel_name = getattr(self.sysmon_collector, "log_name", "Sysmon")
                self._process_channel_batch(self.sysmon_collector, channel_name)
            except Exception as e:
                self.logger.error(f"Sysmon batch processing error: {e}")

        # 4. Drain pending outbox notifications across all initialized collectors
        self._drain_all_checkpoint_notifications()

    def shutdown(self, worker_join_timeout: float = 10.0):
        """Gracefully terminates delivery worker and flushes pending outbox events."""
        if self.delivery_worker:
            self.delivery_worker.stop(timeout=worker_join_timeout)

        if self.heartbeat_worker:
            self.heartbeat_worker.stop()
            if self.heartbeat_worker.is_alive():
                self.heartbeat_worker.join(timeout=5.0)

        if self.delivery_worker and self.delivery_worker.is_alive():
            self.logger.error(
                "DeliveryWorker failed to terminate within timeout; aborting final outbox flush to prevent concurrent execution race."
            )
        else:
            try:
                self._drain_all_checkpoint_notifications()
            except Exception as e:
                self.logger.error(f"Error during shutdown checkpoint drain: {e}")
            try:
                self.delivery_manager.process_outbox(timeout=5.0)
            except Exception as e:
                self.logger.error(f"Error during shutdown outbox flush: {e}")

        if hasattr(self.collector, "shutdown"):
            self.collector.shutdown()
        if self.system_collector and hasattr(self.system_collector, "shutdown"):
            self.system_collector.shutdown()
        if self.sysmon_collector and hasattr(self.sysmon_collector, "shutdown"):
            self.sysmon_collector.shutdown()
