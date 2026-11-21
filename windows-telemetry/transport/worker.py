import threading
import time
import logging
import inspect
from typing import Optional, Any
from .outbox import OutboxLock

class DeliveryWorker(threading.Thread):
    """
    DeliveryWorker thread for processing the SQLite Outbox queue.

    Enforces mandatory process-level and cross-process mutual exclusion via OutboxLock.
    A valid persistent database path is strictly required for production delivery.
    Isolated testing without filesystem locking is supported only via explicit opt-in:
    `allow_unlocked_for_testing=True`.
    """
    def __init__(
        self,
        delivery_manager: Any,
        logger: logging.Logger,
        poll_interval: float = 5.0,
        checkpoint_interval_seconds: float = 60.0,
        allow_unlocked_for_testing: bool = False
    ):
        super().__init__(name="DeliveryWorker", daemon=True)
        self.delivery_manager = delivery_manager
        self.logger = logger
        self.poll_interval = poll_interval
        self.checkpoint_interval_seconds = checkpoint_interval_seconds
        self.allow_unlocked_for_testing = allow_unlocked_for_testing
        self._last_checkpoint_time = time.time()
        self._stop_event = threading.Event()
        self._lock: Optional[OutboxLock] = None

        if not self.allow_unlocked_for_testing:
            # Production delivery contract: valid delivery_manager, outbox, and persistent db_path required
            if delivery_manager is None:
                raise ValueError("DeliveryWorker requires a valid delivery_manager instance")

            outbox_inst = getattr(delivery_manager, "outbox", None)
            if outbox_inst is None:
                raise ValueError("DeliveryManager contract violation: missing required 'outbox' instance")

            db_path = getattr(outbox_inst, "db_path", None)
            if not isinstance(db_path, str) or not db_path.strip():
                raise ValueError(
                    f"Outbox contract violation: 'db_path' must be a non-empty persistent database path, got {db_path!r}"
                )

            clean_path = db_path.strip()
            if clean_path == ":memory:":
                raise ValueError(
                    "Outbox contract violation: ':memory:' database cannot be used for production locking. "
                    "Pass allow_unlocked_for_testing=True for isolated in-memory test delivery."
                )

            self._lock = OutboxLock(clean_path, logger=logger)
        else:
            self.logger.warning(
                "DeliveryWorker: allow_unlocked_for_testing=True enabled. Process locking is disabled for test execution."
            )

    def run(self):
        self.logger.info("DeliveryWorker started.")

        if not self.allow_unlocked_for_testing:
            if self._lock is None:
                self.logger.error("DeliveryWorker cannot run: OutboxLock is uninitialized. Terminating worker.")
                return

            if not self._lock.acquire():
                self.logger.warning(
                    f"Could not acquire outbox lock for {self._lock.canonical_db_path}. "
                    "Another DeliveryWorker is already active. Terminating worker thread."
                )
                return

        # Determine invocation arguments for delivery_manager.process_outbox
        process_outbox_kwargs = {}
        target_fn = getattr(self.delivery_manager, "process_outbox", None)
        if callable(target_fn):
            try:
                sig = inspect.signature(target_fn)
                params = sig.parameters
                if "lock_already_acquired" in params or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
                    process_outbox_kwargs["lock_already_acquired"] = True
            except (ValueError, TypeError):
                process_outbox_kwargs["lock_already_acquired"] = True

        self._last_checkpoint_time = time.time()
        try:
            while not self._stop_event.is_set():
                try:
                    self.delivery_manager.process_outbox(**process_outbox_kwargs)
                except Exception as e:
                    self.logger.error(f"Unexpected error in DeliveryWorker loop: {e}")

                now = time.time()
                if (now - self._last_checkpoint_time) >= self.checkpoint_interval_seconds:
                    try:
                        outbox_inst = getattr(self.delivery_manager, "outbox", None)
                        if outbox_inst is not None and hasattr(outbox_inst, "checkpoint"):
                            outbox_inst.checkpoint()
                    except Exception as e:
                        self.logger.warning(f"Periodic WAL checkpoint failed: {e}")
                    self._last_checkpoint_time = now

                # Wait for the poll interval or until stop is requested
                self._stop_event.wait(self.poll_interval)
        finally:
            try:
                outbox_inst = getattr(self.delivery_manager, "outbox", None)
                if outbox_inst is not None and hasattr(outbox_inst, "checkpoint"):
                    outbox_inst.checkpoint()
            except Exception:
                pass
            if self._lock is not None:
                self._lock.release()
            self.logger.info("DeliveryWorker stopped.")

    def stop(self, timeout: float = 10.0):
        self._stop_event.set()
        if self.is_alive():
            self.join(timeout=timeout)
