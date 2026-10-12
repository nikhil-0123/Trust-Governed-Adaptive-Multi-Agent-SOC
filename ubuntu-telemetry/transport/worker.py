import threading
import logging
from typing import Optional
from .delivery import DeliveryManager

class DeliveryWorker(threading.Thread):
    """
    Background worker that periodically triggers outbox delivery to decouple
    the local detection pipeline from network availability and SOC latency.
    """
    def __init__(self, delivery_manager: DeliveryManager, logger: Optional[logging.Logger] = None, poll_interval: float = 2.0):
        super().__init__(daemon=True, name="DeliveryWorker")
        self.delivery_manager = delivery_manager
        self.logger = logger or logging.getLogger("DeliveryWorker")
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()

    def run(self):
        self.logger.info("DeliveryWorker thread started.")
        while not self._stop_event.is_set():
            try:
                self.delivery_manager.process_outbox()
            except Exception as e:
                self.logger.error(f"Unexpected error in DeliveryWorker loop: {e}")
            self._stop_event.wait(self.poll_interval)
        self.logger.info("DeliveryWorker thread stopped.")

    def stop(self):
        self._stop_event.set()
