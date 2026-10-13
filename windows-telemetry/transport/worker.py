import threading
import time
import logging
from .delivery import DeliveryManager

class DeliveryWorker(threading.Thread):
    def __init__(self, delivery_manager: DeliveryManager, logger: logging.Logger, poll_interval: float = 5.0):
        super().__init__(name="DeliveryWorker", daemon=True)
        self.delivery_manager = delivery_manager
        self.logger = logger
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()

    def run(self):
        self.logger.info("DeliveryWorker started.")
        while not self._stop_event.is_set():
            try:
                self.delivery_manager.process_outbox()
            except Exception as e:
                self.logger.error(f"Unexpected error in DeliveryWorker loop: {e}")
            
            # Wait for the poll interval or until stop is requested
            self._stop_event.wait(self.poll_interval)
        self.logger.info("DeliveryWorker stopped.")

    def stop(self):
        self._stop_event.set()
        if self.is_alive():
            self.join(timeout=10.0)
