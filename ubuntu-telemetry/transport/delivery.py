import logging
import json
from typing import Optional
from .outbox import Outbox
from .client import TransportClient

class DeliveryManager:
    """
    Coordinates asynchronous outbox polling and dispatching events via TransportClient.
    """
    def __init__(self, outbox: Outbox, client: TransportClient, logger: Optional[logging.Logger] = None):
        self.outbox = outbox
        self.client = client
        self.logger = logger or logging.getLogger("DeliveryManager")

    def process_outbox(self):
        try:
            pending_events = self.outbox.get_pending_events()
        except Exception as e:
            self.logger.error(f"Failed to retrieve pending events from outbox: {e}")
            return

        for row in pending_events:
            event_id = row["detection_event_id"]
            try:
                event_data = json.loads(row["event_data"])
            except Exception as e:
                self.logger.error(f"Corrupted event data in outbox for {event_id}: {e}")
                self.outbox.mark_failed(event_id, f"JSON parse error: {e}")
                continue

            success, duplicate, error = self.client.send_event(event_data)
            if success:
                if duplicate:
                    self.logger.info(f"Event {event_id} delivered to Central SOC (server noted duplicate).")
                else:
                    self.logger.info(f"Event {event_id} successfully delivered to Central SOC.")
                self.outbox.mark_delivered(event_id)
            else:
                self.logger.warning(f"Failed to deliver event {event_id} to Central SOC: {error}")
                self.outbox.mark_failed(event_id, error)
