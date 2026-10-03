import logging
import json
from .outbox import Outbox
from .client import TransportClient

class DeliveryManager:
    def __init__(self, outbox: Outbox, client: TransportClient, logger: logging.Logger):
        self.outbox = outbox
        self.client = client
        self.logger = logger
        
    def process_outbox(self):
        try:
            pending_events = self.outbox.get_pending_events()
        except Exception as e:
            self.logger.error(f"Failed to retrieve pending events: {e}")
            return

        for row in pending_events:
            event_id = row["detection_event_id"]
            try:
                event_data = json.loads(row["event_data"])
            except Exception as e:
                self.logger.error(f"Corrupt event data in outbox for {event_id}")
                self.outbox.mark_failed(event_id, f"JSON parse error: {e}")
                continue
                
            success, duplicate, error = self.client.send_event(event_data)
            if success:
                if duplicate:
                    self.logger.info(f"Event {event_id} delivered to Central SOC (duplicate).")
                else:
                    self.logger.info(f"Event {event_id} delivered to Central SOC.")
                self.outbox.mark_delivered(event_id)
            else:
                self.logger.warning(f"Failed to deliver {event_id} to Central SOC: {error}")
                self.outbox.mark_failed(event_id, error)
