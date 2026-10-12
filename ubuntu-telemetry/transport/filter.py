import os
from typing import Dict, Any
from config.settings import config

class ImportantEventFilter:
    """
    Implements the Important Event Filter on the Ubuntu endpoint.
    Only forwards events that meet severity and confidence thresholds to Central SOC:
    - HIGH and CRITICAL severity events.
    - MEDIUM severity events with confidence >= MEDIUM_CONFIDENCE_THRESHOLD.
    """
    @staticmethod
    def should_forward(detection_event: Dict[str, Any]) -> bool:
        severity = str(detection_event.get("severity", "")).upper()
        try:
            confidence = float(detection_event.get("confidence", 0.0))
        except (ValueError, TypeError):
            confidence = 0.0

        if severity in ("HIGH", "CRITICAL"):
            return True

        if severity == "MEDIUM":
            if confidence >= config.medium_confidence_threshold:
                return True

        return False
