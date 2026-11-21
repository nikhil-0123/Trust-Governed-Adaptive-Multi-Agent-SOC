from typing import Dict, Any
from config.settings import config

# Threshold for forwarding medium severity events centralized in Settings
# Kept as alias for backward compatibility with existing imports
MEDIUM_CONFIDENCE_THRESHOLD = config.medium_confidence_threshold

class ImportantEventFilter:
    """
    Implements the Important Event Filter.
    Forward to Central SOC only:
    - HIGH severity events
    - CRITICAL severity events
    - MEDIUM severity events with high confidence
    """

    @staticmethod
    def should_forward(detection_event: Dict[str, Any]) -> bool:
        severity = str(detection_event.get("severity", "")).lower()
        try:
            confidence = float(detection_event.get("confidence", 0.0))
        except (ValueError, TypeError):
            confidence = 0.0

        if severity in ("high", "critical"):
            return True

        if severity == "medium":
            if confidence >= config.medium_confidence_threshold:
                return True

        # low severity, or medium with low confidence, or unknown
        return False
