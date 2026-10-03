import os
from typing import Dict, Any

# Threshold for forwarding medium severity events
# Documentation specifies "sufficient confidence", leaving the exact value to be determined.
# This parameter is exposed for experimental tuning.
MEDIUM_CONFIDENCE_THRESHOLD = float(os.getenv("MEDIUM_CONFIDENCE_THRESHOLD", "0.8"))

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
            if confidence >= MEDIUM_CONFIDENCE_THRESHOLD:
                return True
                
        # low severity, or medium with low confidence, or unknown
        return False
