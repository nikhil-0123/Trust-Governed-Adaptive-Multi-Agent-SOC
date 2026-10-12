import logging
from typing import List, Dict, Any, Optional
from .models import DetectionResult
from .rules import LinuxSSHBruteForceRule, LinuxSuspiciousSudoRule

class DetectionEngine:
    """
    Consumes normalized Linux events and runs deterministic security rules.
    Returns detected results without mutating input events.
    """
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger("DetectionEngine")
        self.rules = [
            LinuxSSHBruteForceRule(),
            LinuxSuspiciousSudoRule()
        ]

    def process_event(self, normalized_event: Dict[str, Any]) -> List[DetectionResult]:
        results = []
        for rule in self.rules:
            try:
                result = rule.evaluate(normalized_event)
                if result:
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Rule {rule.name} failed during evaluation: {e}")
        return results

    def reset_rules(self):
        """Resets in-memory state of all rules (useful for test isolation)."""
        for rule in self.rules:
            rule.reset_state()
