from typing import List, Dict, Any
from .models import DetectionResult
from .rules import (
    BruteForceRule,
    SuspiciousPowerShellRule,
    SuspiciousLolbinsDownloadRule,
    ReconnaissanceCommandsRule,
    DefenseEvasionRule
)
from .xgboost_detector import XGBoostDetector, ModelNotAvailableError
import logging

class DetectionEngine:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        # Rules and models initialized here
        self.rules = [
            BruteForceRule(),
            SuspiciousPowerShellRule(),
            SuspiciousLolbinsDownloadRule(),
            ReconnaissanceCommandsRule(),
            DefenseEvasionRule()
        ]
        self.ml_detector = XGBoostDetector(logger)


    def process_event(self, normalized_event: Dict[str, Any]) -> List[DetectionResult]:
        """
        Consumes a normalized event and runs deterministic rules and ML detectors.
        Returns a list of DetectionResults. Does NOT mutate the input event.
        """
        results = []
        
        # 1. Deterministic Rules
        for rule in self.rules:
            try:
                result = rule.evaluate(normalized_event)
                if result:
                    results.append(result)
            except NotImplementedError as e:
                self.logger.warning(f"Rule {rule.name} blocked: {e}")
            except Exception as e:
                self.logger.error(f"Rule {rule.name} failed during evaluation: {e}")

        # 2. ML Detector
        try:
            ml_result = self.ml_detector.evaluate(normalized_event)
            if ml_result:
                results.append(ml_result)
        except ModelNotAvailableError as e:
            self.logger.warning(f"ML Detector skipped: {e}")
        except Exception as e:
            self.logger.error(f"ML Detector failed during evaluation: {e}")

        return results
