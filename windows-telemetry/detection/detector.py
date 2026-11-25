from typing import List, Dict, Any, Optional
import os
import logging
from .models import DetectionResult
from .rules import (
    BruteForceRule,
    SuspiciousPowerShellRule,
    SuspiciousLolbinsDownloadRule,
    ReconnaissanceCommandsRule,
    DefenseEvasionRule
)
from .xgboost_detector import XGBoostDetector, ModelNotAvailableError

import re

class DetectionEngine:
    def __init__(self, logger: logging.Logger, detector_version: Optional[str] = None):
        self.logger = logger
        if detector_version is not None:
            stripped = str(detector_version).strip()
            if not stripped:
                raise ValueError("detector_version cannot be empty or whitespace-only.")
            if not re.match(r"^\d+\.\d+\.\d+$", stripped):
                raise ValueError(f"detector_version must be valid SemVer 'X.Y.Z', got '{detector_version}'")
            self.detector_version = stripped
        elif "WINDOWS_DETECTOR_VERSION" in os.environ:
            raw_env = os.environ["WINDOWS_DETECTOR_VERSION"].strip()
            if not raw_env:
                raise ValueError("WINDOWS_DETECTOR_VERSION cannot be empty or whitespace-only.")
            if not re.match(r"^\d+\.\d+\.\d+$", raw_env):
                raise ValueError(f"WINDOWS_DETECTOR_VERSION must be valid SemVer 'X.Y.Z', got '{raw_env}'")
            self.detector_version = raw_env
        else:
            self.detector_version = "1.0.0"

        if self.detector_version == "1.0.0":
            logger.warning("Stale detector version 1.0.0 detected; this version is deprecated and incompatible with Phase 2.1 production payloads.")

        # Rules and models initialized here
        self.rules = [
            BruteForceRule(logger=logger, detector_version=self.detector_version),
            SuspiciousPowerShellRule(detector_version=self.detector_version),
            SuspiciousLolbinsDownloadRule(detector_version=self.detector_version),
            ReconnaissanceCommandsRule(detector_version=self.detector_version),
            DefenseEvasionRule(detector_version=self.detector_version)
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
                    if not result.rules_digest and hasattr(rule, "get_rules_digest"):
                        result.rules_digest = rule.get_rules_digest()
                    if result.thresholds is None and hasattr(rule, "get_thresholds"):
                        result.thresholds = rule.get_thresholds()
                    if result.detector_config is None and hasattr(rule, "get_detector_config"):
                        result.detector_config = rule.get_detector_config()
                    if hasattr(rule, "detector_version"):
                        result.detector_version = rule.detector_version
                    if hasattr(rule, "detector_name") and not getattr(result, "detector_name", None):
                        result.detector_name = rule.detector_name
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
