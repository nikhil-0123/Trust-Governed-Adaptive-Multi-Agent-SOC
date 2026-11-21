"""
Deterministic Detector Revision Manifest and Hashing Specification.
Implements TGAM-RCC-v1 canonical serialization for detector configuration,
rules digest, thresholds, and model artifact digests.
"""

import hashlib
from typing import Dict, Any, Optional
from canonical import canonicalize_tgam_rcc_v1


def build_detector_revision_manifest(
    detector_name: str,
    detector_version: str = "1.0.0",
    rules_digest: Optional[str] = None,
    thresholds: Optional[Dict[str, Any]] = None,
    detector_config: Optional[Dict[str, Any]] = None,
    model_artifact_digest: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Constructs a deterministic detector revision manifest for TGAM-RCC-v1 canonical serialization.
    All keys are sorted and values normalized to primitive types supported by TGAM-RCC-v1.
    """
    clean_name = str(detector_name).strip() if detector_name else "unknown_detector"
    clean_version = str(detector_version).strip() if detector_version else "1.0.0"

    clean_rules_digest = (
        str(rules_digest).strip()
        if rules_digest
        else hashlib.sha256(clean_name.encode("utf-8")).hexdigest()
    )
    clean_thresholds = thresholds.copy() if isinstance(thresholds, dict) else {}
    clean_config = detector_config.copy() if isinstance(detector_config, dict) else {}
    clean_model_digest = (
        str(model_artifact_digest).strip() if model_artifact_digest else ""
    )

    return {
        "detector_config": clean_config,
        "detector_name": clean_name,
        "detector_version": clean_version,
        "model_artifact_digest": clean_model_digest,
        "rules_digest": clean_rules_digest,
        "thresholds": clean_thresholds,
    }


def compute_detector_revision_hash(manifest: Dict[str, Any]) -> str:
    """
    Serializes the detector manifest using canonical TGAM-RCC-v1 and returns the SHA256 hex digest.
    Deterministic across process restarts, platforms, and Python runtime instances.
    """
    canonical_bytes = canonicalize_tgam_rcc_v1(manifest)
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_rules_digest(rule_signature: Dict[str, Any]) -> str:
    """
    Serializes a rule signature dictionary using canonical TGAM-RCC-v1 and returns the SHA256 hex digest.
    Deterministic across process restarts, platforms, and Python runtime instances.
    """
    canonical_bytes = canonicalize_tgam_rcc_v1(rule_signature)
    return hashlib.sha256(canonical_bytes).hexdigest()
