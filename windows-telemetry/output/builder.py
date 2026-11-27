import hashlib
from typing import Dict, Any, Optional
from detection.models import DetectionResult
from detection.manifest import build_detector_revision_manifest, compute_detector_revision_hash
from .models import DetectionEvent

class DetectionEventBuilder:
    @staticmethod
    def build(normalized_event: Dict[str, Any], result: DetectionResult) -> Optional[DetectionEvent]:
        if not result.detected:
            return None
            
        required_keys = ["agent_id", "hostname", "os", "timestamp"]
        for key in required_keys:
            if key not in normalized_event:
                raise ValueError(f"Normalized event missing required key: {key}")
                
        if not result.detection_type or result.confidence is None or not result.severity or not result.detector_name:
            raise ValueError("DetectionResult missing required fields")
            
        source_event_id = result.source_event_id or normalized_event.get("event_id")
        if not source_event_id:
            raise ValueError("Source event ID is missing")

        # Resolve explicit schema version (V1 legacy vs V2 revision-identity)
        norm_evidence = normalized_event.get("evidence") or {}
        schema_version = (
            norm_evidence.get("schema_version")
            or normalized_event.get("schema_version")
            or (result.evidence or {}).get("schema_version")
            or "1.0"
        )
            
        det_name = result.detector_name
        det_version = getattr(result, "detector_version", None) or (result.evidence or {}).get("detector_version") or "1.0.0"

        # Construct canonical detector revision manifest
        rules_digest = (
            getattr(result, "rules_digest", None)
            or (result.evidence or {}).get("rules_digest")
            or hashlib.sha256((result.detection_type or det_name).encode("utf-8")).hexdigest()
        )
        thresholds = (
            getattr(result, "thresholds", None)
            or (result.evidence or {}).get("thresholds")
            or {}
        )
        detector_config = (
            getattr(result, "detector_config", None)
            or (result.evidence or {}).get("detector_config")
            or {}
        )
        raw_model_digest = (
            getattr(result, "model_artifact_digest", None)
            or (result.evidence or {}).get("model_artifact_digest")
            or (result.evidence or {}).get("model_hash")
            or ""
        )
        model_source = "none"
        if raw_model_digest:
            model_source = (result.evidence or {}).get("model_artifact_source") or "externally_supplied"

        manifest = getattr(result, "detector_manifest", None) or build_detector_revision_manifest(
            detector_name=det_name,
            detector_version=det_version,
            rules_digest=rules_digest,
            thresholds=thresholds,
            detector_config=detector_config,
            model_artifact_digest=raw_model_digest,
        )
        detector_revision = compute_detector_revision_hash(manifest)

        # Explicit schema-version-based identity selection:
        # V1 historical identity: SHA256(agent_id | source_event_id | detection_type | detector_name)
        # V2 revision identity:   SHA256(agent_id | source_event_id | detection_type | detector_revision_hash)
        if schema_version == "2.0":
            hash_input = f"{normalized_event['agent_id']}|{source_event_id}|{result.detection_type}|{detector_revision}".encode("utf-8")
        else:
            hash_input = f"{normalized_event['agent_id']}|{source_event_id}|{result.detection_type}|{det_name}".encode("utf-8")
        detection_event_id = hashlib.sha256(hash_input).hexdigest()

        # WP-1C & Phase 5: Ensure all canonical identity attributes survive into DetectionEvent.evidence
        evidence = result.evidence.copy() if result.evidence else {}
        evidence["detector_version"] = det_version
        evidence["detector_revision"] = detector_revision
        evidence["detector_manifest"] = manifest
        evidence["schema_version"] = schema_version
        evidence["model_artifact_source"] = model_source
        norm_evidence = normalized_event.get("evidence") or {}
        for id_field in (
            "target_account_id",
            "target_user",
            "target_domain",
            "domain_status",
            "domain_namespace",
            "caller_user",
            "caller_domain",
            "channel_epoch",
            "source_manifest",
            "log_name",
            "channel",
            "record_id",
            "schema_version",
            "identity_type",
        ):
            if id_field in norm_evidence:
                evidence[id_field] = norm_evidence[id_field]

        if "username" in normalized_event and "username" not in evidence:
            evidence["username"] = normalized_event["username"]

        # Phase 2: Preserve Sysmon process, network, and DNS attributes
        for fld in (
            "sysmon_event_id",
            "process_guid",
            "parent_process_guid",
            "process_id",
            "parent_process_id",
            "process_name",
            "parent_process_name",
            "sha256",
            "md5",
            "sha1",
            "imphash",
            "integrity_level",
            "current_directory",
            "destination_ip",
            "destination_port",
            "source_port",
            "protocol",
            "initiated",
            "query_name",
            "query_status",
            "query_results",
            "query_name_normalized",
            "dns_query_length",
            "dns_label_count",
            "dns_max_label_length",
            "dns_query_entropy",
            "dns_max_label_entropy",
            "hashes_validated",
            "invalid_hashes",
            "duplicate_hashes",
            "unknown_hashes",
            "source_ip_canonical",
            "source_ip_raw",
            "source_ip_version",
            "source_ip_scope",
            "source_ip_mapped_ipv4",
            "destination_ip_canonical",
            "destination_ip_raw",
            "destination_ip_version",
            "destination_ip_scope",
            "destination_ip_mapped_ipv4",
            "source_port_raw",
            "destination_port_raw",
        ):
            if fld in norm_evidence and fld not in evidence:
                evidence[fld] = norm_evidence[fld]
        
        return DetectionEvent(
            detection_event_id=detection_event_id,
            timestamp=normalized_event["timestamp"],
            agent_id=normalized_event["agent_id"],
            hostname=normalized_event["hostname"],
            os=normalized_event["os"],
            source_event_id=source_event_id,
            detection_type=result.detection_type,
            confidence=result.confidence,
            severity=result.severity,
            detector_name=result.detector_name,
            evidence=evidence,
            detector_version=det_version,
            detector_revision=detector_revision
        )
