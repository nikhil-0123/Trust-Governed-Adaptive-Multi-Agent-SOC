import hashlib
import logging
from typing import Dict, Any, List, Optional
from core.agent_identity import AgentIdentity
from canonical import (
    canonicalize_tgam_rcc_v1,
    build_source_identity_manifest_v2,
    generate_source_event_id_v2,
    validate_epoch,
    validate_record_id,
)

class WindowsEventNormalizer:
    def __init__(self, agent_identity: AgentIdentity, logger: logging.Logger):
        self.agent_identity = agent_identity
        self.logger = logger
        
    def _map_severity(self, level: Optional[int]) -> str:
        # Windows levels: 1=Critical, 2=Error, 3=Warning, 4=Info, 0=Log Always
        if level == 1:
            return "critical"
        elif level == 2:
            return "high"
        elif level == 3:
            return "medium"
        else:
            return "low"
            
    def _generate_event_id(self, record_id: str, hostname: str, log_name: str) -> str:
        """Legacy V1 pipe-delimited event ID generation."""
        agent_id = self.agent_identity.agent_id
        raw_identity = f"{agent_id}|{hostname}|{log_name}|{record_id}"
        return hashlib.sha256(raw_identity.encode('utf-8')).hexdigest()

    def normalize(
        self,
        raw_event: Dict[str, Any],
        log_name: str = "Security",
        epoch: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Normalizes a single raw Windows event to the standard contract.
        
        If epoch is supplied (integer >= 1), generates a V2 structured, epoch-aware
        source_event_id using TGAM-RCC-v1 canonical serialization.
        
        If epoch is None (legacy fallback mode), preserves the legacy V1 pipe-delimited
        identity generation.
        """
        if "record_id" not in raw_event:
            raise ValueError("Raw event missing required 'record_id'")
        if "timestamp" not in raw_event:
            raise ValueError("Raw event missing required 'timestamp'")
            
        hostname = raw_event.get("computer")
        if not hostname:
            hostname = self.agent_identity.get_hostname()

        # Evidence preserves untrusted raw source info
        evidence = {
            "record_id": raw_event.get("record_id"),
            "provider": raw_event.get("provider"),
            "log_name": log_name,
            "level": raw_event.get("level"),
            "task": raw_event.get("task"),
            "keywords": raw_event.get("keywords")
        }

        # WP-1E.1: Versioned Source Identity Generation
        if epoch is not None:
            valid_epoch = validate_epoch(epoch)
            valid_record_id = validate_record_id(raw_event["record_id"])
                
            source_manifest = build_source_identity_manifest_v2(
                agent_id=self.agent_identity.agent_id,
                channel=log_name,
                epoch=valid_epoch,
                hostname=hostname,
                record_id=valid_record_id
            )
            canonical_bytes = canonicalize_tgam_rcc_v1(source_manifest)
            event_id = hashlib.sha256(canonical_bytes).hexdigest()
            
            evidence["schema_version"] = "2.0"
            evidence["identity_type"] = "source"
            evidence["channel_epoch"] = valid_epoch
            evidence["source_manifest"] = source_manifest
        else:
            # Explicit legacy V1 fallback: do NOT invent or guess an epoch
            event_id = self._generate_event_id(str(raw_event["record_id"]), hostname, log_name)
            evidence["schema_version"] = "1.0"
            evidence["channel_epoch"] = None

        severity = self._map_severity(raw_event.get("level"))
        
        win_event_id = raw_event.get("event_id")
        if win_event_id is not None:
            evidence["windows_event_id"] = win_event_id

        # WP-1C: Invariant resolution for identity fields
        raw_tu = raw_event.get("target_user")
        if raw_tu is None and "username" in raw_event and win_event_id in (4624, 4625):
            raw_tu = raw_event.get("username")
        target_user = str(raw_tu).strip() if raw_tu and str(raw_tu).strip() not in ("", "-") else None

        raw_td = raw_event.get("target_domain")
        target_domain = str(raw_td).strip() if raw_td and str(raw_td).strip() not in ("", "-") else None

        raw_su = raw_event.get("subject_user")
        caller_user = str(raw_su).strip() if raw_su and str(raw_su).strip() not in ("", "-") else None

        raw_sd = raw_event.get("subject_domain")
        caller_domain = str(raw_sd).strip() if raw_sd and str(raw_sd).strip() not in ("", "-") else None

        if target_user is None:
            domain_status = "UNVERIFIED"
            domain_namespace = "UNVERIFIED"
            target_account_id = None
        elif target_domain == ".":
            domain_status = "LOCAL_SAM"
            domain_namespace = "LOCAL_SAM"
            target_account_id = f"LOCAL_SAM\\{target_user.lower()}"
        elif target_domain is not None:
            domain_status = "OBSERVED_DOMAIN"
            domain_namespace = f"DOMAIN:{target_domain.upper()}"
            target_account_id = f"{domain_namespace}\\{target_user.lower()}"
        else:
            domain_status = "UNVERIFIED"
            domain_namespace = "UNVERIFIED"
            target_account_id = None

        evidence["target_user"] = target_user
        evidence["target_domain"] = target_domain
        evidence["domain_status"] = domain_status
        evidence["domain_namespace"] = domain_namespace
        evidence["target_account_id"] = target_account_id
        evidence["caller_user"] = caller_user
        evidence["caller_domain"] = caller_domain

        if "workstation_name" in raw_event and raw_event["workstation_name"]:
            evidence["workstation_name"] = raw_event["workstation_name"]
        if "ip_port" in raw_event and raw_event["ip_port"]:
            evidence["ip_port"] = raw_event["ip_port"]
        if "status" in raw_event and raw_event["status"]:
            evidence["status"] = raw_event["status"]
        if "sub_status" in raw_event and raw_event["sub_status"]:
            evidence["sub_status"] = raw_event["sub_status"]

        # Top-level username: Strictly target_user for authentication events.
        if win_event_id in (4624, 4625):
            username = target_user
        else:
            username = caller_user or target_user or raw_event.get("username", None) or raw_event.get("user", None)

        if "logon_type" in raw_event and raw_event["logon_type"] is not None:
            evidence["logon_type"] = raw_event["logon_type"]

        if "process_name" in raw_event and raw_event["process_name"]:
            evidence["process_name"] = raw_event["process_name"]

        if "command_line" in raw_event and raw_event["command_line"]:
            evidence["command_line"] = raw_event["command_line"]

        if "parent_process_name" in raw_event and raw_event["parent_process_name"]:
            evidence["parent_process_name"] = raw_event["parent_process_name"]

        if "process_id" in raw_event and raw_event["process_id"]:
            evidence["process_id"] = raw_event["process_id"]

        if "raw_xml" in raw_event:
            evidence["raw_xml"] = raw_event["raw_xml"]

        # Sysmon & Event Type Mapping
        is_sysmon = (
            "sysmon" in str(raw_event.get("provider", "")).lower()
            or "sysmon" in str(log_name).lower()
            or win_event_id in (1, 3, 22)
        )

        if is_sysmon and win_event_id is not None:
            evidence["sysmon_event_id"] = win_event_id

        # Copy Sysmon/Process/Network/DNS evidence fields if present
        for fld in (
            "parent_command_line", "parent_user", "process_guid", "parent_process_guid",
            "parent_process_id", "integrity_level", "current_directory", "user",
            "hashes", "hashes_parsed", "sha256", "md5", "sha1", "imphash",
            "original_file_name", "file_version", "description", "product", "company",
            "terminal_session_id", "logon_guid", "logon_id", "utc_time",
            "destination_ip", "destination_port", "source_port", "protocol", "initiated",
            "destination_hostname", "source_hostname",
            "query_name", "query_status", "query_results"
        ):
            if fld in raw_event and raw_event[fld] is not None:
                evidence[fld] = raw_event[fld]

        if is_sysmon and win_event_id == 1:
            event_type = "windows_process_event"
        elif is_sysmon and win_event_id == 3:
            event_type = "windows_network_event"
        elif is_sysmon and win_event_id == 22:
            event_type = "windows_dns_event"
        else:
            event_type = "windows_security_event"

        return {
            "event_id": event_id,
            "timestamp": raw_event["timestamp"],
            "agent_id": self.agent_identity.agent_id,
            "hostname": hostname,
            "os": "Windows",
            "event_type": event_type,
            "source_ip": raw_event.get("source_ip", None),
            "username": username,
            "severity": severity,
            "detection_type": None,
            "confidence": None,
            "evidence": evidence
        }

    def normalize_batch(
        self,
        raw_events: List[Dict[str, Any]],
        log_name: str = "Security",
        epoch: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Normalizes a batch of raw events sequentially, preserving order."""
        normalized_events = []
        for raw_event in raw_events:
            try:
                normalized = self.normalize(raw_event, log_name, epoch=epoch)
                normalized_events.append(normalized)
            except Exception as e:
                self.logger.error(f"Failed to normalize event: {e}. Raw keys: {list(raw_event.keys())}")
        return normalized_events
