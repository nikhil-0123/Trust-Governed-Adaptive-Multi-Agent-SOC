from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import re
import time
import heapq
import logging
import math
from .models import DetectionResult
from .manifest import compute_rules_digest

class BruteForceRule:
    def __init__(
        self,
        failure_threshold: int = 5,
        window_seconds: int = 60,
        max_state_keys: Optional[int] = None,
        cleanup_interval_seconds: Optional[float] = None,
        logger: Optional[logging.Logger] = None,
        detector_version: Optional[str] = None,
    ):
        self.name = "windows_bruteforce_rule"
        self.detector_name = "windows_bruteforce_rule"
        self.detector_version = str(detector_version) if detector_version is not None else "1.0.0"

        # Validate failure_threshold
        if isinstance(failure_threshold, bool) or not isinstance(failure_threshold, int) or failure_threshold < 3:
            raise ValueError(f"failure_threshold must be an integer >= 3 to maintain distinct classification tiers, got {failure_threshold}")
        self.failure_threshold = failure_threshold

        # Validate window_seconds
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or window_seconds <= 0:
            raise ValueError(f"window_seconds must be a positive integer, got {window_seconds}")
        self.window_seconds = window_seconds

        self.logger = logger or logging.getLogger(self.name)

        # Resolve and validate max_state_keys
        if max_state_keys is None:
            from config.settings import config
            max_state_keys = getattr(config, 'windows_detection_max_state_keys', 10000)

        if isinstance(max_state_keys, bool) or not isinstance(max_state_keys, int):
            raise TypeError(f"max_state_keys must be an int, got {type(max_state_keys).__name__}")
        if max_state_keys < 2:
            raise ValueError(f"max_state_keys must be an integer >= 2, got {max_state_keys}")
        self.max_state_keys = max_state_keys

        # Guarantee 0 < low_watermark < max_state_keys for all valid max_state_keys
        self.low_watermark = max(1, min(int(self.max_state_keys * 0.85), self.max_state_keys - 1))

        # Resolve and validate cleanup_interval_seconds
        if cleanup_interval_seconds is None:
            from config.settings import config
            cleanup_interval_seconds = getattr(config, 'windows_detection_cleanup_interval_seconds', 5.0)

        if isinstance(cleanup_interval_seconds, bool) or not isinstance(cleanup_interval_seconds, (int, float)):
            raise TypeError(f"cleanup_interval_seconds must be a float or int, got {type(cleanup_interval_seconds).__name__}")
        if not math.isfinite(cleanup_interval_seconds):
            raise ValueError(f"cleanup_interval_seconds must be finite, got {cleanup_interval_seconds}")
        if cleanup_interval_seconds <= 0:
            raise ValueError(f"cleanup_interval_seconds must be > 0, got {cleanup_interval_seconds}")
        self.cleanup_interval = float(cleanup_interval_seconds)

        self.state = {}
        self._last_cleanup_monotonic = 0.0
        self._last_cleanup_event_time = None
        self._max_observed_event_time = None
        self._last_warning_monotonic = 0.0
        self.metrics = {
            "evaluations": 0,
            "fast_path_evaluations": 0,
            "ttl_cleanups": 0,
            "capacity_classification_scans": 0,
            "heap_selection_operations": 0,
            "tier1_evictions": 0,
            "tier2_evictions": 0,
            "forced_tier3_evictions": 0,
            "forced_tier4_evictions": 0,
            "forced_active_state_evictions": 0,
            "total_evictions": 0
        }

    def get_thresholds(self) -> Dict[str, Any]:
        return {
            "failure_threshold": float(self.failure_threshold),
            "window_seconds": float(self.window_seconds),
        }

    def get_detector_config(self) -> Dict[str, Any]:
        return {
            "cleanup_interval_seconds": float(self.cleanup_interval),
            "low_watermark": int(self.low_watermark),
            "max_state_keys": int(self.max_state_keys),
        }

    def get_rules_digest(self) -> str:
        sig = {
            "detector_name": self.detector_name,
            "failure_threshold": int(self.failure_threshold),
            "target_event_id": 4625,
            "tracked_entities": ["endpoint_hostname", "source_ip", "target_account_id"],
            "window_seconds": int(self.window_seconds),
        }
        return compute_rules_digest(sig)

    def _cleanup_stale_keys(self, current_time: Optional[datetime] = None, active_key: Optional[tuple] = None, force: bool = False):
        """
        Prunes inactive keys from state memory whose events and duplicate-alert suppression
        windows are older than cutoff relative to _max_observed_event_time (non-regressing watermark).
        Throttled by monotonic wall-clock and event-time progression unless force=True.
        """
        now_mono = time.monotonic()
        mono_due = (now_mono - self._last_cleanup_monotonic >= self.cleanup_interval)

        watermark = self._max_observed_event_time
        if watermark is None and current_time is not None:
            watermark = current_time

        event_time_due = False
        if watermark is not None:
            if self._last_cleanup_event_time is not None:
                if (watermark - self._last_cleanup_event_time).total_seconds() >= self.cleanup_interval:
                    event_time_due = True
            else:
                event_time_due = True

        if not force and not mono_due and not event_time_due:
            return

        self._last_cleanup_monotonic = now_mono
        if watermark is not None:
            if self._last_cleanup_event_time is None or watermark > self._last_cleanup_event_time:
                self._last_cleanup_event_time = watermark
        self.metrics["ttl_cleanups"] += 1

        if watermark is None:
            return

        cutoff = watermark - timedelta(seconds=self.window_seconds)

        stale_keys = []
        for key, group_state in self.state.items():
            if key == active_key:
                continue
            # Filter events older than cutoff
            group_state["events"] = [(t, eid) for t, eid in group_state["events"] if t >= cutoff]
            last_alert = group_state.get("last_alert_time")
            # If no active events remain and no active alert suppression remains, key is stale
            if not group_state["events"] and (last_alert is None or last_alert < cutoff):
                stale_keys.append(key)
        for key in stale_keys:
            del self.state[key]

    def _classify_and_evict_batch(self, current_time: datetime, active_key: Optional[tuple] = None):
        """
        Deterministically evicts keys when state exceeds capacity (max_state_keys)
        down to low watermark using 4 mutually exclusive tiers.

        Routine Eviction:
        - Tier 1: Noise (len <= 1, not alert-active) - priority 1
        - Tier 2: Low Multi-Attempt (2 <= len <= T-2, not alert-active) - priority 2

        Forced Eviction (Protected State Fallback):
        - Tier 3: Alerted Ongoing (alert-active) - sacrificed first to preserve duplicate suppression
                  only as long as possible while avoiding dropped unalerted attacks
        - Tier 4: Near-Threshold (len >= T-1, not alert-active) - sacrificed last to protect active attacks
        """
        if len(self.state) <= self.max_state_keys:
            return

        # Step 1: Force TTL cleanup first
        self._cleanup_stale_keys(current_time, active_key=active_key, force=True)
        if len(self.state) <= self.max_state_keys:
            return

        num_to_evict = len(self.state) - self.low_watermark
        if num_to_evict <= 0:
            return

        self.metrics["capacity_classification_scans"] += 1

        watermark = self._max_observed_event_time if self._max_observed_event_time is not None else current_time
        cutoff = watermark - timedelta(seconds=self.window_seconds)

        # Mutually exclusive tier collectors:
        # Tier 1 (Noise): len(events) <= 1 and not is_alert_active -> priority 1
        # Tier 2 (Low Multi-Attempt): 2 <= len(events) <= T - 2 and not is_alert_active -> priority 2
        # Tier 3 (Alerted Ongoing): is_alert_active -> PROTECTED (Forced Stage 1 fallback)
        # Tier 4 (Near-Threshold): len(events) >= T - 1 and not is_alert_active -> PROTECTED (Forced Stage 2 fallback)
        tier1 = []
        tier2 = []
        tier3 = []
        tier4 = []

        for key, group_state in self.state.items():
            if key == active_key:
                continue
            evts = group_state["events"]
            cnt = len(evts)
            last_alert = group_state.get("last_alert_time")
            is_alert_active = (last_alert is not None and last_alert >= cutoff)

            username = str(key[0]) if key[0] is not None else ""
            ip = str(key[1]) if key[1] is not None else ""
            key_repr = repr(key)

            if is_alert_active:
                # Tier 3: Alerted ongoing cluster under duplicate suppression
                tier3.append((last_alert, username, ip, key_repr, key))
            else:
                # Alert is expired or None
                if cnt <= 1:
                    t_val = evts[0][0] if evts else cutoff
                    tier1.append((t_val, username, ip, key_repr, key))
                elif 2 <= cnt <= self.failure_threshold - 2:
                    tier2.append((evts[0][0], username, ip, key_repr, key))
                elif cnt >= self.failure_threshold - 1:
                    latest_t = evts[-1][0] if evts else current_time
                    tier4.append((latest_t, username, ip, key_repr, key))

        evicted_keys = []

        def evict_from_tier(candidates, needed):
            if not candidates or needed <= 0:
                return 0
            if len(candidates) <= needed:
                for item in candidates:
                    evicted_keys.append(item[4])
                return len(candidates)
            self.metrics["heap_selection_operations"] += 1
            selected = heapq.nsmallest(needed, candidates)
            for item in selected:
                evicted_keys.append(item[4])
            return needed

        # --- ROUTINE EVICTION ---
        # Priority 1: Evict Tier 1 (Noise)
        evicted_t1 = evict_from_tier(tier1, num_to_evict)
        self.metrics["tier1_evictions"] += evicted_t1
        num_to_evict -= evicted_t1

        # Priority 2: Evict Tier 2 (Low Multi-Attempt) if still needed
        if num_to_evict > 0:
            evicted_t2 = evict_from_tier(tier2, num_to_evict)
            self.metrics["tier2_evictions"] += evicted_t2
            num_to_evict -= evicted_t2

        # --- FORCED EVICTION (PROTECTED TIERS FALLBACK) ---
        # Entered ONLY when Tier 1 and Tier 2 are exhausted and capacity cannot otherwise be maintained
        evicted_t3 = 0
        evicted_t4 = 0

        # Forced Stage 1: Evict Tier 3 (Alerted Groups)
        # Oldest last_alert_time evicted first
        if num_to_evict > 0 and tier3:
            evicted_t3 = evict_from_tier(tier3, num_to_evict)
            self.metrics["forced_tier3_evictions"] += evicted_t3
            num_to_evict -= evicted_t3

        # Forced Stage 2: Evict Tier 4 (Near-Threshold Groups)
        # Oldest latest_event_time evicted first
        if num_to_evict > 0 and tier4:
            evicted_t4 = evict_from_tier(tier4, num_to_evict)
            self.metrics["forced_tier4_evictions"] += evicted_t4
            num_to_evict -= evicted_t4

        total_forced = evicted_t3 + evicted_t4
        now_mono = time.monotonic()
        if total_forced > 0 and (now_mono - self._last_warning_monotonic >= 5.0):
            if evicted_t3 > 0 and evicted_t4 > 0:
                eviction_tier_name = "Tier 3 (Alerted) + Tier 4 (Near-Threshold)"
                msg = f"State forced eviction executed: evicted {evicted_t3} Tier 3 and {evicted_t4} Tier 4 candidate(s)"
            elif evicted_t3 > 0:
                eviction_tier_name = "Tier 3 (Alerted)"
                msg = f"State forced eviction executed: evicted {evicted_t3} Tier 3 candidate(s)"
            else:
                eviction_tier_name = "Tier 4 (Near-Threshold)"
                msg = f"State forced eviction executed: evicted {evicted_t4} Tier 4 candidate(s)"

            extra_payload = {
                "event_type": "state_forced_eviction",
                "eviction_tier": eviction_tier_name,
                "forced_eviction_count": total_forced,
                "current_size": len(self.state),
                "max_capacity": self.max_state_keys,
                "low_watermark": self.low_watermark,
            }
            self.logger.warning(msg, extra=extra_payload)
            self._last_warning_monotonic = now_mono

        self.metrics["forced_active_state_evictions"] = (
            self.metrics["forced_tier3_evictions"] + self.metrics["forced_tier4_evictions"]
        )

        for k in evicted_keys:
            if k in self.state:
                del self.state[k]

        self.metrics["total_evictions"] += len(evicted_keys)

    def evaluate(self, normalized_event: Dict[str, Any]) -> Optional[DetectionResult]:
        self.metrics["evaluations"] += 1
        evidence = normalized_event.get("evidence", {})

        # Fast-path 1: Only process Windows Event ID 4625 (Failed Logon)
        if evidence.get("windows_event_id") != 4625:
            self.metrics["fast_path_evaluations"] += 1
            return None

        endpoint_hostname = normalized_event.get("hostname", "unknown-host")

        # WP-1C: Require verified target_account_id for account-level brute-force tracking
        target_account_id = evidence.get("target_account_id")
        if not target_account_id:
            # Events with unverified target domain must not increment account-level counter
            if evidence.get("domain_status") == "UNVERIFIED":
                self.metrics["fast_path_evaluations"] += 1
                return None
            username = normalized_event.get("username")
            if not username:
                self.metrics["fast_path_evaluations"] += 1
                return None
            # Synthetic legacy unit test compatibility (when target_account_id not provided in evidence)
            source_ip = normalized_event.get("source_ip")
            group_key = (username, source_ip)
            target_account_id = f"LOCAL_SAM\\{username.lower()}"
        else:
            source_ip = normalized_event.get("source_ip")
            group_key = (target_account_id, endpoint_hostname, source_ip)

        timestamp_str = normalized_event.get("timestamp")
        try:
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            current_time = datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError, AttributeError) as e:
            raise ValueError(f"Invalid timestamp in event: {timestamp_str}") from e

        if self._max_observed_event_time is None or current_time > self._max_observed_event_time:
            self._max_observed_event_time = current_time

        # Clean up stale keys periodically (throttled by monotonic/event-time interval)
        self._cleanup_stale_keys(current_time, active_key=group_key)

        group_state = self.state.setdefault(group_key, {"events": [], "last_alert_time": None})
        events = group_state["events"]

        event_id = normalized_event.get("event_id")

        # Fast-path 3: Check for repeated events with the same event_id to prevent duplicate counting
        if event_id and any(eid == event_id for _, eid in events):
            self.metrics["fast_path_evaluations"] += 1
            return None

        events.append((current_time, event_id))

        # Sort events by timestamp to reliably handle out-of-order event arrivals
        events.sort(key=lambda x: x[0])

        # Group reference time is the latest timestamp observed in the group
        group_ref_time = max(current_time, events[-1][0])
        cutoff = group_ref_time - timedelta(seconds=self.window_seconds)

        # Keep events within the window (>= cutoff)
        group_state["events"] = [(t, eid) for t, eid in events if t >= cutoff]

        # Enforce capacity bounds with deterministic watermark batch eviction
        if len(self.state) > self.max_state_keys:
            self._classify_and_evict_batch(current_time, active_key=group_key)

        if len(group_state["events"]) >= self.failure_threshold:
            last_alert = group_state["last_alert_time"]

            # Suppress duplicate alerts in the same sliding window
            if last_alert is None or last_alert < cutoff:
                group_state["last_alert_time"] = current_time

                username = normalized_event.get("username")
                result_evidence = {
                    "windows_event_id": 4625,
                    "failure_count": len(group_state["events"]),
                    "threshold": self.failure_threshold,
                    "window_seconds": self.window_seconds,
                    "target_account_id": target_account_id,
                    "target_user": evidence.get("target_user") or username,
                    "target_domain": evidence.get("target_domain"),
                    "domain_status": evidence.get("domain_status", "LOCAL_SAM"),
                    "domain_namespace": evidence.get("domain_namespace", "LOCAL_SAM"),
                    "username": username,
                    "hostname": endpoint_hostname,
                    "related_event_ids": [eid for t, eid in group_state["events"]]
                }

                if source_ip is not None:
                    result_evidence["source_ip"] = source_ip

                return DetectionResult(
                    detected=True,
                    detection_type=self.name,
                    confidence=1.0,
                    severity="high",
                    detector_name=self.detector_name,
                    source_event_id=event_id,
                    evidence=result_evidence,
                    detector_version=self.detector_version,
                    rules_digest=self.get_rules_digest(),
                    thresholds=self.get_thresholds(),
                    detector_config=self.get_detector_config(),
                )

        return None

    def reset_state(self):
        self.state.clear()
        self._last_cleanup_monotonic = 0.0
        self._last_cleanup_event_time = None
        self._max_observed_event_time = None
        self._last_warning_monotonic = 0.0
        for k in self.metrics:
            self.metrics[k] = 0


def _extract_cmd_line(normalized_event: Dict[str, Any]) -> str:
    evidence = normalized_event.get("evidence", {})
    cmd = evidence.get("command_line") or normalized_event.get("command_line") or ""
    if not cmd and "raw_xml" in evidence:
        raw_xml = evidence["raw_xml"]
        m = re.search(r'<Data Name=["\'](?:CommandLine|ScriptBlockText)["\']>(.*?)</Data>', raw_xml, re.IGNORECASE)
        if m:
            cmd = m.group(1)
    return str(cmd).strip()


class SuspiciousPowerShellRule:
    """
    Detects obfuscated PowerShell, Base64 EncodedCommands, and download cradles.
    MITRE ATT&CK: T1059.001 (Command and Scripting Interpreter: PowerShell)
    """
    def __init__(self, detector_version: Optional[str] = None):
        self.name = "windows_powershell_execution"
        self.detector_name = "windows_powershell_rule"
        self.detector_version = str(detector_version) if detector_version is not None else "1.0.0"
        self.patterns = [
            (r'(?i)-(?:e|enc|encodedcommand)\s+[a-zA-Z0-9+/=]{6,}', "Base64 EncodedCommand"),
            (r'(?i)downloadstring|downloadfile|net\.webclient', "WebClient Download Cradle"),
            (r'(?i)\b(?:iwr|invoke-webrequest|invoke-restmethod)\b.*https?://', "PowerShell Web Download"),
            (r'(?i)\b(?:iex|invoke-expression)\b', "Invoke-Expression (IEX) Dynamic Execution"),
            (r'(?i)-(?:w|windowstyle)\s+hidden', "Hidden WindowStyle"),
            (r'(?i)-(?:executionpolicy|ep)\s+bypass', "ExecutionPolicy Bypass")
        ]

    def get_thresholds(self) -> Dict[str, Any]:
        return {"confidence": 0.95}

    def get_detector_config(self) -> Dict[str, Any]:
        return {
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution"
        }

    def get_rules_digest(self) -> str:
        pattern_specs = [
            {"description": desc, "pattern": pat}
            for pat, desc in sorted(self.patterns, key=lambda x: str(x[0]))
        ]
        sig = {
            "detector_name": self.detector_name,
            "patterns": pattern_specs,
            "technique_id": "T1059.001",
        }
        return compute_rules_digest(sig)

    def evaluate(self, normalized_event: Dict[str, Any]) -> Optional[DetectionResult]:
        cmd = _extract_cmd_line(normalized_event)
        if not cmd:
            return None

        matched_patterns = []
        for pat, desc in self.patterns:
            if re.search(pat, cmd):
                matched_patterns.append(desc)

        if matched_patterns:
            event_id = normalized_event.get("event_id")
            evidence = {
                "command_line": cmd,
                "matched_patterns": matched_patterns,
                "mitre_technique_id": "T1059.001",
                "mitre_technique_name": "Command and Scripting Interpreter: PowerShell",
                "mitre_tactic": "Execution"
            }
            if "process_name" in normalized_event.get("evidence", {}):
                evidence["process_name"] = normalized_event["evidence"]["process_name"]

            return DetectionResult(
                detected=True,
                detection_type=self.name,
                confidence=0.95,
                severity="high",
                detector_name=self.detector_name,
                source_event_id=event_id,
                evidence=evidence,
                detector_version=self.detector_version,
                rules_digest=self.get_rules_digest(),
                thresholds=self.get_thresholds(),
                detector_config=self.get_detector_config(),
            )
        return None


class SuspiciousLolbinsDownloadRule:
    """
    Detects Living-off-the-Land Binaries (LOLBins) used for ingress tool transfer and malware staging.
    MITRE ATT&CK: T1105 (Ingress Tool Transfer)
    """
    def __init__(self, detector_version: Optional[str] = None):
        self.name = "windows_lolbin_download"
        self.detector_name = "windows_lolbin_rule"
        self.detector_version = str(detector_version) if detector_version is not None else "1.0.0"
        self.patterns = [
            (r'(?i)\bcertutil(?:\.exe)?\b.*[-/](?:urlcache|split)', "Certutil URLCache Stager"),
            (r'(?i)\bbitsadmin(?:\.exe)?\b.*[/-](?:transfer|create|addfile|resume)', "Bitsadmin Transfer"),
            (r'(?i)\bmshta(?:\.exe)?\b.*(?:https?://|javascript:|vbscript:)', "MSHTA Remote Script Execution"),
            (r'(?i)\brundll32(?:\.exe)?\b.*(?:https?://|javascript:)', "Rundll32 Remote URL / Script"),
            (r'(?i)\b(?:curl|wget)(?:\.exe)?\b.*https?://.*\.(?:exe|dll|ps1|bat|vbs|sh)', "Curl/Wget Tool Download")
        ]

    def get_thresholds(self) -> Dict[str, Any]:
        return {"confidence": 0.90}

    def get_detector_config(self) -> Dict[str, Any]:
        return {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control"
        }

    def get_rules_digest(self) -> str:
        pattern_specs = [
            {"description": desc, "pattern": pat}
            for pat, desc in sorted(self.patterns, key=lambda x: str(x[0]))
        ]
        sig = {
            "detector_name": self.detector_name,
            "patterns": pattern_specs,
            "technique_id": "T1105",
        }
        return compute_rules_digest(sig)

    def evaluate(self, normalized_event: Dict[str, Any]) -> Optional[DetectionResult]:
        cmd = _extract_cmd_line(normalized_event)
        if not cmd:
            return None

        matched = []
        for pat, desc in self.patterns:
            if re.search(pat, cmd):
                matched.append(desc)

        if matched:
            event_id = normalized_event.get("event_id")
            evidence = {
                "command_line": cmd,
                "matched_patterns": matched,
                "mitre_technique_id": "T1105",
                "mitre_technique_name": "Ingress Tool Transfer",
                "mitre_tactic": "Command and Control"
            }
            return DetectionResult(
                detected=True,
                detection_type=self.name,
                confidence=0.90,
                severity="high",
                detector_name=self.detector_name,
                source_event_id=event_id,
                evidence=evidence,
                detector_version=self.detector_version,
                rules_digest=self.get_rules_digest(),
                thresholds=self.get_thresholds(),
                detector_config=self.get_detector_config(),
            )
        return None


class ReconnaissanceCommandsRule:
    """
    Detects discovery and enumeration commands executed after initial access.
    MITRE ATT&CK: T1082 (System Information Discovery), T1087 (Account Discovery)
    """
    def __init__(self, detector_version: Optional[str] = None):
        self.name = "windows_reconnaissance"
        self.detector_name = "windows_reconnaissance_rule"
        self.detector_version = str(detector_version) if detector_version is not None else "1.0.0"
        self.patterns = [
            (r'(?i)\bwhoami(?:\.exe)?\s+/(?:all|priv)\b', "Whoami Privilege Enumeration", "T1033"),
            (r'(?i)\bnet(?:\.exe)?\s+localgroup\s+administrators\b', "Local Admin Discovery", "T1087"),
            (r'(?i)\bnet(?:\.exe)?\s+user\s+[a-zA-Z0-9_\-]+\s+/domain\b', "Domain User Discovery", "T1087"),
            (r'(?i)\bsysteminfo(?:\.exe)?\b', "Systeminfo Discovery", "T1082"),
            (r'(?i)\bnltest(?:\.exe)?\s+/(?:dclist|domain_trusts)\b', "Domain Controller Enumeration", "T1018")
        ]

    def get_thresholds(self) -> Dict[str, Any]:
        return {"confidence": 0.85}

    def get_detector_config(self) -> Dict[str, Any]:
        return {
            "technique_id": "T1082",
            "technique_name": "Discovery",
            "tactic": "Discovery"
        }

    def get_rules_digest(self) -> str:
        pattern_specs = [
            {"description": desc, "pattern": pat, "technique_id": tech_id}
            for pat, desc, tech_id in sorted(self.patterns, key=lambda x: str(x[0]))
        ]
        sig = {
            "detector_name": self.detector_name,
            "patterns": pattern_specs,
        }
        return compute_rules_digest(sig)

    def evaluate(self, normalized_event: Dict[str, Any]) -> Optional[DetectionResult]:
        cmd = _extract_cmd_line(normalized_event)
        if not cmd:
            return None

        for pat, desc, tech_id in self.patterns:
            if re.search(pat, cmd):
                event_id = normalized_event.get("event_id")
                evidence = {
                    "command_line": cmd,
                    "recon_type": desc,
                    "mitre_technique_id": tech_id,
                    "mitre_technique_name": "Discovery",
                    "mitre_tactic": "Discovery"
                }
                return DetectionResult(
                    detected=True,
                    detection_type=self.name,
                    confidence=0.85,
                    severity="medium",
                    detector_name=self.detector_name,
                    source_event_id=event_id,
                    evidence=evidence,
                    detector_version=self.detector_version,
                    rules_digest=self.get_rules_digest(),
                    thresholds=self.get_thresholds(),
                    detector_config=self.get_detector_config(),
                )
        return None


class DefenseEvasionRule:
    """
    Detects attempts to disable Windows Defender, clear event logs, or delete volume shadow copies.
    MITRE ATT&CK: T1562.001 (Impair Defenses), T1070.001 (Clear Event Logs)
    """
    def __init__(self, detector_version: Optional[str] = None):
        self.name = "windows_defense_evasion"
        self.detector_name = "windows_defense_evasion_rule"
        self.detector_version = str(detector_version) if detector_version is not None else "1.0.0"
        self.patterns = [
            (r'(?i)\b(?:sc|net)(?:\.exe)?\s+stop\s+windefend\b', "Stop Windows Defender Service", "T1562.001"),
            (r'(?i)set-mppreference.*-disablerealtime', "Disable Defender Real-time Protection", "T1562.001"),
            (r'(?i)\bwevtutil(?:\.exe)?\s+cl\s+(?:security|system)\b', "Clear Windows Security Logs", "T1070.001"),
            (r'(?i)\bvssadmin(?:\.exe)?\s+delete\s+shadows\b', "Delete Shadow Copies (Ransomware Prep)", "T1490")
        ]

    def get_thresholds(self) -> Dict[str, Any]:
        return {"confidence": 0.98}

    def get_detector_config(self) -> Dict[str, Any]:
        return {
            "technique_id": "T1562.001",
            "technique_name": "Impair Defenses",
            "tactic": "Defense Evasion"
        }

    def get_rules_digest(self) -> str:
        pattern_specs = [
            {"description": desc, "pattern": pat, "technique_id": tech_id}
            for pat, desc, tech_id in sorted(self.patterns, key=lambda x: str(x[0]))
        ]
        sig = {
            "detector_name": self.detector_name,
            "patterns": pattern_specs,
        }
        return compute_rules_digest(sig)

    def evaluate(self, normalized_event: Dict[str, Any]) -> Optional[DetectionResult]:
        cmd = _extract_cmd_line(normalized_event)
        if not cmd:
            return None

        for pat, desc, tech_id in self.patterns:
            if re.search(pat, cmd):
                event_id = normalized_event.get("event_id")
                evidence = {
                    "command_line": cmd,
                    "tamper_action": desc,
                    "mitre_technique_id": tech_id,
                    "mitre_technique_name": "Impair Defenses",
                    "mitre_tactic": "Defense Evasion"
                }
                return DetectionResult(
                    detected=True,
                    detection_type=self.name,
                    confidence=0.98,
                    severity="critical",
                    detector_name=self.detector_name,
                    source_event_id=event_id,
                    evidence=evidence,
                    detector_version=self.detector_version,
                    rules_digest=self.get_rules_digest(),
                    thresholds=self.get_thresholds(),
                    detector_config=self.get_detector_config(),
                )
        return None
