from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from .models import DetectionResult

class BruteForceRule:
    def __init__(self):
        self.name = "windows_bruteforce_rule"
        self.failure_threshold = 5
        self.window_seconds = 60
        self.state = {}

    def evaluate(self, normalized_event: Dict[str, Any]) -> Optional[DetectionResult]:
        evidence = normalized_event.get("evidence", {})
        
        # Only process Windows Event ID 4625 (Failed Logon)
        if evidence.get("windows_event_id") != 4625:
            return None
            
        username = normalized_event.get("username")
        if not username:
            # Cannot group safely without a username
            return None
            
        source_ip = normalized_event.get("source_ip")
        group_key = (username, source_ip)
        
        timestamp_str = normalized_event.get("timestamp")
        try:
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            current_time = datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError, AttributeError) as e:
            raise ValueError(f"Invalid timestamp in event: {timestamp_str}") from e

        group_state = self.state.setdefault(group_key, {"events": [], "last_alert_time": None})
        events = group_state["events"]
        
        event_id = normalized_event.get("event_id")
        events.append((current_time, event_id))
        
        cutoff = current_time - timedelta(seconds=self.window_seconds)
        # Keep events within the window (>= cutoff)
        group_state["events"] = [(t, eid) for t, eid in events if t >= cutoff]
        
        if len(group_state["events"]) >= self.failure_threshold:
            last_alert = group_state["last_alert_time"]
            
            # Suppress duplicate alerts in the same sliding window
            if last_alert is None or last_alert < cutoff:
                group_state["last_alert_time"] = current_time
                
                result_evidence = {
                    "windows_event_id": 4625,
                    "failure_count": len(group_state["events"]),
                    "threshold": self.failure_threshold,
                    "window_seconds": self.window_seconds,
                    "username": username,
                    "related_event_ids": [eid for t, eid in group_state["events"]]
                }
                
                if source_ip is not None:
                    result_evidence["source_ip"] = source_ip
                    
                return DetectionResult(
                    detected=True,
                    detection_type=self.name,
                    confidence=1.0,
                    severity="high",
                    detector_name=self.name,
                    source_event_id=event_id,
                    evidence=result_evidence
                )
                
        return None

    def reset_state(self):
        self.state.clear()


import re

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
    def __init__(self):
        self.name = "windows_powershell_execution"
        self.patterns = [
            (r'(?i)-(?:e|enc|encodedcommand)\s+[a-zA-Z0-9+/=]{6,}', "Base64 EncodedCommand"),
            (r'(?i)downloadstring|downloadfile|net\.webclient', "WebClient Download Cradle"),
            (r'(?i)\b(?:iwr|invoke-webrequest|invoke-restmethod)\b.*https?://', "PowerShell Web Download"),
            (r'(?i)\b(?:iex|invoke-expression)\b', "Invoke-Expression (IEX) Dynamic Execution"),
            (r'(?i)-(?:w|windowstyle)\s+hidden', "Hidden WindowStyle"),
            (r'(?i)-(?:executionpolicy|ep)\s+bypass', "ExecutionPolicy Bypass")
        ]

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
                detector_name="windows_powershell_rule",
                source_event_id=event_id,
                evidence=evidence
            )
        return None


class SuspiciousLolbinsDownloadRule:
    """
    Detects Living-off-the-Land Binaries (LOLBins) used for ingress tool transfer and malware staging.
    MITRE ATT&CK: T1105 (Ingress Tool Transfer)
    """
    def __init__(self):
        self.name = "windows_lolbin_download"
        self.patterns = [
            (r'(?i)\bcertutil(?:\.exe)?\b.*[-/](?:urlcache|split)', "Certutil URLCache Stager"),
            (r'(?i)\bbitsadmin(?:\.exe)?\b.*[/-](?:transfer|create|addfile|resume)', "Bitsadmin Transfer"),
            (r'(?i)\bmshta(?:\.exe)?\b.*(?:https?://|javascript:|vbscript:)', "MSHTA Remote Script Execution"),
            (r'(?i)\brundll32(?:\.exe)?\b.*(?:https?://|javascript:)', "Rundll32 Remote URL / Script"),
            (r'(?i)\b(?:curl|wget)(?:\.exe)?\b.*https?://.*\.(?:exe|dll|ps1|bat|vbs|sh)', "Curl/Wget Tool Download")
        ]

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
                detector_name="windows_lolbin_rule",
                source_event_id=event_id,
                evidence=evidence
            )
        return None


class ReconnaissanceCommandsRule:
    """
    Detects discovery and enumeration commands executed after initial access.
    MITRE ATT&CK: T1082 (System Information Discovery), T1087 (Account Discovery)
    """
    def __init__(self):
        self.name = "windows_reconnaissance"
        self.patterns = [
            (r'(?i)\bwhoami(?:\.exe)?\s+/(?:all|priv)\b', "Whoami Privilege Enumeration", "T1033"),
            (r'(?i)\bnet(?:\.exe)?\s+localgroup\s+administrators\b', "Local Admin Discovery", "T1087"),
            (r'(?i)\bnet(?:\.exe)?\s+user\s+[a-zA-Z0-9_\-]+\s+/domain\b', "Domain User Discovery", "T1087"),
            (r'(?i)\bsysteminfo(?:\.exe)?\b', "Systeminfo Discovery", "T1082"),
            (r'(?i)\bnltest(?:\.exe)?\s+/(?:dclist|domain_trusts)\b', "Domain Controller Enumeration", "T1018")
        ]

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
                    detector_name="windows_reconnaissance_rule",
                    source_event_id=event_id,
                    evidence=evidence
                )
        return None


class DefenseEvasionRule:
    """
    Detects attempts to disable Windows Defender, clear event logs, or delete volume shadow copies.
    MITRE ATT&CK: T1562.001 (Impair Defenses), T1070.001 (Clear Event Logs)
    """
    def __init__(self):
        self.name = "windows_defense_evasion"
        self.patterns = [
            (r'(?i)\b(?:sc|net)(?:\.exe)?\s+stop\s+windefend\b', "Stop Windows Defender Service", "T1562.001"),
            (r'(?i)set-mppreference.*-disablerealtime', "Disable Defender Real-time Protection", "T1562.001"),
            (r'(?i)\bwevtutil(?:\.exe)?\s+cl\s+(?:security|system)\b', "Clear Windows Security Logs", "T1070.001"),
            (r'(?i)\bvssadmin(?:\.exe)?\s+delete\s+shadows\b', "Delete Shadow Copies (Ransomware Prep)", "T1490")
        ]

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
                    detector_name="windows_defense_evasion_rule",
                    source_event_id=event_id,
                    evidence=evidence
                )
        return None

