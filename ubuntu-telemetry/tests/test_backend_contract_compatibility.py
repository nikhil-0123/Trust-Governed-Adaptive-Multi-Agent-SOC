import unittest
import os
import sys
import json
import dataclasses
import jsonschema

# Add backend to path for direct model import
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
backend_path = os.path.join(repo_root, "SOC", "backend")
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.models import DetectionEvent as BackendDetectionEvent
from output.builder import DetectionEventBuilder
from detection.models import DetectionResult
from normalizer.ubuntu_event_normalizer import UbuntuEventNormalizer
from core.agent_identity import AgentIdentity

class TestBackendContractCompatibility(unittest.TestCase):
    def test_ubuntu_detection_event_validates_against_backend_model(self):
        norm_event = {
            "event_id": "raw-ubuntu-001",
            "timestamp": "2026-10-11T21:00:00+00:00",
            "agent_id": "test-agent-ubuntu-001",
            "hostname": "ubuntu-employee-pc",
            "os": "Linux"
        }
        det_result = DetectionResult(
            detected=True,
            detection_type="brute_force",
            confidence=1.0,
            severity="high",
            detector_name="linux_ssh_bruteforce_rule",
            source_event_id="raw-ubuntu-001",
            evidence={
                "source_ip": "192.168.1.100",
                "username": "root",
                "failure_count": 5,
                "process": "sshd"
            }
        )

        ubuntu_event = DetectionEventBuilder.build(norm_event, det_result)
        event_dict = dataclasses.asdict(ubuntu_event)

        # Validate against Central SOC Backend Pydantic model
        backend_event = BackendDetectionEvent(**event_dict)
        self.assertEqual(backend_event.os, "Linux")
        self.assertEqual(backend_event.detection_type, "brute_force")
        self.assertEqual(backend_event.confidence, 1.0)
        self.assertEqual(backend_event.evidence["username"], "root")

    def test_normalized_event_validates_against_json_schema(self):
        schema_path = os.path.join(repo_root, "docs", "contracts", "normalized_event_contract_v1.schema.json")
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        identity = AgentIdentity(os.path.join(repo_root, "ubuntu-telemetry"))
        normalizer = UbuntuEventNormalizer(identity)

        raw = {
            "record_id": 42,
            "timestamp": "2026-10-11T21:00:00+00:00",
            "hostname": "ubuntu-test",
            "auth_status": "failed",
            "username": "admin",
            "source_ip": "192.168.1.100"
        }
        normalized = normalizer.normalize(raw)

        # Validate against JSON schema
        jsonschema.validate(instance=normalized, schema=schema)

if __name__ == "__main__":
    unittest.main()
