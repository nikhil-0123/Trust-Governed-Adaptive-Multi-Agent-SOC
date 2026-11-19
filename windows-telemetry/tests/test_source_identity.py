import hashlib
import logging
import tempfile
import pytest
from core.agent_identity import AgentIdentity
from normalizer.windows_event_normalizer import WindowsEventNormalizer
from canonical import (
    canonicalize_tgam_rcc_v1,
    build_source_identity_manifest_v2,
    generate_source_event_id_v2,
)

logger = logging.getLogger("test_source_identity")

@pytest.fixture
def agent_identity():
    temp_dir = tempfile.TemporaryDirectory()
    identity = AgentIdentity(data_dir=temp_dir.name)
    identity.agent_id = "AGT-WIN-01"
    yield identity
    temp_dir.cleanup()

@pytest.fixture
def normalizer(agent_identity):
    return WindowsEventNormalizer(agent_identity=agent_identity, logger=logger)

class TestSourceIdentityV2:
    def test_reproducible_v2_vector(self):
        """
        Tests exact independent reproducibility of the V2 source identity vector:
        agent_id: AGT-WIN-01, channel: System, epoch: 2, hostname: WORKSTATION-01, record_id: 45020.
        """
        manifest = build_source_identity_manifest_v2(
            agent_id="AGT-WIN-01",
            channel="System",
            epoch=2,
            hostname="WORKSTATION-01",
            record_id=45020
        )
        canonical_bytes = canonicalize_tgam_rcc_v1(manifest)
        digest = hashlib.sha256(canonical_bytes).hexdigest()
        
        expected_hex = "7b226167656e745f6964223a224147542d57494e2d3031222c226368616e6e656c223a2253797374656d222c2265706f6368223a322c22686f73746e616d65223a22574f524b53544154494f4e2d3031222c226964656e746974795f74797065223a22736f75726365222c227265636f72645f6964223a34353032302c22736368656d615f76657273696f6e223a22322e30227d"
        assert canonical_bytes.hex() == expected_hex
        assert len(canonical_bytes) == 148
        assert digest == "d40a7ee1bf8c5d8299f0ea1bb67a404ae7918e5232c2c8795d43f5dc44d94182"
        assert generate_source_event_id_v2("AGT-WIN-01", "System", 2, "WORKSTATION-01", 45020) == digest

    def test_same_record_id_different_epochs_produce_different_ids(self):
        """Proof that log resets reusing record IDs across epochs produce distinct event IDs."""
        id_epoch_1 = generate_source_event_id_v2("AGT-WIN-01", "Security", 1, "WORKSTATION-01", 500)
        id_epoch_2 = generate_source_event_id_v2("AGT-WIN-01", "Security", 2, "WORKSTATION-01", 500)
        assert id_epoch_1 != id_epoch_2

    def test_same_record_id_different_channels_produce_different_ids(self):
        """Proof that the same record ID on Security vs System produces distinct event IDs."""
        id_security = generate_source_event_id_v2("AGT-WIN-01", "Security", 1, "WORKSTATION-01", 100)
        id_system = generate_source_event_id_v2("AGT-WIN-01", "System", 1, "WORKSTATION-01", 100)
        assert id_security != id_system

    def test_same_record_id_different_hosts_produce_different_ids(self):
        """Proof that identical record IDs across different agents/hosts produce distinct event IDs."""
        id_host1 = generate_source_event_id_v2("AGT-WIN-01", "Security", 1, "WORKSTATION-01", 100)
        id_host2 = generate_source_event_id_v2("AGT-WIN-02", "Security", 1, "WORKSTATION-02", 100)
        assert id_host1 != id_host2

    def test_identical_source_identity_produces_identical_id(self):
        """Proof of deterministic idempotency."""
        id_a = generate_source_event_id_v2("AGT-WIN-01", "Security", 1, "WORKSTATION-01", 100)
        id_b = generate_source_event_id_v2("AGT-WIN-01", "Security", 1, "WORKSTATION-01", 100)
        assert id_a == id_b

    def test_altered_manifest_fields_fail_verification(self):
        """Altering any manifest field alters the resulting identity hash."""
        base_id = generate_source_event_id_v2("AGT-WIN-01", "Security", 1, "WORKSTATION-01", 100)
        
        # Altered hostname
        assert generate_source_event_id_v2("AGT-WIN-01", "Security", 1, "WORKSTATION-02", 100) != base_id
        # Altered epoch
        assert generate_source_event_id_v2("AGT-WIN-01", "Security", 2, "WORKSTATION-01", 100) != base_id
        # Altered channel
        assert generate_source_event_id_v2("AGT-WIN-01", "System", 1, "WORKSTATION-01", 100) != base_id
        # Altered record ID
        assert generate_source_event_id_v2("AGT-WIN-01", "Security", 1, "WORKSTATION-01", 101) != base_id

    def test_legacy_v1_fallback_when_epoch_is_none(self, normalizer):
        """
        When epoch is None, normalizer preserves legacy V1 pipe-delimited format,
        sets schema_version='1.0', and channel_epoch=None.
        """
        raw = {
            "record_id": 500,
            "timestamp": "2026-11-10T12:00:00Z",
            "computer": "WORKSTATION-01",
            "event_id": 4625,
            "target_user": "alice",
            "target_domain": "."
        }
        event = normalizer.normalize(raw, log_name="Security", epoch=None)
        
        expected_legacy_id = hashlib.sha256("AGT-WIN-01|WORKSTATION-01|Security|500".encode("utf-8")).hexdigest()
        assert event["event_id"] == expected_legacy_id
        assert event["evidence"]["schema_version"] == "1.0"
        assert event["evidence"]["channel_epoch"] is None

    def test_v2_identity_generation_when_epoch_supplied(self, normalizer):
        """
        When authoritative epoch is supplied, normalizer uses V2 structured manifest,
        sets schema_version='2.0', and records channel_epoch and source_manifest.
        """
        raw = {
            "record_id": 45020,
            "timestamp": "2026-11-10T12:00:00Z",
            "computer": "WORKSTATION-01",
            "event_id": 104,
            "target_user": "SYSTEM",
            "target_domain": "."
        }
        event = normalizer.normalize(raw, log_name="System", epoch=2)
        
        expected_v2_id = "d40a7ee1bf8c5d8299f0ea1bb67a404ae7918e5232c2c8795d43f5dc44d94182"
        assert event["event_id"] == expected_v2_id
        assert event["evidence"]["schema_version"] == "2.0"
        assert event["evidence"]["channel_epoch"] == 2
        assert event["evidence"]["source_manifest"]["record_id"] == 45020
        assert event["evidence"]["source_manifest"]["epoch"] == 2
        assert event["evidence"]["source_manifest"]["hostname"] == "WORKSTATION-01"

    def test_legacy_and_v2_do_not_collide(self, normalizer):
        """V1 and V2 identities for the exact same event cannot collide."""
        raw = {
            "record_id": 500,
            "timestamp": "2026-11-10T12:00:00Z",
            "computer": "WORKSTATION-01",
            "event_id": 4624,
            "target_user": "alice",
            "target_domain": "."
        }
        v1_event = normalizer.normalize(raw, log_name="Security", epoch=None)
        v2_event = normalizer.normalize(raw, log_name="Security", epoch=1)
        assert v1_event["event_id"] != v2_event["event_id"]

    def test_strict_epoch_validation_rejections(self, normalizer):
        """
        Strict epoch validation:
        - Booleans (True/False) must be explicitly rejected with TypeError.
        - Floats, strings, and non-ints must be rejected with TypeError.
        - Values < 1 (zero, negative) must be rejected with ValueError.
        """
        raw = {"record_id": 500, "timestamp": "2026-11-10T12:00:00Z"}
        
        # Booleans rejected
        with pytest.raises(TypeError, match="genuine Python integer"):
            normalizer.normalize(raw, epoch=True)
        with pytest.raises(TypeError, match="genuine Python integer"):
            normalizer.normalize(raw, epoch=False)
            
        # Floats and strings rejected
        with pytest.raises(TypeError, match="genuine Python integer"):
            normalizer.normalize(raw, epoch=1.0)
        with pytest.raises(TypeError, match="genuine Python integer"):
            normalizer.normalize(raw, epoch="1")
            
        # Zero and negative integers rejected
        with pytest.raises(ValueError, match="must be >= 1"):
            normalizer.normalize(raw, epoch=0)
        with pytest.raises(ValueError, match="must be >= 1"):
            normalizer.normalize(raw, epoch=-1)

    def test_strict_record_id_validation_rejections(self, normalizer):
        """
        Strict record ID validation:
        - Booleans (True/False) must be rejected with TypeError.
        - Floats (e.g. 45020.9, 45020.0) must be rejected with TypeError without int truncation.
        - Malformed strings ('45020.9', 'abc', '', '-1') and negative ints must be rejected with ValueError.
        """
        base_raw = {"timestamp": "2026-11-10T12:00:00Z"}
        
        # Booleans
        with pytest.raises(TypeError, match="must not be a boolean"):
            normalizer.normalize({**base_raw, "record_id": True}, epoch=1)
        with pytest.raises(TypeError, match="must not be a boolean"):
            normalizer.normalize({**base_raw, "record_id": False}, epoch=1)
            
        # Floats (never truncated by int())
        with pytest.raises(TypeError, match="must not be a float"):
            normalizer.normalize({**base_raw, "record_id": 45020.9}, epoch=1)
        with pytest.raises(TypeError, match="must not be a float"):
            normalizer.normalize({**base_raw, "record_id": 45020.0}, epoch=1)
            
        # Malformed strings and negative values
        with pytest.raises(ValueError, match="must be a non-negative decimal integer"):
            normalizer.normalize({**base_raw, "record_id": "45020.9"}, epoch=1)
        with pytest.raises(ValueError, match="must be a non-negative decimal integer"):
            normalizer.normalize({**base_raw, "record_id": "abc"}, epoch=1)
        with pytest.raises(ValueError, match="must be a non-negative decimal integer"):
            normalizer.normalize({**base_raw, "record_id": ""}, epoch=1)
        with pytest.raises(ValueError, match="must be a non-negative decimal integer"):
            normalizer.normalize({**base_raw, "record_id": "-1"}, epoch=1)
        with pytest.raises(ValueError, match="must be non-negative"):
            normalizer.normalize({**base_raw, "record_id": -5}, epoch=1)

    def test_valid_record_id_representations_produce_approved_vector(self, normalizer):
        """
        Both valid integer record_id (45020) and legitimate Windows string record_id ("45020")
        produce the approved V2 test vector without collision or data loss.
        """
        raw_int = {
            "record_id": 45020,
            "timestamp": "2026-11-10T12:00:00Z",
            "computer": "WORKSTATION-01"
        }
        raw_str = {
            "record_id": "45020",
            "timestamp": "2026-11-10T12:00:00Z",
            "computer": "WORKSTATION-01"
        }
        
        event_int = normalizer.normalize(raw_int, log_name="System", epoch=2)
        event_str = normalizer.normalize(raw_str, log_name="System", epoch=2)
        
        expected_digest = "d40a7ee1bf8c5d8299f0ea1bb67a404ae7918e5232c2c8795d43f5dc44d94182"
        assert event_int["event_id"] == expected_digest
        assert event_str["event_id"] == expected_digest
        assert event_int["evidence"]["source_manifest"]["record_id"] == 45020
        assert event_str["evidence"]["source_manifest"]["record_id"] == 45020

    def test_wp1c_identity_fields_preserved_in_v2(self, normalizer):
        """Proof that WP-1C canonical identity contract fields are preserved under V2."""
        raw_local = {
            "record_id": 1001,
            "timestamp": "2026-11-10T12:00:00Z",
            "computer": "WORKSTATION-01",
            "event_id": 4625,
            "target_user": "Alice",
            "target_domain": "."
        }
        event_local = normalizer.normalize(raw_local, epoch=3)
        assert event_local["evidence"]["domain_status"] == "LOCAL_SAM"
        assert event_local["evidence"]["target_account_id"] == "LOCAL_SAM\\alice"
        assert event_local["evidence"]["domain_namespace"] == "LOCAL_SAM"
        assert event_local["username"] == "Alice"

        raw_domain = {
            "record_id": 1002,
            "timestamp": "2026-11-10T12:00:00Z",
            "computer": "WORKSTATION-01",
            "event_id": 4625,
            "target_user": "Bob",
            "target_domain": "CORP"
        }
        event_domain = normalizer.normalize(raw_domain, epoch=3)
        assert event_domain["evidence"]["domain_status"] == "OBSERVED_DOMAIN"
        assert event_domain["evidence"]["target_account_id"] == "DOMAIN:CORP\\bob"
        assert event_domain["evidence"]["domain_namespace"] == "DOMAIN:CORP"
        assert event_domain["username"] == "Bob"

        raw_unverified = {
            "record_id": 1003,
            "timestamp": "2026-11-10T12:00:00Z",
            "computer": "WORKSTATION-01",
            "event_id": 4625,
            "target_user": "Charlie",
            "target_domain": ""
        }
        event_unverified = normalizer.normalize(raw_unverified, epoch=3)
        assert event_unverified["evidence"]["domain_status"] == "UNVERIFIED"
        assert event_unverified["evidence"]["target_account_id"] is None
        assert event_unverified["evidence"]["domain_namespace"] == "UNVERIFIED"
