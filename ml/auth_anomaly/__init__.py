"""
TGAM-SOC Windows Authentication Anomaly ML Pipeline (Phase 3A/3B).

Provides offline read-only Windows Security collection, independent scenario
manifest ground truth, deterministic feature generation, schema validation,
identifier sanitization, manifest provenance, and leakage-free splitting.
Does NOT deploy production models or mutate frozen Phase 2 collectors.
"""

from .schema import (
    DATASET_SCHEMA_VERSION,
    FEATURE_COLUMNS,
    AVAILABILITY_COLUMNS,
    CONTEXT_FEATURE_COLUMNS,
    MODEL_INPUT_COLUMNS,
    PROVENANCE_COLUMNS,
    TelemetryOrigin,
    LabelAssignment,
    AuthDatasetRow,
    DatasetManifest,
    pseudonymize_identifier,
    validate_feature_row,
)
from .extractor import (
    BusinessHoursConfig,
    OfflineAuthFeatureExtractor,
    adapt_raw_security_event_to_contract_v1,
)
from .collector import (
    CollectorIsolationError,
    DiscontinuityError,
    OfflineCollectionSummary,
    OfflineSecurityAuthCollector,
    validate_isolated_ml_paths,
)
from .scenarios import (
    CoverageStatus,
    ScenarioFamily,
    ScenarioRecord,
    create_pseudonymized_scenario,
    load_scenario_manifest,
    save_scenario_manifest,
    scenario_manifest_to_label_assignments,
    validate_scenario_manifest,
)
from .splitting import (
    chronological_split_with_embargo,
    scenario_grouped_split,
    combined_chronological_scenario_split,
    assert_no_partition_leakage,
)
from .dataset_builder import (
    DatasetBuildConfig,
    analyze_dataset_statistics,
    build_auth_feature_dataset,
    compute_file_sha256,
)

__all__ = [
    "DATASET_SCHEMA_VERSION",
    "FEATURE_COLUMNS",
    "AVAILABILITY_COLUMNS",
    "CONTEXT_FEATURE_COLUMNS",
    "MODEL_INPUT_COLUMNS",
    "PROVENANCE_COLUMNS",
    "TelemetryOrigin",
    "LabelAssignment",
    "AuthDatasetRow",
    "DatasetManifest",
    "pseudonymize_identifier",
    "validate_feature_row",
    "OfflineAuthFeatureExtractor",
    "BusinessHoursConfig",
    "adapt_raw_security_event_to_contract_v1",
    "CollectorIsolationError",
    "DiscontinuityError",
    "OfflineCollectionSummary",
    "OfflineSecurityAuthCollector",
    "validate_isolated_ml_paths",
    "CoverageStatus",
    "ScenarioFamily",
    "ScenarioRecord",
    "create_pseudonymized_scenario",
    "load_scenario_manifest",
    "save_scenario_manifest",
    "scenario_manifest_to_label_assignments",
    "validate_scenario_manifest",
    "chronological_split_with_embargo",
    "scenario_grouped_split",
    "combined_chronological_scenario_split",
    "assert_no_partition_leakage",
    "DatasetBuildConfig",
    "analyze_dataset_statistics",
    "build_auth_feature_dataset",
    "compute_file_sha256",
]
