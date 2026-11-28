"""
TGAM-SOC Separate Research-Only Benchmark Contract for LANL Cyber1 (`lanl_auth_features_v1`).

Completely decoupled from native Windows `auth_anomaly_features_v1`.
Never fabricates Windows Event IDs, IP addresses, absolute timestamps, or missing failures.
"""

from .schema import (
    LANL_SCHEMA_VERSION,
    LANL_FEATURE_COLUMNS,
    LANL_AVAILABILITY_COLUMNS,
    LANL_CONTEXT_COLUMNS,
    LANL_MODEL_INPUT_COLUMNS,
    LANL_PROVENANCE_COLUMNS,
    LanlRawAuthEvent,
    LanlRedteamAnnotation,
    LanlAuthDatasetRow,
    LanlDatasetManifest,
    get_lanl_pyarrow_schema,
    normalize_lanl_auth_type_family,
    validate_lanl_feature_row,
)
from .parser import (
    iter_lanl_auth_gz,
    iter_lanl_auth_lines,
    load_redteam_annotations_gz,
    load_redteam_annotations_lines,
)
from .labels import (
    MatchStatus,
    RedteamJoinResult,
    RedteamAnnotationIndex,
)
from .features import LanlCausalFeatureExtractor
from .pipeline import (
    LanlBlockSpec,
    LanlBuildConfig,
    audit_lanl_partition_hygiene,
    build_lanl_benchmark_dataset,
    build_lanl_block_parquet_dataset,
    lanl_chronological_split_with_embargo,
)

__all__ = [
    "LANL_SCHEMA_VERSION",
    "LANL_FEATURE_COLUMNS",
    "LANL_AVAILABILITY_COLUMNS",
    "LANL_CONTEXT_COLUMNS",
    "LANL_MODEL_INPUT_COLUMNS",
    "LANL_PROVENANCE_COLUMNS",
    "LanlRawAuthEvent",
    "LanlRedteamAnnotation",
    "LanlAuthDatasetRow",
    "LanlDatasetManifest",
    "get_lanl_pyarrow_schema",
    "normalize_lanl_auth_type_family",
    "validate_lanl_feature_row",
    "iter_lanl_auth_gz",
    "iter_lanl_auth_lines",
    "load_redteam_annotations_gz",
    "load_redteam_annotations_lines",
    "MatchStatus",
    "RedteamJoinResult",
    "RedteamAnnotationIndex",
    "LanlCausalFeatureExtractor",
    "LanlBlockSpec",
    "LanlBuildConfig",
    "audit_lanl_partition_hygiene",
    "build_lanl_benchmark_dataset",
    "build_lanl_block_parquet_dataset",
    "lanl_chronological_split_with_embargo",
]
