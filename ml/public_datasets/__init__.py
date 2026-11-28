"""Read-only public dataset adapters for TGAM-SOC offline research qualification."""

from .otrf_adapter import (
    OTRF_SCHEMA_VERSION,
    OtrfAuthRecord,
    OtrfCaptureSummary,
    iter_otrf_json_lines,
    iter_otrf_zip_records,
    parse_otrf_auth_event,
    summarize_otrf_auth_capture,
)

__all__ = [
    "OTRF_SCHEMA_VERSION",
    "OtrfAuthRecord",
    "OtrfCaptureSummary",
    "iter_otrf_json_lines",
    "iter_otrf_zip_records",
    "parse_otrf_auth_event",
    "summarize_otrf_auth_capture",
]
