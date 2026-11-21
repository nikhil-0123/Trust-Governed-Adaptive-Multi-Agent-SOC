"""
TGAM-RCC-v1: Restricted Canonicalization Contract for TGAM-SOC
=============================================================

This module implements the TGAM-RCC-v1 restricted canonicalization specification
engineered specifically for deterministic identity generation, payload hashing,
and collision-free event deduplication across the TGAM-SOC architecture.

Notice: TGAM-RCC-v1 is NOT RFC 8785 (JSON Canonicalization Scheme / JCS).
It is an independent deterministic serialization contract.
"""

import math
import hashlib
import json
from typing import Any, Dict, List, Tuple, Union

SAFE_INT_MIN = -9007199254740991  # -(2^53 - 1)
SAFE_INT_MAX = 9007199254740991   # 2^53 - 1


class TGAMCanonicalizationError(Exception):
    """Raised when data violates TGAM-RCC-v1 canonicalization rules."""
    pass


class DuplicateKeyError(TGAMCanonicalizationError):
    """Raised when duplicate keys are encountered in raw JSON input."""
    pass


def validate_epoch(epoch: Any) -> int:
    """
    Validates that epoch is a genuine Python integer >= 1.
    Strictly rejects booleans (True/False), floats, strings, None, zero, and negative values.
    Does not silently convert values.
    """
    if isinstance(epoch, bool) or not isinstance(epoch, int):
        raise TypeError(
            f"Authoritative epoch must be a genuine Python integer >= 1, got {type(epoch).__name__} ({epoch!r})"
        )
    if epoch < 1:
        raise ValueError(
            f"Authoritative epoch must be >= 1, got {epoch!r}"
        )
    return epoch


def validate_record_id(record_id: Any) -> int:
    """
    Validates and normalizes record_id:
    - Accepts genuine non-negative integers (>= 0).
    - Accepts non-negative decimal integer strings (e.g. '45020').
    - Strictly rejects booleans (True/False).
    - Strictly rejects floating-point values (e.g. 45020.9, 45020.0).
    - Strictly rejects malformed strings (e.g. '45020.9', '', 'abc', '-1').
    - Never uses int() to truncate floats.
    """
    if isinstance(record_id, bool):
        raise TypeError(f"record_id must not be a boolean, got {record_id!r}")
    if isinstance(record_id, float):
        raise TypeError(f"record_id must not be a float, got {record_id!r}")
    if isinstance(record_id, int):
        if record_id < 0:
            raise ValueError(f"record_id must be non-negative, got {record_id}")
        if record_id > SAFE_INT_MAX:
            raise ValueError(f"record_id exceeds safe integer maximum ({SAFE_INT_MAX}): {record_id}")
        return record_id
    if isinstance(record_id, str):
        s = record_id.strip()
        if not s or not s.isascii() or not s.isdigit():
            raise ValueError(f"record_id string must be a non-negative decimal integer, got {record_id!r}")
        val = int(s)
        if val > SAFE_INT_MAX:
            raise ValueError(f"record_id exceeds safe integer maximum ({SAFE_INT_MAX}): {val}")
        return val
    raise TypeError(
        f"record_id must be an integer or decimal integer string, got {type(record_id).__name__} ({record_id!r})"
    )


def reject_duplicate_keys_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """
    JSONDecoder object_pairs_hook that strictly rejects duplicate keys.
    Prevents duplicate-key smuggling before framework model parsing.
    """
    keys = set()
    result = {}
    for k, v in pairs:
        if k in keys:
            raise DuplicateKeyError(f"Duplicate key rejected: {k}")
        keys.add(k)
        result[k] = v
    return result


def parse_raw_json(raw_bytes: bytes) -> Any:
    """
    Parses raw UTF-8 JSON bytes, enforcing duplicate key rejection and UTF-8 validity.
    """
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise TypeError("Input must be bytes or bytearray")
    try:
        decoded = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise TGAMCanonicalizationError(f"Invalid UTF-8 sequence: {e}") from e
    return json.loads(decoded, object_pairs_hook=reject_duplicate_keys_hook)


def serialize_string(s: str) -> str:
    """
    Serializes a string per TGAM-RCC-v1 rules:
    - Escapes quotation mark (\"), backslash (\\\\), and standard control chars (\\b, \\f, \\n, \\r, \\t).
    - Escapes control characters U+0000 through U+001F as \\u00XX (lowercase hex).
    - Rejects lone/unpaired surrogate code points (U+D800 to U+DFFF).
    - Emits all other Unicode characters directly as UTF-8.
    """
    if not isinstance(s, str):
        raise TypeError(f"Expected str, got {type(s).__name__}")
    
    out = ['"']
    for char in s:
        cp = ord(char)
        if 0xD800 <= cp <= 0xDFFF:
            raise TGAMCanonicalizationError(f"Lone surrogate character detected: U+{cp:04X}")
        if char == '"':
            out.append(r'\"')
        elif char == '\\':
            out.append(r'\\')
        elif char == '\b':
            out.append(r'\b')
        elif char == '\f':
            out.append(r'\f')
        elif char == '\n':
            out.append(r'\n')
        elif char == '\r':
            out.append(r'\r')
        elif char == '\t':
            out.append(r'\t')
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def serialize_number(n: Union[int, float]) -> str:
    """
    Serializes an integer or float per TGAM-RCC-v1 rules:
    - Booleans are rejected by this function (must be handled prior to number check).
    - Integers must be within IEEE 754 safe bounds [-9007199254740991, 9007199254740991].
    - Floats must be finite. NaN, Infinity, and -Infinity raise TGAMCanonicalizationError.
    - Zero (both 0.0 and -0.0) is serialized as "0".
    """
    if isinstance(n, bool):
        raise TypeError("Boolean passed to serialize_number")
    if isinstance(n, int):
        if n < SAFE_INT_MIN or n > SAFE_INT_MAX:
            raise TGAMCanonicalizationError(
                f"Integer {n} outside safe range [{SAFE_INT_MIN}, {SAFE_INT_MAX}]"
            )
        return str(n)
    if isinstance(n, float):
        if math.isnan(n) or math.isinf(n):
            raise TGAMCanonicalizationError("Non-finite float values (NaN, Infinity) are rejected")
        if n == 0.0:
            return "0"
        return repr(n)
    raise TypeError(f"Unsupported number type: {type(n).__name__}")


def serialize_value(val: Any) -> str:
    """
    Recursively serializes an arbitrary Python object into a canonical JSON string.
    Keys are strictly strings and sorted by UTF-16 code units (UTF-16 Big Endian order).
    """
    if val is None:
        return "null"
    # IMPORTANT: Check bool BEFORE int because bool is a subclass of int in Python
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return serialize_number(val)
    if isinstance(val, str):
        return serialize_string(val)
    if isinstance(val, (list, tuple)):
        return "[" + ",".join(serialize_value(item) for item in val) + "]"
    if isinstance(val, dict):
        for k in val.keys():
            if not isinstance(k, str):
                raise TGAMCanonicalizationError(f"Dictionary keys must be strings, got {type(k).__name__}")
        # Sort keys lexicographically by UTF-16 code units (matching RFC 8785 / ECMAScript sorting)
        sorted_keys = sorted(val.keys(), key=lambda k: k.encode("utf-16-be"))
        items = []
        for k in sorted_keys:
            items.append(serialize_string(k) + ":" + serialize_value(val[k]))
        return "{" + ",".join(items) + "}"
    raise TGAMCanonicalizationError(f"Unsupported data type for canonicalization: {type(val).__name__}")


def canonicalize_tgam_rcc_v1(val: Any) -> bytes:
    """
    Converts a Python structure into canonical UTF-8 bytes per TGAM-RCC-v1.
    """
    canonical_str = serialize_value(val)
    return canonical_str.encode("utf-8")


def build_source_identity_manifest_v2(
    agent_id: str,
    channel: str,
    epoch: Any,
    hostname: str,
    record_id: Any
) -> Dict[str, Any]:
    """
    Builds the authoritative V2 Source Event Identity manifest dictionary.
    Strictly validates epoch and record_id types.
    """
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise ValueError("agent_id must be a non-empty string")
    if not isinstance(channel, str) or not channel.strip():
        raise ValueError("channel must be a non-empty string")
    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError("hostname must be a non-empty string")

    valid_epoch = validate_epoch(epoch)
    valid_record_id = validate_record_id(record_id)

    return {
        "agent_id": agent_id.strip(),
        "channel": channel.strip(),
        "epoch": valid_epoch,
        "hostname": hostname.strip(),
        "identity_type": "source",
        "record_id": valid_record_id,
        "schema_version": "2.0",
    }


def generate_source_event_id_v2(
    agent_id: str,
    channel: str,
    epoch: Any,
    hostname: str,
    record_id: Any
) -> str:
    """
    Generates the deterministic SHA-256 source_event_id for a V2 event using TGAM-RCC-v1.
    """
    manifest = build_source_identity_manifest_v2(
        agent_id=agent_id,
        channel=channel,
        epoch=epoch,
        hostname=hostname,
        record_id=record_id
    )
    canonical_bytes = canonicalize_tgam_rcc_v1(manifest)
    return hashlib.sha256(canonical_bytes).hexdigest()
