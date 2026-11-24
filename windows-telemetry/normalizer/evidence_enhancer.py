"""
Phase 2.1: Sysmon Evidence Enhancement & Deterministic Feature Extraction Engine.

Implements deterministic Shannon entropy calculation, DNS query feature extraction,
IP address canonicalization (IPv4/IPv6/scoped/mapped), network port validation,
and process hash validation conforming to Normalized Event Contract v1.
"""

from collections import Counter
import ipaddress
import math
from typing import Any, Dict, List, Optional, Tuple

SAFE_MAX_INPUT_LENGTH = 2048

SUPPORTED_HASH_ALGORITHMS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
    "imphash": 32,
}

HEX_CHARACTERS = frozenset("0123456789abcdefABCDEF")


# =========================================================================
# Task 1: Deterministic Shannon Entropy & DNS Feature Extraction
# =========================================================================

def calculate_shannon_entropy(s: str, max_chars: int = SAFE_MAX_INPUT_LENGTH) -> float:
    """
    Computes deterministic Shannon entropy H in bits per character:
        H = -sum(p(x) * log2(p(x)))

    Semantics & Guarantees:
    - Empty string returns 0.0.
    - Single character or repeated identical characters returns 0.0.
    - Uniform distribution over N distinct characters returns log2(N).
    - Returns a non-negative finite float rounded to 4 decimal places.
    - Never emits NaN, +inf, or -inf.
    - Bounded input length up to max_chars to prevent resource exhaustion.
    """
    if not s or not isinstance(s, str):
        return 0.0

    if len(s) > max_chars:
        s = s[:max_chars]

    length = len(s)
    if length <= 1:
        return 0.0

    counts = Counter(s)
    if len(counts) == 1:
        return 0.0

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    if math.isnan(entropy) or math.isinf(entropy) or entropy < 0.0:
        return 0.0

    return round(entropy, 4)


def extract_dns_features(
    query_name: Optional[str],
    query_status: Optional[Any] = None,
    query_results: Optional[str] = None,
    max_len: int = SAFE_MAX_INPUT_LENGTH,
) -> Dict[str, Any]:
    """
    Extracts deterministic DNS features from Sysmon Event ID 22 evidence.

    Semantics:
    - query_name_raw: Original query string preserved intact.
    - query_name_normalized: Lowercased, stripped of leading/trailing whitespace,
      with trailing dot (representing DNS root label) removed.
    - dns_query_length: Length of query_name_normalized (0 if empty/missing).
    - dns_label_count: Count of non-empty dot-separated labels.
    - dns_max_label_length: Maximum length of any individual label (0 if none).
    - dns_query_entropy: Whole-query Shannon entropy calculated on query_name_normalized.
    - dns_max_label_entropy: Maximum Shannon entropy computed across any individual label.
    - query_status: Integer status code preserved if valid, else raw value.
    - query_results: Original resolution results preserved intact.

    Policy:
    - Bounded processing: Truncates oversized inputs to max_len.
    - Unicode & Punycode: Fully supported without network or DNS resolution calls.
    - No classification: Does not classify high entropy as malicious.
    """
    raw_qname = query_name if query_name is not None else None
    features: Dict[str, Any] = {
        "query_name": raw_qname,
        "query_name_normalized": None,
        "dns_query_length": 0,
        "dns_label_count": 0,
        "dns_max_label_length": 0,
        "dns_query_entropy": 0.0,
        "dns_max_label_entropy": 0.0,
    }

    if query_status is not None:
        try:
            features["query_status"] = int(str(query_status).strip())
        except (ValueError, TypeError):
            features["query_status"] = query_status

    if query_results is not None:
        features["query_results"] = str(query_results).strip()

    if not raw_qname or not isinstance(raw_qname, str):
        return features

    cleaned = raw_qname.strip()
    if not cleaned or cleaned == "-":
        return features

    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]

    # Case normalization (DNS names are case-insensitive per RFC 1035)
    normalized = cleaned.lower()

    # Trailing dot handling: represents DNS root label, strip for entropy & label counts
    if normalized.endswith(".") and len(normalized) > 1:
        normalized = normalized[:-1]
    elif normalized == ".":
        normalized = ""

    features["query_name_normalized"] = normalized
    features["dns_query_length"] = len(normalized)

    if not normalized:
        return features

    # Split into labels, filtering out empty segments (e.g. consecutive dots)
    labels = [lb for lb in normalized.split(".") if lb]
    features["dns_label_count"] = len(labels)

    if labels:
        features["dns_max_label_length"] = max(len(lb) for lb in labels)
        label_entropies = [calculate_shannon_entropy(lb, max_chars=max_len) for lb in labels]
        features["dns_max_label_entropy"] = max(label_entropies) if label_entropies else 0.0
    else:
        features["dns_max_label_length"] = 0
        features["dns_max_label_entropy"] = 0.0

    features["dns_query_entropy"] = calculate_shannon_entropy(normalized, max_chars=max_len)

    return features


# =========================================================================
# Task 2: IP Address Canonicalization
# =========================================================================

def canonicalize_ip_address(raw_ip: Optional[str]) -> Dict[str, Any]:
    """
    Canonicalizes an IPv4 or IPv6 address using Python's standard ipaddress module.

    Semantics & Policies:
    - Strips whitespace.
    - Placeholder values ('-', '', None) are identified with validation_status='MISSING'.
    - Valid IPv4 addresses are returned in standard dotted-decimal notation.
    - Valid IPv6 addresses are compressed per RFC 5952 standard representation.
    - Scoped IPv6 addresses (e.g. 'fe80::1%12') isolate the scope ID so distinct
      scoped entities on separate network interfaces are not mistakenly merged.
    - IPv4-mapped IPv6 addresses (e.g. '::ffff:192.168.1.1') are identified with
      is_ipv4_mapped=True, and mapped_ipv4 containing the extracted IPv4 address.
    - Unspecified addresses ('0.0.0.0', '::') are flagged with is_unspecified=True.
    - Malformed addresses are flagged with validation_status='MALFORMED' while
      preserving raw forensic evidence without throwing unhandled exceptions.
    """
    result: Dict[str, Any] = {
        "canonical_ip": None,
        "raw_ip": raw_ip,
        "ip_version": None,
        "validation_status": "MISSING",
        "is_valid": False,
        "is_ipv4_mapped": False,
        "mapped_ipv4": None,
        "scope_id": None,
        "is_unspecified": False,
        "is_loopback": False,
        "is_private": False,
    }

    if raw_ip is None or not isinstance(raw_ip, str):
        return result

    cleaned = raw_ip.strip()
    if not cleaned or cleaned == "-":
        return result

    # Check for IPv6 scope identifier (e.g. fe80::1%12 or fe80::a%eth0)
    scope_id = None
    clean_ip_str = cleaned
    if "%" in cleaned:
        parts = cleaned.split("%", 1)
        clean_ip_str = parts[0].strip()
        scope_id = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None

    try:
        addr = ipaddress.ip_address(clean_ip_str)
        result["is_valid"] = True
        result["ip_version"] = addr.version
        result["is_unspecified"] = addr.is_unspecified
        result["is_loopback"] = addr.is_loopback
        result["is_private"] = addr.is_private

        # Scoped IPv6 preservation
        if scope_id:
            result["scope_id"] = scope_id
            result["canonical_ip"] = f"{addr.compressed}%{scope_id}"
        else:
            result["canonical_ip"] = addr.compressed

        # IPv4-mapped IPv6 detection (::ffff:x.x.x.x)
        if addr.version == 6:
            mapped = getattr(addr, "ipv4_mapped", None)
            if mapped is not None:
                result["is_ipv4_mapped"] = True
                result["mapped_ipv4"] = str(mapped)

        result["validation_status"] = "VALID"

    except (ValueError, TypeError):
        result["validation_status"] = "MALFORMED"
        result["is_valid"] = False

    return result


# =========================================================================
# Task 3: Network Port Validation
# =========================================================================

def validate_network_port(raw_port: Any) -> Dict[str, Any]:
    """
    Validates a network port number against the standard IANA range 0–65535.

    Semantics:
    - Accepts integers and numeric strings.
    - Strips whitespace from string inputs.
    - Rejects negative values (e.g. -1), out-of-range values (> 65535),
      and non-numeric strings ('-', 'http', 'abc').
    - Empty or None values are flagged with status='MISSING'.
    - Preserves raw malformed evidence in raw_port while setting port to None.
    - Does not raise unhandled exceptions.
    """
    result: Dict[str, Any] = {
        "port": None,
        "raw_port": raw_port,
        "is_valid": False,
        "status": "MISSING",
    }

    if raw_port is None:
        return result

    if isinstance(raw_port, bool):
        result["status"] = "MALFORMED"
        return result

    if isinstance(raw_port, int):
        val = raw_port
    elif isinstance(raw_port, str):
        cleaned = raw_port.strip()
        if not cleaned or cleaned == "-":
            return result
        try:
            val = int(cleaned)
        except (ValueError, TypeError):
            result["status"] = "MALFORMED"
            return result
    else:
        result["status"] = "MALFORMED"
        return result

    if 0 <= val <= 65535:
        result["port"] = val
        result["is_valid"] = True
        result["status"] = "VALID"
    else:
        result["status"] = "OUT_OF_RANGE"

    return result


# =========================================================================
# Task 4: Process Hash Parsing & Validation
# =========================================================================

def validate_process_hashes(
    raw_hashes: Optional[str],
    parsed_hashes: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Parses and validates Sysmon Event ID 1 process hashes.

    Supported Algorithms:
    - MD5: Exactly 32 hexadecimal characters.
    - SHA-1: Exactly 40 hexadecimal characters.
    - SHA-256: Exactly 64 hexadecimal characters.
    - IMPHASH: Exactly 32 hexadecimal characters.

    Handling & Policies:
    - Validates hexadecimal character set [0-9a-fA-F].
    - Normalizes valid hashes to canonical lowercase hexadecimal.
    - Unknown algorithms are isolated in unknown_hashes.
    - Duplicate algorithm entries are tracked in duplicate_hashes with conflict warnings.
    - Invalid hashes (wrong length or non-hex chars) are isolated in invalid_hashes.
    - Preserves raw hash string in hashes_raw.
    - Handles malformed separators (commas, semicolons, extra spaces, trailing delimiters).
    """
    result: Dict[str, Any] = {
        "hashes_raw": raw_hashes,
        "hashes_validated": {},
        "sha256": None,
        "md5": None,
        "sha1": None,
        "imphash": None,
        "unknown_hashes": {},
        "duplicate_hashes": [],
        "invalid_hashes": {},
        "is_valid": False,
    }

    # If already parsed dictionary supplied and raw_hashes not provided
    token_pairs: List[Tuple[str, str]] = []
    if raw_hashes and isinstance(raw_hashes, str) and raw_hashes.strip() and raw_hashes.strip() != "-":
        # Handle delimiters: comma, semicolon, space
        normalized_str = raw_hashes.replace(";", ",")
        for raw_token in normalized_str.split(","):
            token = raw_token.strip()
            if not token or token == "-":
                continue
            if "=" in token:
                parts = token.split("=", 1)
                k = parts[0].strip().lower()
                v = parts[1].strip()
                if k and v and v != "-":
                    token_pairs.append((k, v))
            else:
                result["invalid_hashes"][f"unpaired_{token[:16]}"] = token
    elif parsed_hashes and isinstance(parsed_hashes, dict):
        for k, v in parsed_hashes.items():
            if isinstance(k, str) and isinstance(v, str):
                token_pairs.append((k.strip().lower(), v.strip()))

    if not token_pairs:
        return result

    seen_algorithms: Dict[str, str] = {}
    valid_count = 0

    for algo, hash_val in token_pairs:
        # Check if algorithm is supported
        if algo not in SUPPORTED_HASH_ALGORITHMS:
            result["unknown_hashes"][algo] = hash_val
            continue

        # Check for duplicate algorithm entry
        if algo in seen_algorithms:
            existing_val = seen_algorithms[algo]
            result["duplicate_hashes"].append({
                "algorithm": algo,
                "first_value": existing_val,
                "duplicate_value": hash_val,
                "values_differ": existing_val.lower() != hash_val.lower(),
            })
            # Preserve existing if already valid; if differing, record warning
            continue

        seen_algorithms[algo] = hash_val
        expected_len = SUPPORTED_HASH_ALGORITHMS[algo]

        # Length validation
        if len(hash_val) != expected_len:
            result["invalid_hashes"][algo] = {
                "value": hash_val,
                "reason": f"Invalid length {len(hash_val)}, expected {expected_len}",
            }
            continue

        # Hexadecimal character validation
        if not set(hash_val).issubset(HEX_CHARACTERS):
            result["invalid_hashes"][algo] = {
                "value": hash_val,
                "reason": "Contains non-hexadecimal characters",
            }
            continue

        # Valid hash: canonicalize to lowercase
        canonical_hash = hash_val.lower()
        result["hashes_validated"][algo] = canonical_hash
        result[algo] = canonical_hash
        valid_count += 1

    result["is_valid"] = valid_count > 0

    return result
