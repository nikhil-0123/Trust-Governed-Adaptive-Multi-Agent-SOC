import math
import hashlib
import json
import pytest
from canonical import (
    canonicalize_tgam_rcc_v1,
    parse_raw_json,
    serialize_string,
    serialize_number,
    serialize_value,
    validate_epoch,
    validate_record_id,
    TGAMCanonicalizationError,
    DuplicateKeyError,
    SAFE_INT_MIN,
    SAFE_INT_MAX,
)

class TestTGAMCanonicalizationContract:
    def test_vector_6_exact_code_points_and_digest(self):
        """
        Vector 6 tests sorting where a supplementary plane character (U+10000,
        represented in UTF-16 as surrogate pair 0xD800, 0xDC00) is compared with
        U+FFFD (UTF-16 code unit 0xFFFD). Because 0xD800 < 0xFFFD, U+10000 sorts first.
        """
        k1 = chr(0x10000)
        k2 = chr(0xFFFD)
        val = {k1: 2, k2: 1}
        
        canonical_bytes = canonicalize_tgam_rcc_v1(val)
        digest = hashlib.sha256(canonical_bytes).hexdigest()
        
        # Exact code point assertions
        assert ord(k1) == 0x10000
        assert ord(k2) == 0xFFFD
        
        # Exact byte sequence and length assertions
        expected_bytes = b'{"\xf0\x90\x80\x80":2,"\xef\xbf\xbd":1}'
        expected_byte_list = [123, 34, 240, 144, 128, 128, 34, 58, 50, 44, 34, 239, 191, 189, 34, 58, 49, 125]
        
        assert list(canonical_bytes) == expected_byte_list
        assert canonical_bytes == expected_bytes
        assert len(canonical_bytes) == 18
        assert digest == "2be8040fe3029f9de464f315235716337d3ef13fe83fe32a481281b77a32112c"
        
        # Verify decoded string representation matches escaped form
        decoded = canonical_bytes.decode("utf-8")
        assert decoded == '{"\U00010000":2,"\uFFFD":1}'

    def test_negative_zero_normalization(self):
        """Both +0.0 and -0.0 must be serialized as integer 0 ('0')."""
        val = {"pos": 0.0, "neg": -0.0, "zero_int": 0}
        out = canonicalize_tgam_rcc_v1(val).decode("utf-8")
        assert out == '{"neg":0,"pos":0,"zero_int":0}'

    def test_boolean_precedence_over_integer(self):
        """Booleans must serialize as 'true'/'false', not '1'/'0' despite Python bool subclassing."""
        val = {"flag_true": True, "flag_false": False, "one": 1, "zero": 0}
        out = canonicalize_tgam_rcc_v1(val).decode("utf-8")
        assert out == '{"flag_false":false,"flag_true":true,"one":1,"zero":0}'

    def test_safe_integer_boundaries(self):
        """Integers within [-9007199254740991, 9007199254740991] pass; outside values raise."""
        val = {"min": SAFE_INT_MIN, "max": SAFE_INT_MAX}
        out = canonicalize_tgam_rcc_v1(val).decode("utf-8")
        assert out == '{"max":9007199254740991,"min":-9007199254740991}'
        
        with pytest.raises(TGAMCanonicalizationError, match="outside safe range"):
            canonicalize_tgam_rcc_v1({"too_large": SAFE_INT_MAX + 1})
            
        with pytest.raises(TGAMCanonicalizationError, match="outside safe range"):
            canonicalize_tgam_rcc_v1({"too_small": SAFE_INT_MIN - 1})

    def test_non_finite_float_rejection(self):
        """NaN, Infinity, and -Infinity must be strictly rejected."""
        with pytest.raises(TGAMCanonicalizationError, match="Non-finite float"):
            canonicalize_tgam_rcc_v1({"val": float("nan")})
            
        with pytest.raises(TGAMCanonicalizationError, match="Non-finite float"):
            canonicalize_tgam_rcc_v1({"val": float("inf")})
            
        with pytest.raises(TGAMCanonicalizationError, match="Non-finite float"):
            canonicalize_tgam_rcc_v1({"val": float("-inf")})

    def test_control_character_escaping(self):
        """Control chars 0x00-0x1F must be escaped; quotes and backslashes escaped."""
        val = {"test": "\"\b\f\n\r\t\\\x01\x1f"}
        out = canonicalize_tgam_rcc_v1(val).decode("utf-8")
        # In raw string, single backslash followed by control escape letter:
        assert out == r'{"test":"\"\b\f\n\r\t\\\u0001\u001f"}'

    def test_lone_surrogate_rejection(self):
        """Lone/unpaired surrogate code points must be rejected."""
        with pytest.raises(TGAMCanonicalizationError, match="Lone surrogate"):
            serialize_string("\uD800")
            
        with pytest.raises(TGAMCanonicalizationError, match="Lone surrogate"):
            serialize_string("\uDFFF")

    def test_duplicate_key_rejection(self):
        """Duplicate keys in raw JSON input bytes must be rejected."""
        raw_duplicate = b'{"agent_id": "AGT-01", "channel": "Security", "agent_id": "AGT-02"}'
        with pytest.raises(DuplicateKeyError, match="Duplicate key rejected: agent_id"):
            parse_raw_json(raw_duplicate)

    def test_non_string_dict_key_rejection(self):
        """Non-string dictionary keys must be rejected."""
        with pytest.raises(TGAMCanonicalizationError, match="must be strings"):
            canonicalize_tgam_rcc_v1({123: "value"})

    def test_validate_epoch_strictness(self):
        """
        validate_epoch must reject booleans, floats, strings, None, zero, and negative values.
        It must accept only genuine integers >= 1.
        """
        assert validate_epoch(1) == 1
        assert validate_epoch(42) == 42
        
        # Booleans must be rejected explicitly with TypeError
        with pytest.raises(TypeError, match="genuine Python integer"):
            validate_epoch(True)
        with pytest.raises(TypeError, match="genuine Python integer"):
            validate_epoch(False)
            
        # Floats, strings, None must be rejected with TypeError
        with pytest.raises(TypeError, match="genuine Python integer"):
            validate_epoch(1.0)
        with pytest.raises(TypeError, match="genuine Python integer"):
            validate_epoch(2.5)
        with pytest.raises(TypeError, match="genuine Python integer"):
            validate_epoch("1")
        with pytest.raises(TypeError, match="genuine Python integer"):
            validate_epoch(None)
            
        # Zero and negative integers must be rejected with ValueError
        with pytest.raises(ValueError, match="must be >= 1"):
            validate_epoch(0)
        with pytest.raises(ValueError, match="must be >= 1"):
            validate_epoch(-1)

    def test_validate_record_id_strictness(self):
        """
        validate_record_id must reject booleans, floats, and malformed strings.
        It must never use int() truncation on floats.
        It must accept genuine non-negative integers and valid decimal integer strings.
        """
        assert validate_record_id(0) == 0
        assert validate_record_id(45020) == 45020
        assert validate_record_id("45020") == 45020
        assert validate_record_id(" 45020 ") == 45020
        
        # Booleans must be rejected explicitly with TypeError
        with pytest.raises(TypeError, match="must not be a boolean"):
            validate_record_id(True)
        with pytest.raises(TypeError, match="must not be a boolean"):
            validate_record_id(False)
            
        # Floats must be rejected explicitly with TypeError (preventing int truncation)
        with pytest.raises(TypeError, match="must not be a float"):
            validate_record_id(45020.9)
        with pytest.raises(TypeError, match="must not be a float"):
            validate_record_id(45020.0)
            
        # None and unsupported types
        with pytest.raises(TypeError, match="must be an integer or decimal integer string"):
            validate_record_id(None)
        with pytest.raises(TypeError, match="must be an integer or decimal integer string"):
            validate_record_id([45020])
            
        # Negative integers and malformed strings
        with pytest.raises(ValueError, match="must be non-negative"):
            validate_record_id(-1)
        with pytest.raises(ValueError, match="must be a non-negative decimal integer"):
            validate_record_id("45020.9")
        with pytest.raises(ValueError, match="must be a non-negative decimal integer"):
            validate_record_id("abc")
        with pytest.raises(ValueError, match="must be a non-negative decimal integer"):
            validate_record_id("")
        with pytest.raises(ValueError, match="must be a non-negative decimal integer"):
            validate_record_id("-1")
