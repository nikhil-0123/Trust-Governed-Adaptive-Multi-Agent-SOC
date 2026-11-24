import unittest
from transport.filter import ImportantEventFilter, MEDIUM_CONFIDENCE_THRESHOLD

class TestImportantEventFilter(unittest.TestCase):
    def test_high_severity_forwarded(self):
        event = {"severity": "high", "confidence": 0.1}
        self.assertTrue(ImportantEventFilter.should_forward(event))

    def test_critical_severity_forwarded(self):
        event = {"severity": "critical", "confidence": 0.0}
        self.assertTrue(ImportantEventFilter.should_forward(event))

    def test_medium_high_confidence_forwarded(self):
        event = {"severity": "medium", "confidence": MEDIUM_CONFIDENCE_THRESHOLD + 0.1}
        self.assertTrue(ImportantEventFilter.should_forward(event))
        
        event_exact = {"severity": "medium", "confidence": MEDIUM_CONFIDENCE_THRESHOLD}
        self.assertTrue(ImportantEventFilter.should_forward(event_exact))

    def test_medium_low_confidence_not_forwarded(self):
        event = {"severity": "medium", "confidence": MEDIUM_CONFIDENCE_THRESHOLD - 0.1}
        self.assertFalse(ImportantEventFilter.should_forward(event))

    def test_low_severity_not_forwarded(self):
        event = {"severity": "low", "confidence": 1.0}
        self.assertFalse(ImportantEventFilter.should_forward(event))

    def test_missing_or_invalid_fields(self):
        self.assertFalse(ImportantEventFilter.should_forward({}))
        self.assertFalse(ImportantEventFilter.should_forward({"severity": "medium", "confidence": "invalid"}))
