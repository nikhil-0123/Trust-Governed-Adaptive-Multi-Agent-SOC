import unittest
from transport.filter import ImportantEventFilter

class TestImportantEventFilter(unittest.TestCase):
    def test_high_severity_forwarded(self):
        event = {"severity": "HIGH", "confidence": 0.5}
        self.assertTrue(ImportantEventFilter.should_forward(event))

    def test_critical_severity_forwarded(self):
        event = {"severity": "CRITICAL", "confidence": 0.1}
        self.assertTrue(ImportantEventFilter.should_forward(event))

    def test_medium_high_confidence_forwarded(self):
        event = {"severity": "MEDIUM", "confidence": 0.85}
        self.assertTrue(ImportantEventFilter.should_forward(event))

    def test_medium_low_confidence_suppressed(self):
        event = {"severity": "MEDIUM", "confidence": 0.70}
        self.assertFalse(ImportantEventFilter.should_forward(event))

    def test_low_severity_suppressed(self):
        event = {"severity": "LOW", "confidence": 1.0}
        self.assertFalse(ImportantEventFilter.should_forward(event))

    def test_missing_or_invalid_fields(self):
        self.assertFalse(ImportantEventFilter.should_forward({}))
        self.assertFalse(ImportantEventFilter.should_forward({"severity": "UNKNOWN"}))

if __name__ == "__main__":
    unittest.main()
