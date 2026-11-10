import json
from pathlib import Path
import tempfile
import unittest

from pairinglens.core import analyze, compare, decode_pairing_pdu
from pairinglens.cli import main

T = "2026-11-09T12:00:00Z"


class Tests(unittest.TestCase):
    def test_indicators(self):
        trace = {"events": [{"timestamp": T, "pdu_hex": "010300080f0101"},
                            {"timestamp": T, "pdu_hex": "020300080f0101"},
                            {"timestamp": T, "event": "encryption_change", "encrypted": True}]}
        result = analyze(trace)
        self.assertEqual(result["method_indicator"], "Just Works indicated")
        self.assertTrue(result["encryption_observed"])
        self.assertIn("below 16", result["indicators"][1])
        self.assertFalse(compare(result, result)["method_changed"])

    def test_reject_secret_and_malformed(self):
        with self.assertRaises(ValueError):
            decode_pairing_pdu("06" + "00" * 16)
        with self.assertRaises(ValueError):
            analyze({"events": [{"timestamp": T, "pdu_hex": "06" + "00" * 16}]})
        with self.assertRaises(ValueError):
            analyze({"events": [{"timestamp": "2026-11-09T12:00:00", "event": "bonded"}]})

    def test_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / "trace.json").write_text(json.dumps({"events": [{"timestamp": T, "event": "bonded"}]}))
            self.assertEqual(main([str(p / "trace.json"), "--output", str(p / "out.json")]), 0)
            self.assertEqual(json.loads((p / "out.json").read_text())["bonding_events"], 1)


if __name__ == "__main__":
    unittest.main()
