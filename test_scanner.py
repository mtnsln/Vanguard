import json
import tempfile
import unittest
from pathlib import Path

from vanguard.scanner import Scanner
from vanguard.quarantine import QuarantineManager

# This marker is the distinctive text within the harmless EICAR test pattern.
EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

class ScannerTests(unittest.TestCase):
    def test_clean_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sigs = root / "signatures.json"
            sigs.write_text(json.dumps({"sha256": {}}), encoding="utf-8")
            sample = root / "hello.txt"
            sample.write_text("ordinary sample text", encoding="utf-8")
            result = Scanner(sigs)._scan_file(sample)
            self.assertEqual(result.status, "CLEAN")
            self.assertTrue(result.sha256)

    def test_eicar_marker_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sigs = root / "signatures.json"
            sigs.write_text(json.dumps({"sha256": {}}), encoding="utf-8")
            sample = root / "test.txt"
            sample.write_bytes(b"prefix-" + EICAR_MARKER + b"-suffix")
            result = Scanner(sigs)._scan_file(sample)
            self.assertEqual(result.status, "DETECTED")
            self.assertIn("EICAR", result.reason)

    def test_hash_signature_detected(self):
        import hashlib
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "sample.bin"
            sample.write_bytes(b"known sample")
            digest = hashlib.sha256(b"known sample").hexdigest()
            sigs = root / "signatures.json"
            sigs.write_text(json.dumps({"sha256": {digest: "Test signature"}}), encoding="utf-8")
            result = Scanner(sigs)._scan_file(sample)
            self.assertEqual(result.status, "DETECTED")
            self.assertEqual(result.reason, "Test signature")

    def test_quarantine_and_restore(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            qdir = root / "quarantine"
            original = root / "sample.txt"
            original.write_text("test content", encoding="utf-8")
            manager = QuarantineManager(qdir)
            record = manager.quarantine(original, "unit test")
            self.assertFalse(original.exists())
            restored = root / "restored.txt"
            manager.restore(record["id"], restored)
            self.assertTrue(restored.exists())
            self.assertEqual(restored.read_text(encoding="utf-8"), "test content")
            self.assertEqual(manager.list_items(), [])

if __name__ == "__main__":
    unittest.main()
