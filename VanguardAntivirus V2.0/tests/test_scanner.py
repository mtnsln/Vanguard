import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path

from vanguard.scanner import Scanner, EICAR_MARKER
from vanguard.quarantine import QuarantineManager


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.signatures = self.root / "signatures.json"
        self.signatures.write_text(json.dumps({"sha256": {}}), encoding="utf-8")
        self.scanner = Scanner(self.signatures)

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_file_and_hash(self):
        sample = self.root / "clean.txt"
        sample.write_text("ordinary text", encoding="utf-8")
        result = self.scanner._scan_file(sample)
        self.assertEqual(result.status, "CLEAN")
        self.assertEqual(result.sha256, hashlib.sha256(b"ordinary text").hexdigest())

    def test_eicar_marker_detected(self):
        sample = self.root / "test.txt"
        sample.write_bytes(b"prefix-" + EICAR_MARKER + b"-suffix")
        self.assertEqual(self.scanner._scan_file(sample).status, "DETECTED")

    def test_marker_across_chunk_boundary(self):
        sample = self.root / "boundary.bin"
        sample.write_bytes(b"x" * (1024 * 1024 - 8) + EICAR_MARKER)
        self.assertEqual(self.scanner._scan_file(sample).status, "DETECTED")

    def test_hash_signature_detected(self):
        sample = self.root / "known.bin"
        sample.write_bytes(b"known sample")
        digest = hashlib.sha256(b"known sample").hexdigest()
        self.signatures.write_text(json.dumps({"sha256": {digest: "Test signature"}}), encoding="utf-8")
        self.scanner.reload_signatures()
        result = self.scanner._scan_file(sample)
        self.assertEqual((result.status, result.reason), ("DETECTED", "Test signature"))

    def test_invalid_hash_is_ignored(self):
        self.signatures.write_text(json.dumps({"sha256": {"not-a-hash": "bad"}}), encoding="utf-8")
        self.assertEqual(Scanner(self.signatures).signatures, {})

    def test_missing_path_returns_error(self):
        results = list(self.scanner.scan_path(self.root / "missing"))
        self.assertEqual(results[0].status, "ERROR")

    def test_cancelled_scan(self):
        event = threading.Event()
        event.set()
        sample = self.root / "cancel.txt"
        sample.write_text("test", encoding="utf-8")
        result = self.scanner._scan_file(sample, event)
        self.assertEqual(result.status, "CANCELLED")


class QuarantineTests(unittest.TestCase):
    def test_quarantine_and_restore(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "sample.txt"
            source.write_text("test content", encoding="utf-8")
            manager = QuarantineManager(root / "quarantine")
            record = manager.quarantine(source, "unit test")
            self.assertFalse(source.exists())
            restored = root / "restored.txt"
            manager.restore(record["id"], restored)
            self.assertEqual(restored.read_text(encoding="utf-8"), "test content")
            self.assertEqual(manager.list_items(), [])

    def test_refuses_changed_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "sample.txt"
            source.write_text("first", encoding="utf-8")
            manager = QuarantineManager(root / "quarantine")
            old_hash = manager._hash_file(source)
            source.write_text("changed", encoding="utf-8")
            with self.assertRaises(ValueError):
                manager.quarantine(source, "test", old_hash)

    def test_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "sample.txt"
            source.write_text("data", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable")
            manager = QuarantineManager(root / "quarantine")
            with self.assertRaises(ValueError):
                manager.quarantine(link, "test")


if __name__ == "__main__":
    unittest.main()
