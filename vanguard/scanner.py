from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

CHUNK_SIZE = 1024 * 1024
EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"


@dataclass(slots=True)
class ScanResult:
    path: Path
    status: str
    reason: str
    sha256: str = ""
    size: int = 0

    @property
    def is_threat(self) -> bool:
        return self.status == "DETECTED"


class Scanner:
    """Local scanner using exact SHA-256 matches and EICAR test-pattern recognition.

    A CLEAN result means no match in this scanner's local rules; it is not a
    guarantee that a file is safe.
    """

    def __init__(self, signatures_file: Path, logger=None):
        self.signatures_file = Path(signatures_file)
        self.logger = logger
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> dict[str, str]:
        try:
            data = json.loads(self.signatures_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("sha256", {}), dict):
                raise ValueError("Signature database must contain a sha256 object.")
            clean = {}
            for digest, label in data.get("sha256", {}).items():
                digest = str(digest).lower().strip()
                if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
                    clean[digest] = str(label)[:200]
                elif self.logger:
                    self.logger.warning("Ignoring invalid SHA-256 signature: %s", digest)
            return clean
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            if self.logger:
                self.logger.error("Could not load signatures database: %s", exc)
            return {}

    def reload_signatures(self) -> int:
        self.signatures = self._load_signatures()
        return len(self.signatures)

    def _scan_file(self, path: Path, cancel_event: threading.Event | None = None) -> ScanResult:
        digest = hashlib.sha256()
        overlap = b""
        eicar_found = False
        size = 0
        try:
            with path.open("rb") as handle:
                while True:
                    if cancel_event and cancel_event.is_set():
                        return ScanResult(path, "CANCELLED", "Scan cancelled")
                    chunk = handle.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
                    if not eicar_found and EICAR_MARKER in overlap + chunk:
                        eicar_found = True
                    overlap = (overlap + chunk)[-len(EICAR_MARKER):]
            sha = digest.hexdigest()
            if eicar_found:
                return ScanResult(path, "DETECTED", "EICAR antivirus test pattern (harmless test file)", sha, size)
            if sha in self.signatures:
                return ScanResult(path, "DETECTED", self.signatures[sha], sha, size)
            return ScanResult(path, "CLEAN", "No match in local signatures", sha, size)
        except OSError as exc:
            return ScanResult(path, "ERROR", f"Could not read file: {exc}", size=size)

    def scan_path(
        self,
        target: Path,
        excluded_dirs: set[Path] | None = None,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[Path], None] | None = None,
    ) -> Iterator[ScanResult]:
        target = Path(target).expanduser()
        excluded = set()
        for item in excluded_dirs or set():
            try:
                excluded.add(Path(item).resolve())
            except OSError:
                continue

        if target.is_symlink():
            yield ScanResult(target, "ERROR", "Symbolic links are not scanned.")
            return
        if target.is_file():
            yield self._scan_file(target, cancel_event)
            return
        if not target.is_dir():
            yield ScanResult(target, "ERROR", "Path does not exist or is not a regular file/folder.")
            return

        for root, dirs, names in os.walk(target, followlinks=False):
            if cancel_event and cancel_event.is_set():
                break
            root_path = Path(root)
            kept = []
            for dirname in dirs:
                child = root_path / dirname
                try:
                    if child.is_symlink() or child.resolve() in excluded:
                        continue
                except OSError:
                    continue
                kept.append(dirname)
            dirs[:] = kept

            for name in names:
                if cancel_event and cancel_event.is_set():
                    break
                path = root_path / name
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    result = self._scan_file(path, cancel_event)
                    yield result
                    if on_progress:
                        on_progress(path)
                except OSError as exc:
                    yield ScanResult(path, "ERROR", f"Could not inspect file: {exc}")
