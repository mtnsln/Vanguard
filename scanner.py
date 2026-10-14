from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

CHUNK_SIZE = 1024 * 1024

@dataclass
class ScanResult:
    path: Path
    status: str  # CLEAN, DETECTED, ERROR
    reason: str
    sha256: str = ""

    @property
    def is_threat(self) -> bool:
        return self.status == "DETECTED"

class Scanner:
    """Local scanner using exact SHA-256 matches and the harmless EICAR test pattern."""

    def __init__(self, signatures_file: Path, logger=None):
        self.signatures_file = Path(signatures_file)
        self.logger = logger
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> dict[str, str]:
        try:
            data = json.loads(self.signatures_file.read_text(encoding="utf-8"))
            signatures = data.get("sha256", {})
            return {str(k).lower(): str(v) for k, v in signatures.items()}
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError, AttributeError) as exc:
            if self.logger:
                self.logger.warning("Could not load signatures database: %s", exc)
            return {}

    def _scan_file(self, path: Path) -> ScanResult:
        digest = hashlib.sha256()
        eicar = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        overlap = b""
        eicar_found = False
        try:
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
                    if not eicar_found and eicar in overlap + chunk:
                        eicar_found = True
                    overlap = (overlap + chunk)[-len(eicar):]
            sha = digest.hexdigest()
            if eicar_found:
                return ScanResult(path, "DETECTED", "EICAR antivirus test pattern (harmless test file)", sha)
            if sha.lower() in self.signatures:
                return ScanResult(path, "DETECTED", self.signatures[sha.lower()], sha)
            return ScanResult(path, "CLEAN", "No matching signature found", sha)
        except (OSError, PermissionError) as exc:
            return ScanResult(path, "ERROR", f"Could not read file: {exc}")

    def scan_path(self, target: Path, excluded_dirs: set[Path] | None = None) -> Iterator[ScanResult]:
        target = Path(target)
        excluded = {Path(p).resolve() for p in (excluded_dirs or set())}
        if target.is_file():
            yield self._scan_file(target)
            return
        if not target.is_dir():
            yield ScanResult(target, "ERROR", "Path does not exist or is not a regular file/folder")
            return
        for root, dirs, names in os.walk(target, followlinks=False):
            root_path = Path(root)
            # Do not descend into symlinked directories or excluded application data.
            dirs[:] = [d for d in dirs if not (root_path / d).is_symlink()
                       and (root_path / d).resolve() not in excluded]
            for name in names:
                path = root_path / name
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    yield self._scan_file(path)
                except OSError as exc:
                    yield ScanResult(path, "ERROR", f"Could not inspect file: {exc}")
