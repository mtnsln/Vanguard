from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

class QuarantineManager:
    """Moves files into a dedicated folder and keeps a JSON manifest for restoration."""

    def __init__(self, directory: Path, logger=None):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.directory / "manifest.json"
        self.logger = logger
        if not self.manifest_path.exists():
            self._write_manifest([])

    def _read_manifest(self) -> list[dict]:
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def _write_manifest(self, items: list[dict]) -> None:
        temp = self.manifest_path.with_suffix(".tmp")
        temp.write_text(json.dumps(items, indent=2), encoding="utf-8")
        temp.replace(self.manifest_path)

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def list_items(self) -> list[dict]:
        return self._read_manifest()

    def quarantine(self, source: Path, reason: str, sha256: str = "") -> dict:
        source = Path(source).resolve(strict=True)
        if not source.is_file() or source.is_symlink():
            raise ValueError("Only regular files can be quarantined.")
        if self.directory == source or self.directory in source.parents:
            raise ValueError("A file already in quarantine cannot be quarantined again.")
        actual_hash = self._hash_file(source)
        if sha256 and actual_hash.lower() != sha256.lower():
            raise ValueError("File changed after scanning; scan it again before quarantine.")
        item_id = uuid.uuid4().hex
        stored_name = f"{item_id}.quarantined"
        destination = self.directory / stored_name
        # Move rather than copy, so the original path no longer contains the file.
        shutil.move(str(source), str(destination))
        record = {
            "id": item_id,
            "stored_name": stored_name,
            "original_path": str(source),
            "reason": reason,
            "sha256": actual_hash,
            "quarantined_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        }
        items = self._read_manifest()
        items.append(record)
        self._write_manifest(items)
        if self.logger:
            self.logger.warning("Quarantined file %s (%s)", source, reason)
        return record

    def restore(self, item_id: str, destination: Path) -> Path:
        items = self._read_manifest()
        record = next((x for x in items if x.get("id") == item_id), None)
        if not record:
            raise ValueError("Quarantine item was not found.")
        stored = (self.directory / record["stored_name"]).resolve()
        if self.directory not in stored.parents or not stored.is_file():
            raise FileNotFoundError("Quarantined file is missing.")
        destination = Path(destination).expanduser().resolve()
        if destination.exists():
            raise FileExistsError("The destination already exists; choose a different path.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if self._hash_file(stored) != record["sha256"]:
            raise ValueError("Quarantined file integrity check failed; refusing to restore.")
        shutil.move(str(stored), str(destination))
        items = [x for x in items if x.get("id") != item_id]
        self._write_manifest(items)
        if self.logger:
            self.logger.info("Restored quarantine item %s to %s", item_id, destination)
        return destination
