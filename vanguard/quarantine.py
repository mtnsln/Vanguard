from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path


class QuarantineManager:
    """Local quarantine with an atomic manifest and integrity checks."""

    def __init__(self, directory: Path, logger=None):
        self.directory = Path(directory).expanduser().resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.directory / "manifest.json"
        self.logger = logger
        if not self.manifest_path.exists():
            self._write_manifest([])

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _read_manifest(self) -> list[dict]:
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise ValueError("Quarantine manifest must be a list.")
            return [x for x in data if isinstance(x, dict) and x.get("id") and x.get("stored_name")]
        except FileNotFoundError:
            return []
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(f"Quarantine manifest could not be read: {exc}") from exc

    def _write_manifest(self, items: list[dict]) -> None:
        temp = self.manifest_path.with_name(f".manifest-{uuid.uuid4().hex}.tmp")
        try:
            temp.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
            temp.replace(self.manifest_path)
        finally:
            if temp.exists():
                temp.unlink(missing_ok=True)

    def list_items(self) -> list[dict]:
        return self._read_manifest()

    def quarantine(self, source: Path, reason: str, sha256: str = "") -> dict:
        source = Path(source).expanduser()
        if source.is_symlink():
            raise ValueError("Symbolic links cannot be quarantined.")
        source = source.resolve(strict=True)
        if not source.is_file():
            raise ValueError("Only regular files can be quarantined.")
        if source == self.directory or self.directory in source.parents:
            raise ValueError("A file already in quarantine cannot be quarantined again.")

        actual_hash = self._hash_file(source)
        if sha256 and actual_hash.lower() != sha256.lower():
            raise ValueError("File changed after scanning; scan it again before quarantine.")

        item_id = uuid.uuid4().hex
        stored_name = f"{item_id}.quarantined"
        destination = self.directory / stored_name
        record = {
            "id": item_id,
            "stored_name": stored_name,
            "original_path": str(source),
            "reason": str(reason)[:500],
            "sha256": actual_hash,
            "size": source.stat().st_size,
            "quarantined_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        }

        # Persist metadata first; roll it back if moving the file fails.
        items = self._read_manifest()
        items.append(record)
        self._write_manifest(items)
        try:
            shutil.move(str(source), str(destination))
        except Exception:
            self._write_manifest([x for x in items if x.get("id") != item_id])
            raise

        if self.logger:
            self.logger.warning("Quarantined file %s (%s)", source, reason)
        return record

    def restore(self, item_id: str, destination: Path) -> Path:
        items = self._read_manifest()
        record = next((x for x in items if x.get("id") == item_id), None)
        if not record:
            raise ValueError("Quarantine item was not found.")

        stored_name = Path(str(record["stored_name"]))
        if stored_name.name != str(stored_name) or not str(stored_name).endswith(".quarantined"):
            raise ValueError("Invalid quarantine manifest entry.")
        stored = self.directory / stored_name
        if not stored.is_file() or stored.is_symlink():
            raise FileNotFoundError("Quarantined file is missing.")
        destination = Path(destination).expanduser().resolve()
        if destination.exists():
            raise FileExistsError("The destination already exists; choose a different path.")
        if self._hash_file(stored) != record.get("sha256"):
            raise ValueError("Quarantined file integrity check failed; refusing to restore.")

        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(stored), str(destination))
        try:
            self._write_manifest([x for x in items if x.get("id") != item_id])
        except Exception:
            # Keep the file recoverable if manifest update fails.
            shutil.move(str(destination), str(stored))
            raise
        if self.logger:
            self.logger.info("Restored quarantine item %s to %s", item_id, destination)
        return destination
