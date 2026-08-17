"""Versioned, filesystem-backed investigation artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ip_enricher.errors import StorageError
from ip_enricher.models import InvestigationResult

_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SECRET_NAMES = {"api_key", "apikey", "authorization", "access_token", "secret", "password"}


class JSONInvestigationStore:
    """Store each investigation below *root* using atomic UTF-8 JSON writes."""

    schema_version = 1

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _validate_component(value: str, label: str) -> str:
        if not isinstance(value, str) or not value or not _SAFE_COMPONENT.fullmatch(value):
            raise StorageError(f"Invalid {label}: expected one safe path component")
        return value

    def _investigation_dir(self, investigation_id: str) -> Path:
        component = self._validate_component(investigation_id, "investigation id")
        directory = (self.root / component).resolve()
        root = self.root.resolve()
        if directory.parent != root:
            raise StorageError("Investigation path escapes storage root")
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _safe_path(self, investigation_id: str, relative_path: str) -> Path:
        directory = self._investigation_dir(investigation_id)
        if not isinstance(relative_path, str) or not relative_path:
            raise StorageError("Artifact path must be a non-empty relative path")
        raw_parts = relative_path.replace("\\", "/").split("/")
        if any(part in ("", ".", "..") for part in raw_parts):
            raise StorageError("Artifact path must not be absolute or traverse directories")
        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise StorageError("Artifact path must not be absolute or traverse directories")
        if any(not _SAFE_COMPONENT.fullmatch(part) for part in candidate.parts):
            raise StorageError("Artifact path contains an unsafe component")
        path = (directory / candidate).resolve()
        if path != directory and directory not in path.parents:
            raise StorageError("Artifact path escapes investigation directory")
        return path

    @classmethod
    def _scrub(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json")
        if isinstance(value, dict):
            return {
                str(key): cls._scrub(item)
                for key, item in value.items()
                if str(key).lower() not in _SECRET_NAMES
            }
        if isinstance(value, (list, tuple)):
            return [cls._scrub(item) for item in value]
        return value

    @staticmethod
    def _json_default(value: Any) -> Any:
        if isinstance(value, Path):
            return str(value)
        raise TypeError(f"Value is not JSON serializable: {type(value).__name__}")

    def _write(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(
            self._scrub(payload),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            default=self._json_default,
        )
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(data)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def save_raw(self, investigation_id: str, relative_path: str, payload: Any) -> None:
        self._write(self._safe_path(investigation_id, relative_path), payload)

    def save_result(self, result: InvestigationResult) -> None:
        self._write(self._safe_path(result.investigation_id, "result.json"), result)

    def _cache_path(self, investigation_id: str, key: str) -> Path:
        if not isinstance(key, str) or not key:
            raise StorageError("Cache key must be a non-empty string")
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self._safe_path(investigation_id, f"cache/{digest}.json")

    def load_cached(self, investigation_id: str, key: str) -> Any | None:
        path = self._cache_path(investigation_id, key)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StorageError(f"Unable to read cached artifact: {exc}") from exc

    def save_cached(self, investigation_id: str, key: str, payload: Any) -> None:
        self._write(self._cache_path(investigation_id, key), payload)
