from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from ip_enricher.errors import ConfigurationError


class ShodanSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_key: SecretStr
    request_timeout_seconds: float = Field(default=20.0, gt=0)
    max_retries: int = Field(default=3, ge=0, le=10)
    max_concurrent_requests: int = Field(default=4, ge=1, le=20)


class DiscoverySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_query_credits_per_run: int = Field(default=10, ge=0, le=10)
    max_results_per_query: int = Field(default=25, ge=1, le=50)
    max_pages_per_query: int = Field(default=1, ge=1, le=100)
    max_candidate_pool: int = Field(default=50, ge=1, le=50)
    max_candidates_per_rule: int = Field(default=50, ge=1, le=50)
    minimum_independent_indicators: int = Field(default=1, ge=1)
    maximum_investigation_depth: int = Field(default=1, ge=0, le=5)
    max_xs_source_count: int = Field(default=150_000, ge=1, le=150_000)
    enabled_rules: list[str] = Field(
        default_factory=lambda: [
            "exact_tls_fingerprint",
            "exact_banner_hash",
            "favicon_and_http_title",
        ]
    )


class StorageSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root: Path = Path("data/investigations")


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    shodan: ShodanSettings
    discovery: DiscoverySettings = Field(default_factory=DiscoverySettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)


def load_settings(path: Path | None = None, *, require_api_key: bool = True) -> Settings:
    data: dict[str, Any] = {}
    if path is not None:
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigurationError(f"Unable to read configuration: {exc}") from exc
        if loaded is not None and not isinstance(loaded, dict):
            raise ConfigurationError("Configuration root must be an object")
        data = loaded or {}

    shodan_data = dict(data.get("shodan", {}))
    api_key = os.getenv("SHODAN_API_KEY")
    if api_key:
        shodan_data["api_key"] = api_key
    elif not require_api_key:
        shodan_data["api_key"] = "not-required-for-offline-command"
    data["shodan"] = shodan_data

    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError(str(exc)) from exc
