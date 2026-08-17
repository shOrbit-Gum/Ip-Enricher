from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from ip_enricher.config import DiscoverySettings


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_query_credits_per_run", 11),
        ("max_results_per_query", 51),
        ("max_candidate_pool", 51),
        ("max_candidates_per_rule", 51),
    ],
)
def test_conservative_shodan_caps_cannot_be_increased(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        DiscoverySettings.model_validate({field: value})


def test_builtin_rules_match_example_configuration() -> None:
    example = yaml.safe_load(Path("config.example.yaml").read_text(encoding="utf-8"))

    assert DiscoverySettings().enabled_rules == example["discovery"]["enabled_rules"]
    assert "exact_ssh_host_key" not in DiscoverySettings().enabled_rules
    assert "port_product_and_version" not in DiscoverySettings().enabled_rules


def test_discovery_limits_default_to_production_caps() -> None:
    settings = DiscoverySettings()

    assert settings.max_results_per_query == 25
    assert settings.max_candidate_pool == 50
    assert settings.max_candidates_per_rule == 50
    assert settings.max_xs_source_count == 150_000


@pytest.mark.parametrize("value", [1, 150_000])
def test_xs_source_count_accepts_configured_positive_values(value: int) -> None:
    settings = DiscoverySettings.model_validate({"max_xs_source_count": value})

    assert settings.max_xs_source_count == value


@pytest.mark.parametrize("value", [0, -1])
def test_xs_source_count_rejects_non_positive_values(value: int) -> None:
    with pytest.raises(ValidationError):
        DiscoverySettings.model_validate({"max_xs_source_count": value})


def test_xs_source_count_yaml_override() -> None:
    payload = yaml.safe_load("discovery:\n  max_xs_source_count: 1234\n")

    settings = DiscoverySettings.model_validate(payload["discovery"])

    assert settings.max_xs_source_count == 1234
