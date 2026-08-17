from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ip_enricher import cli as cli_module
from ip_enricher.cli import (
    OutputFormat,
    _indicator_reason,
    _read_seed_file,
    _render_batch_table,
    _render_table,
    app,
)
from ip_enricher.models import (
    BatchInvestigationResult,
    CandidateEvidence,
    HostProfile,
    Indicator,
    IndicatorKind,
    InvestigationResult,
    QueryRecord,
    ScoreContribution,
)


def _investigation_result() -> InvestigationResult:
    indicator = Indicator(
        kind=IndicatorKind.TLS_FINGERPRINT,
        value="0123456789abcdef0123456789abcdef01234567",
        searchable=True,
        search_filter="ssl.cert.fingerprint",
        source_path="services[0].tls.fingerprints.sha1",
        evidence_group="tls_certificate:test",
        port=443,
        transport="tcp",
    )
    return InvestigationResult(
        investigation_id="case-table",
        seed=HostProfile(ip="192.0.2.10"),
        indicators=[indicator],
        queries=[
            QueryRecord(
                rule_id="exact_banner_hash",
                rule_version=1,
                query='hash:"42"',
                total=100,
                stopped_reason="candidate pool exceeds configured limit",
            )
        ],
        candidates=[
            CandidateEvidence(
                seed_ip="192.0.2.10",
                candidate_ip="198.51.100.8",
                candidate_asn="AS64500",
                rule_id="exact_tls_fingerprint",
                rule_version=1,
                query='ssl.cert.fingerprint:"0123456789abcdef"',
                candidate_pool_size=2,
                matching_indicators=[indicator],
                score=100,
                score_contributions=[
                    ScoreContribution(
                        indicator_kind=IndicatorKind.TLS_FINGERPRINT,
                        value=indicator.value,
                        weight=100,
                        evidence_group=indicator.evidence_group,
                    )
                ],
            )
        ],
    )


def test_report_does_not_require_shodan_api_key(tmp_path: Path) -> None:
    root = tmp_path / "investigations"
    case = root / "case-1"
    case.mkdir(parents=True)
    (case / "result.json").write_text(json.dumps({"investigation_id": "case-1"}), encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text(f"storage:\n  root: '{root}'\n", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["report", "case-1", "--config", str(config), "--format", "json"]
    )

    assert result.exit_code == 0
    assert '"investigation_id": "case-1"' in result.stdout


def test_human_table_contains_candidate_evidence_without_diagnostic_noise() -> None:
    output = _render_table(_investigation_result())

    assert "Seed: 192.0.2.10" in output
    assert "198.51.100.8" in output
    assert "AS64500" in output
    assert "exact_tls_fingerprint" in output
    assert "Same TLS certificate on 443/tcp" in output
    assert "0123456789abcdef0123456789abcdef01234567" not in output
    assert "candidate pool exceeds configured limit" not in output
    assert 'query: hash:"42"' not in output
    assert "Active verification" not in output
    assert "active_verification_status" not in output


def test_report_supports_table_format(tmp_path: Path) -> None:
    root = tmp_path / "investigations"
    case = root / "case-table"
    case.mkdir(parents=True)
    (case / "result.json").write_text(_investigation_result().model_dump_json(), encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text(f"storage:\n  root: '{root}'\n", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        ["report", "case-table", "--config", str(config), "--format", OutputFormat.TABLE],
    )

    assert result.exit_code == 0
    assert "198.51.100.8" in result.stdout
    assert "Active verification" not in result.stdout


def test_report_rejects_unknown_format() -> None:
    result = CliRunner().invoke(app, ["report", "case-table", "--format", "bogus"])

    assert result.exit_code != 0
    assert "Invalid value" in result.output


def test_seed_file_ignores_comments_and_blank_lines(tmp_path: Path) -> None:
    input_path = tmp_path / "seeds.txt"
    input_path.write_text(
        "# report IOCs\n192.0.2.10\n\n203.0.113.9  # secondary\n",
        encoding="utf-8",
    )

    assert _read_seed_file(input_path) == ["192.0.2.10", "203.0.113.9"]


def test_empty_seed_file_is_rejected(tmp_path: Path) -> None:
    input_path = tmp_path / "seeds.txt"
    input_path.write_text("# no addresses\n", encoding="utf-8")

    with pytest.raises(ValueError, match="no seed"):
        _read_seed_file(input_path)


def test_batch_table_summarizes_all_results_and_errors() -> None:
    batch = BatchInvestigationResult(
        results=[_investigation_result()],
        errors=["Seed 203.0.113.9 failed: unavailable"],
        query_credits_used=1,
    )

    output = _render_batch_table(batch)

    assert "Seeds completed: 1" in output
    assert "Search-budget units used: 1" in output
    assert "198.51.100.8" in output
    assert "Seed 203.0.113.9 failed: unavailable" in output


def test_table_groups_multiple_rules_per_candidate() -> None:
    investigation = _investigation_result()
    first = investigation.candidates[0]
    investigation.candidates.append(
        first.model_copy(
            update={
                "rule_id": "exact_banner_hash",
                "candidate_pool_size": 5,
                "score": 80,
            }
        )
    )

    output = _render_table(investigation)

    assert "Candidates discovered: 1" in output
    assert output.count("198.51.100.8") == 1
    assert "exact_tls_fingerprint (2 rules)" in output
    assert "AS64500" in output
    assert "ASN" not in output
    assert "Why it matched" in output


def test_json_preserves_active_verification_status() -> None:
    output = _investigation_result().model_dump_json()

    assert '"active_verification_status":"not_performed"' in output


def test_hash_reason_omits_raw_value() -> None:
    indicator = Indicator(
        kind=IndicatorKind.BANNER_HASH,
        value="615129173",
        searchable=True,
        search_filter="hash",
        source_path="services[0].banner_hash",
        evidence_group="banner_hash:615129173",
        port=9000,
        transport="tcp",
    )

    reason = _indicator_reason(indicator)

    assert reason == "Same service banner on 9000/tcp"
    assert "615129173" not in reason


@pytest.mark.parametrize("extra_args, expected", [([], False), (["--xs"], True)])
def test_discover_xs_option_defaults_off_and_forwards(
    monkeypatch: pytest.MonkeyPatch,
    extra_args: list[str],
    expected: bool,
) -> None:
    calls: list[dict[str, object]] = []

    async def fake_run(*args: object, **kwargs: object) -> None:
        calls.append({"args": args, **kwargs})

    monkeypatch.setattr(cli_module, "_run", fake_run)

    result = CliRunner().invoke(app, ["discover", "192.0.2.10", *extra_args])

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    assert calls[0]["cross_service"] is expected


@pytest.mark.parametrize("extra_args, expected", [([], False), (["--xs"], True)])
def test_discover_batch_xs_option_defaults_off_and_forwards(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    extra_args: list[str],
    expected: bool,
) -> None:
    input_path = tmp_path / "seeds.txt"
    input_path.write_text("192.0.2.10\n", encoding="utf-8")
    calls: list[dict[str, object]] = []

    async def fake_run_batch(*args: object, **kwargs: object) -> None:
        calls.append({"args": args, **kwargs})

    monkeypatch.setattr(cli_module, "_run_batch", fake_run_batch)

    result = CliRunner().invoke(app, ["discover-batch", "--input", str(input_path), *extra_args])

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    assert calls[0]["cross_service"] is expected
