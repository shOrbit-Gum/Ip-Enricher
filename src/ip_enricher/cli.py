from __future__ import annotations

import asyncio
import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from ip_enricher.config import load_settings
from ip_enricher.errors import EnricherError
from ip_enricher.models import (
    BatchInvestigationResult,
    CandidateEvidence,
    Indicator,
    IndicatorKind,
    InvestigationResult,
)
from ip_enricher.pipeline import EnrichmentPipeline
from ip_enricher.providers.shodan import HttpShodanProvider
from ip_enricher.storage import JSONInvestigationStore

app = typer.Typer(no_args_is_help=True, help="High-confidence Shodan IP enrichment")


class OutputFormat(StrEnum):
    JSON = "json"
    TABLE = "table"


def _shorten(value: str, *, limit: int = 28) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:16]}...{value[-8:]}"


def _indicator_reason(indicator: Indicator) -> str:
    location = ""
    if indicator.port is not None:
        location = f" on {indicator.port}/{indicator.transport or 'unknown'}"
    descriptions = {
        IndicatorKind.TLS_FINGERPRINT: "Same TLS certificate",
        IndicatorKind.SSH_FINGERPRINT: "Same SSH host key",
        IndicatorKind.BANNER_HASH: "Same service banner",
        IndicatorKind.FAVICON_HASH: "Same HTTP favicon",
        IndicatorKind.HTTP_HTML_HASH: "Same HTTP content",
        IndicatorKind.HTTP_HEADERS_HASH: "Same HTTP headers",
        IndicatorKind.JARM: "Same TLS JARM fingerprint",
        IndicatorKind.JA3S: "Same TLS JA3S fingerprint",
    }
    if indicator.kind == IndicatorKind.HTTP_TITLE:
        return f'HTTP title "{_shorten(indicator.value)}"{location}'
    if indicator.kind == IndicatorKind.PORT_PRODUCT_VERSION:
        product, separator, version = indicator.value.partition("\u001f")
        service = f"{product} {version}" if separator else indicator.value
        return f"Same service {_shorten(service)}{location}"
    return f"{descriptions.get(indicator.kind, 'Same technical indicator')}{location}"


def _render_table(result: InvestigationResult) -> str:
    grouped: dict[str, list[CandidateEvidence]] = {}
    for candidate in result.candidates:
        grouped.setdefault(candidate.candidate_ip, []).append(candidate)

    lines = [
        f"Investigation: {result.investigation_id}",
        f"Seed: {result.seed.ip}",
        f"Candidates discovered: {len(grouped)}",
        "",
    ]
    headers = ("Candidate", "AS", "Score", "Rule", "Pool", "Why it matched")
    rows: list[tuple[str, ...]] = []
    for candidate_ip, matches in grouped.items():
        rules = list(dict.fromkeys(match.rule_id for match in matches))
        rule_summary = rules[0] if len(rules) == 1 else f"{rules[0]} ({len(rules)} rules)"
        indicators: list[Indicator] = []
        for match in matches:
            for indicator in match.matching_indicators:
                if indicator not in indicators:
                    indicators.append(indicator)
        rows.append(
            (
                candidate_ip,
                next((match.candidate_asn for match in matches if match.candidate_asn), "-"),
                str(max(match.score for match in matches)),
                rule_summary,
                str(min(match.candidate_pool_size for match in matches)),
                "; ".join(_indicator_reason(item) for item in indicators),
            )
        )
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows)) if rows else len(header)
        for index, header in enumerate(headers)
    ]

    def render_row(row: tuple[str, ...]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip()

    lines.extend((render_row(headers), render_row(tuple("-" * width for width in widths))))
    lines.extend(render_row(row) for row in rows)
    if not rows:
        lines.append("(none)")

    if result.errors:
        lines.extend(("", "Errors:"))
        lines.extend(f"- {error}" for error in result.errors)
    return "\n".join(lines)


def _echo_result(result: InvestigationResult, output_format: OutputFormat) -> None:
    if output_format == OutputFormat.TABLE:
        typer.echo(_render_table(result))
    else:
        typer.echo(result.model_dump_json(indent=2))


def _read_seed_file(path: Path) -> list[str]:
    seeds: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            seeds.append(value)
    if not seeds:
        raise ValueError("Input file contains no seed IP addresses")
    return seeds


def _render_batch_table(batch: BatchInvestigationResult) -> str:
    sections = [
        "Batch discovery",
        f"Seeds completed: {len(batch.results)}",
        f"Search-budget units used: {batch.query_credits_used}",
    ]
    for result in batch.results:
        sections.extend(("", "=" * 72, _render_table(result)))
    if batch.errors:
        sections.extend(("", "Batch errors:"))
        sections.extend(f"- {error}" for error in batch.errors)
    return "\n".join(sections)


def _echo_batch(batch: BatchInvestigationResult, output_format: OutputFormat) -> None:
    if output_format == OutputFormat.TABLE:
        typer.echo(_render_batch_table(batch))
    else:
        typer.echo(batch.model_dump_json(indent=2))


async def _run(
    ip: str,
    config: Path | None,
    *,
    discover: bool,
    cross_service: bool = False,
    output_format: OutputFormat,
) -> None:
    settings = load_settings(config)
    provider = HttpShodanProvider(
        settings.shodan.api_key,
        request_timeout_seconds=settings.shodan.request_timeout_seconds,
        max_retries=settings.shodan.max_retries,
        max_concurrent_requests=settings.shodan.max_concurrent_requests,
    )
    store = JSONInvestigationStore(settings.storage.root)
    try:
        result = await EnrichmentPipeline(provider, store, settings.discovery).run(
            ip, discover=discover, cross_service=cross_service
        )
    finally:
        await provider.close()
    _echo_result(result, output_format)


async def _run_batch(
    input_path: Path,
    config: Path | None,
    *,
    cross_service: bool = False,
    output_format: OutputFormat,
) -> None:
    seeds = _read_seed_file(input_path)
    settings = load_settings(config)
    provider = HttpShodanProvider(
        settings.shodan.api_key,
        request_timeout_seconds=settings.shodan.request_timeout_seconds,
        max_retries=settings.shodan.max_retries,
        max_concurrent_requests=settings.shodan.max_concurrent_requests,
    )
    store = JSONInvestigationStore(settings.storage.root)
    try:
        batch = await EnrichmentPipeline(provider, store, settings.discovery).run_batch(
            seeds, cross_service=cross_service
        )
    finally:
        await provider.close()
    _echo_batch(batch, output_format)


@app.command()
def enrich(
    ip: Annotated[str, typer.Argument(help="IPv4 seed address")],
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    output_format: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.TABLE,
) -> None:
    """Retrieve and normalize Shodan host information without discovery."""
    try:
        asyncio.run(_run(ip, config, discover=False, output_format=output_format))
    except (EnricherError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def discover(
    ip: Annotated[str, typer.Argument(help="IPv4 seed address")],
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    output_format: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.TABLE,
    xs: Annotated[bool, typer.Option("--xs", help="Enable cross-service correlation")] = False,
) -> None:
    """Enrich a seed and discover small high-confidence Shodan candidate pools."""
    try:
        asyncio.run(_run(ip, config, discover=True, cross_service=xs, output_format=output_format))
    except (EnricherError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("discover-batch")
def discover_batch(
    input_path: Annotated[
        Path,
        typer.Option(
            "--input",
            "-i",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="UTF-8 file containing one IPv4 seed per line",
        ),
    ],
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    output_format: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.TABLE,
    xs: Annotated[bool, typer.Option("--xs", help="Enable cross-service correlation")] = False,
) -> None:
    """Discover candidates for a bounded list of seed IPs."""
    try:
        asyncio.run(_run_batch(input_path, config, cross_service=xs, output_format=output_format))
    except (EnricherError, ValueError, OSError, UnicodeError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def report(
    investigation_id: Annotated[str, typer.Argument(help="Investigation identifier")],
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    output_format: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.TABLE,
) -> None:
    """Print a stored investigation result."""
    try:
        settings = load_settings(config, require_api_key=False)
        path = (settings.storage.root / investigation_id / "result.json").resolve()
        root = settings.storage.root.resolve()
        if path.parent != root / investigation_id or not path.is_file():
            raise ValueError("Investigation result was not found")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if output_format == OutputFormat.TABLE:
            _echo_result(InvestigationResult.model_validate(payload), output_format)
        else:
            typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
    except (EnricherError, ValueError, OSError, json.JSONDecodeError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()
