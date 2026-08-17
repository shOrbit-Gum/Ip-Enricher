from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TLSInfo(StrictModel):
    fingerprints: dict[str, str] = Field(default_factory=dict)
    subject: dict[str, Any] = Field(default_factory=dict)
    issuer: dict[str, Any] = Field(default_factory=dict)
    serial: str | None = None
    jarm: str | None = None
    ja3s: str | None = None


class HTTPInfo(StrictModel):
    title: str | None = None
    favicon_hash: int | None = None
    html_hash: int | None = None
    headers_hash: int | None = None
    robots_hash: int | None = None
    server_hash: int | None = None
    status: int | None = None
    redirect_location: str | None = None


class ServiceObservation(StrictModel):
    port: int = Field(ge=1, le=65535)
    transport: Literal["tcp", "udp"]
    source: Literal["shodan"] = "shodan"
    observed_at: datetime | None = None
    module: str | None = None
    product: str | None = None
    version: str | None = None
    service_name: str | None = None
    banner: str | None = None
    banner_hash: int | None = None
    cpes: list[str] = Field(default_factory=list)
    tls: TLSInfo | None = None
    http: HTTPInfo | None = None
    ssh_fingerprint: str | None = None
    vulnerabilities: list[str] = Field(default_factory=list)


class HostProfile(StrictModel):
    ip: str
    source: Literal["shodan"] = "shodan"
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_update: datetime | None = None
    asn: str | None = None
    organization: str | None = None
    isp: str | None = None
    network: str | None = None
    operating_system: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    services: list[ServiceObservation] = Field(default_factory=list)


class IndicatorKind(StrEnum):
    TLS_FINGERPRINT = "tls_fingerprint"
    SSH_FINGERPRINT = "ssh_fingerprint"
    BANNER_HASH = "banner_hash"
    FAVICON_HASH = "favicon_hash"
    HTTP_HTML_HASH = "http_html_hash"
    HTTP_HEADERS_HASH = "http_headers_hash"
    JARM = "jarm"
    JA3S = "ja3s"
    HTTP_TITLE = "http_title"
    PORT_PRODUCT_VERSION = "port_product_version"


class Indicator(StrictModel):
    kind: IndicatorKind
    value: str
    searchable: bool
    search_filter: str | None = None
    source_path: str
    evidence_group: str
    port: int | None = None
    transport: str | None = None


class QueryRecord(StrictModel):
    rule_id: str
    rule_version: int
    query: str
    total: int
    pages_requested: int = 0
    results_retrieved: int = 0
    projected_credits: int = 0
    budget_credits_charged: int = 0
    observed_credits: int = 0
    retrieval_method: str | None = None
    complete: bool = False
    cache_hit: bool = False
    stopped_reason: str | None = None


class ScoreContribution(StrictModel):
    indicator_kind: IndicatorKind
    value: str
    weight: int
    evidence_group: str


class CandidateEvidence(StrictModel):
    seed_ip: str
    candidate_ip: str
    candidate_asn: str | None = None
    rule_id: str
    rule_version: int
    query: str
    candidate_pool_size: int
    matching_indicators: list[Indicator]
    score: int
    score_contributions: list[ScoreContribution]
    active_verification_status: Literal["not_performed"] = "not_performed"


class InvestigationResult(StrictModel):
    schema_version: int = 1
    investigation_id: str
    seed: HostProfile
    indicators: list[Indicator]
    queries: list[QueryRecord] = Field(default_factory=list)
    candidates: list[CandidateEvidence] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class BatchInvestigationResult(StrictModel):
    schema_version: int = 1
    results: list[InvestigationResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    query_credits_used: int = 0
