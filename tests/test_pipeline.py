from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ip_enricher.config import DiscoverySettings
from ip_enricher.interfaces import SearchResponse
from ip_enricher.pipeline import EnrichmentPipeline
from ip_enricher.storage import JSONInvestigationStore


class FakeShodan:
    def __init__(self, *, total: int = 2) -> None:
        self.total = total
        self.calls: list[tuple[str, str]] = []
        self._metadata_cache: dict[tuple[str, int, tuple[str, ...], bool], dict[str, Any]] = {}

    async def api_info(self) -> dict[str, Any]:
        self.calls.append(("info", ""))
        return {"query_credits": 100, "plan": "basic"}

    async def host(self, ip: str) -> dict[str, Any]:
        self.calls.append(("host", ip))
        return {
            "ip_str": ip,
            "asn": "AS64500",
            "data": [
                {
                    "port": 443,
                    "transport": "tcp",
                    "hash": 12345,
                    "ssl": {"cert": {"fingerprint": {"sha1": "AA:BB"}}},
                }
            ],
        }

    async def count(self, query: str) -> int:
        self.calls.append(("count", query))
        return self.total

    async def search(
        self,
        query: str,
        *,
        page: int = 1,
        fields: tuple[str, ...] = (),
        minify: bool = True,
    ) -> dict[str, Any]:
        assert any(kind == "count" and value == query for kind, value in self.calls)
        self.calls.append(("search", query))
        matches = [{"ip_str": "198.51.100.8"}]
        if self.total > 1:
            matches.insert(0, {"ip_str": "192.0.2.10"})
        return {"total": self.total, "matches": matches}

    async def search_with_metadata(
        self,
        query: str,
        *,
        page: int = 1,
        fields: tuple[str, ...] = (),
        minify: bool = True,
    ) -> SearchResponse:
        key = (query, page, fields, minify)
        cache_hit = key in self._metadata_cache
        if not cache_hit:
            self._metadata_cache[key] = await self.search(
                query, page=page, fields=fields, minify=minify
            )
        return SearchResponse(
            payload=self._metadata_cache[key],
            cache_hit=cache_hit,
            budget_credits_charged=0 if cache_hit else 1,
        )

    def is_search_cached(
        self,
        query: str,
        *,
        page: int = 1,
        fields: tuple[str, ...] = (),
        minify: bool = True,
    ) -> bool:
        return (query, page, fields, minify) in self._metadata_cache

    async def close(self) -> None:
        return None


class DuplicateBannerShodan(FakeShodan):
    async def host(self, ip: str) -> dict[str, Any]:
        self.calls.append(("host", ip))
        return {
            "ip_str": ip,
            "data": [
                {"port": 53, "transport": "tcp", "hash": 12345},
                {"port": 53, "transport": "udp", "hash": 12345},
            ],
        }


class FailingSeedShodan(FakeShodan):
    async def host(self, ip: str) -> dict[str, Any]:
        if ip == "198.51.100.20":
            self.calls.append(("host", ip))
            raise RuntimeError("host unavailable")
        return await super().host(ip)


class SSHRuleShodan(FakeShodan):
    async def host(self, ip: str) -> dict[str, Any]:
        self.calls.append(("host", ip))
        return {
            "ip_str": ip,
            "asn": "AS64500",
            "data": [
                {
                    "port": 22,
                    "transport": "tcp",
                    "ssh": {"fingerprint": ("aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99")},
                }
            ],
        }


class ProductVersionRuleShodan(FakeShodan):
    async def host(self, ip: str) -> dict[str, Any]:
        self.calls.append(("host", ip))
        return {
            "ip_str": ip,
            "asn": "AS64500",
            "data": [
                {
                    "port": 8443,
                    "transport": "tcp",
                    "product": "Example Service",
                    "version": "1.2.3",
                }
            ],
        }


class CrossServiceShodan(FakeShodan):
    def __init__(self, *, source_total: int = 2, facet_complete: bool = True) -> None:
        super().__init__(total=source_total)
        self.facet_complete = facet_complete

    async def host(self, ip: str) -> dict[str, Any]:
        self.calls.append(("host", ip))
        return {
            "ip_str": ip,
            "asn": "AS64500",
            "data": [
                {"port": 8080, "transport": "tcp", "hash": 111},
                {
                    "port": 443,
                    "transport": "tcp",
                    "ssl": {"cert": {"fingerprint": {"sha1": "AA:BB"}}},
                },
            ],
        }

    async def facet(self, query: str, *, name: str, limit: int) -> dict[str, Any]:
        self.calls.append(("facet", query))
        represented = self.total if self.facet_complete else max(0, self.total - 1)
        return {
            "total": self.total,
            "facets": {"ip": [{"value": "198.51.100.8", "count": represented}]},
        }


class PaginatedCrossServiceShodan(CrossServiceShodan):
    async def search(
        self,
        query: str,
        *,
        page: int = 1,
        fields: tuple[str, ...] = (),
        minify: bool = True,
    ) -> dict[str, Any]:
        self.calls.append(("search", f"{query}|{page}|{','.join(fields)}"))
        start = 1 if page == 1 else 101
        stop = 101 if page == 1 else 102
        return {
            "total": 101,
            "matches": [{"ip_str": f"198.51.100.{index}"} for index in range(start, stop)],
        }


class MultiSourceCrossServiceShodan(CrossServiceShodan):
    async def host(self, ip: str) -> dict[str, Any]:
        self.calls.append(("host", ip))
        return {
            "ip_str": ip,
            "data": [
                {"port": 8080, "transport": "tcp", "hash": 111},
                {"port": 8443, "transport": "tcp", "hash": 222},
                {
                    "port": 443,
                    "transport": "tcp",
                    "ssl": {"cert": {"fingerprint": {"sha1": "AA:BB"}}},
                },
            ],
        }


class SeedOnlyCrossServiceShodan(CrossServiceShodan):
    async def facet(self, query: str, *, name: str, limit: int) -> dict[str, Any]:
        self.calls.append(("facet", query))
        return {
            "total": self.total,
            "facets": {"ip": [{"value": "192.0.2.10", "count": self.total}]},
        }


class CachedMetadataShodan(FakeShodan):
    """Fake provider exposing the production search cache metadata contract."""


@pytest.mark.asyncio
async def test_pipeline_counts_before_search_and_revalidates(tmp_path: Path) -> None:
    provider = FakeShodan()
    settings = DiscoverySettings(enabled_rules=["exact_tls_fingerprint"], max_candidate_pool=25)
    result = await EnrichmentPipeline(provider, JSONInvestigationStore(tmp_path), settings).run(
        "192.0.2.10", investigation_id="case-1"
    )

    assert result.candidates[0].candidate_ip == "198.51.100.8"
    assert result.candidates[0].candidate_asn == "AS64500"
    assert result.candidates[0].active_verification_status == "not_performed"
    operations = [item[0] for item in provider.calls]
    assert operations.index("count") < operations.index("search")
    assert (tmp_path / "case-1" / "result.json").is_file()


@pytest.mark.asyncio
async def test_pipeline_stops_broad_pool_before_search(tmp_path: Path) -> None:
    provider = FakeShodan(total=5000)
    settings = DiscoverySettings(enabled_rules=["exact_tls_fingerprint"])
    result = await EnrichmentPipeline(provider, JSONInvestigationStore(tmp_path), settings).run(
        "192.0.2.10", investigation_id="case-2"
    )

    assert not result.candidates
    assert all(call[0] != "search" for call in provider.calls)
    assert result.queries[0].stopped_reason == "candidate pool exceeds configured limit"


@pytest.mark.asyncio
async def test_pipeline_stops_singleton_pool_before_paid_search(tmp_path: Path) -> None:
    provider = FakeShodan(total=1)
    result = await EnrichmentPipeline(
        provider,
        JSONInvestigationStore(tmp_path),
        DiscoverySettings(enabled_rules=["exact_tls_fingerprint"]),
    ).run("192.0.2.10", investigation_id="singleton")

    assert not result.candidates
    assert all(kind != "search" for kind, _ in provider.calls)
    assert result.queries[0].stopped_reason == "seed is the only reported match"


@pytest.mark.asyncio
async def test_pipeline_rejects_ipv6(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="IPv4"):
        await EnrichmentPipeline(
            FakeShodan(), JSONInvestigationStore(tmp_path), DiscoverySettings()
        ).run("2001:db8::1")


@pytest.mark.asyncio
async def test_pipeline_executes_equivalent_query_once(tmp_path: Path) -> None:
    provider = DuplicateBannerShodan()
    settings = DiscoverySettings(enabled_rules=["exact_banner_hash"])

    result = await EnrichmentPipeline(provider, JSONInvestigationStore(tmp_path), settings).run(
        "192.0.2.10", investigation_id="case-duplicate"
    )

    assert len(result.queries) == 1
    assert [call[0] for call in provider.calls].count("count") == 1
    assert [call[0] for call in provider.calls].count("search") == 1
    assert len(result.candidates) == 1
    assert {item.transport for item in result.candidates[0].matching_indicators} == {
        "tcp",
        "udp",
    }


@pytest.mark.asyncio
async def test_batch_shares_preflight_and_credit_budget(tmp_path: Path) -> None:
    provider = FakeShodan()
    settings = DiscoverySettings(
        enabled_rules=["exact_tls_fingerprint"], max_query_credits_per_run=1
    )

    batch = await EnrichmentPipeline(
        provider, JSONInvestigationStore(tmp_path), settings
    ).run_batch(["192.0.2.10", "192.0.2.10", "203.0.113.9"])

    assert [result.seed.ip for result in batch.results] == ["192.0.2.10", "203.0.113.9"]
    assert [call[0] for call in provider.calls].count("info") == 1
    assert [call[0] for call in provider.calls].count("search") == 1
    assert batch.query_credits_used == 1
    assert batch.results[1].queries[0].cache_hit is True
    assert batch.results[1].queries[0].budget_credits_charged == 0
    assert batch.results[1].queries[0].stopped_reason is None


@pytest.mark.asyncio
async def test_batch_cached_search_charges_budget_once(tmp_path: Path) -> None:
    provider = CachedMetadataShodan()
    settings = DiscoverySettings(
        enabled_rules=["exact_tls_fingerprint"], max_query_credits_per_run=1
    )

    batch = await EnrichmentPipeline(
        provider, JSONInvestigationStore(tmp_path), settings
    ).run_batch(["192.0.2.10", "203.0.113.9"])

    assert len(batch.results) == 2
    assert batch.query_credits_used == 1
    first = batch.results[0].queries[0]
    second = batch.results[1].queries[0]
    assert first.cache_hit is False
    assert first.budget_credits_charged == 1
    assert first.observed_credits == 0
    assert second.cache_hit is True
    assert second.budget_credits_charged == 0
    assert second.observed_credits == 0
    assert second.stopped_reason is None


@pytest.mark.asyncio
async def test_batch_validates_all_seeds_before_preflight(tmp_path: Path) -> None:
    provider = FakeShodan()

    with pytest.raises(ValueError):
        await EnrichmentPipeline(
            provider, JSONInvestigationStore(tmp_path), DiscoverySettings()
        ).run_batch(["192.0.2.10", "not-an-ip"])

    assert provider.calls == []


@pytest.mark.asyncio
async def test_batch_preserves_results_across_seed_failure(tmp_path: Path) -> None:
    provider = FailingSeedShodan(total=0)

    batch = await EnrichmentPipeline(
        provider, JSONInvestigationStore(tmp_path), DiscoverySettings()
    ).run_batch(["192.0.2.10", "198.51.100.20", "203.0.113.9"])

    assert [result.seed.ip for result in batch.results] == ["192.0.2.10", "203.0.113.9"]
    assert batch.errors == ["Seed 198.51.100.20 failed: host unavailable"]


@pytest.mark.asyncio
async def test_pipeline_excludes_ssh_host_keys_from_discovery(tmp_path: Path) -> None:
    provider = SSHRuleShodan()

    result = await EnrichmentPipeline(
        provider,
        JSONInvestigationStore(tmp_path),
        DiscoverySettings(enabled_rules=["exact_ssh_host_key"]),
    ).run("192.0.2.10", investigation_id="case-ssh")

    assert not result.queries
    assert not result.candidates
    assert result.errors == ["Unknown discovery rule: exact_ssh_host_key"]
    assert all(kind not in {"count", "search"} for kind, _ in provider.calls)


@pytest.mark.asyncio
async def test_pipeline_discovers_by_port_product_version(tmp_path: Path) -> None:
    provider = ProductVersionRuleShodan()

    result = await EnrichmentPipeline(
        provider,
        JSONInvestigationStore(tmp_path),
        DiscoverySettings(enabled_rules=["port_product_and_version"]),
    ).run("192.0.2.10", investigation_id="case-product-version")

    expected = 'port:8443 product:"Example Service" version:"1.2.3"'
    assert result.queries[0].query == expected
    assert result.candidates[0].candidate_ip == "198.51.100.8"
    assert provider.calls.index(("count", expected)) < provider.calls.index(("search", expected))


@pytest.mark.asyncio
async def test_xs_is_default_off(tmp_path: Path) -> None:
    provider = CrossServiceShodan()
    result = await EnrichmentPipeline(
        provider, JSONInvestigationStore(tmp_path), DiscoverySettings(enabled_rules=[])
    ).run("192.0.2.10", investigation_id="xs-off")

    assert not result.candidates
    assert all(kind != "facet" for kind, _ in provider.calls)


@pytest.mark.asyncio
async def test_xs_uses_complete_facets_intersects_and_revalidates(tmp_path: Path) -> None:
    provider = CrossServiceShodan()
    result = await EnrichmentPipeline(
        provider, JSONInvestigationStore(tmp_path), DiscoverySettings(enabled_rules=[])
    ).run("192.0.2.10", investigation_id="xs-facet", cross_service=True)

    assert [item.candidate_ip for item in result.candidates] == ["198.51.100.8"]
    assert result.candidates[0].rule_id == "cross_service_correlation"
    sources = [item for item in result.queries if item.rule_id == "cross_service_source"]
    assert len(sources) == 2
    assert all(item.complete and item.retrieval_method == "ip_facet" for item in sources)
    assert all(
        item.projected_credits == item.budget_credits_charged == 0 and item.observed_credits == 0
        for item in sources
    )
    assert (tmp_path / "xs-facet" / "queries" / "xs-facet-0001.json").is_file()


@pytest.mark.asyncio
async def test_xs_records_each_terminal_source_once(tmp_path: Path) -> None:
    provider = MultiSourceCrossServiceShodan(source_total=150_001)
    result = await EnrichmentPipeline(
        provider, JSONInvestigationStore(tmp_path), DiscoverySettings(enabled_rules=[])
    ).run("192.0.2.10", investigation_id="xs-terminal", cross_service=True)

    sources = [item for item in result.queries if item.rule_id == "cross_service_source"]
    assert len(sources) == len({item.query for item in sources}) == 3
    assert all(
        item.stopped_reason == "XS source count exceeds configured limit" for item in sources
    )
    assert not [item for item in result.queries if item.rule_id == "cross_service_correlation"]


@pytest.mark.asyncio
async def test_xs_removes_seed_before_intersection(tmp_path: Path) -> None:
    provider = SeedOnlyCrossServiceShodan(source_total=2)
    result = await EnrichmentPipeline(
        provider, JSONInvestigationStore(tmp_path), DiscoverySettings(enabled_rules=[])
    ).run("192.0.2.10", investigation_id="xs-seed-only", cross_service=True)

    assert not [item for item in result.queries if item.rule_id == "cross_service_correlation"]
    assert not result.candidates
    assert [kind for kind, _ in provider.calls].count("host") == 1


@pytest.mark.asyncio
async def test_xs_source_count_boundary_and_configured_override(tmp_path: Path) -> None:
    at_boundary = CrossServiceShodan(source_total=150_000)
    result = await EnrichmentPipeline(
        at_boundary, JSONInvestigationStore(tmp_path), DiscoverySettings(enabled_rules=[])
    ).run("192.0.2.10", investigation_id="xs-boundary", cross_service=True)
    assert any(kind == "facet" for kind, _ in at_boundary.calls)
    assert all("exceeds" not in (item.stopped_reason or "") for item in result.queries)

    above_override = CrossServiceShodan(source_total=101)
    result = await EnrichmentPipeline(
        above_override,
        JSONInvestigationStore(tmp_path),
        DiscoverySettings(enabled_rules=[], max_xs_source_count=100),
    ).run("192.0.2.10", investigation_id="xs-override", cross_service=True)
    assert all(kind != "facet" for kind, _ in above_override.calls)
    assert all(
        item.stopped_reason == "XS source count exceeds configured limit"
        for item in result.queries
        if item.rule_id == "cross_service_source"
    )


@pytest.mark.asyncio
async def test_xs_falls_back_to_complete_ip_pagination(tmp_path: Path) -> None:
    provider = PaginatedCrossServiceShodan(source_total=101, facet_complete=False)
    result = await EnrichmentPipeline(
        provider,
        JSONInvestigationStore(tmp_path),
        DiscoverySettings(enabled_rules=[], max_pages_per_query=2),
    ).run("192.0.2.10", investigation_id="xs-pages", cross_service=True)

    sources = [item for item in result.queries if item.rule_id == "cross_service_source"]
    assert len(sources) == 2
    assert all(item.complete and item.retrieval_method == "ip_only_search" for item in sources)
    assert all(
        item.projected_credits == item.budget_credits_charged == 2 and item.observed_credits == 0
        for item in sources
    )
    assert [kind for kind, _ in provider.calls].count("search") == 4


@pytest.mark.asyncio
async def test_xs_pagination_stops_before_spending_over_budget(tmp_path: Path) -> None:
    provider = PaginatedCrossServiceShodan(source_total=101, facet_complete=False)
    result = await EnrichmentPipeline(
        provider,
        JSONInvestigationStore(tmp_path),
        DiscoverySettings(enabled_rules=[], max_pages_per_query=2, max_query_credits_per_run=1),
    ).run("192.0.2.10", investigation_id="xs-budget", cross_service=True)

    sources = [item for item in result.queries if item.rule_id == "cross_service_source"]
    assert sources
    assert all(item.stopped_reason == "per-run query-credit budget reached" for item in sources)
    assert all(kind != "search" for kind, _ in provider.calls)
