from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address
from itertools import combinations
from math import ceil
from typing import Any
from uuid import uuid4

from ip_enricher.config import DiscoverySettings
from ip_enricher.indicators import extract_indicators
from ip_enricher.interfaces import InvestigationStore, ShodanProvider
from ip_enricher.models import (
    BatchInvestigationResult,
    CandidateEvidence,
    Indicator,
    InvestigationResult,
    QueryRecord,
)
from ip_enricher.providers.shodan import normalize_host
from ip_enricher.query import ShodanQueryBuilder
from ip_enricher.rules import default_rules
from ip_enricher.scoring import score_indicators

_SEARCH_FIELDS = ("ip_str", "port", "transport")


@dataclass(slots=True)
class _CreditBudget:
    limit: int
    used: int = 0


class EnrichmentPipeline:
    """Coordinate deterministic, credit-aware Shodan enrichment and discovery."""

    def __init__(
        self,
        provider: ShodanProvider,
        store: InvestigationStore,
        settings: DiscoverySettings,
    ) -> None:
        self.provider = provider
        self.store = store
        self.settings = settings
        self._rules = default_rules()

    async def run(
        self,
        seed_ip: str,
        *,
        discover: bool = True,
        investigation_id: str | None = None,
        cross_service: bool = False,
    ) -> InvestigationResult:
        errors: list[str] = []
        api_info: dict[str, Any] | None = None

        try:
            api_info = await self.provider.api_info()
        except Exception as exc:  # provider failures become useful partial results
            errors.append(f"Shodan API preflight failed: {exc}")

        return await self._run_seed(
            self._validate_seed(seed_ip),
            discover=discover,
            investigation_id=investigation_id,
            api_info=api_info,
            preflight_errors=errors,
            credit_budget=_CreditBudget(self.settings.max_query_credits_per_run),
            cross_service=cross_service,
        )

    async def run_batch(
        self, seed_ips: list[str], *, cross_service: bool = False
    ) -> BatchInvestigationResult:
        """Run ordered, deduplicated seeds under one Shodan credit budget."""
        seeds = list(dict.fromkeys(self._validate_seed(seed) for seed in seed_ips))
        if not seeds:
            raise ValueError("At least one IPv4 seed address is required")

        errors: list[str] = []
        api_info: dict[str, Any] | None = None
        try:
            api_info = await self.provider.api_info()
        except Exception as exc:
            errors.append(f"Shodan API preflight failed: {exc}")

        budget = _CreditBudget(self.settings.max_query_credits_per_run)
        results: list[InvestigationResult] = []
        for seed in seeds:
            try:
                result = await self._run_seed(
                    seed,
                    discover=True,
                    investigation_id=None,
                    api_info=api_info,
                    preflight_errors=[],
                    credit_budget=budget,
                    cross_service=cross_service,
                )
            except Exception as exc:
                errors.append(f"Seed {seed} failed: {exc}")
                continue
            results.append(result)
        return BatchInvestigationResult(
            results=results,
            errors=errors,
            query_credits_used=budget.used,
        )

    async def _run_seed(
        self,
        seed: str,
        *,
        discover: bool,
        investigation_id: str | None,
        api_info: dict[str, Any] | None,
        preflight_errors: list[str],
        credit_budget: _CreditBudget,
        cross_service: bool,
    ) -> InvestigationResult:
        run_id = investigation_id or uuid4().hex
        errors = list(preflight_errors)
        if api_info is not None:
            self.store.save_raw(run_id, "shodan/api-info.json", api_info)

        raw_seed = await self.provider.host(seed)
        self.store.save_raw(run_id, f"seeds/{seed}/raw-shodan.json", raw_seed)
        seed_profile = normalize_host(raw_seed)
        indicators = extract_indicators(seed_profile)
        self.store.save_raw(run_id, f"seeds/{seed}/profile.json", seed_profile)
        self.store.save_raw(run_id, f"seeds/{seed}/indicators.json", indicators)

        result = InvestigationResult(
            investigation_id=run_id,
            seed=seed_profile,
            indicators=indicators,
            errors=errors,
        )
        if discover and api_info is not None:
            await self._discover(result, api_info, credit_budget)
            await self._discover_same_service(result, api_info, credit_budget)
            if cross_service:
                await self._discover_cross_service(result, api_info, credit_budget)
        elif discover:
            result.errors.append("Discovery skipped because API plan information is unavailable")

        self.store.save_raw(run_id, "queries/queries.json", result.queries)
        self.store.save_raw(run_id, "candidates/candidates.json", result.candidates)
        self.store.save_result(result)
        return result

    async def _discover(
        self,
        result: InvestigationResult,
        api_info: dict[str, Any],
        credit_budget: _CreditBudget,
    ) -> None:
        available = api_info.get("query_credits")
        available_credits = (
            available if isinstance(available, int) and not isinstance(available, bool) else None
        )

        for rule_id in self.settings.enabled_rules:
            rule = self._rules.get(rule_id)
            if rule is None:
                result.errors.append(f"Unknown discovery rule: {rule_id}")
                continue
            accepted_for_rule = 0
            selections_by_query: dict[str, list[tuple[Indicator, ...]]] = {}
            for selected in rule.select(result.indicators):
                query = rule.build_query(selected)
                selections_by_query.setdefault(query, []).append(selected)

            for query, equivalent_selections in selections_by_query.items():
                record = QueryRecord(
                    rule_id=rule.id, rule_version=rule.version, query=query, total=0
                )
                result.queries.append(record)
                try:
                    total = await self.provider.count(query)
                    record.total = total
                except Exception as exc:
                    record.stopped_reason = f"count failed: {exc}"
                    continue

                if total <= 1:
                    record.stopped_reason = (
                        "no matches" if total == 0 else "seed is the only reported match"
                    )
                    continue
                if total > self.settings.max_candidate_pool:
                    record.stopped_reason = "candidate pool exceeds configured limit"
                    continue
                projected = 0 if self.provider.is_search_cached(query, page=1, minify=False) else 1
                record.projected_credits = projected
                if credit_budget.used + projected > credit_budget.limit:
                    record.stopped_reason = "per-run query-credit budget reached"
                    return
                if (
                    available_credits is not None
                    and credit_budget.used + projected > available_credits
                ):
                    record.stopped_reason = "Shodan query credits exhausted"
                    return

                try:
                    response = await self.provider.search_with_metadata(query, page=1, minify=False)
                except Exception as exc:
                    record.stopped_reason = f"search failed: {exc}"
                    continue
                payload = response.payload
                credit_budget.used += response.budget_credits_charged
                record.budget_credits_charged = response.budget_credits_charged
                record.cache_hit = response.cache_hit
                record.pages_requested = 1
                record.retrieval_method = "full_search"
                self.store.save_raw(
                    result.investigation_id,
                    f"queries/search-{len(result.queries):04d}.json",
                    payload,
                )
                matches = payload.get("matches")
                if not isinstance(matches, list):
                    record.stopped_reason = "search response has no matches list"
                    continue
                if len(matches) < total:
                    record.stopped_reason = "incomplete or truncated result set"
                    continue
                ips = self._candidate_ips(matches, result.seed.ip)
                ips = ips[: self.settings.max_results_per_query]
                record.results_retrieved = len(ips)
                record.complete = len(matches) >= total

                for candidate_ip in ips:
                    if accepted_for_rule >= self.settings.max_candidates_per_rule:
                        record.stopped_reason = "rule candidate limit reached"
                        break
                    try:
                        raw_candidate = await self.provider.host(candidate_ip)
                        candidate = normalize_host(raw_candidate)
                    except Exception as exc:
                        result.errors.append(f"Candidate {candidate_ip} lookup failed: {exc}")
                        continue
                    self.store.save_raw(
                        result.investigation_id,
                        f"candidates/{candidate_ip}/raw-shodan.json",
                        raw_candidate,
                    )
                    self.store.save_raw(
                        result.investigation_id,
                        f"candidates/{candidate_ip}/profile.json",
                        candidate,
                    )
                    accepted_selections = [
                        selected
                        for selected in equivalent_selections
                        if rule.accepts(candidate, selected)
                    ]
                    if not accepted_selections:
                        continue
                    matching_indicators: list[Indicator] = []
                    for selected in accepted_selections:
                        for indicator in selected:
                            if indicator not in matching_indicators:
                                matching_indicators.append(indicator)
                    score, contributions = score_indicators(matching_indicators)
                    result.candidates.append(
                        CandidateEvidence(
                            seed_ip=result.seed.ip,
                            candidate_ip=candidate_ip,
                            candidate_asn=candidate.asn,
                            rule_id=rule.id,
                            rule_version=rule.version,
                            query=query,
                            candidate_pool_size=total,
                            matching_indicators=matching_indicators,
                            score=score,
                            score_contributions=contributions,
                        )
                    )
                    accepted_for_rule += 1

    @staticmethod
    def _query_terms(indicator: Indicator) -> list[tuple[str, str | int]]:
        if indicator.kind.value == "tls_fingerprint":
            return [("ssl.cert.fingerprint", indicator.value)]
        if indicator.kind.value == "banner_hash":
            return [("hash", indicator.value)]
        if indicator.kind.value == "favicon_hash":
            return [("http.favicon.hash", indicator.value)]
        if indicator.kind.value == "http_title":
            return [("http.title", indicator.value)]
        if indicator.kind.value == "port_product_version":
            product, separator, version = indicator.value.partition("\u001f")
            if not separator or indicator.port is None:
                raise ValueError("Malformed service indicator")
            return [("port", indicator.port), ("product", product), ("version", version)]
        raise ValueError("Indicator is not supported for correlation")

    def _correlation_indicators(self, result: InvestigationResult) -> list[Indicator]:
        supported = {
            "tls_fingerprint",
            "banner_hash",
            "favicon_hash",
            "http_title",
            "port_product_version",
        }
        return [
            item
            for item in result.indicators
            if item.searchable and item.kind.value in supported and item.port is not None
        ]

    async def _discover_same_service(
        self, result: InvestigationResult, api_info: dict[str, Any], budget: _CreditBudget
    ) -> None:
        by_service: dict[tuple[int, str | None], list[Indicator]] = {}
        for item in self._correlation_indicators(result):
            by_service.setdefault((item.port or 0, item.transport), []).append(item)
        seen: set[str] = {record.query for record in result.queries}
        for service_items in by_service.values():
            for size in (2, 3):
                for selected in combinations(service_items, size):
                    terms = [term for item in selected for term in self._query_terms(item)]
                    port = selected[0].port
                    if port is not None and not any(name == "port" for name, _ in terms):
                        terms.insert(0, ("port", port))
                    query = ShodanQueryBuilder.build(terms)
                    if query in seen:
                        continue
                    seen.add(query)
                    await self._run_correlation_query(
                        result,
                        api_info,
                        budget,
                        "same_service_correlation",
                        query,
                        tuple(selected),
                        reported_pool=None,
                    )

    async def _run_correlation_query(
        self,
        result: InvestigationResult,
        api_info: dict[str, Any],
        budget: _CreditBudget,
        rule_id: str,
        query: str,
        selected: tuple[Indicator, ...],
        *,
        reported_pool: int | None,
        candidate_ips: list[str] | None = None,
    ) -> None:
        record = QueryRecord(rule_id=rule_id, rule_version=1, query=query, total=0)
        result.queries.append(record)
        if reported_pool is None:
            try:
                record.total = await self.provider.count(query)
            except Exception as exc:
                record.stopped_reason = f"count failed: {exc}"
                return
            if record.total <= 1:
                record.stopped_reason = (
                    "no matches" if record.total == 0 else "seed is the only reported match"
                )
                return
            if record.total > self.settings.max_candidate_pool:
                record.stopped_reason = "candidate pool exceeds configured limit"
                return
            projected = 0 if self.provider.is_search_cached(query, page=1, minify=False) else 1
            if not self._credits_available(api_info, budget, projected):
                record.projected_credits = projected
                record.stopped_reason = "per-run query-credit budget reached"
                return
            record.projected_credits = projected
            try:
                response = await self.provider.search_with_metadata(query, page=1, minify=False)
            except Exception as exc:
                record.stopped_reason = f"search failed: {exc}"
                return
            payload = response.payload
            budget.used += response.budget_credits_charged
            record.budget_credits_charged = response.budget_credits_charged
            record.cache_hit = response.cache_hit
            record.pages_requested = 1
            record.retrieval_method = "full_search"
            self.store.save_raw(
                result.investigation_id,
                f"queries/search-{len(result.queries):04d}.json",
                payload,
            )
            matches = payload.get("matches")
            if not isinstance(matches, list):
                record.stopped_reason = "search response has no matches list"
                return
            record.complete = len(matches) >= record.total
            if not record.complete:
                record.stopped_reason = "incomplete or truncated result set"
                return
            candidate_ips = self._candidate_ips(matches, result.seed.ip)
        else:
            record.total = reported_pool
            record.complete = True
            record.retrieval_method = "complete_set_intersection"
        candidate_ips = (candidate_ips or [])[: self.settings.max_candidates_per_rule]
        record.results_retrieved = len(candidate_ips)
        for candidate_ip in candidate_ips:
            try:
                raw = await self.provider.host(candidate_ip)
                candidate = normalize_host(raw)
            except Exception as exc:
                result.errors.append(f"Candidate {candidate_ip} lookup failed: {exc}")
                continue
            candidate_values = {
                (item.kind, item.value, item.port, item.transport)
                for item in extract_indicators(candidate)
            }
            required = {(item.kind, item.value, item.port, item.transport) for item in selected}
            if not required <= candidate_values:
                continue
            self.store.save_raw(
                result.investigation_id,
                f"candidates/{candidate_ip}/raw-shodan.json",
                raw,
            )
            self.store.save_raw(
                result.investigation_id,
                f"candidates/{candidate_ip}/profile.json",
                candidate,
            )
            score, contributions = score_indicators(list(selected))
            result.candidates.append(
                CandidateEvidence(
                    seed_ip=result.seed.ip,
                    candidate_ip=candidate_ip,
                    candidate_asn=candidate.asn,
                    rule_id=rule_id,
                    rule_version=1,
                    query=query,
                    candidate_pool_size=record.total,
                    matching_indicators=list(selected),
                    score=score,
                    score_contributions=contributions,
                )
            )

    def _credits_available(
        self, api_info: dict[str, Any], budget: _CreditBudget, projected: int
    ) -> bool:
        available = api_info.get("query_credits")
        return budget.used + projected <= budget.limit and (
            not isinstance(available, int)
            or isinstance(available, bool)
            or budget.used + projected <= available
        )

    async def _discover_cross_service(
        self, result: InvestigationResult, api_info: dict[str, Any], budget: _CreditBudget
    ) -> None:
        items = self._correlation_indicators(result)
        sources: dict[tuple[str, int, str | None], tuple[Indicator, str]] = {}
        for item in items:
            terms = self._query_terms(item)
            if item.port is not None and not any(name == "port" for name, _ in terms):
                terms.insert(0, ("port", item.port))
            query = ShodanQueryBuilder.build(terms)
            sources[(query, item.port or 0, item.transport)] = (item, query)
        values = list(sources.values())
        source_outcomes: dict[str, set[str] | None] = {}

        async def get_source(item: Indicator, query: str) -> set[str] | None:
            if query in source_outcomes:
                return source_outcomes[query]
            record = QueryRecord(
                rule_id="cross_service_source", rule_version=1, query=query, total=0
            )
            result.queries.append(record)
            try:
                total = await self.provider.count(query)
                record.total = total
            except Exception as exc:
                record.stopped_reason = f"count failed: {exc}"
                source_outcomes[query] = None
                return None
            if total <= 1:
                record.complete = True
                record.stopped_reason = (
                    "no matches" if total == 0 else "seed is the only reported match"
                )
                source_outcomes[query] = set()
                return set()
            if total > self.settings.max_xs_source_count:
                record.stopped_reason = "XS source count exceeds configured limit"
                source_outcomes[query] = None
                return None
            try:
                facet_payload = await self.provider.facet(query, name="ip", limit=total)
            except (AttributeError, NotImplementedError, ValueError):
                facet_payload = {}
            facets = facet_payload.get("facets") if isinstance(facet_payload, dict) else None
            entries = facets.get("ip") if isinstance(facets, dict) else None
            if isinstance(entries, list):
                ips: set[str] = set()
                represented = 0
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    value, count = entry.get("value"), entry.get("count")
                    if isinstance(value, str) and isinstance(count, int) and count >= 0:
                        try:
                            parsed = ip_address(value)
                        except ValueError:
                            continue
                        if isinstance(parsed, IPv4Address):
                            ips.add(str(parsed))
                            represented += count
                self.store.save_raw(
                    result.investigation_id,
                    f"queries/xs-facet-{len(result.queries):04d}.json",
                    facet_payload,
                )
                record.retrieval_method = "ip_facet"
                record.results_retrieved = len(ips)
                if represented >= total:
                    record.complete = True
                    ips.discard(result.seed.ip)
                    source_outcomes[query] = ips
                    return ips

            pages = ceil(total / 100)
            record.projected_credits = pages
            if pages > self.settings.max_pages_per_query:
                record.stopped_reason = "complete XS pagination exceeds configured page limit"
                source_outcomes[query] = None
                return None
            projected = sum(
                not self.provider.is_search_cached(
                    query, page=page, fields=("ip_str",), minify=True
                )
                for page in range(1, pages + 1)
            )
            record.projected_credits = projected
            if not self._credits_available(api_info, budget, projected):
                record.stopped_reason = "per-run query-credit budget reached"
                source_outcomes[query] = None
                return None
            ips = set()
            retrieved = 0
            for page in range(1, pages + 1):
                try:
                    response = await self.provider.search_with_metadata(
                        query, page=page, fields=("ip_str",), minify=True
                    )
                except Exception as exc:
                    record.stopped_reason = f"IP-only search failed: {exc}"
                    source_outcomes[query] = None
                    return None
                payload = response.payload
                budget.used += response.budget_credits_charged
                record.budget_credits_charged += response.budget_credits_charged
                record.cache_hit = record.cache_hit or response.cache_hit
                record.pages_requested += 1
                self.store.save_raw(
                    result.investigation_id,
                    f"queries/xs-search-{len(result.queries):04d}-{page:04d}.json",
                    payload,
                )
                matches = payload.get("matches")
                if not isinstance(matches, list):
                    record.stopped_reason = "IP-only response has no matches list"
                    source_outcomes[query] = None
                    return None
                retrieved += len(matches)
                ips.update(self._candidate_ips(matches, result.seed.ip))
            record.retrieval_method = "ip_only_search"
            record.results_retrieved = len(ips)
            if retrieved < total:
                record.stopped_reason = "incomplete or truncated XS source"
                source_outcomes[query] = None
                return None
            record.complete = True
            ips.discard(result.seed.ip)
            source_outcomes[query] = ips
            return ips

        for left_index, (left, left_query) in enumerate(values):
            for right, right_query in values[left_index + 1 :]:
                if (left.port, left.transport) == (right.port, right.transport):
                    continue
                left_set = await get_source(left, left_query)
                right_set = await get_source(right, right_query)
                if left_set is None or right_set is None:
                    continue
                pair = left_set & right_set
                if len(pair) <= self.settings.max_candidate_pool:
                    if pair:
                        await self._run_correlation_query(
                            result,
                            api_info,
                            budget,
                            "cross_service_correlation",
                            f"INTERSECT({left_query}) AND ({right_query})",
                            (left, right),
                            reported_pool=len(pair),
                            candidate_ips=self._sorted_ips(pair, result.seed.ip),
                        )
                    continue
                for third, third_query in values:
                    if third in (left, right) or (third.port, third.transport) in {
                        (left.port, left.transport),
                        (right.port, right.transport),
                    }:
                        continue
                    third_set = await get_source(third, third_query)
                    if third_set is None:
                        continue
                    triple = pair & third_set
                    if 0 < len(triple) <= self.settings.max_candidate_pool:
                        await self._run_correlation_query(
                            result,
                            api_info,
                            budget,
                            "cross_service_correlation",
                            f"INTERSECT({left_query}) AND ({right_query}) AND ({third_query})",
                            (left, right, third),
                            reported_pool=len(triple),
                            candidate_ips=self._sorted_ips(triple, result.seed.ip),
                        )
                        break

    @staticmethod
    def _sorted_ips(values: set[str], seed_ip: str) -> list[str]:
        return sorted(
            (value for value in values if value != seed_ip),
            key=lambda item: int(ip_address(item)),
        )

    @staticmethod
    def _validate_seed(value: str) -> str:
        parsed = ip_address(value)
        if not isinstance(parsed, IPv4Address):
            raise ValueError("The current milestone supports IPv4 seed addresses only")
        return str(parsed)

    @staticmethod
    def _candidate_ips(matches: list[Any], seed_ip: str) -> list[str]:
        unique: set[str] = set()
        for match in matches:
            if not isinstance(match, dict):
                continue
            value = match.get("ip_str")
            if not isinstance(value, str) or value == seed_ip:
                continue
            try:
                parsed = ip_address(value)
            except ValueError:
                continue
            if isinstance(parsed, IPv4Address):
                unique.add(str(parsed))
        return sorted(unique, key=lambda item: int(ip_address(item)))
