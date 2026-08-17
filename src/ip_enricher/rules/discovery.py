"""Rules select seed evidence, render searches, and re-check candidate profiles."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from ip_enricher.indicators import extract_indicators
from ip_enricher.models import HostProfile, Indicator, IndicatorKind
from ip_enricher.query import ShodanQueryBuilder


@dataclass(frozen=True, slots=True)
class DiscoveryRule:
    id: str
    version: int
    required_kinds: tuple[IndicatorKind, ...]
    _query_terms: Callable[[tuple[Indicator, ...]], list[tuple[str, str | int]]]

    def select(self, indicators: Sequence[Indicator]) -> list[tuple[Indicator, ...]]:
        """Return deterministic combinations with all required inputs present."""
        by_kind = {
            kind: [item for item in indicators if item.kind == kind] for kind in self.required_kinds
        }
        if any(not values for values in by_kind.values()):
            return []
        if len(self.required_kinds) == 1:
            return [(item,) for item in by_kind[self.required_kinds[0]]]
        # Compounds are compatible only when observed on the same service port.
        combinations: list[tuple[Indicator, ...]] = []
        first = by_kind[self.required_kinds[0]]
        for item in first:
            selected = [item]
            for kind in self.required_kinds[1:]:
                match = next((other for other in by_kind[kind] if other.port == item.port), None)
                if match is None:
                    break
                selected.append(match)
            else:
                combinations.append(tuple(selected))
        return combinations

    def build_query(self, selected: Sequence[Indicator]) -> str:
        values = tuple(selected)
        if (
            len(values) != len(self.required_kinds)
            or tuple(item.kind for item in values) != self.required_kinds
        ):
            raise ValueError(f"{self.id} requires {self.required_kinds!r} in order")
        return ShodanQueryBuilder.build(self._query_terms(values))

    def accepts(self, candidate: HostProfile, selected: Sequence[Indicator]) -> bool:
        selected_values = {(item.kind, item.value, item.port, item.transport) for item in selected}
        candidate_values = {
            (item.kind, item.value, item.port, item.transport)
            for item in extract_indicators(candidate)
        }
        return selected_values <= candidate_values


def _single_filter(
    filter_name: str,
) -> Callable[[tuple[Indicator, ...]], list[tuple[str, str | int]]]:
    return lambda values: [(filter_name, values[0].value)]


def _favicon_title(values: tuple[Indicator, ...]) -> list[tuple[str, str | int]]:
    favicon, title = values
    return [("http.favicon.hash", favicon.value), ("http.title", title.value)]


def _port_product_version(values: tuple[Indicator, ...]) -> list[tuple[str, str | int]]:
    indicator = values[0]
    if indicator.port is None or "\u001f" not in indicator.value:
        raise ValueError("Port/product/version indicator is malformed")
    product, version = indicator.value.split("\u001f", 1)
    return [("port", indicator.port), ("product", product), ("version", version)]


def default_rules() -> dict[str, DiscoveryRule]:
    """Return the fixed rule catalogue for the current Shodan-only milestone."""
    rules = (
        DiscoveryRule(
            "exact_tls_fingerprint",
            1,
            (IndicatorKind.TLS_FINGERPRINT,),
            _single_filter("ssl.cert.fingerprint"),
        ),
        DiscoveryRule("exact_banner_hash", 1, (IndicatorKind.BANNER_HASH,), _single_filter("hash")),
        DiscoveryRule(
            "favicon_and_http_title",
            1,
            (IndicatorKind.FAVICON_HASH, IndicatorKind.HTTP_TITLE),
            _favicon_title,
        ),
        DiscoveryRule(
            "port_product_and_version",
            1,
            (IndicatorKind.PORT_PRODUCT_VERSION,),
            _port_product_version,
        ),
    )
    return {rule.id: rule for rule in rules}
