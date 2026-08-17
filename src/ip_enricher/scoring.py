"""Explainable, non-double-counting candidate scoring."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ip_enricher.models import Indicator, IndicatorKind, ScoreContribution

DEFAULT_INDICATOR_WEIGHTS: dict[IndicatorKind, int] = {
    IndicatorKind.TLS_FINGERPRINT: 100,
    IndicatorKind.SSH_FINGERPRINT: 100,
    IndicatorKind.BANNER_HASH: 80,
    IndicatorKind.FAVICON_HASH: 50,
    IndicatorKind.HTTP_TITLE: 20,
    IndicatorKind.PORT_PRODUCT_VERSION: 40,
}


def score_indicators(
    indicators: Iterable[Indicator],
    weights: Mapping[IndicatorKind, int] | None = None,
) -> tuple[int, list[ScoreContribution]]:
    """Score at most one contribution per correlated evidence group.

    Ties resolve by kind and value, so the explanation is repeatable regardless
    of input ordering.
    """
    configured = DEFAULT_INDICATOR_WEIGHTS if weights is None else weights
    best_by_group: dict[str, tuple[int, Indicator]] = {}
    for indicator in indicators:
        weight = configured.get(indicator.kind, 0)
        if weight <= 0:
            continue
        current = best_by_group.get(indicator.evidence_group)
        candidate_key = (weight, indicator.kind.value, indicator.value)
        if current is None or candidate_key > (current[0], current[1].kind.value, current[1].value):
            best_by_group[indicator.evidence_group] = (weight, indicator)
    contributions = [
        ScoreContribution(
            indicator_kind=item.kind, value=item.value, weight=weight, evidence_group=group
        )
        for group, (weight, item) in best_by_group.items()
    ]
    contributions.sort(
        key=lambda item: (item.evidence_group, item.indicator_kind.value, item.value)
    )
    return sum(item.weight for item in contributions), contributions
