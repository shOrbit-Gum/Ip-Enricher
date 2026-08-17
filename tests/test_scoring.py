from ip_enricher.models import Indicator, IndicatorKind
from ip_enricher.scoring import score_indicators


def test_scoring_counts_one_contribution_per_evidence_group() -> None:
    items = [
        Indicator(
            kind=IndicatorKind.TLS_FINGERPRINT,
            value="a",
            searchable=True,
            source_path="a",
            evidence_group="certificate",
        ),
        Indicator(
            kind=IndicatorKind.BANNER_HASH,
            value="b",
            searchable=True,
            source_path="b",
            evidence_group="certificate",
        ),
        Indicator(
            kind=IndicatorKind.HTTP_TITLE,
            value="title",
            searchable=True,
            source_path="c",
            evidence_group="title",
        ),
    ]
    score, contributions = score_indicators(reversed(items))
    assert score == 120
    assert [(item.evidence_group, item.weight) for item in contributions] == [
        ("certificate", 100),
        ("title", 20),
    ]
