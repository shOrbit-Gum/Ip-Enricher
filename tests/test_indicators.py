import pytest

from ip_enricher.indicators import extract_indicators
from ip_enricher.models import HostProfile, HTTPInfo, ServiceObservation, TLSInfo


def test_extracts_supported_exact_and_compound_indicators() -> None:
    profile = HostProfile(
        ip="192.0.2.10",
        services=[
            ServiceObservation(
                port=443,
                transport="tcp",
                product="nginx",
                version="1.24",
                banner_hash=42,
                ssh_fingerprint="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                tls=TLSInfo(fingerprints={"sha1": "CC:DD"}),
                http=HTTPInfo(favicon_hash=-7, title=" Example  Title "),
            )
        ],
    )

    values = {(item.kind.value, item.value) for item in extract_indicators(profile)}
    assert values == {
        ("tls_fingerprint", "ccdd"),
        ("ssh_fingerprint", "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"),
        ("banner_hash", "42"),
        ("favicon_hash", "-7"),
        ("http_title", "Example Title"),
        ("port_product_version", "nginx\u001f1.24"),
    }


def test_unsupported_ssh_fingerprint_is_not_searchable() -> None:
    profile = HostProfile(
        ip="192.0.2.10",
        services=[ServiceObservation(port=22, transport="tcp", ssh_fingerprint="aabbccdd")],
    )

    assert not extract_indicators(profile)


@pytest.mark.parametrize("banner", [None, ""])
def test_empty_banner_does_not_create_zero_hash_indicator(banner: str | None) -> None:
    profile = HostProfile(
        ip="192.0.2.10",
        services=[
            ServiceObservation(
                port=6666,
                transport="tcp",
                banner=banner,
                banner_hash=0,
            )
        ],
    )

    assert not any(item.kind.value == "banner_hash" for item in extract_indicators(profile))
