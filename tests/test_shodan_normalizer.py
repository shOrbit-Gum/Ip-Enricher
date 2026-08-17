from __future__ import annotations

from datetime import UTC, datetime

from ip_enricher.providers.shodan.normalizer import normalize_host


def test_normalize_host_preserves_supported_shodan_observations() -> None:
    collected_at = datetime(2026, 1, 2, tzinfo=UTC)
    profile = normalize_host(
        {
            "ip_str": "192.0.2.10",
            "last_update": "2026-01-01T10:11:12Z",
            "asn": "AS64496",
            "org": "Example Org",
            "hostnames": ["api.example.test", 1],
            "domains": ["example.test"],
            "tags": ["vpn"],
            "data": [
                {
                    "port": 443,
                    "transport": "tcp",
                    "timestamp": "2026-01-01T09:00:00Z",
                    "product": "nginx",
                    "version": "1.26",
                    "hash": -123,
                    "cpe": ["cpe:/a:nginx:nginx:1.26"],
                    "ssl": {
                        "jarm": "abc",
                        "cert": {
                            "fingerprint": {"sha256": "deadbeef"},
                            "subject": {"CN": "api.example.test"},
                            "issuer": {"CN": "Example CA"},
                            "serial": "01",
                        },
                    },
                    "http": {"title": "Example", "favicon": {"hash": 42}, "status": 200},
                    "vulns": {"CVE-2025-0001": {}},
                }
            ],
        },
        collected_at=collected_at,
    )
    service = profile.services[0]
    assert profile.collected_at == collected_at
    assert profile.last_update == datetime(2026, 1, 1, 10, 11, 12, tzinfo=UTC)
    assert profile.hostnames == ["api.example.test"]
    assert service.banner_hash == -123
    assert service.tls is not None and service.tls.fingerprints == {"sha256": "deadbeef"}
    assert service.http is not None and service.http.favicon_hash == 42
    assert service.vulnerabilities == ["CVE-2025-0001"]


def test_normalize_host_discards_malformed_optional_service_data() -> None:
    profile = normalize_host(
        {
            "ip": "198.51.100.7",
            "data": [
                {"port": "443", "transport": "tcp"},
                {"port": 53, "transport": "udp", "http": "not-an-object", "ssl": []},
            ],
        }
    )
    assert profile.ip == "198.51.100.7"
    assert len(profile.services) == 1
    assert profile.services[0].port == 53
    assert profile.services[0].http is None
    assert profile.services[0].tls is None
