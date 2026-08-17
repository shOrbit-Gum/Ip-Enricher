from ip_enricher.indicators import extract_indicators
from ip_enricher.models import HostProfile, HTTPInfo, ServiceObservation, TLSInfo
from ip_enricher.rules import default_rules


def test_rules_are_versioned_and_build_deterministic_queries() -> None:
    profile = HostProfile(
        ip="192.0.2.10",
        services=[
            ServiceObservation(
                port=443,
                transport="tcp",
                product="nginx",
                version="1.24",
                ssh_fingerprint="aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                tls=TLSInfo(fingerprints={"sha1": "aa:bb"}),
                http=HTTPInfo(favicon_hash=7, title="Panel"),
            )
        ],
    )
    indicators = extract_indicators(profile)
    rules = default_rules()
    assert rules["exact_tls_fingerprint"].version == 1
    assert (
        rules["exact_tls_fingerprint"].build_query(
            rules["exact_tls_fingerprint"].select(indicators)[0]
        )
        == 'ssl.cert.fingerprint:"aabb"'
    )
    compound = rules["favicon_and_http_title"].select(indicators)[0]
    assert (
        rules["favicon_and_http_title"].build_query(compound)
        == 'http.favicon.hash:"7" http.title:"Panel"'
    )
    assert "exact_ssh_host_key" not in rules
    assert (
        rules["port_product_and_version"].build_query(
            rules["port_product_and_version"].select(indicators)[0]
        )
        == 'port:443 product:"nginx" version:"1.24"'
    )


def test_rule_rechecks_candidate_observations() -> None:
    seed = HostProfile(
        ip="192.0.2.10",
        services=[
            ServiceObservation(port=443, transport="tcp", tls=TLSInfo(fingerprints={"sha1": "aa"}))
        ],
    )
    candidate = HostProfile(
        ip="198.51.100.10",
        services=[
            ServiceObservation(port=443, transport="tcp", tls=TLSInfo(fingerprints={"sha1": "aa"}))
        ],
    )
    rule = default_rules()["exact_tls_fingerprint"]
    selected = rule.select(extract_indicators(seed))[0]
    assert rule.accepts(candidate, selected)


def test_port_product_version_requires_matching_transport() -> None:
    seed = HostProfile(
        ip="192.0.2.10",
        services=[ServiceObservation(port=8443, transport="tcp", product="Example", version="1.0")],
    )
    rule = default_rules()["port_product_and_version"]
    selected = rule.select(extract_indicators(seed))[0]
    matching = HostProfile(
        ip="198.51.100.10",
        services=[ServiceObservation(port=8443, transport="tcp", product="Example", version="1.0")],
    )
    wrong_transport = HostProfile(
        ip="198.51.100.11",
        services=[ServiceObservation(port=8443, transport="udp", product="Example", version="1.0")],
    )

    assert rule.accepts(matching, selected)
    assert not rule.accepts(wrong_transport, selected)
