import pytest

from ip_enricher.query import ShodanQueryBuilder, ShodanQueryError


def test_builder_quotes_and_escapes_supported_values() -> None:
    assert (
        ShodanQueryBuilder.build([("http.title", 'A "title"'), ("port", 443)])
        == 'http.title:"A \\"title\\"" port:443'
    )


def test_builder_rejects_unapproved_filter_and_invalid_port() -> None:
    with pytest.raises(ShodanQueryError):
        ShodanQueryBuilder.term("org", "example")
    with pytest.raises(ShodanQueryError):
        ShodanQueryBuilder.term("port", 0)


def test_builder_renders_canonical_ssh_fingerprint_without_quotes() -> None:
    fingerprint = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"

    assert ShodanQueryBuilder.term("ssh.fingerprint", fingerprint) == (
        f"ssh.fingerprint:{fingerprint}"
    )
    with pytest.raises(ShodanQueryError):
        ShodanQueryBuilder.term("ssh.fingerprint", fingerprint.replace(":", ""))
