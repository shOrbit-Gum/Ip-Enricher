"""Deterministic extraction of searchable observations from host profiles."""

from __future__ import annotations

import re

from ip_enricher.models import HostProfile, Indicator, IndicatorKind

_SSH_MD5_FINGERPRINT = re.compile(r"(?:[0-9a-f]{2}:){15}[0-9a-f]{2}")


def _fingerprint(value: str) -> str:
    """Return a canonical hexadecimal fingerprint, preserving non-hex values."""
    compact = value.strip().lower().replace(":", "")
    return compact


def _ssh_fingerprint(value: str) -> str:
    """Normalize case while retaining Shodan's colon-separated representation."""
    return value.strip().lower()


def _text(value: str) -> str:
    return " ".join(value.split())


def extract_indicators(profile: HostProfile) -> list[Indicator]:
    """Extract only stable exact indicators and explicitly supported compounds.

    The function is intentionally conservative: ports, products, versions, and
    titles are never emitted as independently qualifying indicators.
    """
    indicators: list[Indicator] = []
    seen: set[tuple[IndicatorKind, str, int | None, str | None]] = set()

    def add(indicator: Indicator) -> None:
        key = (indicator.kind, indicator.value, indicator.port, indicator.transport)
        if key not in seen:
            seen.add(key)
            indicators.append(indicator)

    for index, service in enumerate(profile.services):
        path = f"services[{index}]"
        if service.tls:
            # Shodan exposes this as ssl.cert.fingerprint; SHA-1 is the
            # supported discovery fingerprint for this milestone.
            sha1 = next(
                (
                    value
                    for name, value in service.tls.fingerprints.items()
                    if name.lower().replace("-", "") == "sha1" and value
                ),
                None,
            )
            if sha1:
                value = _fingerprint(sha1)
                add(
                    Indicator(
                        kind=IndicatorKind.TLS_FINGERPRINT,
                        value=value,
                        searchable=True,
                        search_filter="ssl.cert.fingerprint",
                        source_path=f"{path}.tls.fingerprints.sha1",
                        evidence_group=f"tls_certificate:{value}",
                        port=service.port,
                        transport=service.transport,
                    )
                )
        if service.ssh_fingerprint:
            value = _ssh_fingerprint(service.ssh_fingerprint)
            if _SSH_MD5_FINGERPRINT.fullmatch(value):
                add(
                    Indicator(
                        kind=IndicatorKind.SSH_FINGERPRINT,
                        value=value,
                        searchable=True,
                        search_filter="ssh.fingerprint",
                        source_path=f"{path}.ssh_fingerprint",
                        evidence_group=f"ssh_key:{value}",
                        port=service.port,
                        transport=service.transport,
                    )
                )
        if service.banner_hash is not None and not (
            service.banner_hash == 0 and not (service.banner or "").strip()
        ):
            value = str(service.banner_hash)
            add(
                Indicator(
                    kind=IndicatorKind.BANNER_HASH,
                    value=value,
                    searchable=True,
                    search_filter="hash",
                    source_path=f"{path}.banner_hash",
                    evidence_group=f"banner_hash:{value}",
                    port=service.port,
                    transport=service.transport,
                )
            )
        if service.http:
            if service.http.favicon_hash is not None:
                value = str(service.http.favicon_hash)
                add(
                    Indicator(
                        kind=IndicatorKind.FAVICON_HASH,
                        value=value,
                        searchable=True,
                        search_filter="http.favicon.hash",
                        source_path=f"{path}.http.favicon_hash",
                        evidence_group=f"favicon_hash:{value}",
                        port=service.port,
                        transport=service.transport,
                    )
                )
            if service.http.title:
                value = _text(service.http.title)
                if value:
                    add(
                        Indicator(
                            kind=IndicatorKind.HTTP_TITLE,
                            value=value,
                            searchable=True,
                            search_filter="http.title",
                            source_path=f"{path}.http.title",
                            evidence_group=f"http_title:{value}",
                            port=service.port,
                            transport=service.transport,
                        )
                    )
        if service.product and service.version:
            product, version = _text(service.product), _text(service.version)
            if product and version:
                add(
                    Indicator(
                        kind=IndicatorKind.PORT_PRODUCT_VERSION,
                        value=f"{product}\u001f{version}",
                        searchable=True,
                        search_filter=None,
                        source_path=path,
                        evidence_group=(
                            f"service_fingerprint:{service.port}/{service.transport}:{product}:{version}"
                        ),
                        port=service.port,
                        transport=service.transport,
                    )
                )

    return sorted(indicators, key=lambda item: (item.kind.value, item.value, item.port or 0))
