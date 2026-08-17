"""Conversion of raw Shodan host documents into normalized profiles."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ip_enricher.models import HostProfile, HTTPInfo, ServiceObservation, TLSInfo


def normalize_host(raw: dict[str, Any], *, collected_at: datetime | None = None) -> HostProfile:
    """Normalize a raw Shodan host document, tolerating malformed optional data."""
    ip = _text(raw.get("ip_str")) or _text(raw.get("ip"))
    if ip is None:
        raise ValueError("Shodan host response does not contain an IP address")
    services = [
        service for item in _items(raw.get("data")) if (service := _service(item)) is not None
    ]
    return HostProfile(
        ip=ip,
        collected_at=collected_at or datetime.now(UTC),
        last_update=_datetime(raw.get("last_update")),
        asn=_text(raw.get("asn")),
        organization=_text(raw.get("org")),
        isp=_text(raw.get("isp")),
        network=(
            _text(raw.get("ip")) if "/" in str(raw.get("ip", "")) else _text(raw.get("network"))
        ),
        operating_system=_text(raw.get("os")),
        hostnames=_strings(raw.get("hostnames")),
        domains=_strings(raw.get("domains")),
        tags=_strings(raw.get("tags")),
        services=services,
    )


def _service(item: Any) -> ServiceObservation | None:
    if not isinstance(item, dict):
        return None
    port = item.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return None
    transport = item.get("transport")
    if transport not in {"tcp", "udp"}:
        return None
    return ServiceObservation(
        port=port,
        transport=transport,
        observed_at=_datetime(item.get("timestamp")),
        module=_module(item.get("_shodan")),
        product=_text(item.get("product")),
        version=_text(item.get("version")),
        service_name=_text(item.get("service")) or _text(item.get("service_name")),
        banner=_text(item.get("data")),
        banner_hash=_integer(item.get("hash")),
        cpes=_strings(item.get("cpe")),
        tls=_tls(item.get("ssl")),
        http=_http(item.get("http")),
        ssh_fingerprint=_ssh_fingerprint(item.get("ssh")),
        vulnerabilities=_vulnerabilities(item.get("vulns")),
    )


def _tls(value: Any) -> TLSInfo | None:
    if not isinstance(value, dict):
        return None
    cert = _mapping(value.get("cert"))
    fingerprints = _mapping(cert.get("fingerprint"))
    normalized = {str(k): v for k, v in fingerprints.items() if isinstance(v, str)}
    tls = TLSInfo(
        fingerprints=normalized,
        subject=_mapping(cert.get("subject")),
        issuer=_mapping(cert.get("issuer")),
        serial=_text(cert.get("serial")),
        jarm=_text(value.get("jarm")),
        ja3s=_text(value.get("ja3s")),
    )
    fields = (tls.fingerprints, tls.subject, tls.issuer, tls.serial, tls.jarm, tls.ja3s)
    return tls if any(fields) else None


def _http(value: Any) -> HTTPInfo | None:
    if not isinstance(value, dict):
        return None
    favicon = _mapping(value.get("favicon"))
    info = HTTPInfo(
        title=_text(value.get("title")),
        favicon_hash=_integer(favicon.get("hash")),
        html_hash=_integer(value.get("html_hash")),
        headers_hash=_integer(value.get("headers_hash")),
        robots_hash=_integer(value.get("robots_hash")),
        server_hash=_integer(value.get("server_hash")),
        status=_integer(value.get("status")),
        redirect_location=_text(value.get("location")) or _text(value.get("redirect")),
    )
    return info if any(value is not None for value in info.model_dump().values()) else None


def _ssh_fingerprint(value: Any) -> str | None:
    return _text(value.get("fingerprint")) if isinstance(value, dict) else None


def _module(value: Any) -> str | None:
    return _text(value.get("module")) if isinstance(value, dict) else None


def _vulnerabilities(value: Any) -> list[str]:
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return sorted(value)
    return _strings(value)


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed
