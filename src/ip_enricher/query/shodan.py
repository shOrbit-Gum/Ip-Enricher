"""A deliberately small allowlisted Shodan-query renderer."""

from __future__ import annotations

import re

_SSH_MD5_FINGERPRINT = re.compile(r"(?:[0-9a-f]{2}:){15}[0-9a-f]{2}")


class ShodanQueryError(ValueError):
    """Raised when a query term is unsupported or unsafe."""


class ShodanQueryBuilder:
    """Build conjunctions from filters required by the current discovery rules."""

    ALLOWED_FILTERS = frozenset(
        {
            "ssl.cert.fingerprint",
            "ssh.fingerprint",
            "hash",
            "http.favicon.hash",
            "http.title",
            "port",
            "product",
            "version",
        }
    )

    @classmethod
    def quote(cls, value: str) -> str:
        if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
            raise ShodanQueryError("Query values must be non-empty text without control characters")
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    @classmethod
    def term(cls, name: str, value: str | int) -> str:
        if name not in cls.ALLOWED_FILTERS:
            raise ShodanQueryError(f"Unsupported Shodan filter: {name}")
        if name == "port":
            if not isinstance(value, int) or not 1 <= value <= 65535:
                raise ShodanQueryError("Port must be an integer from 1 through 65535")
            return f"port:{value}"
        if name == "ssh.fingerprint":
            if not isinstance(value, str) or not _SSH_MD5_FINGERPRINT.fullmatch(value):
                raise ShodanQueryError(
                    "SSH fingerprint must be a lowercase colon-separated MD5 fingerprint"
                )
            return f"ssh.fingerprint:{value}"
        return f"{name}:{cls.quote(str(value))}"

    @classmethod
    def build(cls, terms: list[tuple[str, str | int]]) -> str:
        if not terms:
            raise ShodanQueryError("A Shodan query requires at least one term")
        return " ".join(cls.term(name, value) for name, value in terms)
