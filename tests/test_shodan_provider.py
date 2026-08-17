from __future__ import annotations

import httpx
import pytest

from ip_enricher.providers.shodan.client import (
    HttpShodanProvider,
    ShodanAuthenticationError,
    ShodanRateLimitError,
)


@pytest.mark.asyncio
async def test_provider_caches_responses_and_uses_expected_parameters() -> None:
    calls: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/api-info":
            return httpx.Response(200, json={"query_credits": 100})
        if request.url.path == "/shodan/host/count":
            return httpx.Response(200, json={"total": 2})
        if request.url.path == "/shodan/host/search":
            return httpx.Response(200, json={"total": 2, "matches": []})
        return httpx.Response(200, json={"ip_str": "192.0.2.5"})

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.shodan.io"
    )
    provider = HttpShodanProvider("test-key", client=client)
    assert await provider.api_info() == {"query_credits": 100}
    assert await provider.api_info() == {"query_credits": 100}
    assert await provider.host("192.0.2.5") == {"ip_str": "192.0.2.5"}
    assert await provider.host("192.0.2.5") == {"ip_str": "192.0.2.5"}
    assert await provider.count("ssl.cert.fingerprint:abc") == 2
    assert await provider.count("ssl.cert.fingerprint:abc") == 2
    assert await provider.facet("hash:1", name="ip", limit=25) == {"total": 2}
    assert await provider.facet("hash:1", name="ip", limit=25) == {"total": 2}
    first = await provider.search_with_metadata(
        "ssl.cert.fingerprint:abc", fields=("ip_str",), minify=True
    )
    assert first.payload == {"total": 2, "matches": []}
    assert first.cache_hit is False
    assert first.budget_credits_charged == 1
    second = await provider.search_with_metadata(
        "ssl.cert.fingerprint:abc", fields=("ip_str",), minify=True
    )
    assert second.cache_hit is True
    assert second.budget_credits_charged == 0
    # The compatibility method still returns only the payload.
    assert (
        await provider.search("ssl.cert.fingerprint:abc", fields=("ip_str",), minify=True)
        == first.payload
    )
    assert (
        await provider.search("ssl.cert.fingerprint:abc", fields=("ip_str",), minify=True)
        == first.payload
    )
    assert len(calls) == 5
    search = calls[-1]
    assert search.url.params["key"] == "test-key"
    assert search.url.params["fields"] == "ip_str"
    assert search.url.params["page"] == "1"
    await client.aclose()


@pytest.mark.asyncio
async def test_rate_limit_honors_retry_after() -> None:
    attempts = 0
    sleeps: list[float] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "3"})
        return httpx.Response(200, json={"total": 1})

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://api.shodan.io"
    )
    provider = HttpShodanProvider("test-key", max_retries=1, client=client, sleep=sleep)
    assert await provider.count("hash:123") == 1
    assert sleeps == [3.0]
    await client.aclose()


@pytest.mark.asyncio
async def test_authentication_is_not_retried_or_leaked() -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(401)),
        base_url="https://api.shodan.io",
    )
    provider = HttpShodanProvider("very-secret", client=client)
    with pytest.raises(ShodanAuthenticationError) as exc:
        await provider.api_info()
    assert "very-secret" not in str(exc.value)
    await client.aclose()


@pytest.mark.asyncio
async def test_rate_limit_raises_after_bounded_retries() -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(429)),
        base_url="https://api.shodan.io",
    )
    provider = HttpShodanProvider("test-key", max_retries=0, client=client)
    with pytest.raises(ShodanRateLimitError):
        await provider.api_info()
    await client.aclose()
