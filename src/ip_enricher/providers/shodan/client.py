"""A small, bounded async client for the Shodan REST API."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from pydantic import SecretStr

from ip_enricher.errors import AuthenticationError, ProviderError, RateLimitError
from ip_enricher.interfaces import SearchResponse

BASE_URL = "https://api.shodan.io"


class ShodanHTTPError(ProviderError):
    """Shodan returned an unexpected HTTP response."""


class ShodanAuthenticationError(AuthenticationError):
    """Shodan rejected the configured API credential."""


class ShodanRateLimitError(RateLimitError):
    """Shodan kept rate-limiting a request after bounded retries."""


Sleep = Callable[[float], Awaitable[None]]


class HttpShodanProvider:
    """Shodan client with in-run response caching and bounded retry behaviour.

    The API key is sent only as a request parameter and is intentionally never
    included in cache keys or error messages.
    """

    def __init__(
        self,
        api_key: SecretStr | str,
        *,
        request_timeout_seconds: float = 20.0,
        max_retries: int = 3,
        max_concurrent_requests: int = 4,
        client: httpx.AsyncClient | None = None,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        if isinstance(api_key, SecretStr):
            api_key = api_key.get_secret_value()
        if not api_key:
            raise ValueError("A Shodan API key is required")
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        self._api_key = api_key
        self._max_retries = max_retries
        self._sleep = sleep
        self._semaphore = asyncio.Semaphore(max_concurrent_requests)
        self._client = client or httpx.AsyncClient(
            base_url=BASE_URL, timeout=request_timeout_seconds
        )
        self._owns_client = client is None
        self._api_info_cache: dict[str, Any] | None = None
        self._host_cache: dict[str, dict[str, Any]] = {}
        self._count_cache: dict[str, int] = {}
        self._facet_cache: dict[tuple[str, str, int], dict[str, Any]] = {}
        self._search_cache: dict[tuple[str, int, tuple[str, ...], bool], dict[str, Any]] = {}

    async def api_info(self) -> dict[str, Any]:
        if self._api_info_cache is None:
            payload = await self._get_json("/api-info")
            self._api_info_cache = payload
        return self._api_info_cache.copy()

    async def host(self, ip: str) -> dict[str, Any]:
        if ip not in self._host_cache:
            self._host_cache[ip] = await self._get_json(f"/shodan/host/{ip}")
        return self._host_cache[ip].copy()

    async def count(self, query: str) -> int:
        if query not in self._count_cache:
            payload = await self._get_json("/shodan/host/count", {"query": query})
            total = payload.get("total")
            if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                raise ShodanHTTPError("Shodan count response did not contain a valid total")
            self._count_cache[query] = total
        return self._count_cache[query]

    async def facet(self, query: str, *, name: str, limit: int) -> dict[str, Any]:
        if name != "ip":
            raise ValueError("Only the ip facet is supported")
        if limit < 1:
            raise ValueError("facet limit must be positive")
        key = (query, name, limit)
        if key not in self._facet_cache:
            self._facet_cache[key] = await self._get_json(
                "/shodan/host/count", {"query": query, "facets": f"{name}:{limit}"}
            )
        return self._facet_cache[key].copy()

    async def search(
        self,
        query: str,
        *,
        page: int = 1,
        fields: tuple[str, ...] = (),
        minify: bool = True,
    ) -> dict[str, Any]:
        response = await self.search_with_metadata(query, page=page, fields=fields, minify=minify)
        return response.payload

    async def search_with_metadata(
        self,
        query: str,
        *,
        page: int = 1,
        fields: tuple[str, ...] = (),
        minify: bool = True,
    ) -> SearchResponse:
        if page < 1:
            raise ValueError("page must be at least one")
        key = (query, page, fields, minify)
        cache_hit = key in self._search_cache
        if key not in self._search_cache:
            params: dict[str, str | int | bool] = {"query": query, "page": page, "minify": minify}
            if fields:
                params["fields"] = ",".join(fields)
            self._search_cache[key] = await self._get_json("/shodan/host/search", params)
        return SearchResponse(
            payload=self._search_cache[key].copy(),
            cache_hit=cache_hit,
            budget_credits_charged=0 if cache_hit else 1,
        )

    def is_search_cached(
        self,
        query: str,
        *,
        page: int = 1,
        fields: tuple[str, ...] = (),
        minify: bool = True,
    ) -> bool:
        return (query, page, fields, minify) in self._search_cache

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _get_json(
        self, path: str, params: dict[str, str | int | bool] | None = None
    ) -> dict[str, Any]:
        request_params: dict[str, str | int | bool] = {"key": self._api_key}
        if params:
            request_params.update(params)
        async with self._semaphore:
            for attempt in range(self._max_retries + 1):
                try:
                    response = await self._client.get(path, params=request_params)
                except httpx.RequestError as exc:
                    if attempt == self._max_retries:
                        raise ShodanHTTPError("Shodan request failed after retries") from exc
                    await self._sleep(self._backoff_seconds(attempt))
                    continue

                if response.status_code in (401, 403):
                    raise ShodanAuthenticationError("Shodan authentication failed")
                if response.status_code == 429:
                    if attempt == self._max_retries:
                        raise ShodanRateLimitError("Shodan rate limit persisted after retries")
                    await self._sleep(self._retry_after_seconds(response, attempt))
                    continue
                if 500 <= response.status_code <= 599:
                    if attempt == self._max_retries:
                        raise ShodanHTTPError(f"Shodan server error: HTTP {response.status_code}")
                    await self._sleep(self._backoff_seconds(attempt))
                    continue
                if response.status_code >= 400:
                    raise ShodanHTTPError(f"Shodan request failed: HTTP {response.status_code}")
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise ShodanHTTPError("Shodan returned invalid JSON") from exc
                if not isinstance(payload, dict):
                    raise ShodanHTTPError("Shodan returned a non-object JSON response")
                return payload
        raise AssertionError("retry loop must return or raise")

    @staticmethod
    def _backoff_seconds(attempt: int) -> float:
        return float(min(2**attempt, 8))

    def _retry_after_seconds(self, response: httpx.Response, attempt: int) -> float:
        try:
            value = float(response.headers.get("Retry-After", ""))
        except ValueError:
            value = 0.0
        return value if value >= 0 else self._backoff_seconds(attempt)
