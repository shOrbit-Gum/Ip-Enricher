from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ip_enricher.models import InvestigationResult


@dataclass(frozen=True, slots=True)
class SearchResponse:
    payload: dict[str, Any]
    cache_hit: bool
    budget_credits_charged: int


class ShodanProvider(Protocol):
    async def api_info(self) -> dict[str, Any]: ...

    async def host(self, ip: str) -> dict[str, Any]: ...

    async def count(self, query: str) -> int: ...

    async def facet(self, query: str, *, name: str, limit: int) -> dict[str, Any]: ...

    async def search(
        self,
        query: str,
        *,
        page: int = 1,
        fields: tuple[str, ...] = (),
        minify: bool = True,
    ) -> dict[str, Any]: ...

    async def search_with_metadata(
        self,
        query: str,
        *,
        page: int = 1,
        fields: tuple[str, ...] = (),
        minify: bool = True,
    ) -> SearchResponse: ...

    def is_search_cached(
        self,
        query: str,
        *,
        page: int = 1,
        fields: tuple[str, ...] = (),
        minify: bool = True,
    ) -> bool: ...

    async def close(self) -> None: ...


class InvestigationStore(Protocol):
    def save_raw(self, investigation_id: str, relative_path: str, payload: Any) -> None: ...

    def save_result(self, result: InvestigationResult) -> None: ...

    def load_cached(self, investigation_id: str, key: str) -> Any | None: ...

    def save_cached(self, investigation_id: str, key: str, payload: Any) -> None: ...
