from __future__ import annotations

import json
from pathlib import Path

import pytest

from ip_enricher.models import HostProfile, InvestigationResult
from ip_enricher.storage import JSONInvestigationStore, StorageError


def test_raw_result_and_cache_round_trip(tmp_path: Path) -> None:
    store = JSONInvestigationStore(tmp_path)
    store.save_raw("inv-1", "raw/host.json", {"ip": "192.0.2.1", "ok": True})
    assert json.loads((tmp_path / "inv-1" / "raw" / "host.json").read_text()) == {
        "ip": "192.0.2.1",
        "ok": True,
    }

    result = InvestigationResult(
        investigation_id="inv-1",
        seed=HostProfile(ip="192.0.2.1"),
        indicators=[],
    )
    store.save_result(result)
    assert json.loads((tmp_path / "inv-1" / "result.json").read_text())["schema_version"] == 1

    store.save_cached("inv-1", "count:tls", {"total": 2})
    assert store.load_cached("inv-1", "count:tls") == {"total": 2}
    assert store.load_cached("inv-1", "missing") is None


def test_writes_are_utf8_and_replace_existing_atomically(tmp_path: Path) -> None:
    store = JSONInvestigationStore(tmp_path)
    store.save_raw("inv", "notes.json", {"text": "שלום"})
    store.save_raw("inv", "notes.json", {"text": "updated"})
    assert (
        json.loads((tmp_path / "inv" / "notes.json").read_text(encoding="utf-8"))["text"]
        == "updated"
    )
    assert not list((tmp_path / "inv").glob(".*.tmp"))


@pytest.mark.parametrize(
    "investigation_id, relative_path",
    [
        ("../outside", "x.json"),
        ("inv", "../outside.json"),
        ("inv", "C:/outside.json"),
        ("inv", "x/./y.json"),
    ],
)
def test_rejects_unsafe_paths(tmp_path: Path, investigation_id: str, relative_path: str) -> None:
    store = JSONInvestigationStore(tmp_path)
    with pytest.raises(StorageError):
        store.save_raw(investigation_id, relative_path, {})


def test_secret_named_fields_are_not_persisted(tmp_path: Path) -> None:
    store = JSONInvestigationStore(tmp_path)
    store.save_raw("inv", "provider.json", {"api_key": "do-not-store", "data": {"value": 1}})
    saved = json.loads((tmp_path / "inv" / "provider.json").read_text(encoding="utf-8"))
    assert "api_key" not in saved
    assert saved["data"] == {"value": 1}
