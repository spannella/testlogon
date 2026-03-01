from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services import file_bundle_entitlements as svc


class _EntitlementsTable:
    def __init__(self, items):
        self._items = items

    def query(self, **_kwargs):
        return {"Items": list(self._items)}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def test_purchase_bundle_allows_without_expiration(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc)
    items = [
        {
            "product_type": "file_bundle",
            "status": "active",
            "starts_at": _iso(now - timedelta(days=30)),
            "ends_at": None,
            "scope": {
                "date_start": _iso(now - timedelta(days=60)),
                "date_end": _iso(now + timedelta(days=60)),
            },
        }
    ]
    monkeypatch.setattr(svc, "S", SimpleNamespace(catalog_commercialization_enabled=True))
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=_EntitlementsTable(items)))

    svc.assert_file_bundle_access("u1", {"created_at": _iso(now)})


def test_rental_bundle_expired_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc)
    items = [
        {
            "product_type": "file_bundle",
            "status": "active",
            "starts_at": _iso(now - timedelta(days=2)),
            "ends_at": _iso(now - timedelta(minutes=1)),
            "scope": {
                "date_start": _iso(now - timedelta(days=10)),
                "date_end": _iso(now + timedelta(days=10)),
            },
        }
    ]
    monkeypatch.setattr(svc, "S", SimpleNamespace(catalog_commercialization_enabled=True))
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=_EntitlementsTable(items)))

    with pytest.raises(HTTPException) as exc:
        svc.assert_file_bundle_access("u1", {"created_at": _iso(now)})
    assert exc.value.status_code == 403
    assert exc.value.detail["reason"] == "expired_entitlement"


def test_out_of_scope_denied_even_when_active(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc)
    items = [
        {
            "product_type": "file_bundle",
            "status": "active",
            "starts_at": _iso(now - timedelta(days=2)),
            "ends_at": _iso(now + timedelta(days=2)),
            "scope": {
                "date_start": _iso(now - timedelta(days=10)),
                "date_end": _iso(now - timedelta(days=5)),
            },
        }
    ]
    monkeypatch.setattr(svc, "S", SimpleNamespace(catalog_commercialization_enabled=True))
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=_EntitlementsTable(items)))

    with pytest.raises(HTTPException) as exc:
        svc.assert_file_bundle_access("u1", {"created_at": _iso(now)})
    assert exc.value.status_code == 403
    assert exc.value.detail["reason"] == "out_of_scope"


def test_file_bundle_checks_bypassed_when_family_flag_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(svc, "S", SimpleNamespace(catalog_commercialization_enabled=True, catalog_file_bundle_enabled=False))
    monkeypatch.setattr(svc, "T", SimpleNamespace(entitlements=_EntitlementsTable([])))

    svc.assert_file_bundle_access("u1", {"created_at": _iso(now)})
