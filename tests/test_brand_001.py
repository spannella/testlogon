"""BRAND-001 — Hermetic unit tests for platform branding (decision D6).

Pattern: moto-backed ``platform_settings`` table bound to the frozen
``T.platform_settings`` handle via ``object.__setattr__``; frozen ``S``
defaults toggled the same way.  Route coroutines are called directly on a
fresh ``asyncio.new_event_loop()`` — no TestClient (broken in this env).

Covers all twelve test cases from spec §9.1.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_table():
    """Create an in-memory platform_settings table and wire it into T + S."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName="platform_settings",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        from app.core import tables as T_mod
        from app.services import branding as svc

        # Bind the moto-backed table to T (frozen dataclass → object.__setattr__)
        object.__setattr__(T_mod.T, "platform_settings", table)

        # Set env-default settings on S
        object.__setattr__(svc.S, "platform_name", "testlogon")
        object.__setattr__(svc.S, "platform_logo_url", "")
        object.__setattr__(svc.S, "platform_support_email", "")
        object.__setattr__(svc.S, "branding_cache_ttl_seconds", 60)

        svc.invalidate_cache()
        yield table
        svc.invalidate_cache()


# ---------------------------------------------------------------------------
# Test cases (spec §9.1)
# ---------------------------------------------------------------------------

class TestGetBrandingDefaults:
    """TC1: Empty table → env defaults; no exception."""

    def test_empty_table_returns_env_defaults(self):
        from app.services import branding as svc
        b = svc.get_branding()
        assert b["platform_name"] == "testlogon"
        assert b["logo_url"] == ""
        assert b["support_email"] == ""
        assert b["updated_at"] is None
        # No exception raised


class TestGetBrandingNeverRaises:
    """TC2: get_branding never raises even if DDB get_item throws."""

    def test_never_raises_on_ddb_error(self, monkeypatch):
        from app.services import branding as svc
        from app.core import tables as T_mod

        def boom(*args, **kwargs):
            raise RuntimeError("DDB is down")

        # Patch the underlying table's get_item to raise
        monkeypatch.setattr(T_mod.T.platform_settings, "get_item", boom)
        svc.invalidate_cache()

        b = svc.get_branding()  # must not raise
        assert b["platform_name"] == "testlogon"


class TestSetBrandingCreatesRow:
    """TC3: set_branding creates the row; returned dict has expected values."""

    def test_set_branding_round_trip(self):
        from app.services import branding as svc
        b = svc.set_branding(name="Acme Co", actor_sub="root1")
        assert b["platform_name"] == "Acme Co"
        assert b["name"] == "Acme Co"
        assert b["updated_by"] == "root1"
        assert isinstance(b["updated_at"], int)
        assert b["updated_at"] > 0


class TestPartialUpdatePreservesFields:
    """TC4: Partial update leaves other fields untouched."""

    def test_partial_update(self):
        from app.services import branding as svc
        svc.set_branding(name="Acme Co", actor_sub="root1")
        b = svc.set_branding(logo_url="https://x/logo.png", actor_sub="root1")
        assert b["platform_name"] == "Acme Co"
        assert b["logo_url"] == "https://x/logo.png"


class TestReadYourWrites:
    """TC5: get_branding reflects the write immediately (cache invalidated)."""

    def test_read_your_writes(self):
        from app.services import branding as svc
        # Warm the cache with the default
        b1 = svc.get_branding()
        assert b1["platform_name"] == "testlogon"

        # Write a new name
        svc.set_branding(name="New Name", actor_sub="r")

        # Immediately readable (cache was invalidated by set_branding)
        b2 = svc.get_branding()
        assert b2["platform_name"] == "New Name"


class TestNameReservedWordAliasing:
    """TC6: name is a DDB reserved word; ExpressionAttributeNames alias prevents ValidationException."""

    def test_name_reserved_word(self):
        from app.services import branding as svc
        # This must not raise ValidationException
        b = svc.set_branding(name="X", actor_sub="r")
        assert b["platform_name"] == "X"


class TestEmptyStringClearsLogo:
    """TC7: set_branding(logo_url="") stores empty string and get_branding returns ""."""

    def test_empty_string_clears_logo(self):
        from app.services import branding as svc
        svc.set_branding(logo_url="https://example.com/logo.png", actor_sub="r")
        b = svc.set_branding(logo_url="", actor_sub="r")
        assert b["logo_url"] == ""


class TestDecimalCoercion:
    """TC8: updated_at returned as int (Decimal coerced by service)."""

    def test_updated_at_is_int(self):
        from app.services import branding as svc
        svc.set_branding(name="Test", actor_sub="r")
        b = svc.get_branding()
        assert isinstance(b["updated_at"], int)


class TestPlatformNameKeyParity:
    """TC9: get_branding()["name"] == get_branding()["platform_name"]."""

    def test_key_parity_default(self):
        from app.services import branding as svc
        b = svc.get_branding()
        assert b["name"] == b["platform_name"]

    def test_key_parity_after_set(self):
        from app.services import branding as svc
        svc.set_branding(name="ParityTest", actor_sub="r")
        b = svc.get_branding()
        assert b["name"] == b["platform_name"] == "ParityTest"


class TestRouterGetAdminAllowed:
    """TC10: GET /ui/admin/branding — ADMIN user receives a BrandingOut-shaped response."""

    def test_admin_can_read(self):
        from app.routers.branding import get_branding_endpoint
        from app.models import BrandingOut

        stub_user = SimpleNamespace(sub="admin1", role="admin")
        result = _run(get_branding_endpoint(user=stub_user))
        assert isinstance(result, BrandingOut)
        assert result.platform_name == "testlogon"


class TestRouterPutRootOnly:
    """TC11: PUT /ui/admin/branding — ROOT user; CSRF skipped (Bearer-auth stub request)."""

    def test_root_can_put(self):
        from app.routers.branding import put_branding_endpoint
        from app.models import BrandingOut, BrandingUpdateIn

        stub_user = SimpleNamespace(sub="root1", role="root")

        # Stub request with no session cookie → enforce_cookie_csrf is a no-op
        stub_request = SimpleNamespace(
            method="PUT",
            cookies={},
            headers={},
        )

        body = BrandingUpdateIn(name="Z")
        result = _run(put_branding_endpoint(body=body, request=stub_request, user=stub_user))
        assert isinstance(result, BrandingOut)
        assert result.platform_name == "Z"
        assert result.updated_by == "root1"


class TestCacheTtlExpiry:
    """TC12: With TTL=0 the cache is always stale; out-of-band write is visible immediately."""

    def test_cache_ttl_zero(self, setup_table):
        from app.services import branding as svc

        # Force TTL to 0 so the cache is always stale
        object.__setattr__(svc.S, "branding_cache_ttl_seconds", 0)
        svc.invalidate_cache()

        try:
            # Write directly to DDB (bypassing service cache) using the moto table
            setup_table.put_item(Item={
                "pk": "PLATFORM",
                "sk": "BRANDING",
                "name": "DirectWrite",
                "logo_url": "",
                "support_email": "",
                "updated_at": 1,
                "updated_by": "oob",
            })

            # With TTL=0 every get_branding() re-reads DDB → must see the direct write
            b = svc.get_branding()
            assert b["platform_name"] == "DirectWrite"
        finally:
            object.__setattr__(svc.S, "branding_cache_ttl_seconds", 60)
            svc.invalidate_cache()
