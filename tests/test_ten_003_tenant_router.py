"""
TEN-003 hermetic unit tests: tenant router (route handlers called directly).

Isolation:
  - All tenant_svc collaborators stubbed as MagicMock on the router module namespace
  - S.property_tenants_enabled toggled via object.__setattr__
  - No TestClient, no moto needed (service is stubbed)
  - asyncio not needed (router functions are sync)
"""

import importlib
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException


@contextmanager
def _flags(tenants=True, leases=False):
    from app.core.settings import S
    orig_t = S.property_tenants_enabled
    orig_l = getattr(S, "leases_enabled", False)
    object.__setattr__(S, "property_tenants_enabled", tenants)
    object.__setattr__(S, "leases_enabled", leases)
    try:
        yield
    finally:
        object.__setattr__(S, "property_tenants_enabled", orig_t)
        object.__setattr__(S, "leases_enabled", orig_l)


def _make_tenant_item(tenant_id="t001", owner_id="alice", status="prospect"):
    return {
        "tenant_id": tenant_id,
        "owner_id": owner_id,
        "party_id": "party_001",
        "display_name": "Alice",
        "email": "alice@test.com",
        "phone": None,
        "status": status,
        "active_unit_id": None,
        "created_at": 1700000000,
        "updated_at": 1700000000,
    }


def _ctx(user_sub="alice", role=None):
    from app.auth.roles import Role
    return {"user_sub": user_sub, "role": role or Role.USER, "admin_profile": None}


class TestTen003Router(unittest.TestCase):

    def setUp(self):
        import app.routers.property_tenant as router_mod
        self.router_mod = router_mod
        # Reload to pick up any fresh state
        importlib.reload(router_mod)

    # ------------------------------------------------------------------ #
    # Flag-off guard
    # ------------------------------------------------------------------ #

    def test_flag_off_all_endpoints_404(self):
        with _flags(tenants=False):
            rmod = self.router_mod
            for fn in [
                lambda: rmod.list_tenants(ctx=_ctx()),
                lambda: rmod.get_tenant("t001", ctx=_ctx()),
            ]:
                with self.assertRaises(HTTPException) as cm:
                    fn()
                self.assertEqual(cm.exception.status_code, 404)

    # ------------------------------------------------------------------ #
    # POST (create)
    # ------------------------------------------------------------------ #

    def test_post_tenant_201(self):
        from app.models import CreateTenantIn
        body = CreateTenantIn(display_name="Alice")

        with _flags(tenants=True):
            with patch.object(
                self.router_mod, "tenant_svc"
            ) as mock_svc:
                mock_svc.create_tenant.return_value = _make_tenant_item()
                result = self.router_mod.create_tenant(body=body, ctx=_ctx())
                self.assertEqual(result.tenant_id, "t001")
                mock_svc.create_tenant.assert_called_once()

    # ------------------------------------------------------------------ #
    # GET list
    # ------------------------------------------------------------------ #

    def test_get_tenant_list(self):
        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.list_tenants.return_value = {
                    "tenants": [_make_tenant_item()],
                    "count": 1,
                    "next_cursor": None,
                }
                result = self.router_mod.list_tenants(
                    status="prospect", q="alice", cursor=None, limit=50, ctx=_ctx()
                )
                self.assertEqual(result.count, 1)
                mock_svc.list_tenants.assert_called_once_with(
                    owner_id="alice",
                    status="prospect",
                    q="alice",
                    cursor=None,
                    limit=50,
                )

    # ------------------------------------------------------------------ #
    # GET single
    # ------------------------------------------------------------------ #

    def test_get_tenant_single_found(self):
        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = _make_tenant_item(owner_id="alice")
                result = self.router_mod.get_tenant("t001", ctx=_ctx(user_sub="alice"))
                self.assertEqual(result.tenant_id, "t001")

    def test_get_tenant_single_404_not_found(self):
        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = None
                with self.assertRaises(HTTPException) as cm:
                    self.router_mod.get_tenant("bad_id", ctx=_ctx())
                self.assertEqual(cm.exception.status_code, 404)

    def test_get_tenant_single_404_wrong_owner(self):
        """Wrong owner returns 404 (not 403) — security posture."""
        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = _make_tenant_item(owner_id="bob")
                with self.assertRaises(HTTPException) as cm:
                    self.router_mod.get_tenant("t001", ctx=_ctx(user_sub="alice"))
                self.assertEqual(cm.exception.status_code, 404)

    # ------------------------------------------------------------------ #
    # PATCH
    # ------------------------------------------------------------------ #

    def test_patch_tenant(self):
        from app.models import UpdateTenantIn
        body = UpdateTenantIn(display_name="New Name")
        updated = {**_make_tenant_item(), "display_name": "New Name"}

        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = _make_tenant_item(owner_id="alice")
                mock_svc.update_tenant.return_value = updated
                result = self.router_mod.update_tenant("t001", body=body, ctx=_ctx())
                self.assertEqual(result.display_name, "New Name")
                mock_svc.update_tenant.assert_called_once()

    def test_patch_tenant_empty_body_400(self):
        from app.models import UpdateTenantIn
        body = UpdateTenantIn()  # all fields None

        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = _make_tenant_item(owner_id="alice")
                with self.assertRaises(HTTPException) as cm:
                    self.router_mod.update_tenant("t001", body=body, ctx=_ctx())
                self.assertEqual(cm.exception.status_code, 400)

    # ------------------------------------------------------------------ #
    # Profile endpoints
    # ------------------------------------------------------------------ #

    def test_get_profile(self):
        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = _make_tenant_item(owner_id="alice")
                mock_svc.get_profile.return_value = {
                    "employment": {},
                    "income": {},
                    "emergency_contacts": [],
                    "updated_at": None,
                }
                result = self.router_mod.get_profile("t001", ctx=_ctx())
                self.assertIsInstance(result, dict)
                mock_svc.get_profile.assert_called_once_with("t001")

    def test_put_profile(self):
        from app.models import TenantProfileIn, EmploymentIn
        body = TenantProfileIn(employment=EmploymentIn(employer_name="Acme"))

        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = _make_tenant_item(owner_id="alice")
                mock_svc.update_profile.return_value = {
                    "employment": {"employer_name": "Acme"},
                    "income": {},
                    "emergency_contacts": [],
                    "updated_at": 1700000001,
                }
                result = self.router_mod.update_profile("t001", body=body, ctx=_ctx())
                self.assertEqual(result["employment"]["employer_name"], "Acme")

    # ------------------------------------------------------------------ #
    # Income docs
    # ------------------------------------------------------------------ #

    def test_post_income_doc_invalid_doc_kind(self):
        from unittest.mock import MagicMock
        file = MagicMock()
        file.filename = "test.pdf"
        file.content_type = "application/pdf"

        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = _make_tenant_item(owner_id="alice")
                with self.assertRaises(HTTPException) as cm:
                    self.router_mod.upload_income_doc(
                        "t001", file=file, doc_kind="invalid_kind", ctx=_ctx()
                    )
                self.assertEqual(cm.exception.status_code, 422)

    def test_delete_income_doc_204(self):
        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = _make_tenant_item(owner_id="alice")
                mock_svc.remove_income_doc.return_value = False
                # Should not raise
                result = self.router_mod.delete_income_doc("t001", "doc001", ctx=_ctx())
                self.assertIsNone(result)

    # ------------------------------------------------------------------ #
    # Active unit
    # ------------------------------------------------------------------ #

    def test_put_active_unit(self):
        from app.models import ActiveUnitIn
        body = ActiveUnitIn(property_id="prop1", unit_id="unit1")
        updated = {**_make_tenant_item(), "active_unit_id": "unit1", "status": "active"}

        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = _make_tenant_item(owner_id="alice")
                mock_svc.set_active_unit.return_value = updated
                result = self.router_mod.set_active_unit("t001", body=body, ctx=_ctx())
                self.assertEqual(result.active_unit_id, "unit1")
                mock_svc.set_active_unit.assert_called_once_with(
                    "t001", "alice", "prop1", "unit1"
                )

    def test_put_active_unit_clear(self):
        from app.models import ActiveUnitIn
        body = ActiveUnitIn(unit_id=None)
        updated = {**_make_tenant_item(), "active_unit_id": None, "status": "past"}

        with _flags(tenants=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.get_tenant.return_value = _make_tenant_item(owner_id="alice")
                mock_svc.set_active_unit.return_value = updated
                result = self.router_mod.set_active_unit("t001", body=body, ctx=_ctx())
                self.assertEqual(result.status, "past")

    # ------------------------------------------------------------------ #
    # Lease history
    # ------------------------------------------------------------------ #

    def test_get_leases_lse_available(self):
        lease_item = {
            "lease_id": "lease001",
            "unit_id": "unit001",
            "status": "active",
            "start_date": 1700000000,
            "end_date": None,
            "monthly_rent_cents": 150000,
            "security_deposit_cents": 300000,
            "currency": "usd",
        }
        with _flags(tenants=True, leases=True):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.list_tenant_leases.return_value = {
                    "leases": [lease_item],
                    "count": 1,
                    "next_cursor": None,
                }
                result = self.router_mod.get_tenant_leases("t001", ctx=_ctx())
                self.assertEqual(result.count, 1)
                self.assertEqual(result.leases[0].lease_id, "lease001")

    def test_get_leases_lse_unavailable_empty_list(self):
        with _flags(tenants=True, leases=False):
            with patch.object(self.router_mod, "tenant_svc") as mock_svc:
                mock_svc.list_tenant_leases.return_value = {
                    "leases": [],
                    "count": 0,
                    "next_cursor": None,
                }
                result = self.router_mod.get_tenant_leases("t001", ctx=_ctx())
                self.assertEqual(result.count, 0)
                self.assertEqual(result.leases, [])

    # ------------------------------------------------------------------ #
    # Route order safety
    # ------------------------------------------------------------------ #

    def test_route_order_safety(self):
        """Literal sub-paths must appear before /{tenant_id} in route list."""
        import app.routers.property_tenant as rmod
        paths = [str(r.path) for r in rmod.router.routes]
        # Find positions of sub-resource and bare-id routes
        literal_paths = [
            "/ui/property/tenants/{tenant_id}/profile",
            "/ui/property/tenants/{tenant_id}/income-docs",
            "/ui/property/tenants/{tenant_id}/active-unit",
            "/ui/property/tenants/{tenant_id}/leases",
        ]
        bare_get = "/ui/property/tenants/{tenant_id}"
        bare_get_pos = max(
            (i for i, p in enumerate(paths) if p == bare_get), default=-1
        )
        for lit in literal_paths:
            lit_pos = min(
                (i for i, p in enumerate(paths) if p == lit), default=9999
            )
            self.assertLess(
                lit_pos,
                bare_get_pos,
                f"Literal path {lit!r} must appear before bare /{'{tenant_id}'} in route list",
            )


if __name__ == "__main__":
    unittest.main()
