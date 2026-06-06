"""Offline regression tests for GAP-0268 and GAP-0269 (KYC-009).

GAP-0268 — ``require_kyc_tier(N)`` is now applied as a FastAPI dependency to the
Phase-2 mutating endpoints (messaging send/create, image/file share, message
tip/unlock, billing add-card, newsfeed post tip/unlock, subscription subscribe).
Enforcement is gated behind a NEW flag ``S.kyc_tier_enforcement_enabled`` that
**defaults OFF**, so the gate is a pure pass-through in dev/E2E (existing tier-0
users are never blocked). When both that flag and ``S.kyc_tier_gating_enabled``
are on, an under-tier user receives HTTP 403 ``kyc_tier_insufficient``.

GAP-0269 — ``auto_evaluate_tier(user_sub)`` is now invoked (best-effort,
try/except) at three trigger points: email verification (register_confirm),
phone/SMS MFA confirm (sms_devices_confirm), and KYC case approval
(_admin_decide_case). Previously a user who satisfied tier requirements stayed
at tier 0 until they manually called the evaluate endpoint.

Hermetic / offline: a real in-memory DynamoDB ``users`` table is created with
moto and the exact frozen handle ``T.users`` is monkeypatched via
``object.__setattr__`` (NO global ``@mock_aws`` interception of the production
code path — we only use moto to build the table object). Frozen ``Settings``
flags are flipped the same way and always restored. Async dependencies are run
with a fresh ``asyncio`` event loop via ``asyncio.run`` (never
``get_event_loop``).
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from app.core.settings import S
from app.core.tables import T


def _make_users_table(ddb):
    return ddb.create_table(
        TableName="users_test",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _set_flag(name: str, value: bool):
    """Set a frozen-dataclass Settings flag; returns a restore callable."""
    old = getattr(S, name)
    object.__setattr__(S, name, value)

    def restore():
        object.__setattr__(S, name, old)

    return restore


def _patch_users_table(table):
    """Point the frozen T.users handle at the moto table; returns restore."""
    old = T.users
    object.__setattr__(T, "users", table)

    def restore():
        object.__setattr__(T, "users", old)

    return restore


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestRequireKycTierGap0268(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # moto only used to materialize a table object; we patch the exact handle.
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_users_table(ddb)
        self.stack.callback(_patch_users_table(self.table))

    def _seed_user(self, sub: str, tier: int):
        self.table.put_item(Item={"user_sub": sub, "kyc_tier": tier})

    def _fake_request(self):
        return SimpleNamespace(state=SimpleNamespace(tenant_id="default"))

    def _run_gate(self, minimum_tier: int, sub: str):
        from app.auth.deps import require_kyc_tier, AuthenticatedUser

        check = require_kyc_tier(minimum_tier)

        async def _fake_user(_request):
            return AuthenticatedUser(sub=sub)

        # Patch the auth resolver used inside _check so we exercise tier logic only.
        with patch("app.auth.deps.get_authenticated_user", _fake_user):
            return asyncio.run(check(self._fake_request()))

    def test_flag_off_is_passthrough_even_for_tier0(self):
        """GAP-0268 safety: with enforcement OFF (default), a tier-0 user passes.

        FAILS BEFORE FIX: if the new flag did not exist / defaulted ON, this
        tier-0 user would be blocked, breaking dev/E2E.
        PASSES AFTER FIX: enforcement flag defaults OFF → pure pass-through.
        """
        self._seed_user("u_tier0", 0)
        self.stack.callback(_set_flag("kyc_tier_gating_enabled", True))
        # Enforcement flag left at its DEFAULT (off). Assert default really is off.
        self.assertFalse(
            S.kyc_tier_enforcement_enabled,
            "kyc_tier_enforcement_enabled must DEFAULT to False for dev/E2E safety",
        )
        # No exception => pass-through.
        self._run_gate(1, "u_tier0")
        self._run_gate(2, "u_tier0")

    def test_enforcement_on_blocks_insufficient_tier(self):
        """GAP-0268: enforcement ON + insufficient tier → 403 kyc_tier_insufficient.

        FAILS BEFORE FIX: require_kyc_tier was never wired / no enforcement flag,
        so the call returned without raising.
        """
        from fastapi import HTTPException

        self._seed_user("u_tier0", 0)
        self.stack.callback(_set_flag("kyc_tier_gating_enabled", True))
        self.stack.callback(_set_flag("kyc_tier_enforcement_enabled", True))

        with self.assertRaises(HTTPException) as ctx:
            self._run_gate(1, "u_tier0")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "kyc_tier_insufficient")
        self.assertEqual(ctx.exception.detail["required_tier"], 1)
        self.assertEqual(ctx.exception.detail["current_tier"], 0)

    def test_enforcement_on_allows_sufficient_tier(self):
        """GAP-0268: enforcement ON + sufficient tier → passes (no raise)."""
        self._seed_user("u_tier2", 2)
        self.stack.callback(_set_flag("kyc_tier_gating_enabled", True))
        self.stack.callback(_set_flag("kyc_tier_enforcement_enabled", True))
        # Tier 2 user clears a tier-1 and a tier-2 gate.
        self._run_gate(1, "u_tier2")
        self._run_gate(2, "u_tier2")

    def test_enforcement_on_but_gating_off_is_passthrough(self):
        """Both flags required: enforcement ON but gating OFF stays pass-through.

        With gating off, get_user_kyc_tier returns KYC_TIER_MAX so even the
        explicit-flag path would let everyone through; the combined guard makes
        this an unambiguous no-op.
        """
        self._seed_user("u_tier0", 0)
        self.stack.callback(_set_flag("kyc_tier_gating_enabled", False))
        self.stack.callback(_set_flag("kyc_tier_enforcement_enabled", True))
        self._run_gate(2, "u_tier0")  # no raise


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestAutoEvaluateTierGap0269(unittest.TestCase):
    """Trigger-wiring tests: each of the 3 trigger sites calls auto_evaluate_tier."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_users_table(ddb)
        self.stack.callback(_patch_users_table(self.table))
        # auto_evaluate_tier reads real tier only when gating is enabled.
        self.stack.callback(_set_flag("kyc_tier_gating_enabled", True))

    def test_auto_evaluate_promotes_tier1_on_email_and_phone(self):
        """Sanity: auto_evaluate_tier upgrades a 0->1 user once email+phone met.

        Confirms the function the triggers call actually promotes; tier-1 path
        needs no KYC case, so this stays hermetic (users table only).
        """
        from app.services.kyc_tiers import auto_evaluate_tier

        self.table.put_item(Item={
            "user_sub": "u_ready",
            "kyc_tier": 0,
            "email_verified": True,
            "phone_verified": True,
        })
        # check_tier_requirements consults the KYC case store (separate table);
        # tier-1 needs no case, so stub it to keep this fully hermetic.
        with patch("app.services.kyc_cases.STORE.list_cases_by_owner", lambda **kw: []):
            result = auto_evaluate_tier("u_ready")
        self.assertEqual(result["current_tier"], 1)
        item = self.table.get_item(Key={"user_sub": "u_ready"}).get("Item")
        self.assertEqual(int(item["kyc_tier"]), 1)

    def test_register_confirm_calls_auto_evaluate_tier(self):
        """GAP-0269 trigger 1: register_confirm invokes auto_evaluate_tier.

        We stub the heavy registration internals and assert the hook fires with
        the registering user's sub.
        FAILS BEFORE FIX: no call to auto_evaluate_tier in register_confirm.
        """
        import app.routers.register as reg

        calls: list[str] = []

        def _spy(user_sub, *, request=None):
            calls.append(user_sub)
            return {"current_tier": 1}

        with ExitStack() as es:
            es.enter_context(patch("app.routers.register._cognito_available", lambda: False))
            es.enter_context(patch("app.routers.register.verify_registration_code", lambda **kw: {"mfa_setup": [], "sms_phone": None}))
            es.enter_context(patch("app.routers.register.client_ip_from_request", lambda r: "1.2.3.4"))
            es.enter_context(patch("app.routers.register.enforce_lockout", lambda *a, **k: None))
            es.enter_context(patch("app.routers.register.rate_limit_password_recovery", lambda *a, **k: None))
            es.enter_context(patch("app.routers.register.clear_lockout", lambda *a, **k: None))
            es.enter_context(patch("app.routers.register.mark_user_verified", lambda u: {"user_sub": u}))
            es.enter_context(patch("app.routers.register.audit_event", lambda *a, **k: None))
            es.enter_context(patch("app.routers.register.create_real_session", lambda *a, **k: {"session_id": "s1"}))
            es.enter_context(patch("app.routers.register.rotate_session_cookies", lambda *a, **k: None))
            es.enter_context(patch("app.routers.register.session_id_value", lambda s: "s1"))
            es.enter_context(patch("app.services.kyc_tiers.auto_evaluate_tier", _spy))
            self._invoke_register_confirm(reg)

        self.assertEqual(calls, ["u_reg@x.com"], "register_confirm must call auto_evaluate_tier with the user sub")

    def _invoke_register_confirm(self, reg):
        # Build a minimal request + response object usable by the handler.
        request = SimpleNamespace(
            cookies={},
            state=SimpleNamespace(tenant_id="default"),
            headers={},
        )
        response = SimpleNamespace(set_cookie=lambda *a, **k: None, delete_cookie=lambda *a, **k: None)
        body = self._make_confirm_body()
        # register_confirm is async; first positional arg is `req`.
        asyncio.run(reg.register_confirm(request, body, response))

    def _make_confirm_body(self):
        # Construct a RegisterConfirmReq with the email + code the handler reads.
        from app.models import RegisterConfirmReq
        fields = RegisterConfirmReq.model_fields
        kwargs = {}
        for name, f in fields.items():
            if not f.is_required():
                continue
            if name == "email":
                kwargs[name] = "u_reg@x.com"
            elif "code" in name:
                kwargs[name] = "123456"
            else:
                kwargs[name] = "x"
        return RegisterConfirmReq(**kwargs)

    def test_sms_confirm_calls_auto_evaluate_tier(self):
        """GAP-0269 trigger 2: sms_devices_confirm invokes auto_evaluate_tier."""
        import app.routers.mfa_devices as md

        calls: list[str] = []

        def _spy(user_sub, *, request=None):
            calls.append(user_sub)
            return {"current_tier": 1}

        ctx = {"user_sub": "u_sms", "session_id": "sess1"}
        body = SimpleNamespace(challenge_id="ch1", code="123456")
        request = SimpleNamespace(headers={}, state=SimpleNamespace(tenant_id="default"))

        with ExitStack() as es:
            es.enter_context(patch("app.routers.mfa_devices.require_fresh_mfa", lambda c: None))
            es.enter_context(patch("app.routers.mfa_devices.load_challenge_or_401", lambda u, c: {"purpose": "sms_enroll", "send_to": ["+15551234567"], "sms_device_id": "d1"}))
            es.enter_context(patch("app.routers.mfa_devices.verify_code_any_sms", lambda send_to, code: True))
            es.enter_context(patch("app.routers.mfa_devices.T", SimpleNamespace(sms=_FakeSmsTable())))
            es.enter_context(patch("app.routers.mfa_devices.new_recovery_codes", lambda n: []))
            es.enter_context(patch("app.routers.mfa_devices.store_recovery_codes", lambda *a, **k: None))
            es.enter_context(patch("app.routers.mfa_devices.revoke_challenge", lambda *a, **k: None))
            es.enter_context(patch("app.routers.mfa_devices.stamp_mfa_verified", lambda *a, **k: None))
            es.enter_context(patch("app.routers.mfa_devices.audit_event", lambda *a, **k: None))
            es.enter_context(patch("app.services.kyc_tiers.auto_evaluate_tier", _spy))
            asyncio.run(md.sms_devices_confirm(req=request, body=body, ctx=ctx))

        self.assertEqual(calls, ["u_sms"], "sms_devices_confirm must call auto_evaluate_tier with the user sub")

    def test_admin_decide_approve_calls_auto_evaluate_tier(self):
        """GAP-0269 trigger 3: approving a case invokes auto_evaluate_tier."""
        import app.routers.kyc_cases as kc
        from app.auth.deps import AuthenticatedUser
        from app.auth.roles import Role

        calls: list[str] = []

        def _spy(user_sub, *, request=None):
            calls.append(user_sub)
            return {"current_tier": 2}

        approved_case = {"status": "approved", "user_sub": "u_case", "review": {"risk_tier": "low"}}
        pending_case = {"status": "under_review", "user_sub": "u_case", "review": {}}

        fake_store = SimpleNamespace(
            get_case=lambda cid: pending_case,
            apply_admin_decision=lambda **kw: approved_case,
        )
        body = SimpleNamespace(
            decision="approve",
            reason_codes=["verified"],
            note="all good here",
            expected_version=2,
        )
        request = SimpleNamespace(headers={}, state=SimpleNamespace(tenant_id="default"))
        user = AuthenticatedUser(sub="admin1", role=Role.ROOT)

        with ExitStack() as es:
            es.enter_context(patch("app.routers.kyc_cases.STORE", fake_store))
            es.enter_context(patch("app.routers.kyc_cases.normalize_role", lambda r: Role.ROOT))
            es.enter_context(patch("app.routers.kyc_cases._is_scoped_admin_for_case", lambda u, c: True))
            es.enter_context(patch("app.routers.kyc_cases._ensure_decision_ticket_updates", lambda *a, **k: None))
            es.enter_context(patch("app.routers.kyc_cases._audit_state_transition", lambda *a, **k: None))
            es.enter_context(patch("app.routers.kyc_cases._emit_kyc_metric", lambda *a, **k: None))
            es.enter_context(patch("app.routers.kyc_cases._wrap_case", lambda c: c))
            es.enter_context(patch("app.services.kyc_monitoring.create_review_schedule", lambda **kw: None))
            es.enter_context(patch("app.services.kyc_tiers.auto_evaluate_tier", _spy))
            kc._admin_decide_case(case_id="c1", body=body, request=request, user=user, decision="approve")

        self.assertEqual(calls, ["u_case"], "_admin_decide_case must call auto_evaluate_tier on approve")


class _FakeSmsTable:
    def update_item(self, *a, **k):
        return {}

    def query(self, *a, **k):
        return {"Items": [{"enabled": True}]}


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
