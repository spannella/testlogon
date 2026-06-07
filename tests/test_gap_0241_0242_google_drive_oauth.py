"""Offline regression tests for GAP-0241 and GAP-0242 (INTEG-001).

Both gaps live in ``app/routers/google_drive_integration.py``:

GAP-0241 — OAuth state parameter not HMAC-signed. ``initiate_google_drive_connect``
returned a predictable ``state=mock`` literal (mock path) and a bare authorization
URL with no parameters at all (real path), and ``complete_google_drive_connect``
never read or verified ``body.state``. Without a signed, time-limited, per-user state
token the OAuth flow is vulnerable to CSRF (RFC 6749 §10.12). The fix signs the state
in the mock path (HMAC over user_sub + timestamp + nonce) and verifies it in the
callback; the real path delegates to the already-implemented, single-use, DDB-backed
HMAC state in ``app.services.provider_oauth``.

GAP-0242 — real OAuth token exchange not implemented. The non-mock callback path
raised ``HTTPException(501, "Real OAuth not implemented in this environment")``. The
fix delegates to ``complete_google_oauth_callback`` which verifies state, POSTs the
authorization code to ``S.google_oauth_token_url``, and stores access_token, encrypted
refresh_token, and expires_at.

Fully offline:
  * The mock-path state tests are pure HMAC — no AWS, no network.
  * The real-path token-exchange test creates a real in-memory DynamoDB ``projects``
    table with moto and patches the exact ``T.projects`` handle (``T`` is a frozen
    dataclass → ``object.__setattr__``). ``requests.post`` (the Google token endpoint),
    KMS, and the audit sink are patched so nothing touches real AWS or Google.

The async router handlers are invoked directly via ``asyncio.run`` (never
``asyncio.get_event_loop``), each on a fresh event loop.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from fastapi import HTTPException

import app.routers.google_drive_integration as gdrive
from app.core.settings import S


ALICE = "alice-sub-001"
BOB = "bob-sub-002"


def _set_settings(stack: ExitStack, **overrides) -> None:
    """Override frozen Settings fields via object.__setattr__, auto-restored."""
    for key, value in overrides.items():
        original = getattr(S, key)
        object.__setattr__(S, key, value)
        stack.callback(object.__setattr__, S, key, original)


# ─── GAP-0241: mock-path signed state (pure, no AWS) ─────────────────────────────


class TestMockOAuthStateSigningGap0241(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # Deterministic signing secret; no AWS needed for HMAC.
        _set_settings(
            self.stack,
            google_oauth_state_signing_secret="unit-test-secret",
            google_oauth_state_ttl_seconds=600,
            dev_mode=True,
            google_drive_mock_enabled=True,
        )

    def test_connect_returns_signed_state_not_literal_mock(self):
        """GAP-0241: /connect mock path must embed a signed state, not ``state=mock``.

        FAILS BEFORE FIX: auth_url contained the literal ``&state=mock``.
        PASSES AFTER FIX: auth_url carries an opaque HMAC-signed token that verifies.
        """
        ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
        out = asyncio.run(gdrive.initiate_google_drive_connect(ctx=ctx))

        self.assertTrue(out["mock"])
        self.assertNotIn("state=mock&", out["auth_url"] + "&")
        self.assertNotIn("&state=mock", out["auth_url"])
        # Extract the state param and confirm it verifies for Alice.
        state = out["auth_url"].split("&state=", 1)[1]
        self.assertNotEqual(state, "mock")
        gdrive._verify_mock_oauth_state(state, ALICE)  # must not raise

    def test_callback_rejects_missing_state(self):
        """FAILS BEFORE FIX: callback ignored state and stored a credential (200)."""
        ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
        body = gdrive.DriveCallbackReq(code="auth-code", state=None)
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(gdrive.complete_google_drive_connect(body=body, ctx=ctx))
        self.assertEqual(cm.exception.status_code, 400)

    def test_callback_rejects_literal_mock_state(self):
        """The old predictable ``state=mock`` literal must no longer be accepted."""
        ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
        body = gdrive.DriveCallbackReq(code="auth-code", state="mock")
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(gdrive.complete_google_drive_connect(body=body, ctx=ctx))
        self.assertEqual(cm.exception.status_code, 400)

    def test_callback_rejects_wrong_user_state(self):
        """State signed for Bob must not be accepted by Alice's session (CSRF)."""
        bob_state = gdrive._sign_mock_oauth_state(BOB)
        ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
        body = gdrive.DriveCallbackReq(code="auth-code", state=bob_state)
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(gdrive.complete_google_drive_connect(body=body, ctx=ctx))
        self.assertEqual(cm.exception.status_code, 400)

    def test_callback_rejects_tampered_state(self):
        state = gdrive._sign_mock_oauth_state(ALICE)
        tampered = state[:-2] + ("aa" if not state.endswith("aa") else "bb")
        ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
        body = gdrive.DriveCallbackReq(code="auth-code", state=tampered)
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(gdrive.complete_google_drive_connect(body=body, ctx=ctx))
        self.assertEqual(cm.exception.status_code, 400)

    def test_callback_rejects_expired_state(self):
        """Stale state (older than TTL) must be rejected."""
        with ExitStack() as st:
            _set_settings(st, google_oauth_state_ttl_seconds=1)
            state = gdrive._sign_mock_oauth_state(ALICE)
            import time as _t

            with patch.object(gdrive.time, "time", return_value=_t.time() + 5):
                ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
                body = gdrive.DriveCallbackReq(code="auth-code", state=state)
                with self.assertRaises(HTTPException) as cm:
                    asyncio.run(
                        gdrive.complete_google_drive_connect(body=body, ctx=ctx)
                    )
                self.assertEqual(cm.exception.status_code, 400)

    def test_callback_accepts_valid_signed_state(self):
        """Happy path: a freshly signed state for Alice is accepted (200)."""
        with ExitStack() as st:
            # Credential storage in the mock path writes to T.projects; back it
            # with moto so the upsert succeeds hermetically.
            if mock_aws is None:
                self.skipTest("moto is not installed")
            st.enter_context(mock_aws())
            table = _make_projects_table(boto3.resource("dynamodb", region_name="us-east-1"))
            _patch_projects_handle(st, table)
            st.enter_context(
                patch("app.services.provider_credentials.kms_encrypt", lambda p: "ct::" + p)
            )

            state = gdrive._sign_mock_oauth_state(ALICE)
            ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
            body = gdrive.DriveCallbackReq(code="auth-code", state=state)
            out = asyncio.run(gdrive.complete_google_drive_connect(body=body, ctx=ctx))
            self.assertEqual(out, {"ok": True, "connected": True})


# ─── GAP-0242: real token exchange (moto-backed, no real AWS/Google) ─────────────


def _make_projects_table(ddb):
    """Create the ``projects`` table mirroring scripts/local-ddb-init.py (PK/SK + GSIs)."""
    return ddb.create_table(
        TableName="projects",
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _patch_projects_handle(stack: ExitStack, table) -> None:
    """Point the exact T.projects handle at the moto table (T is frozen)."""
    from app.core.tables import T

    original = T.projects
    object.__setattr__(T, "projects", table)
    stack.callback(object.__setattr__, T, "projects", original)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestRealTokenExchangeGap0242(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        self.table = _make_projects_table(
            boto3.resource("dynamodb", region_name="us-east-1")
        )
        _patch_projects_handle(self.stack, self.table)

        _set_settings(
            self.stack,
            dev_mode=False,
            google_drive_mock_enabled=False,
            google_oauth_state_signing_secret="unit-test-secret",
            google_oauth_state_ttl_seconds=600,
            google_oauth_client_id="client-id",
            google_oauth_client_secret="client-secret",
            google_oauth_redirect_uri="https://app.example.com/files",
            google_oauth_redirect_uri_allowlist="https://app.example.com/files",
            google_oauth_scopes="https://www.googleapis.com/auth/drive.file",
            google_oauth_token_url="https://oauth2.googleapis.com/token",
        )
        # KMS + audit sink → hermetic no-ops.
        self.stack.enter_context(
            patch("app.core.crypto.kms_encrypt", lambda p: "ct::" + p)
        )
        self.stack.enter_context(
            patch("app.services.provider_credentials.kms_encrypt", lambda p: "ct::" + p)
        )
        self.stack.enter_context(
            patch("app.services.provider_oauth.audit_event", lambda *a, **k: None)
        )

    def _mint_real_state(self) -> str:
        """Use the production service to mint a signed, DDB-backed state token.

        The state is consumed via a patched ``consume_google_oauth_state`` (see the
        individual tests) — mirroring ``tests/test_provider_oauth.py`` — so the test
        focuses on the *router*'s GAP-0241/0242 behaviour (verify-then-exchange) rather
        than re-testing the already-covered single-use state-store conditional.
        """
        start = gdrive.build_google_oauth_start(ALICE)
        return start["state"]

    def test_connect_real_path_builds_full_auth_url(self):
        """GAP-0241 real path: /connect returns a full Google auth URL with state.

        FAILS BEFORE FIX: returned the bare ``https://accounts.google.com/o/oauth2/v2/auth``
        with no query string at all.
        """
        ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
        out = asyncio.run(gdrive.initiate_google_drive_connect(ctx=ctx))
        self.assertFalse(out["mock"])
        url = out["auth_url"]
        self.assertIn("client_id=client-id", url)
        self.assertIn("redirect_uri=", url)
        self.assertIn("state=", url)
        self.assertIn("response_type=code", url)

    def test_real_callback_exchanges_code_and_stores_tokens(self):
        """GAP-0242: non-mock callback exchanges the code and stores the credential.

        FAILS BEFORE FIX: raised HTTPException(501, "Real OAuth not implemented...").
        PASSES AFTER FIX: 200 + credential row written with access + refresh tokens.
        """
        state = self._mint_real_state()

        class _FakeResp:
            status_code = 200
            content = b"{}"

            @staticmethod
            def json():
                return {
                    "access_token": "ya29.access",
                    "refresh_token": "1//refresh",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": "https://www.googleapis.com/auth/drive.file",
                }

        ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
        body = gdrive.DriveCallbackReq(
            code="real-auth-code",
            redirect_uri="https://app.example.com/files",
            state=state,
        )
        with patch(
            "app.services.provider_oauth.consume_google_oauth_state",
            return_value={"provider": "google_drive", "owner": ALICE},
        ) as consume_spy, patch(
            "app.services.provider_oauth.requests.post", return_value=_FakeResp()
        ) as post_spy:
            out = asyncio.run(
                gdrive.complete_google_drive_connect(body=body, ctx=ctx)
            )
        # GAP-0241: the router-driven flow verified the state before exchanging.
        consume_spy.assert_called_once_with(ALICE, state)

        self.assertEqual(out, {"ok": True, "connected": True})
        post_spy.assert_called_once()
        # Token endpoint POST used the authorization_code grant.
        _, kwargs = post_spy.call_args
        self.assertEqual(kwargs["data"]["grant_type"], "authorization_code")
        self.assertEqual(kwargs["data"]["code"], "real-auth-code")

        # Credential persisted (access token encrypted; refresh token stored).
        from app.services.provider_credentials import get_provider_credential

        cred = get_provider_credential(ALICE, "google_drive", allow_missing=True)
        self.assertIsNotNone(cred)
        self.assertEqual(cred.token_ct_b64, "ct::ya29.access")
        self.assertEqual(cred.metadata.get("refresh_token_ct_b64"), "ct::1//refresh")
        self.assertIsNotNone(cred.metadata.get("expires_at"))

    def test_real_callback_no_longer_returns_501(self):
        """Sanity guard: the 501 stub is gone for the real path."""
        state = self._mint_real_state()

        class _FakeResp:
            status_code = 200
            content = b"{}"

            @staticmethod
            def json():
                return {"access_token": "at", "expires_in": 3600, "scope": ""}

        ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
        body = gdrive.DriveCallbackReq(code="c", state=state)
        with patch(
            "app.services.provider_oauth.consume_google_oauth_state",
            return_value={"provider": "google_drive", "owner": ALICE},
        ), patch("app.services.provider_oauth.requests.post", return_value=_FakeResp()):
            try:
                asyncio.run(
                    gdrive.complete_google_drive_connect(body=body, ctx=ctx)
                )
            except HTTPException as exc:  # pragma: no cover - guards regression
                self.assertNotEqual(exc.status_code, 501, "501 stub must be removed")

    def test_real_callback_rejects_missing_state(self):
        """GAP-0241: real path also requires state before any exchange."""
        ctx = {"user_sub": ALICE, "role": "USER", "admin_profile": None}
        body = gdrive.DriveCallbackReq(code="c", state=None)
        with patch("app.services.provider_oauth.requests.post") as post_spy:
            with self.assertRaises(HTTPException) as cm:
                asyncio.run(
                    gdrive.complete_google_drive_connect(body=body, ctx=ctx)
                )
        self.assertEqual(cm.exception.status_code, 400)
        post_spy.assert_not_called()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
