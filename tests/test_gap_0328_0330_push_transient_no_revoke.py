"""Offline regression tests for GAP-0328 and GAP-0330 (PLATFORM-010 / PLATFORM-016).

Both gaps are the SAME bug in ``app/services/push.py``:

``web_push_send()`` used to return a bare ``bool`` (``False``) for EVERY failure
mode — non-2xx HTTP, 410 Gone, 404 Not Found, timeouts, and any other
exception. Its single caller (``send_push_for_alert``) then ran the auto-revoke
block on ANY falsey result, so TRANSIENT failures (timeouts, 500s, network
blips) permanently DELETED legitimate push subscriptions.

The fix makes ``web_push_send`` return a ``(success, reason)`` tuple and only
revokes when ``reason == "permanent"`` (HTTP 410 / 404). Transient failures keep
the subscription intact and are merely logged.

Fully offline: the ``pywebpush.webpush`` transport is stubbed to simulate each
outcome, and ``revoke_push_device`` is patched to a spy. No real network/AWS.
``S.dev_mode`` is forced ``False`` so the revoke path is reachable, and VAPID
keys are injected so ``web_push_send`` reaches the transport. DDB access in the
caller is replaced by patching ``T.push_devices.query``.
"""
from __future__ import annotations

import json
import sys
import types
import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from app.core.settings import S
import app.services.push as push


def _valid_subscription_json() -> str:
    return json.dumps({
        "endpoint": "https://example.push/endpoint/abc",
        "keys": {"p256dh": "p256dhAAA", "auth": "authBBB"},
    })


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def _install_fake_pywebpush(stack: ExitStack, *, status: int = None, raise_exc: Exception = None):
    """Install a fake ``pywebpush`` module so ``from pywebpush import ...`` works.

    Either returns a response with ``status`` or raises ``raise_exc``.
    """
    fake = types.ModuleType("pywebpush")

    class WebPushException(Exception):
        pass

    def webpush(**kwargs):
        if raise_exc is not None:
            raise raise_exc
        return _FakeResponse(status if status is not None else 201)

    fake.webpush = webpush
    fake.WebPushException = WebPushException
    stack.enter_context(patch.dict(sys.modules, {"pywebpush": fake}))
    return WebPushException


class WebPushSendReturnShapeTest(unittest.TestCase):
    """GAP-0330: web_push_send returns a typed (success, reason) tuple."""

    def setUp(self) -> None:
        self._stack = ExitStack()
        # Force prod-mode + VAPID configured so the real send path is reached.
        for attr, val in (
            ("dev_mode", False),
            ("vapid_private_key", "fake-priv"),
            ("vapid_public_key", "fake-pub"),
            ("vapid_subject", "mailto:test@test.local"),
        ):
            orig = getattr(S, attr)
            object.__setattr__(S, attr, val)
            self._stack.callback(object.__setattr__, S, attr, orig)
        self.addCleanup(self._stack.close)

    def test_success_201_returns_true_none(self):
        with ExitStack() as st:
            _install_fake_pywebpush(st, status=201)
            self.assertEqual(
                push.web_push_send(_valid_subscription_json(), "t", "b"),
                (True, None),
            )

    def test_status_410_is_permanent(self):
        with ExitStack() as st:
            _install_fake_pywebpush(st, status=410)
            self.assertEqual(
                push.web_push_send(_valid_subscription_json(), "t", "b"),
                (False, "permanent"),
            )

    def test_status_404_is_permanent(self):
        with ExitStack() as st:
            _install_fake_pywebpush(st, status=404)
            self.assertEqual(
                push.web_push_send(_valid_subscription_json(), "t", "b"),
                (False, "permanent"),
            )

    def test_status_500_is_transient(self):
        with ExitStack() as st:
            _install_fake_pywebpush(st, status=500)
            self.assertEqual(
                push.web_push_send(_valid_subscription_json(), "t", "b"),
                (False, "transient"),
            )

    def test_exception_410_is_permanent(self):
        with ExitStack() as st:
            WebPushException = _install_fake_pywebpush(
                st, raise_exc=Exception("Push failed: 410 Gone")
            )
            self.assertEqual(
                push.web_push_send(_valid_subscription_json(), "t", "b"),
                (False, "permanent"),
            )

    def test_exception_404_is_permanent(self):
        with ExitStack() as st:
            _install_fake_pywebpush(st, raise_exc=Exception("404 Not Found"))
            self.assertEqual(
                push.web_push_send(_valid_subscription_json(), "t", "b"),
                (False, "permanent"),
            )

    def test_timeout_exception_is_transient(self):
        with ExitStack() as st:
            _install_fake_pywebpush(st, raise_exc=TimeoutError("connection timed out"))
            self.assertEqual(
                push.web_push_send(_valid_subscription_json(), "t", "b"),
                (False, "transient"),
            )

    def test_other_exception_is_transient(self):
        with ExitStack() as st:
            _install_fake_pywebpush(st, raise_exc=ConnectionError("network blip"))
            self.assertEqual(
                push.web_push_send(_valid_subscription_json(), "t", "b"),
                (False, "transient"),
            )


class SendPushForAlertRevokeTest(unittest.TestCase):
    """GAP-0328: only revoke on PERMANENT failures, never on transient ones."""

    USER = "user-sub-1"
    DEVICE = "device-1"

    def setUp(self) -> None:
        self._stack = ExitStack()
        for attr, val in (
            ("dev_mode", False),
            ("push_enabled", True),
            ("web_push_enabled", True),
            ("vapid_private_key", "fake-priv"),
            ("vapid_public_key", "fake-pub"),
        ):
            orig = getattr(S, attr)
            object.__setattr__(S, attr, val)
            self._stack.callback(object.__setattr__, S, attr, orig)
        self.addCleanup(self._stack.close)

        # Alert prefs: enable the alert type so dispatch proceeds.
        self._stack.enter_context(patch(
            "app.services.alerts.get_alert_prefs",
            return_value={"push_event_types": ["new_message"]},
        ))
        self._stack.enter_context(patch.object(
            push, "can_send_alert_channel", return_value=True
        ))

        # Stub the push_devices query to return one web device. ``T`` is a
        # frozen dataclass, so patch the ``query`` method on the existing
        # push_devices table handle rather than swapping the attribute.
        token = _valid_subscription_json()
        fake_query = MagicMock(return_value={"Items": [{
            "token": token,
            "device_id": self.DEVICE,
            "platform": "web",
        }]})
        # ``_FloatSafeTable`` (``__slots__ = ("_t",)``) delegates ``query`` to
        # the wrapped boto3 table via ``__getattr__``. Patch ``query`` on that
        # underlying object so the delegation returns our stub.
        self._stack.enter_context(patch.object(
            push.T.push_devices._t, "query", fake_query
        ))

        # Spy on revoke.
        self.revoke_spy = MagicMock()
        self._stack.enter_context(patch.object(
            push, "revoke_push_device", self.revoke_spy
        ))

    def _dispatch(self):
        push.send_push_for_alert(
            self.USER, "new_message", "Title", "Body", "alert-1"
        )

    def test_revoke_called_on_410_permanent(self):
        with patch.object(push, "web_push_send", return_value=(False, "permanent")):
            self._dispatch()
        self.revoke_spy.assert_called_once_with(self.USER, self.DEVICE)

    def test_revoke_called_on_404_permanent(self):
        # 404 also classifies as "permanent" inside web_push_send.
        with patch.object(push, "web_push_send", return_value=(False, "permanent")):
            self._dispatch()
        self.revoke_spy.assert_called_once_with(self.USER, self.DEVICE)

    def test_revoke_NOT_called_on_transient_500(self):
        with patch.object(push, "web_push_send", return_value=(False, "transient")):
            self._dispatch()
        self.revoke_spy.assert_not_called()

    def test_revoke_NOT_called_on_transient_timeout(self):
        with patch.object(push, "web_push_send", return_value=(False, "transient")):
            self._dispatch()
        self.revoke_spy.assert_not_called()

    def test_revoke_NOT_called_on_success(self):
        with patch.object(push, "web_push_send", return_value=(True, None)):
            self._dispatch()
        self.revoke_spy.assert_not_called()

    def test_revoke_NOT_called_on_config_or_invalid(self):
        for reason in ("config", "invalid"):
            self.revoke_spy.reset_mock()
            with patch.object(push, "web_push_send", return_value=(False, reason)):
                self._dispatch()
            self.revoke_spy.assert_not_called()

    def test_end_to_end_transient_via_real_web_push_send(self):
        """Wire the real web_push_send (transport stubbed to a 500) through the
        caller: subscription must survive (no revoke)."""
        with ExitStack() as st:
            _install_fake_pywebpush(st, status=500)
            self._dispatch()
        self.revoke_spy.assert_not_called()

    def test_end_to_end_permanent_via_real_web_push_send(self):
        """Real web_push_send (transport stubbed to a 410) through the caller:
        subscription must be revoked."""
        with ExitStack() as st:
            _install_fake_pywebpush(st, status=410)
            self._dispatch()
        self.revoke_spy.assert_called_once_with(self.USER, self.DEVICE)


if __name__ == "__main__":
    unittest.main()
