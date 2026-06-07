"""Offline regression test for GAP-0310 (MSG-001).

`edit_message` (app/routers/messaging.py) enforced kind/revoked/sender/encrypted
guards but NO time-window check — a sender could edit a message arbitrarily long
after it was sent. The fix adds a guard:

    if S.message_edit_window_seconds > 0 and now_ts() - created_at > window:
        raise HTTPException(400, "Edit window has expired")

with the new `S.message_edit_window_seconds` setting (0 = unlimited escape hatch).

Fully offline: the handler is called directly with the message lookup + side-effect
collaborators patched out. No FastAPI TestClient, no AWS.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

from fastapi import HTTPException

import app.routers.messaging as m
from app.core.settings import S


@contextmanager
def _set_window(seconds: int):
    """S is a frozen dataclass — mutate via object.__setattr__ and restore."""
    prev = S.message_edit_window_seconds
    object.__setattr__(S, "message_edit_window_seconds", seconds)
    try:
        yield
    finally:
        object.__setattr__(S, "message_edit_window_seconds", prev)


FIXED_NOW = 1_700_000_000
CONV = "c_test"
MID = "m_" + "a" * 32
SENDER = "u_alice"


def _msg(created_at: int) -> dict:
    return {
        "conversation_id": CONV,
        "message_id": MID,
        "sender_id": SENDER,
        "created_at": created_at,
        "kind": "text",
        "text": "original",
    }


class EditWindowTest(unittest.TestCase):
    def setUp(self):
        self._stack = ExitStack()
        # No-op the participant gate and the edit/update side effects.
        self._stack.enter_context(patch.object(m, "require_participant_active", lambda *a, **k: {"status": "active"}))
        self._stack.enter_context(patch.object(m, "now_ts", lambda: FIXED_NOW))
        self.tbl_edits = self._stack.enter_context(patch.object(m, "tbl_edits"))
        self.tbl_msgs = self._stack.enter_context(patch.object(m, "tbl_msgs"))
        # _message_out_from_item is only reached on the success path; stub it.
        self._stack.enter_context(
            patch.object(m, "_message_out_from_item", lambda item, viewer: {"ok": True, "message_id": item["message_id"]})
        )
        # The success path also touches search/gallery/fanout/archive — stub broadly.
        for name in (
            "remove_message_search",
            "index_message_search",
            "_sync_gallery_index_message",
            "_serialize_message_event_payload",
            "fanout_event_to_conversation",
            "audit_event",
            "_emit_message_lifecycle_archive_event_or_503",
        ):
            if hasattr(m, name):
                self._stack.enter_context(patch.object(m, name, lambda *a, **k: None))

    def tearDown(self):
        self._stack.close()

    def _call(self, msg, new_text="edited"):
        with patch.object(m, "_get_message_or_404", lambda c, mid: msg):
            inp = m.EditMessageIn(text=new_text)
            return m.edit_message(CONV, MID, inp, req=None, user_id=SENDER)

    def test_edit_within_window_succeeds(self):
        with _set_window(300):
            # sent 10s ago
            res = self._call(_msg(FIXED_NOW - 10))
        self.assertEqual(res["message_id"], MID)

    def test_edit_outside_window_returns_400(self):
        with _set_window(300):
            # sent 400s ago -> outside the 300s window
            with self.assertRaises(HTTPException) as ctx:
                self._call(_msg(FIXED_NOW - 400))
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Edit window", ctx.exception.detail)

    def test_window_zero_allows_any_age(self):
        with _set_window(0):
            res = self._call(_msg(FIXED_NOW - 999_999))
        self.assertEqual(res["message_id"], MID)


if __name__ == "__main__":
    unittest.main()
