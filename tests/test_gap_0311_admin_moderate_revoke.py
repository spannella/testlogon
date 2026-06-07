"""Offline regression test for GAP-0311 (MSG-001).

Platform admin/root could not delete a message in a conversation they are not a
participant of: `revoke_message_for_all` calls `require_participant_active` +
`_ensure_can_revoke_message` (sender-only + 5-minute window, no platform bypass).

The fix adds a dedicated moderation endpoint
`POST /messaging/conversations/{cid}/messages/{mid}/moderate-revoke` guarded by the
content_moderation admin scope (`require_legal_hold_admin`). It revokes the message
for all participants WITHOUT the participant / sender / time-window restrictions,
reusing the shared `_apply_message_revocation` helper and emitting an admin audit
event.

Fully offline: the handler is invoked directly with a fake authenticated actor and
the DDB / fan-out / archive side effects patched out. Asserts:
  1. The endpoint exists and is registered.
  2. An admin who is NOT a participant and whose message is OLD (past the 5-min
     window) still revokes successfully (the bug-before path would 403 / 400).
  3. The participant `revoke_message_for_all` endpoint still enforces its guards
     (unchanged).
  4. Already-revoked message -> 400.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

import app.routers.messaging as m


CONV = "c_foreign"
MID = "m_" + "b" * 32
ADMIN_SUB = "u_charlie_admin"
SENDER = "u_alice"
OLD_TS = 1_000_000  # far older than MESSAGE_REVOKE_WINDOW_SEC


def _msg(revoked=False):
    item = {
        "conversation_id": CONV,
        "message_id": MID,
        "sender_id": SENDER,
        "created_at": OLD_TS,
        "kind": "text",
        "text": "harmful content",
    }
    if revoked:
        item["revoked_at"] = OLD_TS + 1
    return item


class ModerateRevokeTest(unittest.TestCase):
    def setUp(self):
        self._stack = ExitStack()
        self.fanout = self._stack.enter_context(patch.object(m, "fanout_event_to_conversation", MagicMock()))
        self.audit = self._stack.enter_context(patch.object(m, "audit_event", MagicMock()))
        self._stack.enter_context(patch.object(m, "_emit_message_lifecycle_archive_event_or_503", MagicMock()))
        self._stack.enter_context(patch.object(m, "_serialize_message_event_payload", lambda item, viewer: {}))
        self._stack.enter_context(patch.object(m, "remove_message_search", MagicMock()))
        self._stack.enter_context(patch.object(m, "_sync_gallery_index_message", MagicMock()))
        self._stack.enter_context(
            patch.object(m, "_message_out_from_item", lambda item, viewer: {"message_id": item["message_id"], "revoked_at": item.get("revoked_at")})
        )
        # tbl_msgs / tbl_convos are MagicMocks; convo.get_item returns empty Item.
        self.tbl_msgs = self._stack.enter_context(patch.object(m, "tbl_msgs", MagicMock()))
        self.tbl_convos = self._stack.enter_context(patch.object(m, "tbl_convos", MagicMock()))
        self.tbl_convos.get_item.return_value = {"Item": {}}

    def tearDown(self):
        self._stack.close()

    def test_endpoint_registered(self):
        paths = [r.path for r in m.router.routes if "moderate-revoke" in r.path]
        self.assertEqual(
            paths,
            ["/messaging/conversations/{conversation_id}/messages/{message_id}/moderate-revoke"],
        )

    def test_admin_can_revoke_foreign_old_message(self):
        actor = SimpleNamespace(sub=ADMIN_SUB)
        # _get_message_or_404 first returns the live msg, then the post-update item.
        seq = [_msg(), _msg()]
        with patch.object(m, "_get_message_or_404", side_effect=lambda c, mid: seq.pop(0)):
            res = m.moderate_revoke_message(CONV, MID, req=None, actor=actor)
        self.assertEqual(res["message_id"], MID)
        # The update set revoked_at + moderated_by; verify the mutation ran.
        self.assertTrue(self.tbl_msgs.update_item.called)
        kwargs = self.tbl_msgs.update_item.call_args.kwargs
        self.assertIn("moderated_by", kwargs["UpdateExpression"])
        self.assertEqual(kwargs["ExpressionAttributeValues"][":moderated_by"], ADMIN_SUB)
        # Audit event uses the admin action name.
        self.assertEqual(self.audit.call_args.args[0], "messaging_message_admin_revoked")

    def test_admin_revoke_already_revoked_returns_400(self):
        actor = SimpleNamespace(sub=ADMIN_SUB)
        with patch.object(m, "_get_message_or_404", side_effect=lambda c, mid: _msg(revoked=True)):
            with self.assertRaises(HTTPException) as ctx:
                m.moderate_revoke_message(CONV, MID, req=None, actor=actor)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_participant_revoke_still_enforces_window(self):
        """The participant endpoint is unchanged: an old foreign message is rejected
        by _ensure_can_revoke_message (window expired) even after the fix."""
        with patch.object(m, "require_participant_active", lambda *a, **k: {"status": "active"}):
            with patch.object(m, "_get_message_or_404", side_effect=lambda c, mid: _msg()):
                with patch.object(m, "now_ts", lambda: OLD_TS + m.MESSAGE_REVOKE_WINDOW_SEC + 1000):
                    with self.assertRaises(HTTPException) as ctx:
                        m.revoke_message_for_all(CONV, MID, req=None, user_id=SENDER)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("window", ctx.exception.detail.lower())


if __name__ == "__main__":
    unittest.main()
