"""Offline regression test for GAP-0312 (MSG-002).

`presign_voice_message` issued a deterministic s3_key but did not persist the
mapping, and `create_voice_message` wrote `body.s3_key` verbatim to `audio_url`
with no cross-check — a client could substitute a foreign/arbitrary s3_key.

The fix binds (message_id -> s3_key, conversation_id, user_id, expiry) in the
existing TTL-enabled MessageEdits table at presign time
(`_store_voice_presign_binding`) and verifies the submitted key at create time
(`_verify_voice_presign_binding`), plus a defense-in-depth path-prefix check.

Fully offline: a tiny in-memory fake replaces `messaging.tbl_edits` (no AWS / moto
global interception). Tests cover the store->verify roundtrip and every rejection
branch, and that `create_voice_message` actually invokes the verifier (rejecting a
mismatched key with 400 before writing anything).
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

import app.routers.messaging as m


CONV = "c_voice"
MID = "m_" + "c" * 32
USER = "u_alice"
GOOD_KEY = f"voice-messages/{CONV}/{MID}.webm"
FIXED_NOW = 2_000_000_000


class _FakeEditsTable:
    """Minimal DDB Table stand-in: composite key (message_key, edited_at)."""

    def __init__(self):
        self.store: dict[tuple, dict] = {}

    def put_item(self, Item):
        self.store[(Item["message_key"], Item["edited_at"])] = dict(Item)

    def get_item(self, Key):
        item = self.store.get((Key["message_key"], Key["edited_at"]))
        return {"Item": dict(item)} if item is not None else {}


class VoicePresignBindingTest(unittest.TestCase):
    def setUp(self):
        self._stack = ExitStack()
        self.tbl = _FakeEditsTable()
        self._stack.enter_context(patch.object(m, "tbl_edits", self.tbl))
        self._stack.enter_context(patch.object(m, "now_ts", lambda: FIXED_NOW))

    def tearDown(self):
        self._stack.close()

    def _store(self):
        m._store_voice_presign_binding(MID, GOOD_KEY, CONV, USER)

    def test_roundtrip_matching_key_passes(self):
        self._store()
        # Should not raise.
        m._verify_voice_presign_binding(MID, GOOD_KEY, CONV, USER)

    def test_missing_binding_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            m._verify_voice_presign_binding(MID, GOOD_KEY, CONV, USER)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "voice_presign_not_found")

    def test_key_mismatch_rejected(self):
        self._store()
        foreign = f"voice-messages/{CONV}/m_" + "d" * 32 + ".webm"
        with self.assertRaises(HTTPException) as ctx:
            m._verify_voice_presign_binding(MID, foreign, CONV, USER)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "voice_presign_key_mismatch")

    def test_owner_mismatch_rejected(self):
        self._store()
        with self.assertRaises(HTTPException) as ctx:
            m._verify_voice_presign_binding(MID, GOOD_KEY, CONV, "u_mallory")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail, "voice_presign_owner_mismatch")

    def test_conversation_mismatch_rejected(self):
        # Key prefix is for CONV, but we verify against a different conversation:
        # the prefix guard fires first (defense in depth) -> invalid_key.
        self._store()
        with self.assertRaises(HTTPException) as ctx:
            m._verify_voice_presign_binding(MID, GOOD_KEY, "c_other", USER)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "voice_presign_invalid_key")

    def test_path_traversal_rejected(self):
        self._store()
        with self.assertRaises(HTTPException) as ctx:
            m._verify_voice_presign_binding(MID, "../../../secrets/x.webm", CONV, USER)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "voice_presign_invalid_key")

    def test_expired_binding_rejected(self):
        self._store()
        # Advance time past expiry.
        with patch.object(m, "now_ts", lambda: FIXED_NOW + m.VOICE_PRESIGN_TTL_SEC + 10):
            with self.assertRaises(HTTPException) as ctx:
                m._verify_voice_presign_binding(MID, GOOD_KEY, CONV, USER)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "voice_presign_expired")

    def test_create_voice_message_rejects_unbound_key(self):
        """End-to-end: create_voice_message verifies the binding. With no stored
        binding, a submitted key is rejected with 400 (the bug-before path wrote
        it to audio_url and returned a message)."""
        # Stub everything up to (and not past) the verify call.
        with ExitStack() as st:
            # S.voice_message_enabled is True by default; no need to patch frozen S.
            st.enter_context(patch.object(m, "require_participant_active", lambda *a, **k: {"status": "active"}))
            st.enter_context(patch.object(m, "_get_conversation_or_404", lambda c: {"conversation_id": c}))
            st.enter_context(patch.object(m, "_enforce_helpdesk_send_constraints", MagicMock()))
            st.enter_context(patch.object(m, "require_subscription_access", MagicMock()))
            st.enter_context(patch.object(m, "_enforce_message_send_quota_precheck", MagicMock()))
            st.enter_context(patch.object(m, "_validate_reply_target", MagicMock()))
            fake_parts = MagicMock()
            fake_parts.query.return_value = {"Items": []}
            st.enter_context(patch.object(m, "tbl_parts", fake_parts))

            body = m.CreateVoiceMessageRequest(
                message_id=MID,
                s3_key=GOOD_KEY,
                content_type="audio/webm",
                size_bytes=1024,
                duration_seconds=1.0,
                waveform_data=[0.5] * 10,
            )
            with self.assertRaises(HTTPException) as ctx:
                m.create_voice_message(CONV, body, req=None, user_id=USER)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "voice_presign_not_found")


if __name__ == "__main__":
    unittest.main()
