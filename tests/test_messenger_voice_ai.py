"""Offline regression tests for Messenger Voice & Translation AI (MVA-001..009).

Hermetic / offline (TEST ISOLATION):
* NO real AWS / network / SDK. In-memory fake DynamoDB tables (a dict-backed
  ``_FakeTable``) are bound to the frozen ``T.message_ai_cache`` /
  ``T.llm_provider_keys`` handles and to the messaging router's module-level
  ``tbl_msgs`` / ``tbl_parts`` / ``tbl_convos`` via ``object.__setattr__`` /
  ``setattr`` and restored on cleanup.
* The ElevenLabs / Anthropic SDKs are never imported — all three
  ``messaging_ai`` callers run through their ``S.dev_mode`` mock branch.
* The S3 client is a tiny in-memory fake.
* Heavy messaging collaborators (lifecycle/receipts/send/audit) are patched to
  no-ops so we exercise only the AI behavior under test.
* The frozen ``Settings`` singleton ``S`` is mutated via ``object.__setattr__``.

Covers:
  - ElevenLabs registry entry + key add (default voice) + dev test_key.
  - Translation endpoint: success, cache hit (no second provider call),
    non-text 400, disabled 404.
  - Transcribe endpoint: success+persist, idempotent stored transcript,
    non-voice 400, disabled 404.
  - TTS endpoint: success creates a voice_message item with the right S3 key +
    audio_content_type, over-length 400, disabled 404.
  - Cost recording happens on cache-miss; cache-hit records nothing.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.services import llm_provider_keys as keys_svc
import app.routers.messaging as msg


# ── in-memory fakes ──────────────────────────────────────────────────


class _FakeTable:
    """Minimal dict-backed DynamoDB Table supporting the ops we use."""

    def __init__(self, key_names):
        self.key_names = key_names  # tuple of attribute names forming the key
        self.items = {}

    def _key_of(self, d):
        return tuple(d[k] for k in self.key_names)

    def put_item(self, Item=None, **kw):
        self.items[self._key_of(Item)] = dict(Item)
        return {}

    def get_item(self, Key=None, **kw):
        it = self.items.get(self._key_of(Key))
        return {"Item": dict(it)} if it else {}

    def update_item(self, Key=None, UpdateExpression="", ExpressionAttributeNames=None,
                    ExpressionAttributeValues=None, ConditionExpression=None,
                    ReturnValues=None, **kw):
        names = ExpressionAttributeNames or {}
        vals = ExpressionAttributeValues or {}
        k = self._key_of(Key)
        existing = self.items.get(k)
        if ConditionExpression and "attribute_not_exists(transcript)" in ConditionExpression:
            if existing and existing.get("transcript"):
                raise RuntimeError("ConditionalCheckFailed")
        item = dict(existing) if existing else dict(Key)
        # Handle ADD <name> :v
        expr = UpdateExpression
        if expr.strip().upper().startswith("ADD"):
            # e.g. "ADD #c :one SET #ttl = :ttl"
            add_part = expr[3:]
            set_idx = add_part.upper().find("SET ")
            if set_idx >= 0:
                add_seg = add_part[:set_idx]
                set_seg = add_part[set_idx + 4:]
            else:
                add_seg, set_seg = add_part, ""
            for pair in add_seg.split(","):
                toks = pair.split()
                if len(toks) >= 2:
                    fld = names.get(toks[0], toks[0])
                    item[fld] = int(item.get(fld, 0)) + int(vals[toks[1]])
            for assign in [s for s in set_seg.split(",") if "=" in s]:
                lhs, rhs = assign.split("=")
                fld = names.get(lhs.strip(), lhs.strip())
                item[fld] = vals[rhs.strip()]
        elif expr.strip().upper().startswith("SET"):
            for assign in expr[3:].split(","):
                if "=" not in assign:
                    continue
                lhs, rhs = assign.split("=")
                fld = names.get(lhs.strip(), lhs.strip())
                item[fld] = vals[rhs.strip()]
        self.items[k] = item
        return {"Attributes": dict(item)}

    def query(self, **kw):
        # Only used for participant lookup in TTS — return everything.
        return {"Items": [dict(v) for v in self.items.values()]}


class _FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket=None, Key=None, Body=None, ContentType=None, **kw):
        self.objects[(Bucket, Key)] = (Body, ContentType)
        return {}

    def get_object(self, Bucket=None, Key=None, **kw):
        body, _ = self.objects[(Bucket, Key)]

        class _B:
            def __init__(self, b):
                self._b = b

            def read(self):
                return self._b

        return {"Body": _B(body)}


# ── test case ────────────────────────────────────────────────────────


class MessengerVoiceAiTests(unittest.TestCase):
    USER = "u_alice"
    CONV = "c_1"

    def setUp(self):
        self._stack = ExitStack()
        self.addCleanup(self._stack.close)

        # Frozen S: dev_mode on, AI flags on for what we test.
        for attr, val in {
            "dev_mode": True,
            "messaging_translation_enabled": True,
            "messaging_transcription_enabled": True,
            "messaging_tts_enabled": True,
            "voice_message_enabled": True,
        }.items():
            orig = getattr(S, attr)
            object.__setattr__(S, attr, val)
            self.addCleanup(object.__setattr__, S, attr, orig)

        # Fake tables.
        self.keys_tbl = _FakeTable(("pk", "sk"))
        self.cache_tbl = _FakeTable(("cache_key",))
        self.msgs_tbl = _FakeTable(("conversation_id", "message_id"))
        self.parts_tbl = _FakeTable(("conversation_id", "user_id"))
        self.convos_tbl = _FakeTable(("conversation_id",))
        self.s3 = _FakeS3()

        # Bind frozen T handles.
        for name, tbl in (("llm_provider_keys", self.keys_tbl), ("message_ai_cache", self.cache_tbl)):
            orig = getattr(T, name)
            object.__setattr__(T, name, tbl)
            self.addCleanup(object.__setattr__, T, name, orig)

        # Patch module-level messaging collaborators.
        self._stack.enter_context(patch.object(msg, "tbl_msgs", self.msgs_tbl))
        self._stack.enter_context(patch.object(msg, "tbl_parts", self.parts_tbl))
        self._stack.enter_context(patch.object(msg, "tbl_convos", self.convos_tbl))
        self._stack.enter_context(patch.object(msg, "s3", self.s3))
        self._stack.enter_context(patch.object(msg, "require_participant_active",
                                               lambda uid, cid: {"status": "active"}))
        self._stack.enter_context(patch.object(msg, "_validate_reply_target", lambda *a, **k: None))
        self._stack.enter_context(patch.object(msg, "_message_retention_ttl", lambda *a, **k: 0))
        self._stack.enter_context(patch.object(msg, "_build_reply_linkage_fields", lambda **k: {}))
        self._stack.enter_context(patch.object(msg, "_send_single_destination_message", lambda **k: None))
        self._stack.enter_context(patch.object(msg, "_apply_message_receipts", lambda m, *a, **k: m))
        self._stack.enter_context(patch.object(msg, "audit_event", lambda *a, **k: None))
        self._stack.enter_context(patch.object(msg, "_emit_message_lifecycle_archive_event_or_503", lambda **k: None))
        self._stack.enter_context(patch.object(msg, "_meter_message_send", lambda **k: None))
        self._stack.enter_context(patch.object(msg, "_serialize_message_event_payload", lambda *a, **k: {}))

        # KMS stubs so add_key / decrypt never touch real KMS.
        self._stack.enter_context(patch.object(keys_svc, "kms_encrypt", lambda s: b"enc:" + s.encode()))
        self._stack.enter_context(patch.object(keys_svc, "kms_decrypt", lambda b: b[4:]))

        # Seed conversation row.
        self.convos_tbl.put_item(Item={"conversation_id": self.CONV})

    # ── MVA-001 ──

    def test_registry_has_elevenlabs(self):
        reg = keys_svc.PROVIDER_REGISTRY["elevenlabs"]
        self.assertEqual(reg["display_name"], "ElevenLabs")
        self.assertEqual(reg["auth_header"], "xi-api-key")
        self.assertTrue(reg.get("default_voice_id"))
        self.assertEqual(reg["test_endpoint"], "/voices")

    def test_add_elevenlabs_key_defaults_voice_and_test_key_mock(self):
        out = keys_svc.add_key(
            user_id=self.USER, provider="elevenlabs", label="el", api_key="sk-elevenlabs-1234"
        )
        self.assertEqual(out["provider"], "elevenlabs")
        self.assertEqual(out["voice_preference"], keys_svc.PROVIDER_REGISTRY["elevenlabs"]["default_voice_id"])
        self.assertNotIn("encrypted_api_key", out)
        res = keys_svc.test_key(self.USER, out["key_id"])
        self.assertTrue(res["ok"])
        self.assertEqual(res["models"], keys_svc.PROVIDER_REGISTRY["elevenlabs"]["models"])

    # helpers

    def _add_key(self, provider, **kw):
        return keys_svc.add_key(user_id=self.USER, provider=provider, label=provider,
                                api_key="sk-" + provider + "-12345678", **kw)

    def _put_text_msg(self, mid="m_1", text="hello world", **extra):
        item = {"conversation_id": self.CONV, "message_id": mid, "sender_id": self.USER,
                "kind": "text", "text": text}
        item.update(extra)
        self.msgs_tbl.put_item(Item=item)
        return mid

    def _put_voice_msg(self, mid="v_1"):
        key = f"voice-messages/{self.CONV}/{mid}.webm"
        self.s3.put_object(Bucket=msg.S3_BUCKET_IMAGES, Key=key, Body=b"audiobytes", ContentType="audio/webm")
        self.msgs_tbl.put_item(Item={
            "conversation_id": self.CONV, "message_id": mid, "sender_id": self.USER,
            "kind": "voice_message", "audio_url": key, "audio_content_type": "audio/webm",
        })
        return mid

    # ── MVA-004 translation ──

    def test_translate_success_then_cache_hit_no_double_cost(self):
        self._add_key("anthropic")
        mid = self._put_text_msg(text="hola amigo")
        calls = []
        real = msg.__dict__  # noqa
        with patch("app.services.messaging_ai.translate_text",
                   side_effect=lambda **k: (calls.append(1), ("[fr] hola amigo", "es"))[1]):
            out1 = msg.translate_message(self.CONV, mid, msg.TranslateMessageRequest(target_lang="fr"), user_id=self.USER)
            self.assertFalse(out1.cached)
            self.assertEqual(out1.translated_text, "[fr] hola amigo")
            out2 = msg.translate_message(self.CONV, mid, msg.TranslateMessageRequest(target_lang="fr"), user_id=self.USER)
            self.assertTrue(out2.cached)
            self.assertEqual(out2.translated_text, "[fr] hola amigo")
        self.assertEqual(len(calls), 1, "provider must be called once (cache hit on 2nd)")

    def test_translate_dev_mock_records_cost_on_miss_only(self):
        out = self._add_key("anthropic")
        kid = out["key_id"]
        mid = self._put_text_msg(text="cost me")
        msg.translate_message(self.CONV, mid, msg.TranslateMessageRequest(target_lang="de"), user_id=self.USER)
        after_miss = int(self.keys_tbl.get_item(Key={"pk": f"USER#{self.USER}", "sk": f"KEY#{kid}"})["Item"]["current_month_usage_cents"])
        self.assertGreater(after_miss, 0)
        # cache hit -> no additional cost
        msg.translate_message(self.CONV, mid, msg.TranslateMessageRequest(target_lang="de"), user_id=self.USER)
        after_hit = int(self.keys_tbl.get_item(Key={"pk": f"USER#{self.USER}", "sk": f"KEY#{kid}"})["Item"]["current_month_usage_cents"])
        self.assertEqual(after_miss, after_hit)

    def test_translate_non_text_400(self):
        self.msgs_tbl.put_item(Item={"conversation_id": self.CONV, "message_id": "img1",
                                     "kind": "image", "sender_id": self.USER})
        with self.assertRaises(HTTPException) as cm:
            msg.translate_message(self.CONV, "img1", msg.TranslateMessageRequest(target_lang="fr"), user_id=self.USER)
        self.assertEqual(cm.exception.status_code, 400)

    def test_translate_disabled_404(self):
        object.__setattr__(S, "messaging_translation_enabled", False)
        mid = self._put_text_msg()
        with self.assertRaises(HTTPException) as cm:
            msg.translate_message(self.CONV, mid, msg.TranslateMessageRequest(target_lang="fr"), user_id=self.USER)
        self.assertEqual(cm.exception.status_code, 404)

    # ── MVA-007 transcription ──

    def test_transcribe_success_persists_and_idempotent(self):
        self._add_key("elevenlabs")
        mid = self._put_voice_msg()
        out1 = msg.transcribe_message(self.CONV, mid, user_id=self.USER)
        self.assertFalse(out1.cached)
        self.assertTrue(out1.transcript)
        stored = self.msgs_tbl.get_item(Key={"conversation_id": self.CONV, "message_id": mid})["Item"]
        self.assertEqual(stored["transcript"], out1.transcript)
        out2 = msg.transcribe_message(self.CONV, mid, user_id=self.USER)
        self.assertTrue(out2.cached)
        self.assertEqual(out2.transcript, out1.transcript)

    def test_transcribe_non_voice_400(self):
        self._add_key("elevenlabs")
        mid = self._put_text_msg()
        with self.assertRaises(HTTPException) as cm:
            msg.transcribe_message(self.CONV, mid, user_id=self.USER)
        self.assertEqual(cm.exception.status_code, 400)

    def test_transcribe_disabled_404(self):
        object.__setattr__(S, "messaging_transcription_enabled", False)
        mid = self._put_voice_msg()
        with self.assertRaises(HTTPException) as cm:
            msg.transcribe_message(self.CONV, mid, user_id=self.USER)
        self.assertEqual(cm.exception.status_code, 404)

    # ── MVA-009 TTS ──

    def test_tts_creates_voice_message_item(self):
        self._add_key("elevenlabs")
        out = msg.create_tts_voice_message(
            self.CONV, msg.TtsVoiceMessageRequest(text="speak this please"), req=None, user_id=self.USER
        )
        self.assertEqual(out.kind, "voice_message")
        self.assertTrue(out.voice_message["audio_url"])
        self.assertEqual(out.voice_message["audio_content_type"], "audio/mpeg")
        self.assertTrue(out.voice_message.get("is_tts"))
        # message item persisted with the expected S3 key scheme
        item = self.msgs_tbl.get_item(Key={"conversation_id": self.CONV, "message_id": out.message_id})["Item"]
        self.assertEqual(item["audio_url"], f"voice-messages/{self.CONV}/{out.message_id}.mp3")
        self.assertEqual(item["audio_content_type"], "audio/mpeg")
        self.assertIn((msg.S3_BUCKET_IMAGES, item["audio_url"]), self.s3.objects)

    def test_tts_over_length_400(self):
        self._add_key("elevenlabs")
        object.__setattr__(S, "messaging_tts_max_chars", 5)
        try:
            with self.assertRaises(HTTPException) as cm:
                msg.create_tts_voice_message(
                    self.CONV, msg.TtsVoiceMessageRequest(text="way too long text"), req=None, user_id=self.USER
                )
            self.assertEqual(cm.exception.status_code, 400)
        finally:
            object.__setattr__(S, "messaging_tts_max_chars", 5000)

    def test_tts_disabled_404(self):
        object.__setattr__(S, "messaging_tts_enabled", False)
        self._add_key("elevenlabs")
        with self.assertRaises(HTTPException) as cm:
            msg.create_tts_voice_message(
                self.CONV, msg.TtsVoiceMessageRequest(text="hello"), req=None, user_id=self.USER
            )
        self.assertEqual(cm.exception.status_code, 404)

    def test_tts_no_key_502(self):
        # No elevenlabs key configured -> messaging_ai raises -> 502
        with self.assertRaises(HTTPException) as cm:
            msg.create_tts_voice_message(
                self.CONV, msg.TtsVoiceMessageRequest(text="hello"), req=None, user_id=self.USER
            )
        self.assertEqual(cm.exception.status_code, 502)


if __name__ == "__main__":
    unittest.main()
