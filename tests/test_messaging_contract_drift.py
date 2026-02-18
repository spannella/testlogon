import base64
import json

import pytest
from pydantic import ValidationError
from pathlib import Path

from app.routers.messaging import (
    EditMessageIn,
    MarkReadIn,
    MuteIn,
    SendTextMessageIn,
    StartConversationIn,
)


SWAGGER_PATH = Path("docs/swagger.json")


def test_canonical_contract_source_exists_and_contains_messaging_models():
    assert SWAGGER_PATH.exists(), "Canonical OpenAPI source missing: docs/swagger.json"
    spec = json.loads(SWAGGER_PATH.read_text())
    schemas = spec.get("components", {}).get("schemas", {})

    assert "StartConversationIn" in schemas
    assert "SendTextMessageIn" in schemas
    assert "MarkReadIn" in schemas
    assert "MuteIn" in schemas
    assert "EditMessageIn" in schemas


def test_legacy_start_conversation_payload_is_accepted_for_compatibility_window():
    model = StartConversationIn(participant_id="user-2")
    assert model.participant_ids == ["user-2"]


def test_legacy_send_text_payload_is_accepted_for_compatibility_window():
    model = SendTextMessageIn(body="hello")
    assert model.text == "hello"


def test_legacy_mark_read_payload_is_accepted_for_compatibility_window():
    model = MarkReadIn(last_read_message_id="m1")
    assert model.last_read_message_id == "m1"
    assert model.last_read_at is None


def test_legacy_mute_payload_is_accepted_for_compatibility_window():
    model = MuteIn(muted=True)
    assert model.muted is True
    assert model.muted_until is None


def test_legacy_edit_payload_is_accepted_for_compatibility_window():
    model = EditMessageIn(body="edited")
    assert model.text == "edited"


def test_canonical_start_conversation_shape_is_valid():
    model = StartConversationIn(participant_ids=["user-2"], type="dm")
    assert model.participant_ids == ["user-2"]


def test_canonical_send_text_shape_is_valid():
    model = SendTextMessageIn(text="hello")
    assert model.text == "hello"


def test_canonical_mark_read_shape_is_valid():
    model = MarkReadIn(last_read_at=123456)
    assert model.last_read_at == 123456


def test_canonical_mute_shape_is_valid():
    model = MuteIn(muted_until=0)
    assert model.muted_until == 0


def test_canonical_edit_shape_is_valid():
    model = EditMessageIn(text="edited")
    assert model.text == "edited"


def test_encrypted_send_text_shape_is_valid():
    model = SendTextMessageIn(
        encryption={
            "version": 1,
            "alg": "AES-256-GCM",
            "kdf": "PBKDF2-SHA256",
            "iterations": 600000,
            "salt_b64": base64.b64encode(b"1234567890abcdef").decode(),
            "iv_b64": base64.b64encode(b"123456789012").decode(),
            "ciphertext_b64": base64.b64encode(b"payload-bytes-123456").decode(),
        }
    )
    assert model.encryption is not None
    assert model.text is None


def test_encrypted_send_text_rejects_bad_salt_with_deterministic_code():
    with pytest.raises(ValidationError) as exc:
        SendTextMessageIn(
            encryption={
                "version": 1,
                "alg": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256",
                "iterations": 600000,
                "salt_b64": "%%%%",
                "iv_b64": base64.b64encode(b"123456789012").decode(),
                "ciphertext_b64": base64.b64encode(b"payload-bytes-123456").decode(),
            }
        )
    errors = exc.value.errors()
    assert errors[0]["type"] == "enc_salt_invalid"


def test_encrypted_send_text_rejects_plaintext_and_encryption_mix():
    with pytest.raises(ValidationError) as exc:
        SendTextMessageIn(
            text="hello",
            encryption={
                "version": 1,
                "alg": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256",
                "iterations": 600000,
                "salt_b64": base64.b64encode(b"1234567890abcdef").decode(),
                "iv_b64": base64.b64encode(b"123456789012").decode(),
                "ciphertext_b64": base64.b64encode(b"payload-bytes-123456").decode(),
            },
        )
    errors = exc.value.errors()
    assert errors[0]["type"] == "message_text_encryption_conflict"


def test_encrypted_send_text_rejects_oversized_ciphertext_with_stable_code():
    oversized_ciphertext = base64.b64encode(b"x" * 8193).decode()
    with pytest.raises(ValidationError) as exc:
        SendTextMessageIn(
            encryption={
                "version": 1,
                "alg": "AES-256-GCM",
                "kdf": "PBKDF2-SHA256",
                "iterations": 600000,
                "salt_b64": base64.b64encode(b"1234567890abcdef").decode(),
                "iv_b64": base64.b64encode(b"123456789012").decode(),
                "ciphertext_b64": oversized_ciphertext,
            }
        )
    errors = exc.value.errors()
    assert errors[0]["type"] == "enc_ciphertext_too_large"


def test_send_text_rejects_empty_payload_without_text_or_encryption():
    with pytest.raises(ValidationError) as exc:
        SendTextMessageIn()
    errors = exc.value.errors()
    assert errors[0]["type"] == "message_text_required"
