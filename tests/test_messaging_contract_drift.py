import base64
import json

import pytest
from pydantic import ValidationError
from pathlib import Path

from app.routers.messaging import (
    ConsumeAttachmentIn,
    EditMessageIn,
    MarkReadIn,
    MessageOut,
    MuteIn,
    SendTextMessageIn,
    StartConversationIn,
    _decode_gallery_cursor,
    _encode_gallery_cursor,
)


SWAGGER_PATH = Path("docs/swagger.json")
FRONTEND_TYPES_PATH = Path("frontend/src/api/types.ts")
ONCE_SCHEMA_PATH = Path("docs/messaging-once-media-schema-v1.json")


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


def test_gallery_contract_is_present_in_swagger():
    spec = json.loads(SWAGGER_PATH.read_text())
    paths = spec.get("paths", {})
    schemas = spec.get("components", {}).get("schemas", {})

    assert "/messaging/conversations/{conversation_id}/gallery" in paths
    assert "GalleryPageOut" in schemas
    assert "GalleryItemOut" in schemas


def test_gallery_cursor_roundtrip_is_stable():
    cursor = _encode_gallery_cursor("m_123")
    assert _decode_gallery_cursor(cursor) == "m_123"



def test_gallery_contract_parameters_and_response_shape_are_stable():
    spec = json.loads(SWAGGER_PATH.read_text())
    path_item = spec["paths"]["/messaging/conversations/{conversation_id}/gallery"]["get"]

    params = {p["name"]: p for p in path_item.get("parameters", [])}
    assert "type" in params
    assert "cursor" in params
    assert "limit" in params

    type_schema = params["type"]["schema"]
    assert type_schema.get("type") == "string"

    response_schema = path_item["responses"]["200"]["content"]["application/json"]["schema"]
    assert response_schema == {"$ref": "#/components/schemas/GalleryPageOut"}


def test_gallery_contract_frontend_type_alignment():
    spec = json.loads(SWAGGER_PATH.read_text())
    schemas = spec.get("components", {}).get("schemas", {})

    assert "GalleryItemOut" in schemas
    assert "GalleryPageOut" in schemas

    frontend_types = FRONTEND_TYPES_PATH.read_text()
    assert "export type MessageGalleryType" in frontend_types
    assert "export interface ConversationGalleryItem" in frontend_types
    assert "export interface ConversationGalleryResp" in frontend_types

def test_once_media_schema_exists_and_matches_model_enums_and_types():
    assert ONCE_SCHEMA_PATH.exists(), "Once-media schema missing: docs/messaging-once-media-schema-v1.json"
    schema = json.loads(ONCE_SCHEMA_PATH.read_text())

    consumption_policy_enum = set(schema["properties"]["consumption_policy"]["enum"])
    media_kind_enum = set(schema["properties"]["media_kind"]["enum"])
    consumption_state_enum = set(schema["properties"]["consumption_state"]["enum"])

    message_schema = MessageOut.model_json_schema()
    props = message_schema["properties"]

    assert set(props["consumption_policy"]["anyOf"][0]["enum"]) == consumption_policy_enum
    assert set(props["media_kind"]["anyOf"][0]["enum"]) == media_kind_enum
    assert set(props["consumption_state"]["anyOf"][0]["enum"]) == consumption_state_enum

    consumed_at_any = props["consumed_at"]["anyOf"]
    assert any(item.get("type") == "integer" for item in consumed_at_any)
    assert schema["properties"]["consumed_at"]["oneOf"][0]["type"] == "integer"


def test_once_media_consume_request_contract_shape_is_stable():
    req = ConsumeAttachmentIn(
        consumption_attempt_id="attempt-1234",
        trigger="play",
        playback_seconds=1.2,
    )
    payload = req.model_dump(exclude_none=True)
    assert set(payload.keys()) == {"consumption_attempt_id", "trigger", "playback_seconds"}
    assert payload["trigger"] == "play"


def test_once_media_contract_version_stable_in_schema():
    schema = json.loads(ONCE_SCHEMA_PATH.read_text())
    assert schema["properties"]["messaging_contract_version"]["const"] == "2026-02-once-media-v1"


def test_message_out_supports_nullable_thread_linkage_fields():
    message = MessageOut(
        conversation_id="c1",
        message_id="m1",
        sender_id="u1",
        created_at=1,
        kind="text",
        text="hello",
    )
    payload = message.model_dump(exclude_none=True)
    assert "thread_id" not in payload
    assert "thread_root_message_id" not in payload
    assert "parent_message_id" not in payload


def test_swagger_includes_thread_endpoint_and_unread_contract() -> None:
    spec = json.loads(SWAGGER_PATH.read_text())
    paths = spec.get("paths", {})
    schemas = spec.get("components", {}).get("schemas", {})

    assert "/messaging/threads/{thread_id}/messages" in paths
    assert "ThreadMessagesPageOut" in schemas
    thread_page = schemas["ThreadMessagesPageOut"]
    assert "unread_count" in thread_page.get("properties", {})


def test_swagger_send_text_contract_includes_thread_linkage_fields() -> None:
    spec = json.loads(SWAGGER_PATH.read_text())
    schemas = spec.get("components", {}).get("schemas", {})
    send_text = schemas["SendTextMessageIn"]["properties"]

    assert "reply_to_message_id" in send_text
    assert "parent_message_id" in send_text
    assert "thread_id" in send_text
    assert "thread_root_message_id" in send_text


def test_frontend_types_include_thread_contract_fields() -> None:
    frontend_types = FRONTEND_TYPES_PATH.read_text()

    assert "thread_id?: string;" in frontend_types
    assert "thread_root_message_id?: string;" in frontend_types
    assert "thread_reply_count?: number;" in frontend_types
    assert "export interface ThreadMessagesPage" in frontend_types
    assert "unread_count?: number;" in frontend_types
    assert "parent_message_id?: string;" in frontend_types
