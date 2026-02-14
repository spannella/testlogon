import json
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
