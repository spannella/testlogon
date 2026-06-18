from __future__ import annotations

import pytest

from app.services import signature_packet_store as store


def test_create_draft_packet_persists_origin_metadata(monkeypatch) -> None:
    captured = {}

    class _PacketsTable:
        def put_item(self, **kwargs):
            captured.update(kwargs)

    class _Tables:
        signature_packets = _PacketsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    item = store.create_draft_packet(
        owner_user_id="user-1",
        source_path="/nda.pdf",
        source_content_type="application/pdf",
        source_name="nda.pdf",
        origin_channel="message",
        origin_ref="conversation-1",
    )

    assert item["status"] == "draft"
    assert item["origin_channel"] == "message"
    assert item["origin_ref"] == "conversation-1"
    assert item["source_content_type"] == "application/pdf"
    assert captured["Item"]["packet_id"] == item["packet_id"]


def test_signer_assignment_exists_uses_packet_and_signer_keys(monkeypatch) -> None:
    captured = {}

    class _SignersTable:
        def get_item(self, **kwargs):
            captured.update(kwargs)
            return {"Item": {"packet_id": "sp_1", "signer_id": "user-2"}}

    class _Tables:
        signature_packet_signers = _SignersTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    assert store.signer_assignment_exists("sp_1", "user-2") is True
    assert captured["Key"] == {"packet_id": "sp_1", "signer_id": "user-2"}


def test_delete_packet_field_deletes_by_composite_key(monkeypatch) -> None:
    captured = {}

    class _FieldsTable:
        def delete_item(self, **kwargs):
            captured.update(kwargs)

    class _Tables:
        signature_packet_fields = _FieldsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)
    monkeypatch.setattr(store, "get_packet", lambda _packet_id: {"packet_id": "sp_1", "status": "draft"})

    store.delete_packet_field(packet_id="sp_1", field_id="sf_1")

    assert captured["Key"] == {"packet_id": "sp_1", "field_id": "sf_1"}


def test_delete_packet_field_rejects_after_send(monkeypatch) -> None:
    class _FieldsTable:
        def delete_item(self, **kwargs):
            raise AssertionError("should not delete when sent")

    class _Tables:
        signature_packet_fields = _FieldsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)
    monkeypatch.setattr(store, "get_packet", lambda _packet_id: {"packet_id": "sp_1", "status": "sent"})

    with pytest.raises(ValueError, match="packet_not_draft"):
        store.delete_packet_field(packet_id="sp_1", field_id="sf_1")


def test_mark_packet_sent_updates_status_with_draft_condition(monkeypatch) -> None:
    captured = {}

    class _PacketsTable:
        def update_item(self, **kwargs):
            captured.update(kwargs)
            return {"Attributes": {"packet_id": "sp_1", "status": "sent", "sent_at": "2026-01-01T00:00:00+00:00"}}

    class _Tables:
        signature_packets = _PacketsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)
    monkeypatch.setattr(store, "get_packet", lambda _packet_id: {"packet_id": "sp_1", "status": "sent"})

    out = store.mark_packet_sent("sp_1")

    assert out["status"] == "sent"
    assert captured["Key"] == {"packet_id": "sp_1"}
    assert captured["ExpressionAttributeValues"][":sent"] == "sent"
    assert captured["ExpressionAttributeValues"][":draft"] == "draft"


def test_append_packet_event_writes_event_row(monkeypatch) -> None:
    captured = {}

    class _EventsTable:
        def put_item(self, **kwargs):
            captured.update(kwargs)

    class _Tables:
        signature_packet_events = _EventsTable()

    seen = {}

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)
    monkeypatch.setattr(store, "record_signature_packet_event", lambda **kwargs: seen.update(kwargs))

    item = store.append_packet_event(packet_id="sp_1", actor_user_id="user-1", event_type="packet_sent", event_payload={"x": 1})

    assert item["packet_id"] == "sp_1"
    assert captured["Item"]["event_type"] == "packet_sent"
    assert "created_at" in captured["Item"]
    assert seen["event_type"] == "packet_sent"


def test_get_packet_signer_returns_item_for_participant(monkeypatch) -> None:
    class _SignersTable:
        def get_item(self, **_kwargs):
            return {"Item": {"packet_id": "sp_1", "signer_id": "user-2", "status": "pending"}}

    class _Tables:
        signature_packet_signers = _SignersTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    signer = store.get_packet_signer("sp_1", "user-2")
    assert signer and signer["signer_id"] == "user-2"


def test_get_packet_field_returns_field_item(monkeypatch) -> None:
    class _FieldsTable:
        def get_item(self, **_kwargs):
            return {"Item": {"packet_id": "sp_1", "field_id": "sf_1", "field_type": "signature"}}

    class _Tables:
        signature_packet_fields = _FieldsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    field = store.get_packet_field("sp_1", "sf_1")
    assert field and field["field_id"] == "sf_1"


def test_fill_packet_field_updates_value_and_timestamp(monkeypatch) -> None:
    captured = {}

    class _FieldsTable:
        def get_item(self, **kwargs):
            return {"Item": None}

        def update_item(self, **kwargs):
            captured.update(kwargs)
            return {
                "Attributes": {
                    "packet_id": "sp_1",
                    "field_id": "sf_1",
                    "value": "Jane Doe",
                    "filled_by_signer_id": "user-2",
                    "filled_at": "2026-01-01T00:00:00+00:00",
                }
            }

    class _Tables:
        signature_packet_fields = _FieldsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)
    monkeypatch.setattr(store, "get_packet", lambda _packet_id: {"packet_id": "sp_1", "status": "sent"})

    out = store.fill_packet_field(packet_id="sp_1", field_id="sf_1", value="Jane Doe", filled_by_signer_id="user-2")
    assert out["value"] == "Jane Doe"
    assert captured["Key"] == {"packet_id": "sp_1", "field_id": "sf_1"}


def test_mark_signer_completed_updates_status_conditionally(monkeypatch) -> None:
    captured = {}

    class _SignersTable:
        def update_item(self, **kwargs):
            captured.update(kwargs)
            return {"Attributes": {"packet_id": "sp_1", "signer_id": "user-2", "status": "completed"}}

    class _Tables:
        signature_packet_signers = _SignersTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)
    monkeypatch.setattr(store, "get_packet", lambda _packet_id: {"packet_id": "sp_1", "status": "sent"})

    out = store.mark_signer_completed("sp_1", "user-2", source_ip="203.0.113.7")
    assert out["status"] == "completed"
    assert captured["ExpressionAttributeValues"][":pending"] == "pending"
    assert captured["ExpressionAttributeValues"][":completed"] == "completed"
    assert captured["ExpressionAttributeValues"][":completed_ip"] == "203.0.113.7"


def test_mark_packet_partially_signed_conditions_on_sent(monkeypatch) -> None:
    captured = {}

    class _PacketsTable:
        def update_item(self, **kwargs):
            captured.update(kwargs)
            return {"Attributes": {"packet_id": "sp_1", "status": "partially_signed"}}

    class _Tables:
        signature_packets = _PacketsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)
    monkeypatch.setattr(store, "get_packet", lambda _packet_id: {"packet_id": "sp_1", "status": "sent"})

    out = store.mark_packet_partially_signed("sp_1")
    assert out and out["status"] == "partially_signed"
    assert captured["ExpressionAttributeValues"][":sent"] == "sent"


def test_are_required_signers_completed_checks_only_required_signers(monkeypatch) -> None:
    monkeypatch.setattr(
        store,
        "list_packet_signers",
        lambda _packet_id: [
            {"signer_id": "u1", "status": "completed", "required": True},
            {"signer_id": "u2", "status": "pending", "required": False},
        ],
    )
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    assert store.are_required_signers_completed("sp_1") is True


def test_mark_packet_completed_conditions_on_fillable_status(monkeypatch) -> None:
    captured = {}

    class _PacketsTable:
        def update_item(self, **kwargs):
            captured.update(kwargs)
            return {"Attributes": {"packet_id": "sp_1", "status": "completed", "completed_at": "2026-01-01T00:00:00+00:00"}}

    class _Tables:
        signature_packets = _PacketsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    out = store.mark_packet_completed("sp_1")
    assert out and out["status"] == "completed"
    assert captured["Key"] == {"packet_id": "sp_1"}
    assert captured["ExpressionAttributeValues"][":completed"] == "completed"



def test_get_packet_artifact_reads_artifact_row(monkeypatch) -> None:
    class _ArtifactsTable:
        def get_item(self, **_kwargs):
            return {"Item": {"packet_id": "sp_1", "status": "ready"}}

    class _Tables:
        signature_packet_artifacts = _ArtifactsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    item = store.get_packet_artifact("sp_1")
    assert item and item["status"] == "ready"


def test_put_packet_artifact_writes_row(monkeypatch) -> None:
    captured = {}

    class _ArtifactsTable:
        def put_item(self, **kwargs):
            captured.update(kwargs)

    class _Tables:
        signature_packet_artifacts = _ArtifactsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    out = store.put_packet_artifact("sp_1", {"status": "ready"})
    assert out["status"] == "ready"
    assert captured["Item"]["packet_id"] == "sp_1"


def test_list_completed_packets_scans_by_completed_status(monkeypatch) -> None:
    captured = {}

    class _PacketsTable:
        def scan(self, **kwargs):
            captured.update(kwargs)
            return {"Items": [{"packet_id": "sp_1", "status": "completed"}]}

    class _Tables:
        signature_packets = _PacketsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    out = store.list_completed_packets(limit=5)
    assert out[0]["packet_id"] == "sp_1"
    assert captured["Limit"] == 5


def test_upsert_packet_field_rejects_completed_packet(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_packet", lambda _packet_id: {"packet_id": "sp_1", "status": "completed"})
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    try:
        store.upsert_packet_field(
            packet_id="sp_1",
            field_id="sf_1",
            page=1,
            x=0.1,
            y=0.1,
            width=0.2,
            height=0.1,
            field_type=store.SignatureFieldType.TEXT,
            assigned_signer_id=None,
            required=True,
        )
        assert False, "expected ValueError"
    except ValueError as exc:
        assert str(exc) == "packet_immutable"


def test_fill_packet_field_rejects_completed_packet(monkeypatch) -> None:
    monkeypatch.setattr(store, "get_packet", lambda _packet_id: {"packet_id": "sp_1", "status": "completed"})
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    try:
        store.fill_packet_field(packet_id="sp_1", field_id="sf_1", value="x", filled_by_signer_id="u1")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert str(exc) == "packet_immutable"


def test_mark_completion_notices_sent_sets_marker_once(monkeypatch) -> None:
    captured = {}

    class _ArtifactsTable:
        def update_item(self, **kwargs):
            captured.update(kwargs)
            return {}

    class _Tables:
        signature_packet_artifacts = _ArtifactsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    out = store.mark_completion_notices_sent("sp_1", recipient_user_ids=["owner-1", "user-2", "user-2"])

    assert out is True
    assert captured["Key"] == {"packet_id": "sp_1"}
    assert captured["ExpressionAttributeValues"][":recipient_user_ids"] == ["owner-1", "user-2"]


def test_mark_completion_notices_sent_idempotent_when_already_set(monkeypatch) -> None:
    class _ArtifactsTable:
        def update_item(self, **_kwargs):
            raise store.ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "already set"}},
                "UpdateItem",
            )

    class _Tables:
        signature_packet_artifacts = _ArtifactsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    out = store.mark_completion_notices_sent("sp_1", recipient_user_ids=["owner-1", "user-2"])
    assert out is False


def test_list_packet_events_returns_chronological_order(monkeypatch) -> None:
    class _EventsTable:
        def query(self, **kwargs):
            return {
                "Items": [
                    {"event_id": "ev_b", "created_at": "2026-01-02T00:00:00+00:00"},
                    {"event_id": "ev_a", "created_at": "2026-01-01T00:00:00+00:00"},
                ]
            }

    class _Tables:
        signature_packet_events = _EventsTable()

    monkeypatch.setattr(store, "T", _Tables())
    monkeypatch.setattr(store, "require_signature_pdf_enabled", lambda: None)

    out = store.list_packet_events("sp_1")

    assert [e["event_id"] for e in out] == ["ev_a", "ev_b"]
