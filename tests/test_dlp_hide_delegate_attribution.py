"""DLP-008 — delegate attribution privacy regression test.

When a creator enables `hide_delegate_from_recipients`, a delegate-sent message
must NOT bake the "[via @…]" tag into the shared message text (which the
recipient and the conversation sidebar preview both read), while the structured
delegate fields are still persisted for the creator/delegate views + audit.

Hermetic: no AWS / no moto. The delegate_chat collaborators (permission check,
participant check, profile, creator settings, the three DDB tables, audit) are
monkeypatched on the module, and we inspect the item handed to put_item.
"""
from __future__ import annotations

import types

import app.services.delegate_chat as dc


class _FakeTable:
    def __init__(self):
        self.put_item_calls = []
        self.update_item_calls = []

    def put_item(self, Item):  # noqa: N803 (boto3 kwarg name)
        self.put_item_calls.append(Item)

    def update_item(self, **kwargs):
        self.update_item_calls.append(kwargs)

    def query(self, **kwargs):
        return {"Items": []}


def _send(monkeypatch, *, hide: bool):
    msgs = _FakeTable()
    convos = _FakeTable()
    parts = _FakeTable()

    monkeypatch.setattr(
        dc,
        "require_delegate_permission",
        lambda **_: {
            "show_delegate_tag": True,
            "delegate_tag_format": "[via @{delegate_name}]",
        },
    )
    monkeypatch.setattr(dc, "_require_creator_participant", lambda *a, **k: None)
    monkeypatch.setattr(dc, "get_profile", lambda _id: {"display_name": "Bob"})
    monkeypatch.setattr(
        dc, "get_creator_settings", lambda _id: {"hide_delegate_from_recipients": hide}
    )
    monkeypatch.setattr(dc, "_write_audit", lambda *a, **k: None)
    monkeypatch.setattr(dc, "tbl_msgs", msgs)
    monkeypatch.setattr(dc, "tbl_convos", convos)
    monkeypatch.setattr(dc, "tbl_parts", parts)

    out = dc.send_message_as_creator(
        creator_id="alice",
        delegate_id="bob",
        conversation_id="c1",
        text="Hello there",
    )
    stored = msgs.put_item_calls[0]
    preview = convos.update_item_calls[0]["ExpressionAttributeValues"][":p"]
    return out, stored, preview


def test_tag_visible_when_not_hidden(monkeypatch):
    out, stored, preview = _send(monkeypatch, hide=False)
    # Default behaviour: the "via" tag is baked into the shared text + preview.
    assert "[via @Bob]" in stored["text"]
    assert "[via @Bob]" in preview
    # Structured attribution is present.
    assert stored["sent_by_delegate"] == "bob"
    assert stored["delegate_display_name"] == "Bob"


def test_tag_hidden_from_recipients_when_enabled(monkeypatch):
    out, stored, preview = _send(monkeypatch, hide=True)
    # Recipient-facing text + sidebar preview must NOT carry the attribution.
    assert "via" not in stored["text"]
    assert stored["text"] == "Hello there"
    assert "via" not in preview
    # …but the structured fields are still persisted for the creator/delegate
    # views and the audit trail.
    assert stored["sent_by_delegate"] == "bob"
    assert stored["delegate_display_name"] == "Bob"
