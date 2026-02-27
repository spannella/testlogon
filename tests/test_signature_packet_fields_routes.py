from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes


def _draft_packet(owner: str = "user-1"):
    return {"packet_id": "sp_1", "owner_user_id": owner, "status": "draft"}


def test_field_create_succeeds_for_owner_draft() -> None:
    with (
        patch.object(routes, "get_packet", return_value=_draft_packet()),
        patch.object(routes, "signer_assignment_exists", return_value=True),
        patch.object(routes, "upsert_packet_field", return_value={"field_id": "sf_1", "field_type": "signature"}) as upsert_mock,
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.mutate_signature_packet_field(
            "sp_1",
            routes.SignaturePacketFieldMutationIn(
                action="create",
                page=1,
                x=0.1,
                y=0.1,
                width=0.2,
                height=0.1,
                field_type="signature",
                assigned_signer_id="user-2",
                required=True,
            ),
            user_sub="user-1",
        )
    assert out["action"] == "create"
    assert out["field"]["field_type"] == "signature"
    upsert_mock.assert_called_once()
    event_mock.assert_called_once()
    assert event_mock.call_args.kwargs["event_type"] == "field_created"


def test_field_mutation_rejects_non_draft() -> None:
    with patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "owner_user_id": "user-1", "status": "sent"}):
        with pytest.raises(HTTPException) as exc:
            routes.mutate_signature_packet_field(
                "sp_1",
                routes.SignaturePacketFieldMutationIn(action="delete", field_id="sf_1"),
                user_sub="user-1",
            )
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "signature_packet_not_draft"


def test_field_mutation_rejects_non_owner() -> None:
    with patch.object(routes, "get_packet", return_value=_draft_packet(owner="other")):
        with pytest.raises(HTTPException) as exc:
            routes.mutate_signature_packet_field(
                "sp_1",
                routes.SignaturePacketFieldMutationIn(action="delete", field_id="sf_1"),
                user_sub="user-1",
            )
    assert exc.value.status_code == 403


def test_field_create_rejects_invalid_bounds() -> None:
    with patch.object(routes, "get_packet", return_value=_draft_packet()):
        with pytest.raises(HTTPException) as exc:
            routes.mutate_signature_packet_field(
                "sp_1",
                routes.SignaturePacketFieldMutationIn(
                    action="create",
                    page=1,
                    x=0.95,
                    y=0.1,
                    width=0.1,
                    height=0.1,
                    field_type="date",
                ),
                user_sub="user-1",
            )
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_field_bounds"


def test_field_create_rejects_unknown_signer() -> None:
    with (
        patch.object(routes, "get_packet", return_value=_draft_packet()),
        patch.object(routes, "signer_assignment_exists", return_value=False),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.mutate_signature_packet_field(
                "sp_1",
                routes.SignaturePacketFieldMutationIn(
                    action="create",
                    page=1,
                    x=0.1,
                    y=0.1,
                    width=0.1,
                    height=0.1,
                    field_type="text",
                    assigned_signer_id="missing",
                ),
                user_sub="user-1",
            )
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_assigned_signer"


def test_field_delete_requires_field_id() -> None:
    with patch.object(routes, "get_packet", return_value=_draft_packet()):
        with pytest.raises(HTTPException) as exc:
            routes.mutate_signature_packet_field("sp_1", routes.SignaturePacketFieldMutationIn(action="delete"), user_sub="user-1")
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "missing_field_id"


def test_mutate_field_returns_immutable_on_store_conflict() -> None:
    with (
        patch.object(routes, "_validate_packet_owner_and_draft", return_value={"packet_id": "sp_1", "owner_user_id": "user-1", "status": "draft"}),
        patch.object(routes, "signer_assignment_exists", return_value=True),
        patch.object(routes, "upsert_packet_field", side_effect=ValueError("packet_immutable")),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.mutate_signature_packet_field(
                "sp_1",
                routes.SignaturePacketFieldMutationIn(
                    action="create",
                    page=1,
                    x=0.1,
                    y=0.1,
                    width=0.2,
                    height=0.1,
                    field_type="text",
                    assigned_signer_id="user-2",
                ),
                user_sub="user-1",
            )

    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "signature_packet_immutable"


def test_field_delete_emits_event() -> None:
    with (
        patch.object(routes, "get_packet", return_value=_draft_packet()),
        patch.object(routes, "delete_packet_field"),
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.mutate_signature_packet_field(
            "sp_1",
            routes.SignaturePacketFieldMutationIn(action="delete", field_id="sf_1"),
            user_sub="user-1",
        )

    assert out["action"] == "delete"
    assert event_mock.call_args.kwargs["event_type"] == "field_deleted"
