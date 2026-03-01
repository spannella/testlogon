from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import signature_packets as routes


def test_fill_signature_field_succeeds_for_assigned_signer() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "get_packet_field",
            return_value={"field_id": "sf_1", "field_type": "signature", "assigned_signer_id": "user-2"},
        ),
        patch.object(
            routes,
            "fill_packet_field",
            return_value={
                "packet_id": "sp_1",
                "field_id": "sf_1",
                "value": "Jane Doe",
                "filled_at": "2026-01-01T00:00:00+00:00",
                "filled_by_signer_id": "user-2",
            },
        ) as fill_mock,
        patch.object(routes, "append_packet_event") as event_mock,
    ):
        out = routes.fill_signature_packet_field(
            "sp_1",
            "sf_1",
            routes.SignaturePacketFieldFillIn(value="Jane Doe"),
            user_sub="user-2",
        )

    assert out["value"] == "Jane Doe"
    fill_mock.assert_called_once()
    event_mock.assert_called_once()


def test_fill_signature_field_rejects_cross_signer_edit() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "get_packet_field",
            return_value={"field_id": "sf_1", "field_type": "signature", "assigned_signer_id": "user-3"},
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.fill_signature_packet_field(
                "sp_1",
                "sf_1",
                routes.SignaturePacketFieldFillIn(value="Jane Doe"),
                user_sub="user-2",
            )
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "signature_packet_field_not_assigned_to_signer"


def test_fill_date_field_normalizes_iso_date() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "get_packet_field",
            return_value={"field_id": "sf_2", "field_type": "date", "assigned_signer_id": "user-2"},
        ),
        patch.object(routes, "fill_packet_field", return_value={"value": "2026-01-15", "filled_at": "t", "filled_by_signer_id": "user-2"}) as fill_mock,
        patch.object(routes, "append_packet_event"),
    ):
        routes.fill_signature_packet_field(
            "sp_1",
            "sf_2",
            routes.SignaturePacketFieldFillIn(value="2026-01-15"),
            user_sub="user-2",
        )
    assert fill_mock.call_args.kwargs["value"] == "2026-01-15"


def test_fill_date_field_rejects_non_iso() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "get_packet_field",
            return_value={"field_id": "sf_2", "field_type": "date", "assigned_signer_id": "user-2"},
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.fill_signature_packet_field(
                "sp_1",
                "sf_2",
                routes.SignaturePacketFieldFillIn(value="01/15/2026"),
                user_sub="user-2",
            )
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "invalid_date_format"


def test_fill_text_field_enforces_max_length() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "get_packet_field",
            return_value={"field_id": "sf_3", "field_type": "text", "assigned_signer_id": "user-2"},
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.fill_signature_packet_field(
                "sp_1",
                "sf_3",
                routes.SignaturePacketFieldFillIn(value="x" * 501),
                user_sub="user-2",
            )
    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "text_value_too_long"


def test_fill_rejects_when_packet_became_immutable_during_write() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "partially_signed"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "get_packet_field",
            return_value={"packet_id": "sp_1", "field_id": "sf_1", "field_type": "text", "assigned_signer_id": "user-2"},
        ),
        patch.object(routes, "fill_packet_field", side_effect=ValueError("packet_immutable")),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.fill_signature_packet_field("sp_1", "sf_1", routes.SignaturePacketFieldFillIn(value="ok"), user_sub="user-2")

    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "signature_packet_immutable"


def test_fill_signature_field_typed_mode_persists_capture_payload() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "get_packet_field",
            return_value={"field_id": "sf_1", "field_type": "signature", "assigned_signer_id": "user-2"},
        ),
        patch.object(routes, "fill_packet_field", return_value={"value": "Jane Doe", "filled_at": "t", "filled_by_signer_id": "user-2", "capture_mode": "typed"}) as fill_mock,
        patch.object(routes, "append_packet_event"),
    ):
        out = routes.fill_signature_packet_field(
            "sp_1",
            "sf_1",
            routes.SignaturePacketFieldFillIn(value="Jane Doe", input_mode="typed"),
            user_sub="user-2",
        )

    assert out["capture_mode"] == "typed"
    assert fill_mock.call_args.kwargs["capture_mode"] == "typed"
    assert fill_mock.call_args.kwargs["render_payload"]["kind"] == "typed_text"


def test_fill_signature_field_drawn_mode_persists_payload() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "get_packet_field",
            return_value={"field_id": "sf_1", "field_type": "signature", "assigned_signer_id": "user-2"},
        ),
        patch.object(routes, "fill_packet_field", return_value={"value": "[drawn]", "filled_at": "t", "filled_by_signer_id": "user-2", "capture_mode": "drawn"}) as fill_mock,
        patch.object(routes, "append_packet_event"),
    ):
        out = routes.fill_signature_packet_field(
            "sp_1",
            "sf_1",
            routes.SignaturePacketFieldFillIn(input_mode="drawn", drawn_strokes=[[0.1, 0.2], [0.2, 0.3]]),
            user_sub="user-2",
        )

    assert out["capture_mode"] == "drawn"
    assert fill_mock.call_args.kwargs["capture_mode"] == "drawn"
    assert fill_mock.call_args.kwargs["render_payload"]["kind"] == "drawn_path"


def test_fill_signature_field_drawn_mode_rejects_out_of_bounds_points() -> None:
    with (
        patch.object(routes, "get_packet", return_value={"packet_id": "sp_1", "status": "sent"}),
        patch.object(routes, "get_packet_signer", return_value={"signer_id": "user-2", "status": "pending", "legal_notice_accepted_version": "2026-01"}),
        patch.object(
            routes,
            "get_packet_field",
            return_value={"field_id": "sf_1", "field_type": "signature", "assigned_signer_id": "user-2"},
        ),
    ):
        with pytest.raises(HTTPException) as exc:
            routes.fill_signature_packet_field(
                "sp_1",
                "sf_1",
                routes.SignaturePacketFieldFillIn(input_mode="drawn", drawn_strokes=[[1.4, 0.2], [0.2, 0.3]]),
                user_sub="user-2",
            )

    assert exc.value.status_code == 400
    assert exc.value.detail["code"] == "signature_stroke_out_of_bounds"
