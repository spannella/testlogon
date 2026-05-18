from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models_broadcast import BroadcastProfileModel, BroadcastSessionModel


def test_broadcast_profile_model_requires_name() -> None:
    with pytest.raises(ValidationError):
        BroadcastProfileModel(
            id="p1",
            name="",
            region="us-east-1",
            rendition_preset="720p",
            created_by="user-1",
            created_at="2026-03-24T00:00:00+00:00",
            updated_at="2026-03-24T00:00:00+00:00",
        )


def test_broadcast_session_status_enum() -> None:
    model = BroadcastSessionModel(
        id="s1",
        profile_id="p1",
        status="draft",
        created_by="user-1",
        created_at="2026-03-24T00:00:00+00:00",
        updated_at="2026-03-24T00:00:00+00:00",
    )
    assert model.status == "draft"

    with pytest.raises(ValidationError):
        BroadcastSessionModel(
            id="s2",
            profile_id="p1",
            status="invalid",
            created_by="user-1",
            created_at="2026-03-24T00:00:00+00:00",
            updated_at="2026-03-24T00:00:00+00:00",
        )


def test_broadcast_session_defaults_backward_compatible() -> None:
    model = BroadcastSessionModel(
        id="s3",
        profile_id="p1",
        created_by="user-1",
    )
    assert model.status == "draft"
