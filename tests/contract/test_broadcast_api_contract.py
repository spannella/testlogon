from __future__ import annotations
import os

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers import broadcast


def _app() -> TestClient:
    app = FastAPI()
    app.include_router(broadcast.router)
    app.dependency_overrides[broadcast._ctx] = lambda: {"user_sub": "u1", "session_id": "sess-ui", "role": "admin", "ip": "", "tenant_id": "default"}
    return TestClient(app)


def _session_payload(status: str = "draft") -> dict:
    return {
        "id": "s1",
        "profile_id": "p1",
        "status": status,
        "ingest_url": None,
        "stream_key_ref": None,
        "stream_key_last_rotated_at": None,
        "stream_key_rotation_interval_seconds": 86400,
        "started_at": None,
        "stopped_at": None,
        "created_by": "u1",
        "created_at": "2026-04-01T00:00:00+00:00",
        "updated_at": "2026-04-01T00:00:00+00:00",
    }


def test_profile_session_lifecycle_contract_snapshot() -> None:
    client = _app()
    profile = SimpleNamespace(
        id="p1",
        drm_credentials_ref=None,
        model_dump=lambda: {
            "id": "p1",
            "name": "Main",
            "region": "us-east-1",
            "rendition_preset": "720p",
            "watermark_asset": None,
            "drm_policy_id": None,
            "drm_credentials_ref": None,
            "drm_credentials_last_rotated_at": None,
            "drm_credentials_rotation_interval_seconds": 86400,
            "created_by": "u1",
            "created_at": "2026-04-01T00:00:00+00:00",
            "updated_at": "2026-04-01T00:00:00+00:00",
        },
    )
    # created_by must match the overridden require_ui_session user_sub ("u1") so the
    # SEC-025 ownership gate in _get_owned_session permits the lifecycle operations.
    session = SimpleNamespace(id="s1", created_by="u1", stream_key_ref=None, model_dump=lambda: _session_payload("draft"))
    live_session = SimpleNamespace(id="s1", created_by="u1", stream_key_ref=None, model_dump=lambda: _session_payload("live"))
    output = SimpleNamespace(
        mediapackage_endpoint="https://pkg.example/s1/master.m3u8",
        cloudfront_playback_url="https://d111.cloudfront.net/s1/master.m3u8?cf_token=t&cf_expires=1",
        s3_archive_prefix="s3://broadcast-archive/sessions/s1/",
        aws_input_arn="arn:aws:medialive:input:s1",
        aws_channel_arn="arn:aws:medialive:channel:s1",
        provider_state_snapshot={"provider": "aws"},
    )

    with (
        patch.object(broadcast, "record_broadcast_action"),
        patch.object(broadcast, "create_profile", return_value=profile),
        patch.object(broadcast, "create_session", return_value=session),
        patch.object(broadcast, "start_session_with_provider", return_value=live_session),
        patch.object(broadcast, "get_session", return_value=live_session),
        patch.object(broadcast, "get_output", return_value=output),
    ):
        r1 = client.post("/broadcast/profiles", json={"name": "Main", "region": "us-east-1", "rendition_preset": "720p"})
        r2 = client.post("/broadcast/sessions", json={"profile_id": "p1"})
        r3 = client.post("/broadcast/sessions/s1/start", json={"reason": "go"})
        r4 = client.get("/broadcast/sessions/s1")

    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r3.status_code == 202
    assert r4.status_code == 200

    snapshot = {
        "profile": r1.json(),
        "session_created": r2.json(),
        "session_started": r3.json(),
        "session_get": r4.json(),
    }
    fixture = Path("tests/fixtures/broadcast_api_contract_snapshot.json")
    # Regenerate the contract snapshot fixture with UPDATE_BROADCAST_SNAPSHOT=1 when
    # the broadcast response contract intentionally changes (e.g. new additive fields).
    if os.environ.get("UPDATE_BROADCAST_SNAPSHOT") == "1":
        fixture.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    expected = json.loads(fixture.read_text(encoding="utf-8"))
    assert snapshot == expected
