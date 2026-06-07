"""Offline regression test for GAP-0366 (VOD-001).

Bug: ``app/routers/transcode_jobs.py`` transitioned a video to ``"queued"`` when
a transcode job was submitted. ``"queued"`` is NOT a valid ``VideoStatus`` and is
absent from ``_ALLOWED_TRANSITIONS`` in ``app/services/video_state_machine.py``, so
``transition_video_status`` raised — and the surrounding ``except Exception`` SILENTLY
swallowed it (logged a warning). The video status never advanced.

Fix: transition to ``"pending_encoding"`` instead, which is a valid status AND a
legal transition from ``"probing"`` (the state a video is in when a transcode job
is created): ``"probing": {"pending_encoding", ...}``.

Fully offline:
  * ``test_state_machine_string_fix`` proves the string fix at the state-machine
    level — ``probing -> pending_encoding`` is legal while ``probing -> queued`` is
    illegal. No AWS at all.
  * ``test_submit_transcode_job_transitions_video`` drives the real router handler
    coroutine against a moto-backed ``video_metadata`` table (bound to the exact
    frozen ``T.video_metadata`` handle via ``object.__setattr__`` and restored after),
    with ``create_job`` stubbed. It reads the video back and asserts the status
    ACTUALLY became ``"pending_encoding"`` — fails-before (status stays ``"probing"``
    with the old ``"queued"`` string), passes-after.

The FastAPI TestClient is unusable in this repo, so the handler coroutine is
awaited directly via ``asyncio.run`` with a fake session.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from app.models_video import VideoMetadataModel
from app.services.video_state_machine import validate_transition


class StateMachineStringFixTest(unittest.TestCase):
    """Pure state-machine proof that the status string fix is correct."""

    def test_state_machine_string_fix(self):
        # The buggy target is illegal from probing (and is not a valid status).
        self.assertFalse(
            validate_transition("probing", "queued").legal,
            "probing -> queued must be illegal (the bug)",
        )
        # The fixed target is legal from probing.
        self.assertTrue(
            validate_transition("probing", "pending_encoding").legal,
            "probing -> pending_encoding must be legal (the fix)",
        )


@unittest.skipIf(mock_aws is None, "moto not installed")
class SubmitTranscodeJobTransitionTest(unittest.TestCase):
    """End-to-end-ish: handler must actually advance the video status."""

    def setUp(self):
        from app.core import tables as tables_mod

        self._aws = mock_aws()
        self._aws.start()

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._table = ddb.create_table(
            TableName="video_metadata_test_gap0366",
            KeySchema=[{"AttributeName": "video_id", "KeyType": "HASH"}],
            AttributeDefinitions=[
                {"AttributeName": "video_id", "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        self._table.wait_until_exists()

        # Bind the moto table to the exact frozen T.video_metadata handle.
        self._T = tables_mod.T
        self._orig_handle = self._T.video_metadata
        object.__setattr__(self._T, "video_metadata", self._table)

    def tearDown(self):
        object.__setattr__(self._T, "video_metadata", self._orig_handle)
        self._aws.stop()

    def _seed_video(self, status: str = "probing") -> str:
        from app.services.video_metadata_store import video_to_item

        video = VideoMetadataModel(
            id="vid_gap0366",
            owner_user_id="user_owner",
            title="GAP-0366 test video",
            status=status,
            created_at=1000,
            updated_at=1000,
        )
        self._table.put_item(Item=video_to_item(video))
        return video.id

    def test_submit_transcode_job_transitions_video(self):
        from app.routers import transcode_jobs
        from app.services.video_metadata_store import get_video

        video_id = self._seed_video(status="probing")

        body = transcode_jobs.SubmitTranscodeJobIn(
            video_id=video_id,
            rendition_profiles=[{"label": "720p"}],
        )
        session = {"user_sub": "user_owner", "role": "USER"}

        fake_job = {
            "job_id": "job_1",
            "video_id": video_id,
            "tenant_id": "user_owner",
            "status": "queued",
            "created_at": 1000,
            "updated_at": 1000,
            "attempt": 0,
        }

        with patch.object(
            transcode_jobs, "create_job", return_value=fake_job
        ) as mock_create:
            out = asyncio.run(
                transcode_jobs.submit_transcode_job(body=body, session=session)
            )

        mock_create.assert_called_once()
        self.assertEqual(out.video_id, video_id)

        # The crux: the video status must ACTUALLY have transitioned.
        refreshed = get_video(video_id)
        self.assertEqual(
            refreshed.status,
            "pending_encoding",
            "video status must transition to pending_encoding (was silently "
            "swallowed when target was the invalid 'queued')",
        )


if __name__ == "__main__":
    unittest.main()
