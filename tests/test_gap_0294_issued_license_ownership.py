"""Offline hermetic regression test for GAP-0294 (LICENSE-002 / SECURITY-IDOR).

Bug: ``app/services/issued_licenses.issue_license`` accepted ``licensor_sub`` and
an arbitrary ``content_id`` without verifying that the caller actually owns the
content. Any authenticated user could issue a license (including a blanket
license routing revenue to themselves) for *any* content_id, polluting the
Licensed Content Library and triggering fraudulent revenue splits.

Fix: ``_validate_content_ownership`` resolves the content owner (videos/clips
directly against ``T.video_metadata.owner_user_id``; everything else via the
shared GAP-0200 collaboration_revenue helper) and raises ``PermissionError``
when the licensor is provably not the owner. ADMIN/ROOT callers may bypass via
``skip_ownership_check=True``.

TEST ISOLATION (per task rules): NO global moto / @mock_aws (that interception
leaks to REAL AWS). We monkeypatch the exact frozen ``T`` handles via
``object.__setattr__`` with in-process fakes, and patch ``get_profile`` /
``T.issued_licenses`` so no network call happens.

Fails before fix (no ownership check -> non-owner call succeeds, no
PermissionError) and passes after.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from app.core.tables import T
from app.services import issued_licenses as svc


class _FakeVideoTable:
    """Minimal in-memory stand-in for T.video_metadata (get_item only)."""

    def __init__(self, items=None):
        # keyed by video_id
        self._items = dict(items or {})

    def get_item(self, Key=None, **_kw):
        vid = (Key or {}).get("video_id")
        item = self._items.get(vid)
        return {"Item": item} if item is not None else {}


class _RecordingTable:
    """Captures put_item calls so we can assert no license was written."""

    def __init__(self):
        self.puts = []

    def put_item(self, Item=None, **_kw):
        self.puts.append(Item)
        return {}


class TestGap0294IssuedLicenseOwnership(unittest.TestCase):
    OWNER = "user_owner"
    ATTACKER = "user_attacker"
    VIDEO_ID = "vid_001"

    def setUp(self):
        # Swap the frozen T handles for hermetic fakes (no AWS).
        self._orig_video = T.video_metadata
        self._orig_issued = T.issued_licenses
        self.fake_video = _FakeVideoTable(
            {self.VIDEO_ID: {"video_id": self.VIDEO_ID, "owner_user_id": self.OWNER}}
        )
        self.fake_issued = _RecordingTable()
        object.__setattr__(T, "video_metadata", self.fake_video)
        object.__setattr__(T, "issued_licenses", self.fake_issued)

        # get_profile would hit DDB; stub it.
        self._profile_patch = patch.object(svc, "get_profile", return_value={})
        self._profile_patch.start()

    def tearDown(self):
        self._profile_patch.stop()
        object.__setattr__(T, "video_metadata", self._orig_video)
        object.__setattr__(T, "issued_licenses", self._orig_issued)

    def test_non_owner_is_blocked(self):
        """GAP-0294: a user who does not own the video cannot issue a license.

        FAILS BEFORE FIX: issue_license writes the license records and returns
        normally for the attacker (no PermissionError raised).
        PASSES AFTER FIX: PermissionError is raised and no record is written.
        """
        with self.assertRaises(PermissionError):
            svc.issue_license(
                licensor_sub=self.ATTACKER,
                content_id=self.VIDEO_ID,
                content_type="video",
                license_mode="blanket",
            )
        self.assertEqual(
            self.fake_issued.puts,
            [],
            "no license record may be written when ownership check fails",
        )

    def test_owner_can_issue(self):
        """The real owner can issue a license for their own video."""
        result = svc.issue_license(
            licensor_sub=self.OWNER,
            content_id=self.VIDEO_ID,
            content_type="video",
            license_mode="blanket",
        )
        self.assertEqual(result["licensor_id"], self.OWNER)
        # primary record + licensor index + blanket library index = 3 writes
        self.assertGreaterEqual(len(self.fake_issued.puts), 2)

    def test_admin_override_bypasses_ownership(self):
        """ADMIN/ROOT escape hatch: skip_ownership_check bypasses the guard."""
        result = svc.issue_license(
            licensor_sub=self.ATTACKER,
            content_id=self.VIDEO_ID,
            content_type="video",
            license_mode="blanket",
            skip_ownership_check=True,
        )
        self.assertEqual(result["licensor_id"], self.ATTACKER)

    def test_nonexistent_content_degrades_gracefully(self):
        """Unverifiable ownership (content not found) -> allowed but logged.

        Mirrors the GAP-0200 collaboration content-ownership behaviour: an empty
        resolver result is treated as "unverifiable" rather than a hard block.
        """
        result = svc.issue_license(
            licensor_sub=self.ATTACKER,
            content_id="vid_does_not_exist",
            content_type="video",
            license_mode="blanket",
        )
        self.assertEqual(result["licensor_id"], self.ATTACKER)


if __name__ == "__main__":
    unittest.main()
