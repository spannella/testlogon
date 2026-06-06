"""Offline regression tests for GAP-0199 and GAP-0200 (FIN-011).

Both gaps live in the collaboration-revenue feature
(``app/services/collaboration_revenue.py`` + ``app/routers/collaborations.py``).

GAP-0200 — ``assign_content`` validated that the caller is a *participant* of the
collaboration but never that the caller *owns* the content being assigned. A
participant could assign another creator's content and siphon its revenue. The
fix adds an ownership check (``_resolve_content_owner``) that raises
``PermissionError("content_not_owned")`` when the assigner is not the owner,
with an admin bypass (``skip_ownership_check``) and graceful degradation when
ownership is unverifiable.

GAP-0199 — there was no admin-global dispute queue / arbitration route. Admins
could only reach disputes through ``/ui/collaborations/{collab_id}/disputes``,
requiring the collab_id up front. The fix adds
``GET /ui/admin/collaboration-disputes`` (list all via
``list_disputes(collaboration_id=None)``) and
``POST /ui/admin/collaboration-disputes/{dispute_id}/arbitrate`` (resolve by
dispute_id alone, via the new ``get_dispute_global`` helper).

Fully offline / hermetic — NO real AWS. A real in-memory DynamoDB table is built
with moto and the *exact* table handles the code uses are monkeypatched
(``T.collaboration_agreements`` etc. swapped via object.__setattr__ because ``T``
is frozen; ``dmca_content_operations.ddb`` patched too). The FastAPI TestClient
is unusable in this repo, so router handler functions are invoked directly with a
synthetic ``ctx`` dict (matching the ``require_ui_session`` return shape).
Mirrors tests/test_gap_0176_0177_org_service.py.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_collab_table(ddb):
    """Create the collaboration_agreements table mirroring local-ddb-init.py."""
    return ddb.create_table(
        TableName="collaboration_agreements",
        KeySchema=[
            {"AttributeName": "collaboration_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "collaboration_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi_content_pk", "AttributeType": "S"},
            {"AttributeName": "gsi_content_sk", "AttributeType": "S"},
            {"AttributeName": "gsi_dispute_pk", "AttributeType": "S"},
            {"AttributeName": "gsi_dispute_sk", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByContentId",
                "KeySchema": [
                    {"AttributeName": "gsi_content_pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi_content_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByDisputeStatus",
                "KeySchema": [
                    {"AttributeName": "gsi_dispute_pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi_dispute_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_video_table(ddb):
    return ddb.create_table(
        TableName="video_metadata",
        KeySchema=[{"AttributeName": "video_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "video_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class _CollabTestBase(unittest.TestCase):
    """Builds an in-memory table and patches the exact handles code uses."""

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_collab_table(ddb)
        self.video_table = _make_video_table(ddb)

        from app.core.tables import T as _T
        from app.services import collaboration_revenue as cr
        from app.services import collaborations as collabs
        from app.services import dmca_content_operations as dmca

        self.cr = cr
        self.collabs = collabs
        self.dmca = dmca

        # T is frozen → use object.__setattr__ to swap the bound handles, then
        # restore on cleanup. cr.T, collabs.T, dmca.T are the SAME T singleton.
        self._patch_handle(_T, "collaboration_agreements", self.table)
        self._patch_handle(_T, "video_metadata", self.video_table)

        # dmca_content_operations uses module-level ``ddb`` resource for feed
        # posts; point it at the moto resource so it never touches real AWS.
        self.stack.enter_context(patch.object(dmca, "ddb", ddb))

    def _patch_handle(self, frozen_obj, attr, value):
        original = getattr(frozen_obj, attr)
        object.__setattr__(frozen_obj, attr, value)
        self.addCleanup(lambda: object.__setattr__(frozen_obj, attr, original))

    # -- seeding helpers ----------------------------------------------------

    def _seed_collab(self, collab_id, initiator, recipient, status="accepted"):
        self.table.put_item(
            Item={
                "collaboration_id": collab_id,
                "sk": "CURRENT",
                "initiator_id": initiator,
                "recipient_id": recipient,
                "status": status,
                "content_count": 0,
            }
        )

    def _seed_video(self, video_id, owner):
        self.video_table.put_item(Item={"video_id": video_id, "user_id": owner})

    def _seed_split(self, collab_id, split_id, ts=1000):
        self.table.put_item(
            Item={
                "collaboration_id": collab_id,
                "sk": f"SPLIT#{ts}#{split_id}",
                "split_id": split_id,
                "dispute_status": "none",
            }
        )

    def _seed_dispute(self, collab_id, dispute_id, split_id, ts=2000, status="open"):
        self.table.put_item(
            Item={
                "collaboration_id": collab_id,
                "sk": f"DISPUTE#{ts}#{dispute_id}",
                "dispute_id": dispute_id,
                "split_id": split_id,
                "filed_by": "filer",
                "reason": "split looks wrong",
                "status": status,
                "resolution": "",
                "resolved_by": "",
                "resolved_at": 0,
                "created_at": ts,
                "gsi_dispute_pk": f"DISPUTE_STATUS#{status}",
                "gsi_dispute_sk": ts,
            }
        )


# ===========================================================================
# GAP-0200 — content ownership validated on assign
# ===========================================================================

class TestContentOwnershipGap0200(_CollabTestBase):
    def test_owner_can_assign_own_content(self):
        """Owner assigning their own video succeeds (passes before & after)."""
        self._seed_collab("collab1", "alice", "bob")
        self._seed_video("vid_alice", "alice")
        result = self.cr.assign_content(
            collaboration_id="collab1",
            content_id="vid_alice",
            content_type="video",
            assigned_by="alice",
        )
        self.assertEqual(result["content_id"], "vid_alice")
        self.assertEqual(result["assigned_by"], "alice")

    def test_non_owner_participant_cannot_assign_others_content(self):
        """GAP-0200 core: Bob (participant) assigning Alice's video must fail.

        FAILS BEFORE FIX: no ownership check → assignment succeeds and Bob
        siphons revenue from Alice's video.
        PASSES AFTER FIX: raises PermissionError("content_not_owned").
        """
        self._seed_collab("collab1", "alice", "bob")
        self._seed_video("vid_alice", "alice")
        with self.assertRaises(PermissionError) as ctx:
            self.cr.assign_content(
                collaboration_id="collab1",
                content_id="vid_alice",
                content_type="video",
                assigned_by="bob",
            )
        self.assertIn("content_not_owned", str(ctx.exception))
        # And nothing was persisted.
        self.assertIsNone(
            self.cr.get_content_assignment("collab1", "vid_alice"),
            "fraudulent assignment must not be written",
        )

    def test_admin_bypass_can_assign_any_content(self):
        """skip_ownership_check=True (admin) bypasses the ownership check."""
        self._seed_collab("collab1", "alice", "bob")
        self._seed_video("vid_alice", "alice")
        result = self.cr.assign_content(
            collaboration_id="collab1",
            content_id="vid_alice",
            content_type="video",
            assigned_by="bob",
            skip_ownership_check=True,
        )
        self.assertEqual(result["content_id"], "vid_alice")

    def test_unverifiable_ownership_allows_with_warning(self):
        """Unknown content type → owner == "" → graceful degradation (allow)."""
        self._seed_collab("collab1", "alice", "bob")
        with self.assertLogs("app.services.collaboration_revenue", level="WARNING") as logs:
            result = self.cr.assign_content(
                collaboration_id="collab1",
                content_id="exotic_xyz",
                content_type="exotic_type",
                assigned_by="bob",
            )
        self.assertEqual(result["content_id"], "exotic_xyz")
        self.assertTrue(any("could not verify ownership" in m for m in logs.output))

    def test_resolve_content_owner_returns_correct_user(self):
        self._seed_video("vid_x", "carol")
        self.assertEqual(self.cr._resolve_content_owner("video", "vid_x"), "carol")
        self.assertEqual(self.cr._resolve_content_owner("video", "missing"), "")

    def test_router_returns_403_do_not_own(self):
        """Router translates content_not_owned → 403 'You do not own this content'.

        FAILS BEFORE FIX: assign succeeds (200) → no 403 raised.
        """
        from fastapi import HTTPException
        from app.models import CollabContentAssignIn
        import app.routers.collaborations as router_mod

        self._seed_collab("collab1", "alice", "bob")
        self._seed_video("vid_alice", "alice")

        # Router accepts content_type vod|post|broadcast; "vod" maps to "video".
        body = CollabContentAssignIn(
            content_id="vid_alice", content_type="vod", title="stolen"
        )
        ctx = {"user_sub": "bob", "role": "user"}
        with self.assertRaises(HTTPException) as exc:
            router_mod.assign_content_to_collab("collab1", body, ctx)
        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("do not own", exc.exception.detail)

    def test_router_admin_skips_ownership_check(self):
        """Admin participant → router passes skip_ownership_check=True → can
        assign content they do not personally own (admin escape hatch).

        The admin must still be a participant (participation is enforced before
        ownership); the bypass only relaxes the ownership requirement.
        """
        from app.models import CollabContentAssignIn
        import app.routers.collaborations as router_mod

        # charlie_admin is a participant (recipient) but does not own bob's video.
        self._seed_collab("collab1", "charlie_admin", "bob")
        self._seed_video("vid_bob", "bob")

        body = CollabContentAssignIn(
            content_id="vid_bob", content_type="vod", title="admin assign"
        )
        ctx = {"user_sub": "charlie_admin", "role": "admin"}
        result = router_mod.assign_content_to_collab("collab1", body, ctx)
        self.assertTrue(result["ok"])

        # Sanity: a non-admin participant is blocked from assigning the same
        # (non-owned) content via the service-level ownership check.
        self._seed_video("vid_bob_other", "bob")
        with self.assertRaises(PermissionError):
            self.cr.assign_content(
                collaboration_id="collab1",
                content_id="vid_bob_other",
                content_type="video",
                assigned_by="charlie_admin",  # no admin bypass at service level
            )


# ===========================================================================
# GAP-0199 — admin-global dispute arbitration
# ===========================================================================

class TestAdminDisputeArbitrationGap0199(_CollabTestBase):
    def test_get_dispute_global_finds_across_collaborations(self):
        """get_dispute_global locates a dispute by id without a collab_id.

        FAILS BEFORE FIX: helper did not exist (AttributeError).
        """
        self._seed_collab("collabA", "alice", "bob")
        self._seed_collab("collabB", "carol", "dave")
        self._seed_split("collabB", "sp_b")
        self._seed_dispute("collabB", "disp_target", "sp_b", ts=2222, status="open")
        # decoy in another collab/status
        self._seed_dispute("collabA", "disp_other", "sp_a", ts=1111, status="counter")

        found = self.cr.get_dispute_global("disp_target")
        self.assertIsNotNone(found)
        self.assertEqual(found["collaboration_id"], "collabB")
        self.assertEqual(found["dispute_id"], "disp_target")
        self.assertIsNone(self.cr.get_dispute_global("nope"))

    def test_admin_list_all_disputes_cross_collaboration(self):
        """GET /ui/admin/collaboration-disputes lists disputes from all collabs.

        FAILS BEFORE FIX: endpoint did not exist.
        """
        import app.routers.collaborations as router_mod

        self._seed_collab("collabA", "alice", "bob")
        self._seed_collab("collabB", "carol", "dave")
        self._seed_dispute("collabA", "disp_a", "sp_a", ts=100, status="open")
        self._seed_dispute("collabB", "disp_b", "sp_b", ts=200, status="open")
        self._seed_dispute("collabB", "disp_c", "sp_c", ts=300, status="resolved")

        ctx_admin = {"user_sub": "root", "role": "root"}
        out = router_mod.admin_list_all_disputes(status="open", limit=50, ctx=ctx_admin)
        ids = {d.dispute_id for d in out.items}
        self.assertEqual(ids, {"disp_a", "disp_b"})  # open only, cross-collab

    def test_non_admin_cannot_list_global_disputes(self):
        from fastapi import HTTPException
        import app.routers.collaborations as router_mod

        ctx_user = {"user_sub": "alice", "role": "user"}
        with self.assertRaises(HTTPException) as exc:
            router_mod.admin_list_all_disputes(status="open", limit=50, ctx=ctx_user)
        self.assertEqual(exc.exception.status_code, 403)

    def test_admin_arbitrate_resolves_without_collab_id(self):
        """POST .../{dispute_id}/arbitrate resolves by dispute_id alone.

        FAILS BEFORE FIX: endpoint did not exist.
        """
        from app.models import CollabDisputeResolveIn
        import app.routers.collaborations as router_mod

        self._seed_collab("collabB", "carol", "dave")
        self._seed_split("collabB", "sp_b")
        self._seed_dispute("collabB", "disp_target", "sp_b", ts=2222, status="open")

        body = CollabDisputeResolveIn(resolution="Admin: split is correct.", accept=True)
        ctx_admin = {"user_sub": "root", "role": "root"}
        result = router_mod.admin_arbitrate_dispute("disp_target", body, ctx_admin)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "resolved")
        # The dispute moved to the resolved partition.
        moved = self.cr.get_dispute_global("disp_target")
        self.assertEqual(moved["status"], "resolved")
        # The underlying split is marked resolved too.
        split = self.cr.get_split("collabB", "sp_b")
        self.assertEqual(split["dispute_status"], "resolved")

    def test_admin_arbitrate_404_on_missing_dispute(self):
        from fastapi import HTTPException
        from app.models import CollabDisputeResolveIn
        import app.routers.collaborations as router_mod

        body = CollabDisputeResolveIn(resolution="whatever here", accept=True)
        ctx_admin = {"user_sub": "root", "role": "root"}
        with self.assertRaises(HTTPException) as exc:
            router_mod.admin_arbitrate_dispute("nonexistent", body, ctx_admin)
        self.assertEqual(exc.exception.status_code, 404)

    def test_non_admin_cannot_arbitrate(self):
        from fastapi import HTTPException
        from app.models import CollabDisputeResolveIn
        import app.routers.collaborations as router_mod

        self._seed_collab("collabB", "carol", "dave")
        self._seed_split("collabB", "sp_b")
        self._seed_dispute("collabB", "disp_target", "sp_b", ts=2222, status="open")

        body = CollabDisputeResolveIn(resolution="attempt to resolve", accept=True)
        ctx_user = {"user_sub": "dave", "role": "user"}
        with self.assertRaises(HTTPException) as exc:
            router_mod.admin_arbitrate_dispute("disp_target", body, ctx_user)
        self.assertEqual(exc.exception.status_code, 403)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
