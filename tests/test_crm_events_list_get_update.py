"""Offline regression tests for CRM events list / get-single / update.

Follow-up 2: ``app/routers/crm_events.py`` previously exposed only POST create
and per-event sub-resources. This adds GET list, GET single, and PATCH update
+ backing service fns (``list_events``/``get_event``/``update_event``), gated by
``S.crm_events_enabled``.

Test isolation (SECOPS-007 / repo rules):
  * Real in-memory moto DynamoDB ``crm_events`` table (with ByOwner GSI) bound to
    the frozen ``T.crm_events`` handle via ``object.__setattr__`` + restore.
  * Frozen ``Settings`` flag flipped with ``object.__setattr__``.
  * NO TestClient — route coroutines/service fns called directly.
"""
from __future__ import annotations

import asyncio
import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None


def _make_crm_events_table(ddb):
    return ddb.create_table(
        TableName="crm_events",
        KeySchema=[
            {"AttributeName": "event_id", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "event_id", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "owner_sub", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByOwner",
                "KeySchema": [
                    {"AttributeName": "owner_sub", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestCrmEventsListGetUpdate(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_crm_events_table(ddb)

        from app.core.tables import T
        from app.routers import crm_events as router
        from app.services import crm_events as svc

        self.T = T
        self.router = router
        self.svc = svc
        self.S = router.S

        self._orig = T.crm_events
        object.__setattr__(T, "crm_events", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "crm_events", self._orig))

        self._orig_flag = self.S.crm_events_enabled
        object.__setattr__(self.S, "crm_events_enabled", True)
        self.addCleanup(
            lambda: object.__setattr__(self.S, "crm_events_enabled", self._orig_flag)
        )

    def _ctx(self, sub="alice", role="user"):
        return {"user_sub": sub, "role": role}

    def _create(self, ctx, name="Launch Party", **kw):
        from app import models

        body = models.CrmEventCreateIn(name=name, **kw)
        return asyncio.run(self.router.create_crm_event(body=body, request=None, ctx=ctx))

    # -- create -> list -> get -> update -> get reflects ----------------------

    def test_full_flow(self):
        ctx = self._ctx("alice")
        ev = self._create(ctx, name="Launch Party", description="v1", max_attendance=10)
        event_id = ev["event_id"]

        # list
        listed = asyncio.run(self.router.list_crm_events(limit=50, cursor=None, ctx=ctx))
        self.assertEqual(len(listed["events"]), 1)
        self.assertEqual(listed["events"][0]["event_id"], event_id)

        # get single
        got = asyncio.run(self.router.get_crm_event_endpoint(event_id=event_id, ctx=ctx))
        self.assertEqual(got["name"], "Launch Party")
        self.assertEqual(got["description"], "v1")
        self.assertEqual(got["max_attendance"], 10)

        # update
        from app import models

        upd = models.CrmEventUpdateIn(name="Big Launch", max_attendance=25)
        updated = asyncio.run(
            self.router.update_crm_event_endpoint(
                event_id=event_id, body=upd, request=None, ctx=ctx
            )
        )
        self.assertEqual(updated["name"], "Big Launch")
        self.assertEqual(updated["max_attendance"], 25)
        # description untouched (not in update payload)
        self.assertEqual(updated["description"], "v1")

        # get reflects update
        got2 = asyncio.run(self.router.get_crm_event_endpoint(event_id=event_id, ctx=ctx))
        self.assertEqual(got2["name"], "Big Launch")
        self.assertEqual(got2["max_attendance"], 25)

    def test_list_only_own_events(self):
        a = self._create(self._ctx("alice"), name="A1")
        self._create(self._ctx("bob"), name="B1")
        listed = asyncio.run(self.router.list_crm_events(limit=50, cursor=None, ctx=self._ctx("alice")))
        ids = {e["event_id"] for e in listed["events"]}
        self.assertEqual(ids, {a["event_id"]})

    def test_list_pagination(self):
        ctx = self._ctx("alice")
        for i in range(3):
            self._create(ctx, name=f"E{i}")
        page1 = asyncio.run(self.router.list_crm_events(limit=2, cursor=None, ctx=ctx))
        self.assertEqual(len(page1["events"]), 2)
        self.assertIsNotNone(page1["cursor"])
        page2 = asyncio.run(
            self.router.list_crm_events(limit=2, cursor=page1["cursor"], ctx=ctx)
        )
        self.assertEqual(len(page2["events"]), 1)

    # -- error paths ----------------------------------------------------------

    def test_get_unknown_404(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as cm:
            asyncio.run(self.router.get_crm_event_endpoint(event_id="nope", ctx=self._ctx()))
        self.assertEqual(cm.exception.status_code, 404)

    def test_update_unknown_404(self):
        from fastapi import HTTPException
        from app import models

        upd = models.CrmEventUpdateIn(name="x")
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(
                self.router.update_crm_event_endpoint(
                    event_id="nope", body=upd, request=None, ctx=self._ctx()
                )
            )
        self.assertEqual(cm.exception.status_code, 404)

    def test_non_owner_get_403(self):
        from fastapi import HTTPException

        ev = self._create(self._ctx("alice"), name="A1")
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(
                self.router.get_crm_event_endpoint(
                    event_id=ev["event_id"], ctx=self._ctx("bob")
                )
            )
        self.assertEqual(cm.exception.status_code, 403)

    def test_admin_can_read_other_event(self):
        ev = self._create(self._ctx("alice"), name="A1")
        got = asyncio.run(
            self.router.get_crm_event_endpoint(
                event_id=ev["event_id"], ctx=self._ctx("root", "root")
            )
        )
        self.assertEqual(got["event_id"], ev["event_id"])

    def test_flag_off_404(self):
        from fastapi import HTTPException

        ev = self._create(self._ctx("alice"), name="A1")
        object.__setattr__(self.S, "crm_events_enabled", False)
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(self.router.list_crm_events(limit=50, cursor=None, ctx=self._ctx("alice")))
        self.assertEqual(cm.exception.status_code, 404)
        with self.assertRaises(HTTPException) as cm2:
            asyncio.run(
                self.router.get_crm_event_endpoint(event_id=ev["event_id"], ctx=self._ctx("alice"))
            )
        self.assertEqual(cm2.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
