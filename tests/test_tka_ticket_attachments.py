"""Offline hermetic tests for ticket file attachments (TKA-001/002/003 backend).

Covers presign + confirm (TKA-001), list / download-URL / soft-delete +
get_ticket projection (TKA-002), idempotency, auth, and flag-off 404.

Hermetic / offline (TEST ISOLATION):
* Real in-memory DynamoDB ``tickets`` table via moto, bound to the exact frozen
  ``T.tickets`` handle through ``object.__setattr__`` (restored on cleanup), and
  ``tickets_mod.STORE._table`` repointed (it was bound at import).
* Frozen ``Settings`` singleton ``S`` mutated via ``object.__setattr__``;
  ``S.dev_mode`` forced True so the S3 paths return ``/mock/s3`` proxy URLs and
  no real AWS / network is touched.
* Service functions are called directly (sync); ``HTTPException`` asserted for
  flag-off / not-found / conflict / forbidden paths.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
import app.services.tickets as tickets_mod
import app.services.ticket_attachments as att


def _make_tickets_table(ddb):
    return ddb.create_table(
        TableName="tickets",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


class TicketAttachmentTests(unittest.TestCase):
    def setUp(self):
        if mock_aws is None:
            self.skipTest("moto not available")
        self._stack = ExitStack()
        self._stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tickets = _make_tickets_table(ddb)

        self._orig_tickets = T.tickets
        object.__setattr__(T, "tickets", self.tickets)
        self._orig_store_table = tickets_mod.STORE._table
        object.__setattr__(tickets_mod.STORE, "_table", self.tickets)

        self._orig_flag = getattr(S, "ticket_attachments_enabled", False)
        self._orig_dev = S.dev_mode
        object.__setattr__(S, "ticket_attachments_enabled", True)
        object.__setattr__(S, "dev_mode", True)

    def tearDown(self):
        object.__setattr__(T, "tickets", self._orig_tickets)
        object.__setattr__(tickets_mod.STORE, "_table", self._orig_store_table)
        object.__setattr__(S, "ticket_attachments_enabled", self._orig_flag)
        object.__setattr__(S, "dev_mode", self._orig_dev)
        self._stack.close()

    def _new_ticket(self, owner="alice"):
        t = tickets_mod.STORE.create_ticket(owner_sub=owner, subject="need help", description="x")
        return t["ticket_id"]

    def _upload(self, tid, filename="report.pdf", ct="application/pdf", uploader="alice", size=1234):
        pre = att.presign_attachment(ticket_id=tid, filename=filename, content_type=ct)
        return att.confirm_attachment(
            ticket_id=tid, attachment_id=pre["attachment_id"], filename=filename,
            content_type=ct, size_bytes=size, uploaded_by=uploader,
        ), pre

    # ------------------------------------------------------------- TKA-001
    def test_flag_off_presign_404(self):
        tid = self._new_ticket()
        object.__setattr__(S, "ticket_attachments_enabled", False)
        with self.assertRaises(HTTPException) as ctx:
            att.presign_attachment(ticket_id=tid, filename="a.txt", content_type="text/plain")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_presign_returns_mock_url_and_key(self):
        tid = self._new_ticket()
        pre = att.presign_attachment(ticket_id=tid, filename="a b.txt", content_type="text/plain")
        self.assertTrue(pre["upload_url"].startswith("/mock/s3/"))
        self.assertEqual(len(pre["attachment_id"]), 32)
        self.assertIn(f"tickets/{tid}/attachments/{pre['attachment_id']}/", pre["key"])
        self.assertEqual(pre["content_type"], "text/plain")

    def test_confirm_writes_row(self):
        tid = self._new_ticket()
        row, pre = self._upload(tid)
        self.assertEqual(row["attachment_id"], pre["attachment_id"])
        self.assertEqual(row["filename"], "report.pdf")
        self.assertEqual(row["size_bytes"], 1234)
        self.assertEqual(row["uploaded_by"], "alice")
        self.assertIsInstance(row["created_at"], int)

    def test_confirm_idempotent_conflict(self):
        tid = self._new_ticket()
        _, pre = self._upload(tid)
        with self.assertRaises(HTTPException) as ctx:
            att.confirm_attachment(
                ticket_id=tid, attachment_id=pre["attachment_id"], filename="report.pdf",
                content_type="application/pdf", size_bytes=1234, uploaded_by="alice",
            )
        self.assertEqual(ctx.exception.status_code, 409)

    def test_key_is_server_reconstructed(self):
        # confirm recomputes the key from (ticket_id, attachment_id, filename) — it
        # does not trust a client-supplied key, so the stored key is deterministic.
        tid = self._new_ticket()
        row, pre = self._upload(tid, filename="x.bin")
        rows = att._query_attachment_rows(tid)
        stored = next(r for r in rows if r["attachment_id"] == pre["attachment_id"])
        self.assertEqual(stored["s3_key"], f"tickets/{tid}/attachments/{pre['attachment_id']}/x.bin")

    # ------------------------------------------------------------- TKA-002
    def test_list_returns_active(self):
        tid = self._new_ticket()
        self._upload(tid, filename="a.pdf")
        self._upload(tid, filename="b.pdf")
        items = att.list_attachments(tid)
        self.assertEqual({i["filename"] for i in items}, {"a.pdf", "b.pdf"})

    def test_download_url_dev_mock(self):
        tid = self._new_ticket()
        row, _ = self._upload(tid)
        url = att.get_download_url(ticket_id=tid, attachment_id=row["attachment_id"])
        self.assertTrue(url.startswith("/mock/s3/"))
        self.assertIn(row["attachment_id"], url)

    def test_download_unknown_404(self):
        tid = self._new_ticket()
        with self.assertRaises(HTTPException) as ctx:
            att.get_download_url(ticket_id=tid, attachment_id="nope")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_delete_soft_removes_from_list(self):
        tid = self._new_ticket()
        row, _ = self._upload(tid)
        att.delete_attachment(ticket_id=tid, attachment_id=row["attachment_id"], actor_sub="alice", is_admin=False)
        self.assertEqual(att.list_attachments(tid), [])

    def test_delete_non_uploader_forbidden(self):
        tid = self._new_ticket()
        row, _ = self._upload(tid, uploader="alice")
        with self.assertRaises(HTTPException) as ctx:
            att.delete_attachment(ticket_id=tid, attachment_id=row["attachment_id"], actor_sub="mallory", is_admin=False)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_delete_admin_allowed(self):
        tid = self._new_ticket()
        row, _ = self._upload(tid, uploader="alice")
        out = att.delete_attachment(ticket_id=tid, attachment_id=row["attachment_id"], actor_sub="admin1", is_admin=True)
        self.assertTrue(out["ok"])
        self.assertEqual(att.list_attachments(tid), [])

    def test_get_ticket_projection_includes_attachments(self):
        tid = self._new_ticket()
        self._upload(tid, filename="proj.pdf")
        projected = tickets_mod.STORE.get_ticket(tid)
        self.assertIn("attachments", projected)
        self.assertEqual([a["filename"] for a in projected["attachments"]], ["proj.pdf"])

    def test_projection_empty_when_flag_off(self):
        tid = self._new_ticket()
        self._upload(tid, filename="proj.pdf")
        object.__setattr__(S, "ticket_attachments_enabled", False)
        projected = tickets_mod.STORE.get_ticket(tid)
        self.assertEqual(projected["attachments"], [])


if __name__ == "__main__":
    unittest.main()
