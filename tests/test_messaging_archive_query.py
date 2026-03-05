from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import messaging
from app.services.messaging_archive_query import query_archive_records
from app.services.messaging_archive_writer import FileArchiveWriter, emit_messaging_archive_event


class TestMessagingArchiveQuery(unittest.TestCase):
    def _seed_archive(self, tmp: str) -> None:
        writer = FileArchiveWriter(root_dir=tmp)
        with patch("app.services.messaging_archive_writer._archive_enabled", return_value=True):
            emit_messaging_archive_event(
                event_id="evt_1",
                event_ts=100,
                tenant_id="default",
                conversation_id="c1",
                message_id="m1",
                actor_user_id="u1",
                effective_user_id="u2",
                event_type="message.sent",
                payload={"text": "hello"},
                writer=writer,
            )
            emit_messaging_archive_event(
                event_id="evt_2",
                event_ts=101,
                tenant_id="default",
                conversation_id="c1",
                message_id="m2",
                actor_user_id="u2",
                effective_user_id="u2",
                event_type="report.submitted",
                payload={"report_id": "r1"},
                writer=writer,
            )
            emit_messaging_archive_event(
                event_id="evt_3",
                event_ts=102,
                tenant_id="default",
                conversation_id="c2",
                message_id="m3",
                actor_user_id="u3",
                effective_user_id="u3",
                event_type="message.sent",
                payload={"text": "bye"},
                writer=writer,
            )

    def test_query_archive_records_applies_filters_and_deterministic_sort(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._seed_archive(tmp)

            out = query_archive_records(
                root_dir=tmp,
                tenant_id="default",
                conversation_id="c1",
                user_id="u2",
                from_ts=100,
                to_ts=101,
                sort_order="asc",
                limit=20,
                offset=0,
                include_payload=True,
            )

        self.assertEqual(out.total_matches, 2)
        self.assertEqual([i["event_id"] for i in out.items], ["evt_1", "evt_2"])
        self.assertEqual(out.items[1]["payload"]["report_id"], "r1")

    def test_query_endpoint_paginates_with_cursor(self):
        actor = SimpleNamespace(sub="admin-1")
        with tempfile.TemporaryDirectory() as tmp:
            self._seed_archive(tmp)
            with patch.object(messaging, "_archive_root_dir", return_value=tmp):
                page1 = messaging.query_compliance_archive_events(
                    limit=1,
                    sort="asc",
                    actor=actor,
                )
                self.assertEqual(page1.total_matches, 3)
                self.assertEqual(len(page1.items), 1)
                self.assertIsNotNone(page1.next_cursor)

                page2 = messaging.query_compliance_archive_events(
                    limit=1,
                    sort="asc",
                    cursor=page1.next_cursor,
                    actor=actor,
                )

        self.assertEqual(page1.items[0].event_id, "evt_1")
        self.assertEqual(page2.items[0].event_id, "evt_2")

    def test_query_endpoint_rejects_invalid_cursor(self):
        actor = SimpleNamespace(sub="admin-1")
        with self.assertRaises(HTTPException) as ctx:
            messaging.query_compliance_archive_events(cursor="bad", actor=actor)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_query_endpoint_validates_time_range(self):
        actor = SimpleNamespace(sub="admin-1")
        with self.assertRaises(HTTPException) as ctx:
            messaging.query_compliance_archive_events(from_ts=10, to_ts=1, actor=actor)
        self.assertEqual(ctx.exception.status_code, 422)

    def test_require_compliance_query_operator_enforces_admin_scope(self):
        user = SimpleNamespace(sub="u1")

        async def _run():
            return await messaging.require_compliance_query_operator(user=user, request=None)

        with patch.object(messaging, "require_compliance_query_admin", side_effect=HTTPException(status_code=403, detail="forbidden")):
            with self.assertRaises(HTTPException) as ctx:
                import asyncio

                asyncio.run(_run())

        self.assertEqual(ctx.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
