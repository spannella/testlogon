from __future__ import annotations

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.calendar_integrations.base import CalendarIntegrationError, CalendarIntegrationErrorCode
from app.services.calendar_integrations import outbox, credentials


class TestCalendarPushOutbox(unittest.TestCase):
    def test_transient_failures_are_retried(self):
        now = datetime(2026, 4, 5, 12, 0, 0, tzinfo=timezone.utc)
        provider = SimpleNamespace(
            sync=SimpleNamespace(
                push_event=MagicMock(
                    side_effect=CalendarIntegrationError(
                        code=CalendarIntegrationErrorCode.NETWORK,
                        detail="temporary network",
                        retriable=True,
                    )
                )
            )
        )
        with (
            patch.object(outbox, "get_provider_services", return_value=provider),
            patch.object(outbox, "list_due_apple_push_outbox", return_value=[{"outbox_id": "o1", "connection_id": "c1", "external_calendar_id": "work", "operation": "update", "payload": {}}]),
            patch.object(outbox, "finalize_apple_push_outbox_attempt", return_value={"status": "retry"}) as finalize,
        ):
            stats = outbox.process_apple_push_outbox(now=now)

        self.assertEqual(stats["processed"], 1)
        self.assertEqual(stats["retried"], 1)
        self.assertEqual(finalize.call_args.kwargs["transient"], True)

    def test_terminal_failures_dead_lettered_for_support(self):
        now = datetime(2026, 4, 5, 12, 0, 0, tzinfo=timezone.utc)
        provider = SimpleNamespace(
            sync=SimpleNamespace(push_event=MagicMock(return_value={"status": "conflict", "conflict_reason": "etag_mismatch"}))
        )
        with (
            patch.object(outbox, "get_provider_services", return_value=provider),
            patch.object(outbox, "list_due_apple_push_outbox", return_value=[{"outbox_id": "o2", "connection_id": "c1", "external_calendar_id": "work", "operation": "delete", "payload": {}}]),
            patch.object(outbox, "finalize_apple_push_outbox_attempt", return_value={"status": "dead_letter"}) as finalize,
        ):
            stats = outbox.process_apple_push_outbox(now=now)

        self.assertEqual(stats["dead_lettered"], 1)
        self.assertEqual(finalize.call_args.kwargs["error"], "etag_mismatch")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
