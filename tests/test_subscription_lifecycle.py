from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from app.routers import subscription_server


def test_calculate_proration_mid_cycle():
    proration = subscription_server.calculate_proration(
        current_price=1000,
        new_price=2000,
        now=15,
        period_start=0,
        period_end=30,
    )
    assert proration == 500


def test_refresh_subscription_calendar_events_upserts_and_deletes():
    calendar_table = Mock()
    calendar_table.get_item.return_value = {"Item": {"calendar_id": "cal1", "timezone": "UTC"}}
    with patch.object(subscription_server, "T", SimpleNamespace(calendar=calendar_table)):
        sub = {
            "subscription_id": "sub1",
            "plan_id": "plan1",
            "trial_end": 200,
            "current_period_end": 400,
            "cancel_at_period_end": False,
        }
        plan = {"plan_id": "plan1", "metadata": {"calendar_id": "cal1"}}
        subscription_server.refresh_subscription_calendar_events(sub, plan)

    assert calendar_table.put_item.call_count == 2
    calendar_table.delete_item.assert_called_once_with(Key={"calendar_id": "cal1", "sk": "event#sub_sub1_cancellation"})

