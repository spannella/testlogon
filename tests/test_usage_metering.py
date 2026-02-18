from datetime import datetime, timezone

import pytest

from app.services.usage_metering import (
    build_billing_usage_snapshot_item,
    build_usage_daily_item,
    build_usage_event,
    build_usage_period_totals_item,
    period_bounds_utc,
    period_id_for_datetime,
    period_id_for_timestamp,
    usage_event_id_from_idempotency_key,
)


def test_period_id_for_datetime_month_boundary() -> None:
    end_jan = datetime(2026, 1, 31, 23, 59, 59, tzinfo=timezone.utc)
    start_feb = datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc)

    assert period_id_for_datetime(end_jan) == "2026-01"
    assert period_id_for_datetime(start_feb) == "2026-02"


def test_period_id_for_timestamp_month_boundary() -> None:
    jan = int(datetime(2026, 1, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp())
    feb = int(datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())

    assert period_id_for_timestamp(jan) == "2026-01"
    assert period_id_for_timestamp(feb) == "2026-02"


def test_period_bounds_utc() -> None:
    start, end = period_bounds_utc("2026-12")
    assert start == datetime(2026, 12, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert end == datetime(2027, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_idempotent_event_id_is_stable() -> None:
    key = "user-1|upload|api_upload|req-123|/a.txt|100"
    assert usage_event_id_from_idempotency_key(key) == usage_event_id_from_idempotency_key(key)
    assert usage_event_id_from_idempotency_key(key) != usage_event_id_from_idempotency_key(key + "x")


def test_build_usage_event_contract_and_idempotency() -> None:
    event = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=42,
        source="api_upload",
        resource_path="/docs/a.txt",
        request_id="r1",
    )
    assert set(event.keys()) == {
        "event_id",
        "user_id",
        "event_type",
        "bytes",
        "resource_path",
        "timestamp",
        "request_id",
        "source",
        "idempotency_key",
    }
    again = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=42,
        source="api_upload",
        resource_path="/docs/a.txt",
        request_id="r1",
    )
    assert event["event_id"] == again["event_id"]


def test_build_usage_event_rejects_negative_bytes() -> None:
    with pytest.raises(ValueError):
        build_usage_event(user_id="u1", event_type="download", bytes_count=-1, source="download")


def test_aggregate_item_builders() -> None:
    period = build_usage_period_totals_item(user_id="u1", period_id="2026-03", now="2026-03-20T00:00:00+00:00")
    assert period["PK"] == "USER#u1"
    assert period["SK"] == "USAGE#PERIOD#2026-03"
    assert period["upload_bytes_total"] == 0

    daily = build_usage_daily_item(user_id="u1", day_utc="2026-03-20", now="2026-03-20T00:00:00+00:00")
    assert daily["SK"] == "USAGE#DAY#2026-03-20"
    assert daily["period_id"] == "2026-03"

    snap = build_billing_usage_snapshot_item(user_id="u1", period_id="2026-03", version=2, status="draft")
    assert snap["SK"] == "USAGE#SNAPSHOT#2026-03#V0002"
    assert snap["status"] == "draft"


def test_snapshot_version_validation() -> None:
    with pytest.raises(ValueError):
        build_billing_usage_snapshot_item(user_id="u1", period_id="2026-03", version=0)

class _FakeUsageTable:
    def __init__(self):
        self.events = set()
        self.put_calls = 0
        self.update_calls = 0

    def put_item(self, *, Item, ConditionExpression):
        self.put_calls += 1
        sk = Item["SK"]
        if sk in self.events:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "dup"}}, "PutItem")
        self.events.add(sk)

    def update_item(self, **kwargs):
        self.update_calls += 1


def test_record_usage_event_and_aggregates_is_idempotent() -> None:
    from app.services.usage_metering import record_usage_event_and_aggregates

    table = _FakeUsageTable()
    event = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=99,
        source="api_upload",
        resource_path="/docs/a.txt",
        request_id="req-1",
    )

    assert record_usage_event_and_aggregates(table, event) is True
    assert table.update_calls == 2

    assert record_usage_event_and_aggregates(table, event) is False
    assert table.update_calls == 2


def test_record_usage_event_without_aggregate_mutation() -> None:
    from app.services.usage_metering import record_usage_event_and_aggregates

    table = _FakeUsageTable()
    event = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=50,
        source="upload_zip_total",
        resource_path="/",
    )
    assert record_usage_event_and_aggregates(table, event, apply_aggregates=False) is True
    assert table.update_calls == 0


def test_storage_delta_event_allows_negative_bytes() -> None:
    event = build_usage_event(
        user_id="u1",
        event_type="storage_delta",
        bytes_count=-10,
        source="delete_soft",
        resource_path="/docs/a.txt",
    )
    assert event["bytes"] == -10


class _ApplyingUsageTable:
    def __init__(self):
        self.items = {}

    def put_item(self, *, Item, ConditionExpression=None):
        key = (Item["PK"], Item["SK"])
        if ConditionExpression == "attribute_not_exists(SK)" and key in self.items:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "dup"}}, "PutItem")
        self.items[key] = dict(Item)

    def update_item(self, *, Key, UpdateExpression=None, ExpressionAttributeValues=None, **kwargs):
        item = self.items.get((Key["PK"], Key["SK"]), {"PK": Key["PK"], "SK": Key["SK"]})
        vals = ExpressionAttributeValues or {}
        if "USAGE#PERIOD#" in Key["SK"]:
            item["entity_type"] = "usage_period_totals"
            item["user_id"] = vals[":user_id"]
            item["period_id"] = vals[":period_id"]
            item["upload_bytes_total"] = int(item.get("upload_bytes_total", 0)) + int(vals[":upload_inc"])
            item["download_bytes_total"] = int(item.get("download_bytes_total", 0)) + int(vals[":download_inc"])
            item["storage_bytes_current"] = int(item.get("storage_bytes_current", 0)) + int(vals[":storage_delta"])
            item["storage_bytes_peak"] = int(item.get("storage_bytes_peak", 0))
            item["storage_byte_seconds"] = int(item.get("storage_byte_seconds", 0))
            item["updated_at"] = vals[":updated_at"]
            item["ttl_epoch"] = vals[":ttl_epoch"]
        elif "USAGE#DAY#" in Key["SK"]:
            item["entity_type"] = "usage_daily"
            item["user_id"] = vals[":user_id"]
            item["day_utc"] = vals[":day_utc"]
            item["period_id"] = vals[":period_id"]
            item["upload_bytes_total"] = int(item.get("upload_bytes_total", 0)) + int(vals[":upload_inc"])
            item["download_bytes_total"] = int(item.get("download_bytes_total", 0)) + int(vals[":download_inc"])
            item["storage_bytes_end_of_day"] = int(item.get("storage_bytes_end_of_day", 0)) + int(vals[":storage_delta"])
            item["updated_at"] = vals[":updated_at"]
            item["ttl_epoch"] = vals[":ttl_epoch"]
        self.items[(Key["PK"], Key["SK"])] = item


def test_event_aggregate_correctness_across_event_types() -> None:
    from app.services.usage_metering import record_usage_event_and_aggregates

    table = _ApplyingUsageTable()
    upload_event = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=100,
        source="api_upload",
        resource_path="/docs/a.txt",
        request_id="req-upload",
        timestamp="2026-02-10T00:00:00+00:00",
    )
    download_event = build_usage_event(
        user_id="u1",
        event_type="download",
        bytes_count=40,
        source="download_file",
        resource_path="/docs/a.txt",
        request_id="req-download",
        timestamp="2026-02-10T00:01:00+00:00",
    )
    storage_event = build_usage_event(
        user_id="u1",
        event_type="storage_delta",
        bytes_count=-25,
        source="delete_soft",
        resource_path="/docs/a.txt",
        request_id="req-delete",
        timestamp="2026-02-10T00:02:00+00:00",
    )

    assert record_usage_event_and_aggregates(table, upload_event) is True
    assert record_usage_event_and_aggregates(table, download_event) is True
    assert record_usage_event_and_aggregates(table, storage_event) is True

    period = table.items[("USER#u1", "USAGE#PERIOD#2026-02")]
    assert period["upload_bytes_total"] == 100
    assert period["download_bytes_total"] == 40
    assert period["storage_bytes_current"] == -25

    daily = table.items[("USER#u1", "USAGE#DAY#2026-02-10")]
    assert daily["upload_bytes_total"] == 100
    assert daily["download_bytes_total"] == 40
    assert daily["storage_bytes_end_of_day"] == -25


def test_retry_idempotency_prevents_double_counting_across_retries() -> None:
    from app.services.usage_metering import record_usage_event_and_aggregates

    table = _ApplyingUsageTable()
    event = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=123,
        source="upload_archive_entry",
        resource_path="/archive/a.txt",
        request_id="retry-me",
        timestamp="2026-02-11T00:00:00+00:00",
    )

    assert record_usage_event_and_aggregates(table, event) is True
    assert record_usage_event_and_aggregates(table, event) is False

    period = table.items[("USER#u1", "USAGE#PERIOD#2026-02")]
    assert period["upload_bytes_total"] == 123


class _FlakyPutUsageTable(_ApplyingUsageTable):
    def __init__(self):
        super().__init__()
        self.fail_next_put = True

    def put_item(self, *, Item, ConditionExpression=None):
        if self.fail_next_put:
            self.fail_next_put = False
            raise RuntimeError("simulated metering pipeline outage")
        return super().put_item(Item=Item, ConditionExpression=ConditionExpression)


def test_pipeline_outage_then_replay_applies_once() -> None:
    from app.services.usage_metering import record_usage_event_and_aggregates

    table = _FlakyPutUsageTable()
    event = build_usage_event(
        user_id="u1",
        event_type="download",
        bytes_count=77,
        source="shared_download",
        resource_path="/shared/report.csv",
        request_id="replay-1",
        timestamp="2026-02-12T00:00:00+00:00",
    )

    with pytest.raises(RuntimeError):
        record_usage_event_and_aggregates(table, event)

    assert record_usage_event_and_aggregates(table, event) is True
    period = table.items[("USER#u1", "USAGE#PERIOD#2026-02")]
    assert period["download_bytes_total"] == 77
