from datetime import datetime, timezone

import pytest

from app.services.usage_metering import (
    USAGE_EVENT_SOURCES,
    build_usage_source_idempotency_key,
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
    assert period["message_send_count_total"] == 0
    assert period["post_publish_count_total"] == 0

    daily = build_usage_daily_item(user_id="u1", day_utc="2026-03-20", now="2026-03-20T00:00:00+00:00")
    assert daily["SK"] == "USAGE#DAY#2026-03-20"
    assert daily["period_id"] == "2026-03"
    assert daily["message_send_count_total"] == 0
    assert daily["post_publish_count_total"] == 0

    snap = build_billing_usage_snapshot_item(user_id="u1", period_id="2026-03", version=2, status="draft")
    assert snap["SK"] == "USAGE#SNAPSHOT#2026-03#V0002"
    assert snap["status"] == "draft"
    assert snap["schema_version"] == 2
    assert snap["message_send_count_total"] == 0
    assert snap["post_publish_count_total"] == 0
    assert snap["messaging_upload_bytes_total"] == 0
    assert snap["messaging_download_bytes_total"] == 0
    assert snap["newsfeed_upload_bytes_total"] == 0
    assert snap["newsfeed_download_bytes_total"] == 0


def test_snapshot_version_validation() -> None:
    with pytest.raises(ValueError):
        build_billing_usage_snapshot_item(user_id="u1", period_id="2026-03", version=0)


def test_snapshot_schema_version_validation() -> None:
    with pytest.raises(ValueError):
        build_billing_usage_snapshot_item(user_id="u1", period_id="2026-03", schema_version=0)


def test_mtr001_taxonomy_includes_required_messaging_newsfeed_sources() -> None:
    assert {
        "messaging_send",
        "newsfeed_post",
        "messaging_attachment_upload",
        "messaging_attachment_download",
        "newsfeed_attachment_upload",
        "newsfeed_attachment_download",
    }.issubset(USAGE_EVENT_SOURCES)

    # existing file-manager sources remain available for backward compatibility
    assert {"api_upload", "download", "shared_download", "delete_soft"}.issubset(USAGE_EVENT_SOURCES)


def test_mtr001_idempotency_key_patterns_for_new_sources() -> None:
    assert build_usage_source_idempotency_key(
        "messaging_send",
        user_id="u1",
        conversation_id="c1",
        message_id="m1",
    ) == "u1|messaging_send|c1|m1"

    assert build_usage_source_idempotency_key(
        "newsfeed_post",
        user_id="u1",
        post_id="p1",
    ) == "u1|newsfeed_post|p1"

    assert build_usage_source_idempotency_key(
        "messaging_attachment_upload",
        user_id="u1",
        attachment_key="attachments/a.png",
        operation_id="op-1",
    ) == "u1|messaging_attachment_upload|attachments/a.png|op-1"

    with pytest.raises(ValueError):
        build_usage_source_idempotency_key("not-a-source", user_id="u1")

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
            item["message_send_count_total"] = int(item.get("message_send_count_total", 0)) + int(vals.get(":message_send_inc", 0))
            item["post_publish_count_total"] = int(item.get("post_publish_count_total", 0)) + int(vals.get(":post_publish_inc", 0))
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
            item["message_send_count_total"] = int(item.get("message_send_count_total", 0)) + int(vals.get(":message_send_inc", 0))
            item["post_publish_count_total"] = int(item.get("post_publish_count_total", 0)) + int(vals.get(":post_publish_inc", 0))
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


def test_mtr002_unit_counters_increment_and_backfill_missing_fields() -> None:
    from app.services.usage_metering import record_usage_event_and_aggregates

    table = _ApplyingUsageTable()

    # Simulate older aggregate rows that predate unit counter columns.
    table.items[("USER#u1", "USAGE#PERIOD#2026-02")] = {
        "PK": "USER#u1",
        "SK": "USAGE#PERIOD#2026-02",
        "entity_type": "usage_period_totals",
        "user_id": "u1",
        "period_id": "2026-02",
        "upload_bytes_total": 0,
        "download_bytes_total": 0,
        "storage_bytes_current": 0,
    }
    table.items[("USER#u1", "USAGE#DAY#2026-02-12")] = {
        "PK": "USER#u1",
        "SK": "USAGE#DAY#2026-02-12",
        "entity_type": "usage_daily",
        "user_id": "u1",
        "day_utc": "2026-02-12",
        "period_id": "2026-02",
        "upload_bytes_total": 0,
        "download_bytes_total": 0,
        "storage_bytes_end_of_day": 0,
    }

    msg_event = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=10,
        source="messaging_send",
        timestamp="2026-02-12T00:00:00+00:00",
        idempotency_key="u1|messaging_send|c1|m1",
    )
    post_event = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=20,
        source="newsfeed_post",
        timestamp="2026-02-12T00:01:00+00:00",
        idempotency_key="u1|newsfeed_post|p1",
    )

    assert record_usage_event_and_aggregates(table, msg_event) is True
    assert record_usage_event_and_aggregates(table, post_event) is True

    period = table.items[("USER#u1", "USAGE#PERIOD#2026-02")]
    daily = table.items[("USER#u1", "USAGE#DAY#2026-02-12")]

    assert period["message_send_count_total"] == 1
    assert period["post_publish_count_total"] == 1
    assert daily["message_send_count_total"] == 1
    assert daily["post_publish_count_total"] == 1


def test_qa001_message_and_post_events_are_idempotent_on_retries() -> None:
    from app.services.usage_metering import record_usage_event_and_aggregates

    table = _ApplyingUsageTable()
    message_event = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=0,
        source="messaging_send",
        timestamp="2026-02-15T12:00:00+00:00",
        idempotency_key=build_usage_source_idempotency_key(
            "messaging_send",
            user_id="u1",
            conversation_id="c1",
            message_id="m1",
        ),
    )
    post_event = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=0,
        source="newsfeed_post",
        timestamp="2026-02-15T12:00:01+00:00",
        idempotency_key=build_usage_source_idempotency_key(
            "newsfeed_post",
            user_id="u1",
            post_id="p1",
        ),
    )

    assert record_usage_event_and_aggregates(table, message_event) is True
    assert record_usage_event_and_aggregates(table, message_event) is False
    assert record_usage_event_and_aggregates(table, post_event) is True
    assert record_usage_event_and_aggregates(table, post_event) is False

    period = table.items[("USER#u1", "USAGE#PERIOD#2026-02")]
    daily = table.items[("USER#u1", "USAGE#DAY#2026-02-15")]
    assert period["message_send_count_total"] == 1
    assert period["post_publish_count_total"] == 1
    assert daily["message_send_count_total"] == 1
    assert daily["post_publish_count_total"] == 1


def test_qa001_mixed_event_types_roll_up_in_same_period_and_day() -> None:
    from app.services.usage_metering import record_usage_event_and_aggregates

    table = _ApplyingUsageTable()
    events = [
        build_usage_event(
            user_id="u1",
            event_type="upload",
            bytes_count=0,
            source="messaging_send",
            timestamp="2026-02-16T09:00:00+00:00",
            idempotency_key=build_usage_source_idempotency_key(
                "messaging_send",
                user_id="u1",
                conversation_id="c1",
                message_id="m2",
            ),
        ),
        build_usage_event(
            user_id="u1",
            event_type="upload",
            bytes_count=0,
            source="newsfeed_post",
            timestamp="2026-02-16T09:00:01+00:00",
            idempotency_key=build_usage_source_idempotency_key(
                "newsfeed_post",
                user_id="u1",
                post_id="p2",
            ),
        ),
        build_usage_event(
            user_id="u1",
            event_type="upload",
            bytes_count=120,
            source="messaging_attachment_upload",
            timestamp="2026-02-16T09:01:00+00:00",
            idempotency_key=build_usage_source_idempotency_key(
                "messaging_attachment_upload",
                user_id="u1",
                attachment_key="msg/a.png",
                operation_id="op-1",
            ),
        ),
        build_usage_event(
            user_id="u1",
            event_type="download",
            bytes_count=80,
            source="messaging_attachment_download",
            timestamp="2026-02-16T09:02:00+00:00",
            idempotency_key=build_usage_source_idempotency_key(
                "messaging_attachment_download",
                user_id="u1",
                attachment_key="msg/a.png",
                operation_id="op-2",
            ),
        ),
        build_usage_event(
            user_id="u1",
            event_type="upload",
            bytes_count=50,
            source="newsfeed_attachment_upload",
            timestamp="2026-02-16T09:03:00+00:00",
            idempotency_key=build_usage_source_idempotency_key(
                "newsfeed_attachment_upload",
                user_id="u1",
                attachment_key="post/a.mp4",
                operation_id="op-3",
            ),
        ),
        build_usage_event(
            user_id="u1",
            event_type="download",
            bytes_count=20,
            source="newsfeed_attachment_download",
            timestamp="2026-02-16T09:04:00+00:00",
            idempotency_key=build_usage_source_idempotency_key(
                "newsfeed_attachment_download",
                user_id="u1",
                attachment_key="post/a.mp4",
                operation_id="op-4",
            ),
        ),
    ]

    for event in events:
        assert record_usage_event_and_aggregates(table, event) is True

    period = table.items[("USER#u1", "USAGE#PERIOD#2026-02")]
    daily = table.items[("USER#u1", "USAGE#DAY#2026-02-16")]

    assert period["message_send_count_total"] == 1
    assert period["post_publish_count_total"] == 1
    assert period["upload_bytes_total"] == 170
    assert period["download_bytes_total"] == 100

    assert daily["message_send_count_total"] == 1
    assert daily["post_publish_count_total"] == 1
    assert daily["upload_bytes_total"] == 170
    assert daily["download_bytes_total"] == 100


def test_ops001_metrics_emit_period_and_surface_labels(monkeypatch) -> None:
    from app.services import usage_metering

    table = _ApplyingUsageTable()
    event = build_usage_event(
        user_id="u1",
        event_type="upload",
        bytes_count=42,
        source="messaging_attachment_upload",
        timestamp="2026-02-12T00:00:00+00:00",
        idempotency_key="u1|messaging_attachment_upload|b/key|op1",
    )

    seen = {"event": [], "bytes": [], "units": [], "transfer": []}

    monkeypatch.setattr(usage_metering, "record_usage_metering_event", lambda *a, **k: seen["event"].append((a, k)))
    monkeypatch.setattr(usage_metering, "record_usage_metering_bytes", lambda *a, **k: seen["bytes"].append((a, k)))
    monkeypatch.setattr(usage_metering, "record_usage_surface_units", lambda *a, **k: seen["units"].append((a, k)))
    monkeypatch.setattr(usage_metering, "record_usage_surface_transfer_bytes", lambda *a, **k: seen["transfer"].append((a, k)))

    assert usage_metering.record_usage_event_and_aggregates(table, event) is True

    assert seen["event"][0][1]["period_id"] == "2026-02"
    assert seen["bytes"][0][1]["period_id"] == "2026-02"
    assert seen["transfer"][0][0][0] == "messaging"
    assert seen["transfer"][0][0][1] == "upload"
    assert seen["transfer"][0][1]["period_id"] == "2026-02"
    assert seen["units"] == []
