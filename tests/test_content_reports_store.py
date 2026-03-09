from __future__ import annotations

from botocore.exceptions import ClientError
import pytest

from app.services.content_reports_store import create_content_report
from app.core.aws import ddb


def test_create_content_report_includes_topic_condition_checks(monkeypatch):
    captured = {}

    def _fake_transact_write_items(*, TransactItems):
        captured["items"] = TransactItems
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    monkeypatch.setattr(ddb.meta.client, "transact_write_items", _fake_transact_write_items)

    report_id = create_content_report(
        reporter_user_id="u1",
        content_type="profile_photo",
        content_id="u2",
        topics=["spam", "racist"],
        reason_text="Bad content",
    )

    assert report_id
    items = captured["items"]
    assert items[0]["Put"]["ConditionExpression"] == "attribute_not_exists(report_id)"

    topic_checks = [item["ConditionCheck"]["Key"]["report_id"]["S"] for item in items[1:]]
    assert "TOPIC#spam" in topic_checks
    assert "TOPIC#racist" in topic_checks


def test_create_content_report_invalid_topic_rejected_by_db_condition(monkeypatch):
    def _raise_on_transact(*, TransactItems):
        raise ClientError(
            {
                "Error": {
                    "Code": "TransactionCanceledException",
                    "Message": "ConditionalCheckFailed",
                }
            },
            "TransactWriteItems",
        )

    monkeypatch.setattr(ddb.meta.client, "transact_write_items", _raise_on_transact)

    with pytest.raises(ClientError) as exc:
        create_content_report(
            reporter_user_id="u1",
            content_type="profile_photo",
            content_id="u2",
            topics=["not_allowed"],
            reason_text="Bad content",
        )

    assert exc.value.response["Error"]["Code"] == "TransactionCanceledException"
