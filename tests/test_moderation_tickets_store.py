from __future__ import annotations

from botocore.exceptions import ClientError

from app.services.moderation_tickets_store import score_initial_priority, upsert_open_ticket_for_report


def test_score_initial_priority_is_deterministic() -> None:
    assert score_initial_priority(topics=["spam"]) == "medium"
    assert score_initial_priority(topics=["criminal"]) == "high"
    assert score_initial_priority(topics=["extortion"]) == "critical"
    assert score_initial_priority(topics=["spam", "extortion"]) == "critical"
    assert score_initial_priority(topics=[" extortion ", "SPAM"]) == "critical"


def _conditional_check_failed(operation: str = "PutItem") -> ClientError:
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException", "Message": "conditional failed"}}, operation)


def test_upsert_open_ticket_creates_new_ticket(monkeypatch) -> None:
    from app.services import moderation_tickets_store as store

    calls = {}

    def _put_item(**kwargs):
        calls["put"] = kwargs
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    monkeypatch.setattr(store.T.moderation_tickets, "put_item", _put_item)

    out = upsert_open_ticket_for_report(content_type="feed_post", content_id="post_1", topics=["spam", "racist"], now_ts=1700000000)

    assert out["created"] is True
    assert out["status"] == "open"
    assert out["ticket_id"].startswith("modtk_")
    item = calls["put"]["Item"]
    assert item["content_ref"] == "feed_post#post_1"
    assert item["content_ref_status"] == "feed_post#post_1#open"
    assert item["report_count"] == 1
    assert item["aggregated_topics"] == {"spam", "racist"}
    assert item["priority"] == "high"


def test_upsert_open_ticket_updates_existing_open_ticket(monkeypatch) -> None:
    from app.services import moderation_tickets_store as store

    def _put_item(**kwargs):
        raise _conditional_check_failed("PutItem")

    captured = {}

    def _update_item(**kwargs):
        captured.update(kwargs)
        return {"Attributes": {}}

    monkeypatch.setattr(store.T.moderation_tickets, "put_item", _put_item)
    monkeypatch.setattr(store.T.moderation_tickets, "update_item", _update_item)

    out = upsert_open_ticket_for_report(content_type="message", content_id="msg_9", topics=["criminal"], now_ts=1700000001)

    assert out == {"ticket_id": out["ticket_id"], "status": "open", "created": False}
    assert captured["ConditionExpression"] == "#status = :open"
    assert captured["ExpressionAttributeValues"][":inc"] == 1
    assert captured["ExpressionAttributeValues"][":topics"] == {"criminal"}
    assert captured["ExpressionAttributeValues"][":priority"] == "high"


def test_upsert_open_ticket_creates_new_when_existing_is_not_open(monkeypatch) -> None:
    from app.services import moderation_tickets_store as store

    put_calls = []

    def _put_item(**kwargs):
        put_calls.append(kwargs)
        if len(put_calls) == 1:
            raise _conditional_check_failed("PutItem")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def _update_item(**kwargs):
        raise _conditional_check_failed("UpdateItem")

    monkeypatch.setattr(store.T.moderation_tickets, "put_item", _put_item)
    monkeypatch.setattr(store.T.moderation_tickets, "update_item", _update_item)

    out = upsert_open_ticket_for_report(content_type="profile_photo", content_id="u_2", topics=["sexual"], now_ts=1700000002)

    assert out["created"] is True
    assert out["ticket_id"].endswith("_1700000002")
    assert len(put_calls) == 2
