from scripts.backfill_newsfeed_schedule_due_index import plan_update


def test_plan_update_marks_scheduled_posts_without_index_attrs() -> None:
    item = {
        "Entity": "Post",
        "post_id": "p1",
        "status": "scheduled",
        "publish_at": 1767225600,
    }
    should_update, reason, desired = plan_update(item)
    assert should_update is True
    assert reason is None
    assert desired["GSI_SCHEDULE_PK"] == "SCHEDULED"
    assert desired["GSI_SCHEDULE_SK"] == "001767225600#POST#p1"


def test_plan_update_is_idempotent_when_attrs_already_present() -> None:
    item = {
        "Entity": "Post",
        "post_id": "p1",
        "status": "scheduled",
        "publish_at": 1767225600,
        "GSI_SCHEDULE_PK": "SCHEDULED",
        "GSI_SCHEDULE_SK": "001767225600#POST#p1",
    }
    should_update, reason, desired = plan_update(item)
    assert should_update is False
    assert reason is None
    assert desired == {}


def test_plan_update_skips_non_scheduled_posts() -> None:
    item = {
        "Entity": "Post",
        "post_id": "p1",
        "status": "published",
        "publish_at": 1767225600,
    }
    should_update, reason, desired = plan_update(item)
    assert should_update is False
    assert reason is None
    assert desired == {}


def test_plan_update_reports_malformed_scheduled_publish_at() -> None:
    item = {
        "Entity": "Post",
        "post_id": "p1",
        "status": "scheduled",
        "publish_at": "not-a-number",
    }
    should_update, reason, desired = plan_update(item)
    assert should_update is False
    assert reason == "invalid_publish_at"
    assert desired == {}
