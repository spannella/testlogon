from __future__ import annotations

from datetime import datetime, timezone

from app.services.entitlement_policy import EntitlementGrant, EntitlementPolicyContract


def _ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def test_check_access_file_download_example() -> None:
    policy = EntitlementPolicyContract()
    policy.upsert_grant(
        EntitlementGrant(
            entitlement_id="ent-file-1",
            subject="user:42",
            status="active",
            starts_at=_ts("2026-01-01T00:00:00Z"),
            ends_at=_ts("2026-02-01T00:00:00Z"),
            allowed_actions={"download_file"},
            scope={"date": "2026-01-15"},
            usage_limit=0,
        )
    )
    allowed = policy.check_access(
        subject="user:42",
        action="download_file",
        resource={"date": "2026-01-15", "file_id": "f1"},
        now=_ts("2026-01-16T00:00:00Z"),
    )
    denied = policy.check_access(
        subject="user:42",
        action="download_file",
        resource={"date": "2026-01-16", "file_id": "f2"},
        now=_ts("2026-01-16T00:00:00Z"),
    )
    assert allowed.allowed is True
    assert denied.allowed is False
    assert denied.reason_code == "denied"


def test_check_access_external_api_example_and_expired_error() -> None:
    policy = EntitlementPolicyContract()
    policy.upsert_grant(
        EntitlementGrant(
            entitlement_id="ent-api-1",
            subject="api_key:abc",
            status="active",
            starts_at=_ts("2026-01-01T00:00:00Z"),
            ends_at=_ts("2026-01-10T00:00:00Z"),
            allowed_actions={"call_route"},
            scope={"route_id": "POST:/v1/messages/send"},
        )
    )
    expired = policy.check_access(
        subject="api_key:abc",
        action="call_route",
        resource={"route_id": "POST:/v1/messages/send"},
        now=_ts("2026-01-10T00:00:00Z"),
    )
    assert expired.allowed is False
    assert expired.reason_code == "expired"


def test_check_access_internal_api_example() -> None:
    policy = EntitlementPolicyContract()
    policy.upsert_grant(
        EntitlementGrant(
            entitlement_id="ent-int-1",
            subject="svc:filemanager",
            status="active",
            starts_at=_ts("2026-01-01T00:00:00Z"),
            ends_at=None,
            allowed_actions={"internal_call"},
            scope={"namespace": ["messaging.*", "filemanager.*"]},
        )
    )
    out = policy.check_access(
        subject="svc:filemanager",
        action="internal_call",
        resource={"namespace": "filemanager.*"},
        now=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    assert out.allowed is True


def test_consume_usage_enforces_exhausted_and_idempotent_replay() -> None:
    policy = EntitlementPolicyContract()
    policy.upsert_grant(
        EntitlementGrant(
            entitlement_id="ent-use-1",
            subject="api_key:metered",
            status="active",
            starts_at=_ts("2026-01-01T00:00:00Z"),
            ends_at=None,
            allowed_actions={"request_units"},
            scope={},
            usage_limit=10,
            usage_consumed=0,
        )
    )

    first = policy.consume_usage(subject="api_key:metered", meter="request_units", amount=4, idempotency_key="k1")
    replay = policy.consume_usage(subject="api_key:metered", meter="request_units", amount=4, idempotency_key="k1")
    conflict = policy.consume_usage(subject="api_key:metered", meter="request_units", amount=5, idempotency_key="k1")
    over = policy.consume_usage(subject="api_key:metered", meter="request_units", amount=7, idempotency_key="k2")

    assert first.consumed is True
    assert first.usage_consumed == 4
    assert replay.consumed is True
    assert replay.replayed is True
    assert replay.usage_consumed == 4
    assert conflict.consumed is False
    assert conflict.reason_code == "idempotency_conflict"
    assert over.consumed is False
    assert over.reason_code == "exhausted"
