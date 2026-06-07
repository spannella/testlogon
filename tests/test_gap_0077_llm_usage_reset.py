"""GAP-0077 regression: monthly LLM usage reset must be automated.

Offline test (no real AWS, no network). Uses moto's in-memory DynamoDB and
patches KMS encrypt/decrypt so no real KMS key is required.

Fails before the fix:
  - ``usage_reset_at`` was initialized to 0 even when a budget was set, so the
    reset filter never matched.
  - ``_run_reset_pass`` / ``start_llm_usage_reset_task`` did not exist.

Passes after the fix: the reset pass zeroes monthly usage for due
budget-exceeded keys and advances ``usage_reset_at``; not-yet-due keys and
budgetless keys are untouched.
"""
from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

import app.services.llm_provider_keys as svc
from app.core.time import now_ts


@pytest.fixture
def llm_keys_table(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="llm_provider_keys",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        import app.core.tables as tables_mod

        original = tables_mod.T.llm_provider_keys
        object.__setattr__(tables_mod.T, "llm_provider_keys", ddb.Table("llm_provider_keys"))

        # Avoid requiring a real KMS key — store/return the plaintext as-is.
        monkeypatch.setattr(svc, "kms_encrypt", lambda s: "enc::" + s)
        monkeypatch.setattr(svc, "kms_decrypt", lambda c: c[len("enc::"):].encode("utf-8"))

        try:
            yield ddb.Table("llm_provider_keys")
        finally:
            object.__setattr__(tables_mod.T, "llm_provider_keys", original)


def _backdate_reset(table, user_id: str, key_id: str, ts: int) -> None:
    table.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
        UpdateExpression="SET usage_reset_at = :t",
        ExpressionAttributeValues={":t": ts},
    )


def test_usage_reset_at_set_on_key_creation(llm_keys_table):
    """After fix: usage_reset_at is non-zero when monthly_budget_cents > 0."""
    key = svc.add_key(
        user_id="u1", provider="openai", label="test",
        api_key="sk-x", monthly_budget_cents=1000,
    )
    assert key["usage_reset_at"] > now_ts()


def test_reset_pass_zeroes_overdue_budget_exceeded_key(llm_keys_table):
    """_run_reset_pass zeroes usage and reactivates a due budget_exceeded key."""
    user_id = "u1"
    key = svc.add_key(
        user_id=user_id, provider="openai", label="test",
        api_key="sk-x", monthly_budget_cents=100,
    )
    key_id = key["key_id"]

    # Drive usage past budget -> status flips to budget_exceeded.
    svc.record_usage(user_id=user_id, key_id=key_id, tokens=100, cost_cents=100)
    after = svc.get_key(user_id=user_id, key_id=key_id)
    assert after["status"] == "budget_exceeded"
    assert after["current_month_usage_cents"] == 100

    # Backdate the reset date into the past.
    _backdate_reset(llm_keys_table, user_id, key_id, 1)

    count = svc._run_reset_pass()
    assert count == 1

    reset = svc.get_key(user_id=user_id, key_id=key_id)
    assert reset["current_month_usage_cents"] == 0
    assert reset["status"] == "active"
    assert reset["usage_reset_at"] > now_ts()


def test_reset_pass_leaves_not_yet_due_key_untouched(llm_keys_table):
    """A key whose usage_reset_at is in the future must not be reset."""
    user_id = "u3"
    key = svc.add_key(
        user_id=user_id, provider="openai", label="future",
        api_key="sk-z", monthly_budget_cents=100,
    )
    key_id = key["key_id"]
    svc.record_usage(user_id=user_id, key_id=key_id, tokens=100, cost_cents=100)

    before = svc.get_key(user_id=user_id, key_id=key_id)
    assert before["status"] == "budget_exceeded"
    future_reset = before["usage_reset_at"]
    assert future_reset > now_ts()

    count = svc._run_reset_pass()
    assert count == 0

    after = svc.get_key(user_id=user_id, key_id=key_id)
    assert after["status"] == "budget_exceeded"
    assert after["current_month_usage_cents"] == 100
    assert after["usage_reset_at"] == future_reset


def test_reset_pass_skips_key_without_budget(llm_keys_table):
    """Keys with monthly_budget_cents=0 (unlimited) are never reset."""
    key = svc.add_key(
        user_id="u2", provider="openai", label="free",
        api_key="sk-y", monthly_budget_cents=0,
    )
    assert key["usage_reset_at"] == 0
    assert svc._run_reset_pass() == 0


def test_reset_pass_skips_suspended_key(llm_keys_table):
    """A due key that is suspended (not budget_exceeded) is not reactivated."""
    user_id = "u4"
    key = svc.add_key(
        user_id=user_id, provider="openai", label="suspended",
        api_key="sk-s", monthly_budget_cents=100,
    )
    key_id = key["key_id"]
    svc.record_usage(user_id=user_id, key_id=key_id, tokens=50, cost_cents=50)
    # Admin suspends + backdate reset.
    llm_keys_table.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"KEY#{key_id}"},
        UpdateExpression="SET #st = :s, usage_reset_at = :t",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": "suspended", ":t": 1},
    )

    assert svc._run_reset_pass() == 0
    after = svc.get_key(user_id=user_id, key_id=key_id)
    assert after["status"] == "suspended"
    assert after["current_month_usage_cents"] == 50
