"""Unit tests for CALL-011: Pay-per-minute call billing.

Tests:
  - Heartbeat accumulation and billing cycle triggers
  - Wallet debit and creator credit
  - Finalization with pro-rated charges
  - Insufficient balance handling
  - Call rate CRUD
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from decimal import Decimal

import pytest

from app.services import messaging_call_sessions as sessions
from app.services import messaging_call_lifecycle as lifecycle
from app.services import call_billing_timer as billing
from app.services import billing_shared


# ---------------------------------------------------------------------------
# Fake DDB tables
# ---------------------------------------------------------------------------

@dataclass
class _FakeCallSessionTable:
    items: dict[str, dict] = field(default_factory=dict)

    def put_item(self, *, Item):
        self.items[str(Item["call_id"])] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get(str(Key["call_id"]))
        return {"Item": dict(item)} if item else {}

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues=None, **kw):
        call_id = str(Key["call_id"])
        item = self.items.get(call_id, {})
        # Simple parser for SET expressions
        if UpdateExpression.startswith("SET "):
            assignments = UpdateExpression[4:].split(",")
            for assignment in assignments:
                assignment = assignment.strip()
                parts = assignment.split("=", 1)
                if len(parts) != 2:
                    continue
                field_name = parts[0].strip()
                value_ref = parts[1].strip()
                if ExpressionAttributeValues and value_ref in ExpressionAttributeValues:
                    item[field_name] = ExpressionAttributeValues[value_ref]
        self.items[call_id] = item
        return {"Attributes": dict(item)}

    def query(self, **kwargs):
        conv_id = (kwargs.get("ExpressionAttributeValues") or {}).get(":conversation_id")
        items = [item for item in self.items.values() if item.get("conversation_id") == conv_id]
        items.sort(key=lambda i: int(i.get("start_ts_sort") or 0), reverse=not kwargs.get("ScanIndexForward", False))
        limit = int(kwargs.get("Limit") or len(items))
        return {"Items": items[:limit]}


@dataclass
class _FakeBillingTable:
    items: dict[str, dict] = field(default_factory=dict)

    def _key(self, pk: str, sk: str) -> str:
        return f"{pk}|{sk}"

    def put_item(self, *, Item):
        pk = str(Item.get("pk", ""))
        sk = str(Item.get("sk", ""))
        self.items[self._key(pk, sk)] = dict(Item)

    def get_item(self, *, Key):
        pk = str(Key.get("pk", ""))
        sk = str(Key.get("sk", ""))
        item = self.items.get(self._key(pk, sk))
        return {"Item": dict(item)} if item else {}

    def delete_item(self, *, Key):
        pk = str(Key.get("pk", ""))
        sk = str(Key.get("sk", ""))
        self.items.pop(self._key(pk, sk), None)

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeValues=None,
                    ConditionExpression=None, ReturnValues=None, **kw):
        pk = str(Key.get("pk", ""))
        sk = str(Key.get("sk", ""))
        k = self._key(pk, sk)
        item = self.items.get(k, {"pk": pk, "sk": sk})

        # Handle condition expression for wallet debits
        if ConditionExpression and "wallet_balance_cents >= :needed" in ConditionExpression:
            balance = int(item.get("wallet_balance_cents", 0))
            needed = int(ExpressionAttributeValues.get(":needed", 0))
            if balance < needed:
                from botocore.exceptions import ClientError
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Condition not met"}},
                    "UpdateItem",
                )

        # Simple SET parser
        if UpdateExpression.startswith("SET "):
            assignments = UpdateExpression[4:].split(",")
            for assignment in assignments:
                assignment = assignment.strip()
                parts = assignment.split("=", 1)
                if len(parts) != 2:
                    continue
                field_name = parts[0].strip()
                value_expr = parts[1].strip()

                if "if_not_exists" in value_expr and "+" in value_expr:
                    # if_not_exists(field, :z) + :d
                    delta_ref = value_expr.split("+")[1].strip()
                    delta = ExpressionAttributeValues.get(delta_ref, 0) if ExpressionAttributeValues else 0
                    current = int(item.get(field_name, 0))
                    item[field_name] = current + int(delta)
                elif "+" in value_expr:
                    # field + :d
                    delta_ref = value_expr.split("+")[1].strip()
                    delta = ExpressionAttributeValues.get(delta_ref, 0) if ExpressionAttributeValues else 0
                    current = int(item.get(field_name, 0))
                    item[field_name] = current + int(delta)
                elif ExpressionAttributeValues and value_expr in ExpressionAttributeValues:
                    item[field_name] = ExpressionAttributeValues[value_expr]

        self.items[k] = item
        if ReturnValues == "ALL_NEW":
            return {"Attributes": dict(item)}
        return {}


# ---------------------------------------------------------------------------
# Test clock and setup
# ---------------------------------------------------------------------------

_clock = 1700000000


def _setup(monkeypatch, *, wallet_cents: int = 10000, clock: int = _clock):
    """Create fake tables and patch modules."""
    call_table = _FakeCallSessionTable()
    billing_table = _FakeBillingTable()

    # Patch sessions module
    monkeypatch.setattr(sessions, "_table", lambda: call_table)
    monkeypatch.setattr(sessions, "now_ts", lambda: clock)

    # Patch lifecycle module
    monkeypatch.setattr(lifecycle, "now_ts", lambda: clock)

    # Patch billing timer module
    monkeypatch.setattr(billing, "now_ts", lambda: clock)

    # Patch T.billing and T.message_call_sessions
    class FakeTables:
        pass
    fake_T = FakeTables()
    fake_T.billing = billing_table
    fake_T.message_call_sessions = call_table
    monkeypatch.setattr(billing, "T", fake_T)

    # Patch billing_shared functions to use our fake table
    def fake_get_wallet(table, pk):
        resp = table.get_item(Key={"pk": pk, "sk": "WALLET"})
        row = resp.get("Item") or {}
        return {
            "wallet_balance_cents": int(row.get("wallet_balance_cents", 0)),
            "currency": row.get("currency", "usd"),
            "updated_at": row.get("updated_at"),
        }

    def fake_apply_delta(table, pk, delta_cents, *, currency="usd"):
        if delta_cents >= 0:
            result = table.update_item(
                Key={"pk": pk, "sk": "WALLET"},
                UpdateExpression="SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :d, currency = :c, updated_at = :t",
                ExpressionAttributeValues={":z": 0, ":d": delta_cents, ":c": currency, ":t": clock},
                ReturnValues="ALL_NEW",
            )
        else:
            needed = abs(delta_cents)
            result = table.update_item(
                Key={"pk": pk, "sk": "WALLET"},
                UpdateExpression="SET wallet_balance_cents = wallet_balance_cents + :d, updated_at = :t",
                ConditionExpression="wallet_balance_cents >= :needed",
                ExpressionAttributeValues={":d": delta_cents, ":t": clock, ":needed": needed},
                ReturnValues="ALL_NEW",
            )
        return int(result["Attributes"].get("wallet_balance_cents", 0))

    monkeypatch.setattr(billing, "get_wallet_balance", fake_get_wallet)
    monkeypatch.setattr(billing, "apply_wallet_delta", fake_apply_delta)

    # Patch settings
    class FakeSettings:
        call_billing_enabled = True
        call_billing_platform_fee_percent = 20
        call_billing_cycle_seconds = 60
        call_billing_max_rate_cents_per_min = 9999
        call_billing_heartbeat_interval_seconds = 15
        call_billing_low_balance_warning_cents = 500
        call_billing_grace_period_seconds = 10
    monkeypatch.setattr(billing, "S", FakeSettings())

    # Seed caller wallet
    if wallet_cents > 0:
        billing_table.put_item(Item={
            "pk": "USER#caller",
            "sk": "WALLET",
            "wallet_balance_cents": wallet_cents,
            "currency": "usd",
            "updated_at": clock,
        })

    return call_table, billing_table


def _create_paid_call(monkeypatch, *, wallet_cents=10000, clock=_clock):
    """Create a paid call in connected state."""
    call_table, billing_table = _setup(monkeypatch, wallet_cents=wallet_cents, clock=clock)

    participants = {"caller", "callee"}
    record, _ = lifecycle.create_invite(
        call_id="paid1",
        conversation_id="conv1",
        actor_user_id="caller",
        caller_user_id="caller",
        callee_user_id="callee",
        initial_mode="audio",
        participant_resolver=lambda _: participants,
        timeline_emitter=lambda **kw: kw,
        paid=True,
        rate_cents_per_min=500,
        max_duration_seconds=7200,
    )

    # Accept
    lifecycle.accept_invite(
        call_id="paid1",
        actor_user_id="callee",
        timeline_emitter=lambda **kw: kw,
    )

    # Connect
    sessions.update_call_session_state(
        call_id="paid1",
        state="connected",
        connect_ts=clock,
    )

    # Initialize billing state on the item directly
    call_table.items["paid1"]["billing_start_ts"] = clock
    call_table.items["paid1"]["last_billed_ts"] = clock
    call_table.items["paid1"]["platform_fee_bps"] = 2000
    call_table.items["paid1"]["billing_cycle_count"] = 0
    call_table.items["paid1"]["total_billed_cents"] = 0
    call_table.items["paid1"]["total_billed_seconds"] = 0
    call_table.items["paid1"]["billing_status"] = "active"

    return call_table, billing_table


# ---------------------------------------------------------------------------
# Tests: Call Rate CRUD
# ---------------------------------------------------------------------------

class TestCallRateCrud:
    def test_set_and_get_rate(self, monkeypatch):
        _setup(monkeypatch)
        rate = billing.set_call_rate(
            user_id="creator1",
            rate_cents_per_minute=500,
            enabled=True,
            min_balance_minutes=5,
            max_duration_minutes=120,
        )
        assert rate.rate_cents_per_minute == 500
        assert rate.enabled is True

        fetched = billing.get_call_rate("creator1")
        assert fetched is not None
        assert fetched.rate_cents_per_minute == 500

    def test_get_rate_not_found(self, monkeypatch):
        _setup(monkeypatch)
        assert billing.get_call_rate("nobody") is None

    def test_delete_rate(self, monkeypatch):
        _setup(monkeypatch)
        billing.set_call_rate(user_id="creator1", rate_cents_per_minute=500)
        billing.delete_call_rate("creator1")
        assert billing.get_call_rate("creator1") is None


# ---------------------------------------------------------------------------
# Tests: Balance check
# ---------------------------------------------------------------------------

class TestBalanceCheck:
    def test_sufficient_balance(self, monkeypatch):
        _setup(monkeypatch, wallet_cents=5000)
        result = billing.check_balance_for_paid_call(
            caller_user_id="caller",
            rate_cents_per_minute=500,
            min_balance_minutes=5,
        )
        assert result["wallet_balance_cents"] == 5000

    def test_insufficient_balance(self, monkeypatch):
        _setup(monkeypatch, wallet_cents=1000)
        with pytest.raises(ValueError):
            billing.check_balance_for_paid_call(
                caller_user_id="caller",
                rate_cents_per_minute=500,
                min_balance_minutes=5,
            )


# ---------------------------------------------------------------------------
# Tests: Heartbeat and billing cycles
# ---------------------------------------------------------------------------

class TestHeartbeatBilling:
    def test_skip_before_cycle_due(self, monkeypatch):
        """Heartbeat before 60s should skip billing."""
        call_table, billing_table = _create_paid_call(monkeypatch)
        # clock is at _clock, billing_start_ts is _clock, so 0s elapsed
        result = billing.process_heartbeat("paid1", "caller")
        assert result.action == "skip"
        assert result.next_bill_in > 0

    def test_billing_cycle_triggered(self, monkeypatch):
        """Heartbeat after 60s triggers billing cycle."""
        clock = _clock
        call_table, billing_table = _create_paid_call(monkeypatch, clock=clock)

        # Advance clock past billing cycle
        advanced_clock = clock + 65
        monkeypatch.setattr(billing, "now_ts", lambda: advanced_clock)

        result = billing.process_heartbeat("paid1", "caller")
        assert result.action == "billed"
        assert result.amount_cents == 500  # 1 minute at $5/min
        assert result.total_cost_cents == 500
        assert result.cycle_number == 1

    def test_wallet_debited_on_billing(self, monkeypatch):
        """Wallet is debited after billing cycle."""
        clock = _clock
        call_table, billing_table = _create_paid_call(monkeypatch, wallet_cents=10000, clock=clock)

        monkeypatch.setattr(billing, "now_ts", lambda: clock + 65)
        billing.process_heartbeat("paid1", "caller")

        wallet_item = billing_table.items.get("USER#caller|WALLET")
        assert wallet_item is not None
        assert int(wallet_item["wallet_balance_cents"]) == 9500  # 10000 - 500

    def test_insufficient_balance_ends_call(self, monkeypatch):
        """Call ends when balance is depleted."""
        clock = _clock
        call_table, billing_table = _create_paid_call(monkeypatch, wallet_cents=100, clock=clock)

        monkeypatch.setattr(billing, "now_ts", lambda: clock + 65)
        result = billing.process_heartbeat("paid1", "caller")
        assert result.action == "end_call"
        assert result.reason == "balance_depleted"

    def test_creator_credited(self, monkeypatch):
        """Creator receives credit (minus platform fee) after billing cycle."""
        clock = _clock
        call_table, billing_table = _create_paid_call(monkeypatch, wallet_cents=10000, clock=clock)

        monkeypatch.setattr(billing, "now_ts", lambda: clock + 65)
        billing.process_heartbeat("paid1", "caller")

        # Check for creator credit ledger entry
        credit_entries = [
            v for k, v in billing_table.items.items()
            if k.startswith("USER#callee|LEDGER#") and v.get("type") == "credit"
        ]
        assert len(credit_entries) == 1
        # 500 - 20% = 400
        assert int(credit_entries[0]["amount_cents"]) == 400

    def test_platform_fee_calculation(self, monkeypatch):
        """Platform fee is correctly calculated."""
        clock = _clock
        call_table, billing_table = _create_paid_call(monkeypatch, wallet_cents=10000, clock=clock)

        monkeypatch.setattr(billing, "now_ts", lambda: clock + 65)
        billing.process_heartbeat("paid1", "caller")

        # Debit entry for caller
        debit_entries = [
            v for k, v in billing_table.items.items()
            if k.startswith("USER#caller|LEDGER#") and v.get("type") == "debit"
        ]
        assert len(debit_entries) == 1
        assert int(debit_entries[0]["amount_cents"]) == 500  # Full amount debited

        # Credit entry for creator (after fee)
        credit_entries = [
            v for k, v in billing_table.items.items()
            if k.startswith("USER#callee|LEDGER#") and v.get("type") == "credit"
        ]
        assert int(credit_entries[0]["amount_cents"]) == 400  # 500 - 20% fee


# ---------------------------------------------------------------------------
# Tests: Finalization
# ---------------------------------------------------------------------------

class TestFinalization:
    def test_prorate_partial_minute(self, monkeypatch):
        """Final billing pro-rates partial minutes."""
        clock = _clock
        call_table, billing_table = _create_paid_call(monkeypatch, wallet_cents=10000, clock=clock)

        # Simulate 30 seconds elapsed since last billing
        monkeypatch.setattr(billing, "now_ts", lambda: clock + 30)
        result = billing.finalize_call_billing("paid1")

        # Pro-rate: ceil((500/60) * 30) = ceil(250) = 250
        expected = math.ceil((500 / 60) * 30)
        assert result.final_charge_cents == expected
        assert result.total_cents == expected

    def test_finalize_zero_unbilled(self, monkeypatch):
        """No additional charge when no unbilled time."""
        clock = _clock
        call_table, billing_table = _create_paid_call(monkeypatch, clock=clock)

        # Set last_billed_ts to current time (0 unbilled seconds)
        monkeypatch.setattr(billing, "now_ts", lambda: clock)
        result = billing.finalize_call_billing("paid1")
        assert result.final_charge_cents == 0
        assert result.total_cents == 0

    def test_finalize_insufficient_balance(self, monkeypatch):
        """Finalization deducts whatever balance remains if insufficient for full pro-rate."""
        clock = _clock
        call_table, billing_table = _create_paid_call(monkeypatch, wallet_cents=100, clock=clock)

        monkeypatch.setattr(billing, "now_ts", lambda: clock + 30)
        result = billing.finalize_call_billing("paid1")
        # Should debit remaining 100 cents (not the full pro-rate)
        assert result.final_charge_cents == 100

    def test_finalize_non_paid_call(self, monkeypatch):
        """Finalizing a non-paid call returns zero."""
        _setup(monkeypatch)
        participants = {"caller", "callee"}
        lifecycle.create_invite(
            call_id="free1",
            conversation_id="conv1",
            actor_user_id="caller",
            caller_user_id="caller",
            callee_user_id="callee",
            initial_mode="audio",
            participant_resolver=lambda _: participants,
            timeline_emitter=lambda **kw: kw,
            paid=False,
        )
        result = billing.finalize_call_billing("free1")
        assert result.total_cents == 0


# ---------------------------------------------------------------------------
# Tests: Billing summary
# ---------------------------------------------------------------------------

class TestBillingSummary:
    def test_summary_for_paid_call(self, monkeypatch):
        """Billing summary returns correct data."""
        clock = _clock
        call_table, billing_table = _create_paid_call(monkeypatch, wallet_cents=10000, clock=clock)

        # Run a billing cycle
        monkeypatch.setattr(billing, "now_ts", lambda: clock + 65)
        billing.process_heartbeat("paid1", "caller")

        summary = billing.get_call_billing_summary("paid1")
        assert summary is not None
        assert summary["paid"] is True
        assert summary["rate_cents_per_minute"] == 500
        assert summary["total_cost_cents"] == 500
        assert summary["caller_balance_remaining_cents"] == 9500

    def test_summary_not_found(self, monkeypatch):
        _setup(monkeypatch)
        assert billing.get_call_billing_summary("nonexistent") is None
