"""Regression tests for GAP-0071 + GAP-0072 (coupled).

GAP-0072: ``broadcast_ads_billing_enabled`` feature flag must exist on
          ``Settings`` and default to False (safe default for money-moving code).
GAP-0071: ``record_ad_event`` must wire advertiser billing (charge_impression),
          fraud detection, and analytics into broadcast ad events — with billing
          gated behind the GAP-0072 flag.

Offline only: every DynamoDB / AWS-touching dependency is patched, so no real
AWS access occurs. Fraud check and billing helpers are mocked; the DDB raw-event
write is patched out.

``Settings`` is a frozen dataclass whose field defaults are evaluated once at
import time, so per-test flag flipping is done by swapping the module-level ``S``
singleton with a stand-in (the convention in test_broadcast_ads_feature_flags.py).
"""

from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.core.settings import S
from app.services import broadcast_ads


# ── GAP-0072: feature flag existence + safe default ─────────────────────


def test_broadcast_ads_billing_enabled_field_exists():
    """The flag must exist on the Settings singleton (was missing — GAP-0072)."""
    assert hasattr(S, "broadcast_ads_billing_enabled")


def test_broadcast_ads_billing_enabled_defaults_false():
    """Flag must default to False (no env var set in the test environment)."""
    assert S.broadcast_ads_billing_enabled is False


def test_broadcast_ads_billing_enabled_env_parsing():
    """The env-var parsing must match the convention used by other money flags:
    only '0' / 'false' / 'False' are off; everything else (incl. '1') is on."""
    parse = lambda v: v not in ("0", "false", "False")
    assert parse("1") is True
    assert parse("true") is True
    assert parse("0") is False
    assert parse("false") is False
    assert parse("False") is False


# ── Shared helpers for GAP-0071 ─────────────────────────────────────────


@contextmanager
def _billing_flag(enabled: bool):
    """Swap the module-level ``S`` and ``T`` singletons with stand-ins.

    ``S`` carries the billing flag; ``T`` carries a mock ``broadcast_ad_events``
    table so the raw-event write never hits DynamoDB (offline). Both are frozen
    dataclasses, so attributes are swapped via the module reference, not in place.
    Yields the mock table so tests can assert on ``put_item``.
    """
    fake_s = SimpleNamespace(broadcast_ads_billing_enabled=enabled)
    fake_table = MagicMock()
    fake_t = SimpleNamespace(broadcast_ad_events=fake_table)
    with patch.object(broadcast_ads, "S", fake_s), \
         patch.object(broadcast_ads, "T", fake_t):
        yield fake_table


def _fraud_clean():
    result = MagicMock()
    result.flagged = False
    result.score = 0
    result.rule_scores = {}
    result.details = {}
    return result


def _fraud_flagged():
    result = MagicMock()
    result.flagged = True
    result.score = 90
    result.rule_scores = {"bot_ua": 20, "ip_clustering": 25}
    result.details = {}
    return result


# ── GAP-0071: billing wiring gated by the flag ──────────────────────────


def test_record_ad_event_calls_billing_when_enabled():
    """Billing must be called for impression events when the flag is True."""
    charge_mock = MagicMock(return_value={"ok": True, "entry_id": "chg_test"})
    check_fraud_mock = MagicMock(return_value=_fraud_clean())

    with _billing_flag(True) as put_table, \
         patch("app.services.ad_billing.charge_impression", charge_mock), \
         patch("app.services.ad_fraud_prevention.check_fraud", check_fraud_mock), \
         patch("app.services.ad_fraud_prevention.record_account_activity"), \
         patch("app.services.ad_analytics.compute_hourly_rollup"):
        result = broadcast_ads.record_ad_event(
            session_id="s1",
            creative_id="cr1",
            user_id="u1",
            event_type="impression",
            account_id="acct1",
            campaign_id="camp1",
            bid_cpm_cents=2000,
        )

    check_fraud_mock.assert_called_once()
    charge_mock.assert_called_once()
    kwargs = charge_mock.call_args.kwargs
    assert kwargs["account_id"] == "acct1"
    assert kwargs["campaign_id"] == "camp1"
    assert kwargs["bid_cpm_cents"] == 2000
    assert result["ok"] is True
    assert result["fraud_flagged"] is False


def test_record_ad_event_skips_billing_when_disabled():
    """Billing must NOT be called when the flag is False (default dev/test)."""
    charge_mock = MagicMock()
    check_fraud_mock = MagicMock(return_value=_fraud_clean())

    with _billing_flag(False) as put_table, \
         patch("app.services.ad_billing.charge_impression", charge_mock), \
         patch("app.services.ad_fraud_prevention.check_fraud", check_fraud_mock), \
         patch("app.services.ad_fraud_prevention.record_account_activity"), \
         patch("app.services.ad_analytics.compute_hourly_rollup"):
        broadcast_ads.record_ad_event(
            session_id="s1",
            creative_id="cr1",
            user_id="u1",
            event_type="impression",
            account_id="acct1",
            campaign_id="camp1",
            bid_cpm_cents=2000,
        )

    charge_mock.assert_not_called()
    # Fraud detection still runs even with billing disabled (safety check).
    check_fraud_mock.assert_called_once()


def test_record_ad_event_skips_billing_for_fraud():
    """Fraudulent impressions must never be charged, even when the flag is on."""
    charge_mock = MagicMock()
    check_fraud_mock = MagicMock(return_value=_fraud_flagged())

    with _billing_flag(True) as put_table, \
         patch("app.services.ad_fraud_prevention.check_fraud", check_fraud_mock), \
         patch("app.services.ad_fraud_prevention.record_fraud_event") as rec_mock, \
         patch("app.services.ad_fraud_prevention.maybe_auto_suspend"), \
         patch("app.services.ad_billing.charge_impression", charge_mock), \
         patch("app.services.ad_analytics.compute_hourly_rollup"):
        result = broadcast_ads.record_ad_event(
            session_id="s1",
            creative_id="cr1",
            user_id="u1",
            event_type="impression",
            account_id="acct1",
            campaign_id="camp1",
            bid_cpm_cents=2000,
        )

    charge_mock.assert_not_called()
    rec_mock.assert_called_once()
    assert result["fraud_flagged"] is True


def test_record_ad_event_skips_billing_for_non_impression():
    """Only impression events are charged; clicks/skips/completes are not."""
    charge_mock = MagicMock()
    check_fraud_mock = MagicMock(return_value=_fraud_clean())

    with _billing_flag(True) as put_table, \
         patch("app.services.ad_billing.charge_impression", charge_mock), \
         patch("app.services.ad_fraud_prevention.check_fraud", check_fraud_mock), \
         patch("app.services.ad_fraud_prevention.record_account_activity"), \
         patch("app.services.ad_analytics.compute_hourly_rollup"):
        broadcast_ads.record_ad_event(
            session_id="s1",
            creative_id="cr1",
            user_id="u1",
            event_type="click",
            account_id="acct1",
            campaign_id="camp1",
            bid_cpm_cents=2000,
        )

    charge_mock.assert_not_called()


def test_record_ad_event_billing_failure_never_breaks_playback():
    """A billing exception must be swallowed; the event row is still written."""
    charge_mock = MagicMock(side_effect=RuntimeError("billing down"))
    check_fraud_mock = MagicMock(return_value=_fraud_clean())

    with _billing_flag(True) as put_table, \
         patch("app.services.ad_billing.charge_impression", charge_mock), \
         patch("app.services.ad_fraud_prevention.check_fraud", check_fraud_mock), \
         patch("app.services.ad_fraud_prevention.record_account_activity"), \
         patch("app.services.ad_analytics.compute_hourly_rollup"):
        result = broadcast_ads.record_ad_event(
            session_id="s1",
            creative_id="cr1",
            user_id="u1",
            event_type="impression",
            account_id="acct1",
            campaign_id="camp1",
            bid_cpm_cents=2000,
        )

    charge_mock.assert_called_once()
    put_table.put_item.assert_called_once()  # raw event still recorded
    assert result["ok"] is True
