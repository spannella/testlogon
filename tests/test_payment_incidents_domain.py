from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from app.services.payment_incidents_domain import (
    CustomerActionType,
    DisputeStatus,
    PaymentFailureStatus,
    PaymentIncident,
    PaymentIncidentType,
    PaymentProvider,
    allowed_next_statuses,
    can_transition_dispute_status,
    can_transition_payment_failure_status,
    validate_incident_status_transition,
)


def _sample_ts() -> datetime:
    return datetime(2026, 3, 24, 12, 0, tzinfo=timezone.utc)


def test_dispute_transitions_allow_expected_hops() -> None:
    assert can_transition_dispute_status(DisputeStatus.OPENED, DisputeStatus.EVIDENCE_REQUIRED)
    assert can_transition_dispute_status(DisputeStatus.UNDER_REVIEW, DisputeStatus.WON)


def test_dispute_transitions_reject_terminal_hops() -> None:
    assert not can_transition_dispute_status(DisputeStatus.WON, DisputeStatus.UNDER_REVIEW)


@pytest.mark.parametrize(
    ("current", "next_status"),
    [
        (PaymentFailureStatus.FAILED_INITIAL, PaymentFailureStatus.CUSTOMER_ACTION_REQUIRED),
        (PaymentFailureStatus.READY_TO_RETRY, PaymentFailureStatus.RETRY_PENDING),
        (PaymentFailureStatus.RETRY_PENDING, PaymentFailureStatus.RETRY_SUCCEEDED),
    ],
)
def test_payment_failure_transitions_allow_expected_hops(
    current: PaymentFailureStatus,
    next_status: PaymentFailureStatus,
) -> None:
    assert can_transition_payment_failure_status(current, next_status)


def test_payment_failure_transitions_reject_invalid_hops() -> None:
    assert not can_transition_payment_failure_status(
        PaymentFailureStatus.RETRY_SUCCEEDED,
        PaymentFailureStatus.RETRY_PENDING,
    )


def test_validate_incident_status_transition_rejects_mixed_status_types() -> None:
    with pytest.raises(ValueError, match="require dispute statuses"):
        validate_incident_status_transition(
            PaymentIncidentType.DISPUTE,
            DisputeStatus.OPENED,
            PaymentFailureStatus.RETRY_PENDING,
        )


def test_payment_incident_rejects_incorrect_status_family() -> None:
    ts = _sample_ts()
    with pytest.raises(ValueError, match="must use payment-failure statuses"):
        PaymentIncident(
            incident_id="inc_1",
            provider=PaymentProvider.STRIPE,
            provider_incident_id="evt_1",
            incident_type=PaymentIncidentType.PAYMENT_FAILURE,
            payment_reference="pi_123",
            account_id="acct_1",
            customer_id="cust_1",
            subscription_id=None,
            order_id=None,
            amount=Decimal("12.34"),
            currency="USD",
            status=DisputeStatus.OPENED,
            requires_customer_action=False,
            customer_action_type=None,
            response_due_at=None,
            raw_payload_ref="s3://bucket/path",
            created_at=ts,
            updated_at=ts,
        )


def test_payment_incident_requires_customer_action_type_when_flagged() -> None:
    ts = _sample_ts()
    with pytest.raises(ValueError, match="customer_action_type is required"):
        PaymentIncident(
            incident_id="inc_2",
            provider=PaymentProvider.PAYPAL,
            provider_incident_id="evt_2",
            incident_type=PaymentIncidentType.PAYMENT_FAILURE,
            payment_reference="inv_123",
            account_id="acct_2",
            customer_id="cust_2",
            subscription_id="sub_1",
            order_id=None,
            amount=Decimal("5.00"),
            currency="USD",
            status=PaymentFailureStatus.CUSTOMER_ACTION_REQUIRED,
            requires_customer_action=True,
            customer_action_type=None,
            response_due_at=None,
            raw_payload_ref="ddb://raw/evt_2",
            created_at=ts,
            updated_at=ts,
        )


def test_payment_incident_accepts_valid_canonical_record() -> None:
    ts = _sample_ts()
    incident = PaymentIncident(
        incident_id="inc_3",
        provider=PaymentProvider.CCBILL,
        provider_incident_id="evt_3",
        incident_type=PaymentIncidentType.CHARGEBACK,
        payment_reference="txn_1",
        account_id="acct_3",
        customer_id="cust_3",
        subscription_id="sub_3",
        order_id="ord_3",
        amount=Decimal("29.99"),
        currency="USD",
        status=DisputeStatus.OPENED,
        requires_customer_action=False,
        customer_action_type=None,
        response_due_at=ts,
        raw_payload_ref="ddb://raw/evt_3",
        created_at=ts,
        updated_at=ts,
    )

    assert incident.provider == PaymentProvider.CCBILL
    assert incident.status == DisputeStatus.OPENED


def test_payment_incident_accepts_customer_action_variant() -> None:
    ts = _sample_ts()
    incident = PaymentIncident(
        incident_id="inc_4",
        provider=PaymentProvider.STRIPE,
        provider_incident_id="evt_4",
        incident_type=PaymentIncidentType.PAYMENT_FAILURE,
        payment_reference="pi_4",
        account_id="acct_4",
        customer_id="cust_4",
        subscription_id=None,
        order_id="ord_4",
        amount=Decimal("19.00"),
        currency="USD",
        status=PaymentFailureStatus.CUSTOMER_ACTION_REQUIRED,
        requires_customer_action=True,
        customer_action_type=CustomerActionType.UPDATE_METHOD,
        response_due_at=None,
        raw_payload_ref="ddb://raw/evt_4",
        created_at=ts,
        updated_at=ts,
    )

    assert incident.customer_action_type == CustomerActionType.UPDATE_METHOD


def test_validate_incident_status_transition_rejects_invalid_hop() -> None:
    with pytest.raises(ValueError, match="Invalid dispute status transition"):
        validate_incident_status_transition(
            PaymentIncidentType.DISPUTE,
            DisputeStatus.OPENED,
            DisputeStatus.WON,
        )


def test_allowed_next_statuses_returns_canonical_set() -> None:
    allowed = allowed_next_statuses(PaymentIncidentType.PAYMENT_FAILURE, PaymentFailureStatus.READY_TO_RETRY)
    assert PaymentFailureStatus.RETRY_PENDING in allowed
    assert PaymentFailureStatus.RETRY_SUCCEEDED not in allowed


def test_payment_incident_rejects_negative_amount() -> None:
    ts = _sample_ts()
    with pytest.raises(ValueError, match="amount must be non-negative"):
        PaymentIncident(
            incident_id="inc_5",
            provider=PaymentProvider.STRIPE,
            provider_incident_id="evt_5",
            incident_type=PaymentIncidentType.PAYMENT_FAILURE,
            payment_reference="pi_5",
            account_id="acct_5",
            customer_id="cust_5",
            subscription_id=None,
            order_id=None,
            amount=Decimal("-1.00"),
            currency="USD",
            status=PaymentFailureStatus.FAILED_INITIAL,
            requires_customer_action=False,
            customer_action_type=None,
            response_due_at=None,
            raw_payload_ref="ddb://raw/evt_5",
            created_at=ts,
            updated_at=ts,
        )


def test_payment_incident_rejects_reverse_timestamps() -> None:
    created = datetime(2026, 3, 24, 12, 0, tzinfo=timezone.utc)
    updated = datetime(2026, 3, 24, 11, 59, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="updated_at must be greater than or equal to created_at"):
        PaymentIncident(
            incident_id="inc_6",
            provider=PaymentProvider.STRIPE,
            provider_incident_id="evt_6",
            incident_type=PaymentIncidentType.DISPUTE,
            payment_reference="ch_6",
            account_id="acct_6",
            customer_id="cust_6",
            subscription_id=None,
            order_id="ord_6",
            amount=Decimal("1.00"),
            currency="USD",
            status=DisputeStatus.OPENED,
            requires_customer_action=False,
            customer_action_type=None,
            response_due_at=created,
            raw_payload_ref="ddb://raw/evt_6",
            created_at=created,
            updated_at=updated,
        )
