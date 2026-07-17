from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Final, FrozenSet, Mapping, Protocol


class PaymentProvider(str, Enum):
    STRIPE = "stripe"
    PAYPAL = "paypal"
    CCBILL = "ccbill"


class PaymentIncidentType(str, Enum):
    DISPUTE = "dispute"
    CHARGEBACK = "chargeback"
    PAYMENT_FAILURE = "payment_failure"


class CustomerActionType(str, Enum):
    CONFIRM = "confirm"
    UPDATE_METHOD = "update_method"
    RETRY = "retry"


class DisputeStatus(str, Enum):
    OPENED = "opened"
    EVIDENCE_REQUIRED = "evidence_required"
    RESPONSE_SUBMITTED = "response_submitted"
    UNDER_REVIEW = "under_review"
    WON = "won"
    LOST = "lost"
    ACCEPTED = "accepted"
    CANCELED = "canceled"


class PaymentFailureStatus(str, Enum):
    FAILED_INITIAL = "failed_initial"
    CUSTOMER_ACTION_REQUIRED = "customer_action_required"
    READY_TO_RETRY = "ready_to_retry"
    RETRY_PENDING = "retry_pending"
    RETRY_SUCCEEDED = "retry_succeeded"
    RETRY_FAILED_TERMINAL = "retry_failed_terminal"


IncidentStatus = DisputeStatus | PaymentFailureStatus


# DISP E3: a real Stripe ``charge.dispute.closed`` can arrive directly from ANY
# live state (opened / evidence_required / response_submitted) -- the network
# does not require our intermediate under_review. So every live state may reach a
# terminal {won, lost, accepted}. Still forward-only (terminals stay terminal).
_TERMINAL_OUTCOMES = frozenset({DisputeStatus.WON, DisputeStatus.LOST, DisputeStatus.ACCEPTED})
_VALID_DISPUTE_TRANSITIONS: Final[Mapping[DisputeStatus, FrozenSet[DisputeStatus]]] = {
    DisputeStatus.OPENED: frozenset({DisputeStatus.EVIDENCE_REQUIRED, DisputeStatus.RESPONSE_SUBMITTED,
                                     DisputeStatus.UNDER_REVIEW, DisputeStatus.CANCELED}) | _TERMINAL_OUTCOMES,
    DisputeStatus.EVIDENCE_REQUIRED: frozenset(
        {
            DisputeStatus.RESPONSE_SUBMITTED,
            DisputeStatus.UNDER_REVIEW,
            DisputeStatus.CANCELED,
        }
    ) | _TERMINAL_OUTCOMES,
    DisputeStatus.RESPONSE_SUBMITTED: frozenset({DisputeStatus.UNDER_REVIEW, DisputeStatus.CANCELED}) | _TERMINAL_OUTCOMES,
    DisputeStatus.UNDER_REVIEW: frozenset({DisputeStatus.WON, DisputeStatus.LOST, DisputeStatus.ACCEPTED}),
    DisputeStatus.WON: frozenset(),
    DisputeStatus.LOST: frozenset(),
    DisputeStatus.ACCEPTED: frozenset(),
    DisputeStatus.CANCELED: frozenset(),
}

_VALID_PAYMENT_FAILURE_TRANSITIONS: Final[Mapping[PaymentFailureStatus, FrozenSet[PaymentFailureStatus]]] = {
    PaymentFailureStatus.FAILED_INITIAL: frozenset(
        {
            PaymentFailureStatus.CUSTOMER_ACTION_REQUIRED,
            PaymentFailureStatus.READY_TO_RETRY,
            PaymentFailureStatus.RETRY_FAILED_TERMINAL,
        }
    ),
    PaymentFailureStatus.CUSTOMER_ACTION_REQUIRED: frozenset(
        {
            PaymentFailureStatus.READY_TO_RETRY,
            PaymentFailureStatus.RETRY_FAILED_TERMINAL,
        }
    ),
    PaymentFailureStatus.READY_TO_RETRY: frozenset(
        {
            PaymentFailureStatus.RETRY_PENDING,
            PaymentFailureStatus.RETRY_FAILED_TERMINAL,
        }
    ),
    PaymentFailureStatus.RETRY_PENDING: frozenset(
        {
            PaymentFailureStatus.RETRY_SUCCEEDED,
            PaymentFailureStatus.CUSTOMER_ACTION_REQUIRED,
            PaymentFailureStatus.RETRY_FAILED_TERMINAL,
        }
    ),
    PaymentFailureStatus.RETRY_SUCCEEDED: frozenset(),
    PaymentFailureStatus.RETRY_FAILED_TERMINAL: frozenset(),
}


@dataclass(frozen=True)
class PaymentIncident:
    incident_id: str
    provider: PaymentProvider
    provider_incident_id: str
    incident_type: PaymentIncidentType
    payment_reference: str
    account_id: str
    customer_id: str
    subscription_id: str | None
    order_id: str | None
    amount: Decimal
    currency: str
    status: IncidentStatus
    requires_customer_action: bool
    customer_action_type: CustomerActionType | None
    response_due_at: datetime | None
    raw_payload_ref: str
    created_at: datetime
    updated_at: datetime
    provider_metadata: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.incident_type in {PaymentIncidentType.DISPUTE, PaymentIncidentType.CHARGEBACK}:
            if not isinstance(self.status, DisputeStatus):
                raise ValueError("Dispute/chargeback incidents must use dispute statuses")
        elif self.incident_type is PaymentIncidentType.PAYMENT_FAILURE:
            if not isinstance(self.status, PaymentFailureStatus):
                raise ValueError("Payment failure incidents must use payment-failure statuses")

        if self.requires_customer_action and self.customer_action_type is None:
            raise ValueError("customer_action_type is required when requires_customer_action=true")

        if self.amount < Decimal("0"):
            raise ValueError("amount must be non-negative")

        if not str(self.currency or "").strip():
            raise ValueError("currency is required")

        if self.updated_at < self.created_at:
            raise ValueError("updated_at must be greater than or equal to created_at")


class PaymentIncidentOrchestrator(Protocol):
    def apply_provider_event(self, incident: PaymentIncident, event_name: str) -> PaymentIncident:
        """Apply a provider event and return updated incident state."""

    def apply_admin_action(self, incident: PaymentIncident, action_name: str) -> PaymentIncident:
        """Apply an admin action and return updated incident state."""


def can_transition_dispute_status(current: DisputeStatus, next_status: DisputeStatus) -> bool:
    return next_status in _VALID_DISPUTE_TRANSITIONS[current]


def validate_dispute_status_transition(current: DisputeStatus, next_status: DisputeStatus) -> None:
    if can_transition_dispute_status(current, next_status):
        return
    raise ValueError(f"Invalid dispute status transition: {current.value} -> {next_status.value}")


def can_transition_payment_failure_status(current: PaymentFailureStatus, next_status: PaymentFailureStatus) -> bool:
    return next_status in _VALID_PAYMENT_FAILURE_TRANSITIONS[current]


def validate_payment_failure_status_transition(current: PaymentFailureStatus, next_status: PaymentFailureStatus) -> None:
    if can_transition_payment_failure_status(current, next_status):
        return
    raise ValueError(f"Invalid payment-failure status transition: {current.value} -> {next_status.value}")


def validate_incident_status_transition(
    incident_type: PaymentIncidentType,
    current: IncidentStatus,
    next_status: IncidentStatus,
) -> None:
    if incident_type in {PaymentIncidentType.DISPUTE, PaymentIncidentType.CHARGEBACK}:
        if not isinstance(current, DisputeStatus) or not isinstance(next_status, DisputeStatus):
            raise ValueError("Dispute/chargeback transitions require dispute statuses")
        validate_dispute_status_transition(current, next_status)
        return

    if incident_type is PaymentIncidentType.PAYMENT_FAILURE:
        if not isinstance(current, PaymentFailureStatus) or not isinstance(next_status, PaymentFailureStatus):
            raise ValueError("Payment failure transitions require payment-failure statuses")
        validate_payment_failure_status_transition(current, next_status)
        return

    raise ValueError(f"Unsupported incident type: {incident_type.value}")


def allowed_next_statuses(
    incident_type: PaymentIncidentType,
    current: IncidentStatus,
) -> FrozenSet[IncidentStatus]:
    if incident_type in {PaymentIncidentType.DISPUTE, PaymentIncidentType.CHARGEBACK}:
        if not isinstance(current, DisputeStatus):
            raise ValueError("Dispute/chargeback transitions require dispute statuses")
        return frozenset(_VALID_DISPUTE_TRANSITIONS[current])

    if incident_type is PaymentIncidentType.PAYMENT_FAILURE:
        if not isinstance(current, PaymentFailureStatus):
            raise ValueError("Payment failure transitions require payment-failure statuses")
        return frozenset(_VALID_PAYMENT_FAILURE_TRANSITIONS[current])

    raise ValueError(f"Unsupported incident type: {incident_type.value}")
