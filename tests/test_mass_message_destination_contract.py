from __future__ import annotations

import pytest

from app.services import mass_message_destination_contract as contract


def test_parse_destination_state_accepts_valid_values() -> None:
    assert contract.parse_destination_state("pending") == contract.DestinationState.PENDING
    assert contract.parse_destination_state("SENT") == contract.DestinationState.SENT


def test_parse_destination_state_rejects_invalid_values() -> None:
    with pytest.raises(ValueError, match="invalid destination state"):
        contract.parse_destination_state("queued")


def test_destination_transition_contract_enforced() -> None:
    assert contract.can_transition_destination_state("pending", "sent") is True
    assert contract.can_transition_destination_state("failed", "pending") is True
    assert contract.can_transition_destination_state("sent", "pending") is False


def test_validate_destination_transition_raises_for_invalid_transition() -> None:
    with pytest.raises(ValueError, match="invalid destination state transition"):
        contract.validate_destination_transition("cancelled", "pending")


def test_build_destination_metadata_shape() -> None:
    payload = contract.build_destination_metadata(
        campaign_id="mmc_1",
        conversation_id="c_1",
        state="failed",
        error_code="policy_blocked",
        attempt_count=2,
        updated_at=1700000001,
        created_at=1700000000,
    )
    assert payload == {
        "campaign_id": "mmc_1",
        "conversation_id": "c_1",
        "state": "failed",
        "message_id": None,
        "error_code": "policy_blocked",
        "attempt_count": 2,
        "updated_at": 1700000001,
        "created_at": 1700000000,
        "campaign_state": "mmc_1#failed",
        "idempotency_key": "mmc_1:c_1",
    }


def test_destination_idempotency_key_is_deterministic() -> None:
    assert contract.destination_idempotency_key(campaign_id="mmc_1", conversation_id="c_1") == "mmc_1:c_1"


def test_normalize_destination_error_code_enforces_canonical_taxonomy() -> None:
    assert contract.normalize_destination_error_code(state="failed", error_code="authorization_denied") == "authorization"
    assert contract.normalize_destination_error_code(state="failed", error_code="conversation_not_found") == "conversation_missing"
    assert contract.normalize_destination_error_code(state="failed", error_code="send_failed") == "transient_infra"
    assert contract.normalize_destination_error_code(state="failed", error_code="something_else") == "unknown"


def test_build_destination_metadata_sets_unknown_for_failed_without_error_code() -> None:
    payload = contract.build_destination_metadata(
        campaign_id="mmc_1",
        conversation_id="c_2",
        state="failed",
        error_code=None,
    )
    assert payload["error_code"] == "unknown"
