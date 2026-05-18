from __future__ import annotations

import pytest

from app.services import mass_message_campaign_contract as contract


def test_parse_campaign_mode_accepts_valid_values() -> None:
    assert contract.parse_campaign_mode("immediate") == contract.CampaignMode.IMMEDIATE
    assert contract.parse_campaign_mode("SCHEDULED") == contract.CampaignMode.SCHEDULED


def test_parse_campaign_mode_rejects_invalid_values() -> None:
    with pytest.raises(ValueError, match="invalid mode"):
        contract.parse_campaign_mode("later")


def test_parse_campaign_status_accepts_valid_values() -> None:
    assert contract.parse_campaign_status("pending") == contract.CampaignStatus.PENDING
    assert contract.parse_campaign_status("FAILED") == contract.CampaignStatus.FAILED


def test_parse_campaign_status_rejects_invalid_values() -> None:
    with pytest.raises(ValueError, match="invalid status"):
        contract.parse_campaign_status("unknown")


def test_can_transition_status_enforces_contract() -> None:
    assert contract.can_transition_status("pending", "processing") is True
    assert contract.can_transition_status("processing", "completed") is True
    assert contract.can_transition_status("completed", "processing") is False


def test_validate_status_transition_raises_for_invalid_transition() -> None:
    with pytest.raises(ValueError, match="invalid status transition"):
        contract.validate_status_transition("failed", "processing")


@pytest.mark.parametrize(
    ("current_status", "next_status"),
    [
        ("pending", "processing"),
        ("pending", "failed"),
        ("pending", "cancelled"),
        ("scheduled", "processing"),
        ("scheduled", "failed"),
        ("scheduled", "cancelled"),
        ("processing", "completed"),
        ("processing", "failed"),
        ("processing", "cancelled"),
    ],
)
def test_can_transition_status_accepts_all_valid_transitions(current_status: str, next_status: str) -> None:
    assert contract.can_transition_status(current_status, next_status) is True


@pytest.mark.parametrize(
    ("mode", "status"),
    [
        ("immediate", "scheduled"),
        ("immediate", "completed"),
        ("immediate", "unknown"),
        ("scheduled", "pending"),
        ("scheduled", "completed"),
        ("scheduled", "bogus"),
    ],
)
def test_mode_status_combinations_reject_invalid_initial_status(mode: str, status: str) -> None:
    parsed_mode = contract.parse_campaign_mode(mode)
    if parsed_mode is contract.CampaignMode.IMMEDIATE:
        expected_initial = contract.CampaignStatus.PENDING
    else:
        expected_initial = contract.CampaignStatus.SCHEDULED

    try:
        parsed_status = contract.parse_campaign_status(status)
    except ValueError:
        # Unknown statuses are invalid for every mode.
        return

    assert parsed_status is not expected_initial
