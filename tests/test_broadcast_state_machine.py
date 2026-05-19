from __future__ import annotations

from app.services.broadcast_state_machine import INVALID_TRANSITION_ERROR_CODE, validate_transition


def test_legal_transitions_matrix() -> None:
    assert validate_transition("draft", "provisioning").legal is True
    assert validate_transition("provisioning", "ready").legal is True
    assert validate_transition("ready", "live").legal is True
    assert validate_transition("live", "stopping").legal is True
    assert validate_transition("stopping", "stopped").legal is True
    assert validate_transition("ready", "error").legal is True


def test_illegal_transition_returns_stable_error_code() -> None:
    out = validate_transition("draft", "live")
    assert out.legal is False
    assert out.error_code == INVALID_TRANSITION_ERROR_CODE
