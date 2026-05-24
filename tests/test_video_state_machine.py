from __future__ import annotations

from app.services.video_state_machine import (
    INVALID_TRANSITION_ERROR_CODE,
    _ALLOWED_TRANSITIONS,
    validate_transition,
)


def test_all_valid_transitions() -> None:
    """Every entry in _ALLOWED_TRANSITIONS should validate as legal."""
    for from_status, targets in _ALLOWED_TRANSITIONS.items():
        for to_status in targets:
            result = validate_transition(from_status, to_status)
            assert result.legal is True, f"{from_status} -> {to_status} should be legal"


def test_invalid_transitions() -> None:
    """Representative illegal transitions should return legal=False."""
    illegal_pairs = [
        ("created", "published"),
        ("created", "encoding"),
        ("deleted", "created"),
        ("deleted", "published"),
        ("encoding", "published"),
        ("probe_failed", "encoding"),
        ("pending_review", "encoding"),
    ]
    for from_status, to_status in illegal_pairs:
        result = validate_transition(from_status, to_status)
        assert result.legal is False, f"{from_status} -> {to_status} should be illegal"


def test_deleted_is_terminal() -> None:
    """The 'deleted' state has no allowed transitions out."""
    assert _ALLOWED_TRANSITIONS["deleted"] == set()


def test_every_status_reachable() -> None:
    """Graph traversal from 'created' should reach all non-terminal states."""
    reachable: set = set()
    queue = ["created"]
    while queue:
        current = queue.pop()
        if current in reachable:
            continue
        reachable.add(current)
        for target in _ALLOWED_TRANSITIONS.get(current, set()):
            if target not in reachable:
                queue.append(target)

    all_states = set(_ALLOWED_TRANSITIONS.keys())
    assert reachable == all_states, f"Unreachable states: {all_states - reachable}"


def test_error_code_on_invalid() -> None:
    """Invalid transitions should return the standard error code."""
    result = validate_transition("created", "published")
    assert result.legal is False
    assert result.error_code == INVALID_TRANSITION_ERROR_CODE
