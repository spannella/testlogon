from types import SimpleNamespace

import pytest

from app.services import messaging_turn_credentials as turn


class _Settings(SimpleNamespace):
    messaging_webrtc_turn_enabled = True
    messaging_webrtc_turn_urls = "turn:turn.example.com:3478?transport=udp,turns:turn.example.com:5349?transport=tcp"
    messaging_webrtc_turn_secret = "topsecret"
    messaging_webrtc_turn_ttl_seconds = 600


class _CallRecord(SimpleNamespace):
    caller_user_id = "caller"
    callee_user_id = "callee"
    conversation_id = "conv-1"
    state = "invited"


def _patch(monkeypatch, *, state="invited"):
    monkeypatch.setattr(turn, "S", _Settings())
    monkeypatch.setattr(turn, "now_ts", lambda: 1700000000)
    monkeypatch.setattr(turn, "_record_issue", lambda **_kwargs: None)
    monkeypatch.setattr(turn, "_record_issue_latency", lambda **_kwargs: None)
    monkeypatch.setattr(turn, "_load_conversation_participants", lambda _conversation_id: {"caller", "callee"})
    rec = _CallRecord(state=state)
    monkeypatch.setattr(turn, "get_call_session", lambda _call_id: rec)


def test_issue_turn_credentials_success(monkeypatch):
    _patch(monkeypatch)
    result = turn.issue_turn_credentials(call_id="call-1", actor_user_id="caller")

    assert result.ttl_seconds == 600
    assert result.expires_at == 1700000600
    assert len(result.ice_servers) == 1
    server = result.ice_servers[0]
    assert server["username"].startswith("1700000600:")
    assert len(server["urls"]) == 2
    assert server["credential"]


def test_forbidden_for_non_participant(monkeypatch):
    _patch(monkeypatch)
    with pytest.raises(turn.TurnCredentialIssueError) as exc:
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="outsider")
    assert exc.value.code == "forbidden"


def test_invalid_state_rejected(monkeypatch):
    _patch(monkeypatch, state="ended")
    with pytest.raises(turn.TurnCredentialIssueError) as exc:
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="caller")
    assert exc.value.code == "invalid_state"


def test_disabled_or_unconfigured_rejected(monkeypatch):
    s = _Settings(messaging_webrtc_turn_enabled=False)
    monkeypatch.setattr(turn, "S", s)
    monkeypatch.setattr(turn, "_record_issue", lambda **_kwargs: None)
    with pytest.raises(turn.TurnCredentialIssueError) as exc:
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="caller")
    assert exc.value.code == "feature_disabled"

    s2 = _Settings(messaging_webrtc_turn_urls="", messaging_webrtc_turn_secret="")
    monkeypatch.setattr(turn, "S", s2)
    monkeypatch.setattr(turn, "get_call_session", lambda _call_id: _CallRecord())
    with pytest.raises(turn.TurnCredentialIssueError) as exc2:
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="caller")
    assert exc2.value.code == "turn_not_configured"


def test_invalid_ttl_rejected(monkeypatch):
    s = _Settings(messaging_webrtc_turn_ttl_seconds=0)
    monkeypatch.setattr(turn, "S", s)
    monkeypatch.setattr(turn, "_record_issue", lambda **_kwargs: None)
    monkeypatch.setattr(turn, "_record_issue_latency", lambda **_kwargs: None)
    monkeypatch.setattr(turn, "get_call_session", lambda _call_id: _CallRecord())

    with pytest.raises(turn.TurnCredentialIssueError) as exc:
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="caller")
    assert exc.value.code == "turn_invalid_ttl"

    s2 = _Settings(messaging_webrtc_turn_ttl_seconds="bad")
    monkeypatch.setattr(turn, "S", s2)
    with pytest.raises(turn.TurnCredentialIssueError) as exc2:
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="caller")
    assert exc2.value.code == "turn_invalid_ttl"


def test_invalid_turn_url_rejected(monkeypatch):
    s = _Settings(messaging_webrtc_turn_urls="https://not-a-turn-server.example.com")
    monkeypatch.setattr(turn, "S", s)
    monkeypatch.setattr(turn, "_record_issue", lambda **_kwargs: None)
    monkeypatch.setattr(turn, "_record_issue_latency", lambda **_kwargs: None)
    monkeypatch.setattr(turn, "get_call_session", lambda _call_id: _CallRecord())

    with pytest.raises(turn.TurnCredentialIssueError) as exc:
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="caller")
    assert exc.value.code == "turn_invalid_url"


def test_invalid_identifiers_rejected(monkeypatch):
    _patch(monkeypatch)
    with pytest.raises(turn.TurnCredentialIssueError) as exc:
        turn.issue_turn_credentials(call_id="", actor_user_id="caller")
    assert exc.value.code == "validation_error"

    with pytest.raises(turn.TurnCredentialIssueError) as exc2:
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="u" * 129)
    assert exc2.value.code == "validation_error"


def test_issue_and_latency_metrics_recorded_for_success_and_error(monkeypatch):
    issue_events: list[tuple[str, str]] = []
    latency_events: list[tuple[str, str, float]] = []
    monkeypatch.setattr(turn, "S", _Settings())
    monkeypatch.setattr(turn, "now_ts", lambda: 1700000000)
    monkeypatch.setattr(turn, "get_call_session", lambda _call_id: _CallRecord())
    monkeypatch.setattr(turn, "_load_conversation_participants", lambda _conversation_id: {"caller", "callee"})
    monkeypatch.setattr(turn, "_record_issue", lambda **kwargs: issue_events.append((kwargs["outcome"], kwargs["reason"])))
    monkeypatch.setattr(
        turn,
        "_record_issue_latency",
        lambda **kwargs: latency_events.append((kwargs["outcome"], kwargs["reason"], float(kwargs["elapsed_seconds"]))),
    )

    turn.issue_turn_credentials(call_id="call-1", actor_user_id="caller")
    with pytest.raises(turn.TurnCredentialIssueError):
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="outsider")

    assert ("success", "issued") in issue_events
    assert ("error", "forbidden") in issue_events
    assert any(outcome == "success" and reason == "issued" and elapsed >= 0.0 for outcome, reason, elapsed in latency_events)
    assert any(outcome == "error" and reason == "forbidden" and elapsed >= 0.0 for outcome, reason, elapsed in latency_events)


def test_conversation_membership_revocation_rejected(monkeypatch):
    _patch(monkeypatch)
    monkeypatch.setattr(turn, "_load_conversation_participants", lambda _conversation_id: {"callee"})
    with pytest.raises(turn.TurnCredentialIssueError) as exc:
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="caller")
    assert exc.value.code == "forbidden"


def test_call_participant_mismatch_rejected(monkeypatch):
    _patch(monkeypatch)
    monkeypatch.setattr(turn, "_load_conversation_participants", lambda _conversation_id: {"caller", "different-user"})
    with pytest.raises(turn.TurnCredentialIssueError) as exc:
        turn.issue_turn_credentials(call_id="call-1", actor_user_id="caller")
    assert exc.value.code == "call_participant_mismatch"
