from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services import messaging_call_signaling as signaling


def _envelope(**overrides):
    base = {
        "type": "call.invite",
        "version": 1,
        "event_id": "evt-1",
        "call_id": "call-1",
        "conversation_id": "conv-1",
        "sender_user_id": "caller",
        "recipient_user_id": "callee",
        "nonce": "nonce-12345678",
        "sent_at": 1_700_000_000,
        "payload": {"mode": "audio"},
    }
    base.update(overrides)
    return base


def _call_session(**overrides):
    base = {
        "call_id": "call-1",
        "conversation_id": "conv-1",
        "caller_user_id": "caller",
        "callee_user_id": "callee",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_route_signaling_event_delivers_to_intended_participant():
    writes: list[dict] = []

    monkeypatched_now = 1_700_000_000
    original_now = signaling.now_ts
    signaling.now_ts = lambda: monkeypatched_now  # type: ignore[assignment]
    ack = signaling.route_signaling_event(
        envelope=_envelope(),
        actor_user_id="caller",
        participant_resolver=lambda _cid: {"caller", "callee"},
        call_session_resolver=lambda _call_id: _call_session(),
        put_item=lambda **kwargs: writes.append(kwargs),
        replay_guard=lambda **_kwargs: True,
    )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert ack.status == "delivered"
    assert ack.delivered_to == "callee"
    assert len(writes) == 1
    assert writes[0]["Item"]["user_id"] == "callee"
    assert writes[0]["Item"]["type"] == "call.invite"


def test_spoofed_sender_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(sender_user_id="spoofed"),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "unauthorized"


def test_non_participant_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(recipient_user_id="outsider"),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "forbidden"


def test_delivery_failure_returns_deterministic_error_code():
    def failing_writer(**_kwargs):
        raise RuntimeError("ddb down")

    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=failing_writer,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "delivery_failed"


def test_unsupported_version_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(version=2),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "unsupported_version"


def test_stale_timestamp_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(sent_at=1_699_990_000),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "stale_timestamp"


def test_replay_nonce_rejected_before_delivery():
    seen: set[str] = set()

    def replay_guard(**kwargs):
        key = f"{kwargs['conversation_id']}:{kwargs['sender_user_id']}:{kwargs['nonce']}"
        if key in seen:
            return False
        seen.add(key)
        return True

    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    signaling.route_signaling_event(
        envelope=_envelope(event_id="evt-1", nonce="nonce-replay-1"),
        actor_user_id="caller",
        participant_resolver=lambda _cid: {"caller", "callee"},
        call_session_resolver=lambda _call_id: _call_session(),
        put_item=lambda **_kwargs: None,
        replay_guard=replay_guard,
    )
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(event_id="evt-2", nonce="nonce-replay-1"),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=replay_guard,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "replay_detected"


def test_missing_call_session_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: None,
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "call_not_found"


def test_call_conversation_mismatch_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(conversation_id="conv-x"),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(conversation_id="conv-1"),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "forbidden"


def test_call_participant_mismatch_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(sender_user_id="caller", recipient_user_id="callee"),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(caller_user_id="caller", callee_user_id="other"),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "forbidden"


def test_metrics_recorded_for_success_and_error_paths():
    observed: list[dict[str, object]] = []
    record_metric = lambda **kwargs: observed.append(dict(kwargs))

    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    signaling.route_signaling_event(
        envelope=_envelope(event_id="evt-metric-success"),
        actor_user_id="caller",
        participant_resolver=lambda _cid: {"caller", "callee"},
        call_session_resolver=lambda _call_id: _call_session(),
        put_item=lambda **_kwargs: None,
        replay_guard=lambda **_kwargs: True,
        metrics_recorder=record_metric,
    )
    with pytest.raises(signaling.SignalingValidationError):
        signaling.route_signaling_event(
            envelope=_envelope(event_id="evt-metric-error", recipient_user_id="outsider"),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
            metrics_recorder=record_metric,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert any(
        item["outcome"] == "success"
        and item["reason"] == "delivered"
        and item["event_type"] == "call.invite"
        and float(item["elapsed_seconds"]) >= 0.0
        for item in observed
    )
    assert any(
        item["outcome"] == "error"
        and item["reason"] == "forbidden"
        and item["event_type"] == "call.invite"
        and float(item["elapsed_seconds"]) >= 0.0
        for item in observed
    )


def test_duplicate_event_id_returns_idempotent_ack():
    observed: list[tuple[str, str, str]] = []
    record_metric = lambda **kwargs: observed.append((kwargs["outcome"], kwargs["reason"], kwargs["event_type"]))

    def duplicate_writer(**_kwargs):
        raise RuntimeError("ConditionalCheckFailedException: event_id already exists")

    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    ack = signaling.route_signaling_event(
        envelope=_envelope(event_id="evt-duplicate"),
        actor_user_id="caller",
        participant_resolver=lambda _cid: {"caller", "callee"},
        call_session_resolver=lambda _call_id: _call_session(),
        put_item=duplicate_writer,
        replay_guard=lambda **_kwargs: True,
        metrics_recorder=record_metric,
    )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert ack.status == "duplicate"
    assert ("success", "duplicate", "call.invite") in observed


def test_terminal_call_state_rejects_non_end_signaling():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(type="webrtc.offer"),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(state="ended"),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "invalid_state"


def test_terminal_call_state_allows_call_end_signal():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    ack = signaling.route_signaling_event(
        envelope=_envelope(type="call.end", event_id="evt-terminal-end"),
        actor_user_id="caller",
        participant_resolver=lambda _cid: {"caller", "callee"},
        call_session_resolver=lambda _call_id: _call_session(state="ended"),
        put_item=lambda **_kwargs: None,
        replay_guard=lambda **_kwargs: True,
    )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert ack.status == "delivered"


def test_webrtc_offer_rejected_before_call_accepted():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(type="webrtc.offer"),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(state="invited"),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "invalid_state"


def test_call_accept_allowed_while_invited():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]
    ack = signaling.route_signaling_event(
        envelope=_envelope(type="call.accept", event_id="evt-accept"),
        actor_user_id="caller",
        participant_resolver=lambda _cid: {"caller", "callee"},
        call_session_resolver=lambda _call_id: _call_session(state="invited"),
        put_item=lambda **_kwargs: None,
        replay_guard=lambda **_kwargs: True,
    )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert ack.status == "delivered"


def test_participant_lookup_failure_is_deterministic():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]

    def failing_participants(_conversation_id: str):
        raise RuntimeError("ddb outage")

    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(),
            actor_user_id="caller",
            participant_resolver=failing_participants,
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "participant_lookup_failed"


def test_replay_guard_failure_is_deterministic():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]

    def failing_guard(**_kwargs):
        raise RuntimeError("transient redis error")

    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=failing_guard,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "replay_guard_failed"


def test_call_lookup_failure_is_deterministic():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]

    def failing_call_lookup(_call_id: str):
        raise RuntimeError("table timeout")

    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=failing_call_lookup,
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "call_lookup_failed"


def test_overlong_event_id_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]

    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(event_id="e" * 129),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "validation_error"


def test_overlong_call_id_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]

    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(call_id="c" * 129),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "validation_error"


def test_oversized_payload_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]

    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(payload={"blob": "x" * 9000}),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "validation_error"


def test_non_serializable_payload_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]

    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(payload={"bad": object()}),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "validation_error"


def test_non_object_payload_rejected():
    original_now = signaling.now_ts
    signaling.now_ts = lambda: 1_700_000_000  # type: ignore[assignment]

    with pytest.raises(signaling.SignalingValidationError) as exc:
        signaling.route_signaling_event(
            envelope=_envelope(payload=["not", "an", "object"]),
            actor_user_id="caller",
            participant_resolver=lambda _cid: {"caller", "callee"},
            call_session_resolver=lambda _call_id: _call_session(),
            put_item=lambda **_kwargs: None,
            replay_guard=lambda **_kwargs: True,
        )
    signaling.now_ts = original_now  # type: ignore[assignment]

    assert exc.value.code == "validation_error"
