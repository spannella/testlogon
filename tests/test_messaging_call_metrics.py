from __future__ import annotations

from dataclasses import dataclass, field

from app import metrics


@dataclass
class _FakeMetric:
    label_calls: list[dict[str, str]] = field(default_factory=list)
    inc_calls: int = 0
    observes: list[float] = field(default_factory=list)

    def labels(self, **kwargs):
        self.label_calls.append(dict(kwargs))
        return self

    def inc(self, value: float = 1.0):
        self.inc_calls += 1
        self.observes.append(float(value))

    def observe(self, value: float):
        self.observes.append(float(value))


def test_record_webrtc_call_setup_and_failure_helpers(monkeypatch):
    setup_total = _FakeMetric()
    setup_latency = _FakeMetric()
    failures = _FakeMetric()

    monkeypatch.setattr(metrics, "WEBRTC_CALL_SETUP_EVENTS", setup_total)
    monkeypatch.setattr(metrics, "WEBRTC_CALL_SETUP_LATENCY", setup_latency)
    monkeypatch.setattr(metrics, "WEBRTC_CALL_FAILURE_EVENTS", failures)

    metrics.record_webrtc_call_setup(
        outcome="SUCCESS",
        reason="Invite_Accepted",
        platform="Web",
        browser="Chrome",
        latency_seconds=1.23,
    )
    metrics.record_webrtc_call_failure(reason="NETWORK_DROP", stage="Reconnect", platform="IOS", browser="Safari")

    assert setup_total.label_calls[0]["outcome"] == "success"
    assert setup_total.label_calls[0]["platform"] == "web"
    assert setup_total.label_calls[0]["browser"] == "chrome"
    assert setup_latency.observes[-1] == 1.23

    assert failures.label_calls[0]["reason"] == "network_drop"
    assert failures.label_calls[0]["stage"] == "reconnect"
    assert failures.label_calls[0]["platform"] == "ios"
    assert failures.label_calls[0]["browser"] == "safari"


def test_record_webrtc_duration_and_network_path(monkeypatch):
    duration = _FakeMetric()
    network = _FakeMetric()

    monkeypatch.setattr(metrics, "WEBRTC_CALL_DURATION", duration)
    monkeypatch.setattr(metrics, "WEBRTC_CALL_NETWORK_PATH_EVENTS", network)

    metrics.record_webrtc_call_connected(network_path="TURN")
    metrics.record_webrtc_call_duration(duration_seconds=42.0, end_reason="ENDED", network_path="P2P")

    assert network.label_calls[0]["network_path"] == "turn"
    assert duration.label_calls[0]["end_reason"] == "ended"
    assert duration.label_calls[0]["network_path"] == "p2p"
    assert duration.observes[-1] == 42.0


def test_record_webrtc_signaling_event(monkeypatch):
    signaling_events = _FakeMetric()
    monkeypatch.setattr(metrics, "WEBRTC_SIGNALING_EVENTS", signaling_events)

    metrics.record_webrtc_signaling_event(outcome="ERROR", reason="Replay_Detected", event_type="webrtc.offer")

    assert signaling_events.label_calls[0]["outcome"] == "error"
    assert signaling_events.label_calls[0]["reason"] == "replay_detected"
    assert signaling_events.label_calls[0]["event_type"] == "webrtc.offer"


def test_record_turn_credential_issue_latency(monkeypatch):
    turn_latency = _FakeMetric()
    monkeypatch.setattr(metrics, "TURN_CREDENTIAL_ISSUE_LATENCY", turn_latency)

    metrics.record_turn_credential_issue_latency(outcome="SUCCESS", reason="Issued", elapsed_seconds=0.125)

    assert turn_latency.label_calls[0]["outcome"] == "success"
    assert turn_latency.label_calls[0]["reason"] == "issued"
    assert turn_latency.observes[-1] == 0.125


def test_record_webrtc_signaling_latency(monkeypatch):
    signaling_latency = _FakeMetric()
    monkeypatch.setattr(metrics, "WEBRTC_SIGNALING_LATENCY", signaling_latency)

    metrics.record_webrtc_signaling_latency(
        outcome="SUCCESS",
        reason="Delivered",
        event_type="call.invite",
        elapsed_seconds=0.02,
    )

    assert signaling_latency.label_calls[0]["outcome"] == "success"
    assert signaling_latency.label_calls[0]["reason"] == "delivered"
    assert signaling_latency.label_calls[0]["event_type"] == "call.invite"
    assert signaling_latency.observes[-1] == 0.02
