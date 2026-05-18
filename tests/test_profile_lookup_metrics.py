from app import metrics


class _LabelsRecorder:
    def __init__(self) -> None:
        self.calls = []

    def labels(self, **kwargs):
        self.calls.append(kwargs)
        return self

    def inc(self, *_args, **_kwargs):
        return None

    def observe(self, *_args, **_kwargs):
        return None


def test_record_profile_lookup_normalizes_labels(monkeypatch) -> None:
    events = _LabelsRecorder()
    latency = _LabelsRecorder()
    monkeypatch.setattr(metrics, "PROFILE_LOOKUP_EVENTS", events)
    monkeypatch.setattr(metrics, "PROFILE_LOOKUP_LATENCY", latency)

    metrics.record_profile_lookup(
        audience="PUBLIC",
        result="Denied",
        suppression_reason="HIDDEN",
        elapsed_seconds=0.123,
    )

    assert events.calls == [{"audience": "public", "result": "denied", "suppression_reason": "hidden"}]
    assert latency.calls == [{"audience": "public", "result": "denied"}]


def test_record_profile_lookup_identifier_resolution_normalizes_labels(monkeypatch) -> None:
    resolver = _LabelsRecorder()
    monkeypatch.setattr(metrics, "PROFILE_LOOKUP_IDENTIFIER_RESOLUTION", resolver)

    metrics.record_profile_lookup_identifier_resolution(
        source="ALIAS_SCAN",
        outcome="Resolved",
    )

    assert resolver.calls == [{"source": "alias_scan", "outcome": "resolved"}]
