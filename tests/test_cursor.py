from unittest.mock import patch

from app.core.cursor import decode_cursor, encode_cursor


def test_encode_decode_signed_cursor_round_trip(monkeypatch) -> None:
    monkeypatch.setenv("CURSOR_SIGNING_SECRET", "test-secret")
    key = {"pk": "A", "sk": "B"}

    token = encode_cursor(key)

    assert token is not None
    assert token.startswith("v2.")
    assert decode_cursor(token) == key


def test_decode_cursor_rejects_tampered_signature(monkeypatch) -> None:
    monkeypatch.setenv("CURSOR_SIGNING_SECRET", "test-secret")
    token = encode_cursor({"pk": "A", "sk": "B"})
    assert token is not None

    bad = token[:-1] + ("A" if token[-1] != "A" else "B")

    assert decode_cursor(bad) is None


def test_decode_cursor_supports_legacy_unsigned_cursor(monkeypatch) -> None:
    monkeypatch.setenv("CURSOR_SIGNING_SECRET", "test-secret")
    # legacy encoding for {"pk":"A","sk":"B"}
    legacy = "eyJwayI6IkEiLCJzayI6IkIifQ"

    assert decode_cursor(legacy) == {"pk": "A", "sk": "B"}


def test_decode_cursor_accepts_previous_rotation_secret(monkeypatch) -> None:
    monkeypatch.setenv("CURSOR_SIGNING_SECRET", "new-secret")
    monkeypatch.setenv("CURSOR_SIGNING_SECRET_PREVIOUS", "old-secret")
    token = encode_cursor({"pk": "A", "sk": "B"})
    assert token is not None

    # Simulate token signed before rotation (old secret).
    monkeypatch.setenv("CURSOR_SIGNING_SECRET", "old-secret")
    monkeypatch.setenv("CURSOR_SIGNING_SECRET_PREVIOUS", "")
    old_token = encode_cursor({"pk": "A", "sk": "B"})
    assert old_token is not None

    # Rotate to new secret while still accepting previous.
    monkeypatch.setenv("CURSOR_SIGNING_SECRET", "new-secret")
    monkeypatch.setenv("CURSOR_SIGNING_SECRET_PREVIOUS", "old-secret")

    assert decode_cursor(token) == {"pk": "A", "sk": "B"}
    assert decode_cursor(old_token) == {"pk": "A", "sk": "B"}


def test_decode_cursor_emits_metric_with_previous_key_source(monkeypatch) -> None:
    monkeypatch.setenv("CURSOR_SIGNING_SECRET", "old-secret")
    token = encode_cursor({"pk": "A", "sk": "B"})
    assert token is not None

    monkeypatch.setenv("CURSOR_SIGNING_SECRET", "new-secret")
    monkeypatch.setenv("CURSOR_SIGNING_SECRET_PREVIOUS", "old-secret")
    with patch("app.core.cursor._record_decode_metric") as record_metric:
        assert decode_cursor(token) == {"pk": "A", "sk": "B"}

    record_metric.assert_called_with(format_name="v2", outcome="success", key_source="previous")
