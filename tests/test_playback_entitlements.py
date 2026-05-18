from __future__ import annotations

import base64
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest

from app.services import playback_entitlements


@pytest.fixture()
def patched_settings():
    original = playback_entitlements.S
    playback_entitlements.S = SimpleNamespace(
        playback_entitlement_secret="test-secret",
        playback_entitlement_max_ttl_seconds=300,
        playback_entitlement_expected_audience="playback",
        playback_entitlement_max_clock_skew_seconds=30,
        playback_entitlement_replay_protection_enabled=False,
        playback_entitlement_max_token_length=4096,
        playback_entitlement_max_claim_length=256,
        playback_entitlement_replay_cache_max_entries=100_000,
        playback_entitlement_revocation_jti_cache_max_entries=100_000,
        playback_entitlement_revocation_session_cache_max_entries=100_000,
    )
    playback_entitlements.reset_replay_cache()
    playback_entitlements.reset_revocation_cache()
    try:
        yield
    finally:
        playback_entitlements.S = original
        playback_entitlements.reset_replay_cache()
        playback_entitlements.reset_revocation_cache()
    playback_entitlements.reset_revocation_cache()


def _decode_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    pad = "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64 + pad).decode("utf-8"))


def _replace_payload_and_resign(token: str, payload: object) -> str:
    header_b64, _, _ = token.split(".")
    payload_b64 = playback_entitlements._b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(playback_entitlements._token_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = playback_entitlements._b64url(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _replace_header_and_resign(token: str, header: object) -> str:
    _, payload_b64, _ = token.split(".")
    header_b64 = playback_entitlements._b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(playback_entitlements._token_secret().encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = playback_entitlements._b64url(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def test_issue_and_validate_token_enforces_audience_and_ttl(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=120,
        now_epoch=1_700_000_000,
    )

    claims = playback_entitlements.validate_playback_entitlement(
        token=issued["token"],
        expected_audience="playback",
        now_epoch=1_700_000_050,
    )
    assert claims["asset_id"] == "asset-1"
    assert claims["aud"] == "playback"
    assert isinstance(claims["jti"], str) and claims["jti"]


def test_token_length_limit_enforced(patched_settings) -> None:
    playback_entitlements.S.playback_entitlement_max_token_length = 20
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=("x" * 21),
            expected_audience="playback",
            now_epoch=1_700_000_050,
        )
    assert exc.value.code == "token_too_large"


def test_validate_uses_default_token_length_when_setting_invalid(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    playback_entitlements.S.playback_entitlement_max_token_length = "not-a-number"
    claims = playback_entitlements.validate_playback_entitlement(
        token=issued["token"],
        expected_audience="playback",
        now_epoch=1_700_000_001,
    )
    assert claims["tenant_id"] == "tenant-1"


def test_validate_uses_default_clock_skew_when_setting_invalid(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    payload = _decode_payload(issued["token"])
    payload["iat"] = 1_700_000_031
    payload["exp"] = 1_700_000_091
    tampered = _replace_payload_and_resign(issued["token"], payload)
    playback_entitlements.S.playback_entitlement_max_clock_skew_seconds = "bad-setting"

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_000,
        )
    assert exc.value.code == "token_not_yet_valid"


def test_issue_rejects_non_integer_ttl(patched_settings) -> None:
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.issue_playback_entitlement(
            tenant_id="tenant-1",
            asset_id="asset-1",
            session_id="session-1",
            device_id="device-1",
            profile="widevine",
            audience="playback",
            ttl_seconds="sixty",  # type: ignore[arg-type]
            now_epoch=1_700_000_000,
        )
    assert exc.value.code == "invalid_ttl"


def test_issue_uses_default_max_ttl_when_setting_invalid(patched_settings) -> None:
    playback_entitlements.S.playback_entitlement_max_ttl_seconds = "bad-setting"
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    assert issued["ttl_seconds"] == 60


def test_issue_rejects_boolean_ttl(patched_settings) -> None:
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.issue_playback_entitlement(
            tenant_id="tenant-1",
            asset_id="asset-1",
            session_id="session-1",
            device_id="device-1",
            profile="widevine",
            audience="playback",
            ttl_seconds=True,  # type: ignore[arg-type]
            now_epoch=1_700_000_000,
        )
    assert exc.value.code == "invalid_ttl"


def test_validate_rejects_non_integer_now_epoch(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=issued["token"],
            expected_audience="playback",
            now_epoch="bad-epoch",  # type: ignore[arg-type]
        )
    assert exc.value.code == "invalid_timestamp"


def test_validate_rejects_boolean_now_epoch(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=issued["token"],
            expected_audience="playback",
            now_epoch=False,  # type: ignore[arg-type]
        )
    assert exc.value.code == "invalid_timestamp"


def test_expired_token_rejected_deterministically(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=10,
        now_epoch=1_700_000_000,
    )

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=issued["token"],
            expected_audience="playback",
            now_epoch=1_700_000_011,
        )
    assert exc.value.code == "token_expired"


def test_invalid_audience_rejected_deterministically(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=issued["token"],
            expected_audience="thumbnail",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_audience"


def test_expected_audience_is_trimmed(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    claims = playback_entitlements.validate_playback_entitlement(
        token=issued["token"],
        expected_audience=" playback ",
        now_epoch=1_700_000_001,
    )
    assert claims["aud"] == "playback"


def test_expected_audience_required(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=issued["token"],
            expected_audience=" ",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_audience"


def test_ttl_limit_enforced(patched_settings) -> None:
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.issue_playback_entitlement(
            tenant_id="tenant-1",
            asset_id="asset-1",
            session_id="session-1",
            device_id="device-1",
            profile="widevine",
            audience="playback",
            ttl_seconds=301,
            now_epoch=1_700_000_000,
        )
    assert exc.value.code == "ttl_exceeds_max"


@pytest.mark.parametrize(
    ("field", "kwargs"),
    [
        ("tenant_id", {"tenant_id": "   "}),
        ("asset_id", {"asset_id": ""}),
        ("session_id", {"session_id": "  "}),
        ("device_id", {"device_id": ""}),
        ("profile", {"profile": " "}),
    ],
)
def test_issue_rejects_empty_identity_claims(field: str, kwargs: dict[str, str], patched_settings) -> None:
    base_kwargs = {
        "tenant_id": "tenant-1",
        "asset_id": "asset-1",
        "session_id": "session-1",
        "device_id": "device-1",
        "profile": "widevine",
        "audience": "playback",
        "ttl_seconds": 60,
        "now_epoch": 1_700_000_000,
    }
    base_kwargs.update(kwargs)

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.issue_playback_entitlement(**base_kwargs)
    assert exc.value.code == "invalid_claims", field


def test_issue_rejects_overlong_identity_claims(patched_settings) -> None:
    playback_entitlements.S.playback_entitlement_max_claim_length = 10
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.issue_playback_entitlement(
            tenant_id="tenant-claim-too-long",
            asset_id="asset-1",
            session_id="session-1",
            device_id="device-1",
            profile="widevine",
            audience="playback",
            ttl_seconds=60,
            now_epoch=1_700_000_000,
        )
    assert exc.value.code == "invalid_claims"


def test_replay_detection_when_enabled(patched_settings) -> None:
    playback_entitlements.S.playback_entitlement_replay_protection_enabled = True
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )

    playback_entitlements.validate_playback_entitlement(
        token=issued["token"],
        expected_audience="playback",
        now_epoch=1_700_000_001,
    )

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=issued["token"],
            expected_audience="playback",
            now_epoch=1_700_000_002,
        )
    assert exc.value.code == "replay_detected"


def test_tampered_ttl_claim_rejected_by_policy(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )

    payload = _decode_payload(issued["token"])
    payload["exp"] = payload["iat"] + 9999
    bad_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("utf-8").rstrip("=")
    header, _, sig = issued["token"].split(".")
    tampered_token = f"{header}.{bad_payload_b64}.{sig}"

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered_token,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_signature"


def test_revoked_jti_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    playback_entitlements.revoke_playback_entitlement(jti=issued["jti"], expires_at_epoch=4_100_000_100)

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=issued["token"],
            expected_audience="playback",
            now_epoch=1_700_000_010,
        )
    assert exc.value.code == "token_revoked"


def test_revoked_session_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    playback_entitlements.revoke_playback_entitlement(
        session_id="session-1",
        tenant_id="tenant-1",
        expires_at_epoch=4_100_000_100,
    )

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=issued["token"],
            expected_audience="playback",
            now_epoch=1_700_000_010,
        )
    assert exc.value.code == "session_revoked"


def test_revoked_session_without_tenant_rejected(patched_settings) -> None:
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.revoke_playback_entitlement(
            session_id="session-1",
            expires_at_epoch=4_100_000_100,
        )

    assert exc.value.code == "invalid_revocation_request"


def test_revocation_requires_selector(patched_settings) -> None:
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.revoke_playback_entitlement(expires_at_epoch=4_100_000_100)

    assert exc.value.code == "invalid_revocation_request"


def test_revocation_requires_future_expiry(patched_settings) -> None:
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.revoke_playback_entitlement(
            jti="jti-1",
            expires_at_epoch=1,
        )

    assert exc.value.code == "invalid_revocation_expiry"


def test_revocation_rejects_non_integer_expiry(patched_settings) -> None:
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.revoke_playback_entitlement(
            jti="jti-1",
            expires_at_epoch="soon",  # type: ignore[arg-type]
        )

    assert exc.value.code == "invalid_revocation_expiry"


def test_revocation_rejects_boolean_expiry(patched_settings) -> None:
    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.revoke_playback_entitlement(
            jti="jti-1",
            expires_at_epoch=True,  # type: ignore[arg-type]
        )

    assert exc.value.code == "invalid_revocation_expiry"


def test_revoked_session_is_tenant_scoped(patched_settings) -> None:
    issued_tenant_1 = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    issued_tenant_2 = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-2",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    playback_entitlements.revoke_playback_entitlement(
        session_id="session-1",
        tenant_id="tenant-1",
        expires_at_epoch=4_100_000_100,
    )

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=issued_tenant_1["token"],
            expected_audience="playback",
            now_epoch=1_700_000_010,
        )
    assert exc.value.code == "session_revoked"

    payload = playback_entitlements.validate_playback_entitlement(
        token=issued_tenant_2["token"],
        expected_audience="playback",
        now_epoch=1_700_000_010,
    )
    assert payload["tenant_id"] == "tenant-2"


def test_replay_cache_size_is_bounded(patched_settings) -> None:
    playback_entitlements.S.playback_entitlement_replay_protection_enabled = True
    playback_entitlements.S.playback_entitlement_replay_cache_max_entries = 2

    first = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    second = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-2",
        session_id="session-2",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    third = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-3",
        session_id="session-3",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )

    playback_entitlements.validate_playback_entitlement(
        token=first["token"],
        expected_audience="playback",
        now_epoch=1_700_000_001,
    )
    playback_entitlements.validate_playback_entitlement(
        token=second["token"],
        expected_audience="playback",
        now_epoch=1_700_000_002,
    )
    playback_entitlements.validate_playback_entitlement(
        token=third["token"],
        expected_audience="playback",
        now_epoch=1_700_000_003,
    )

    playback_entitlements.validate_playback_entitlement(
        token=first["token"],
        expected_audience="playback",
        now_epoch=1_700_000_004,
    )


def test_revocation_cache_size_is_bounded(patched_settings) -> None:
    playback_entitlements.S.playback_entitlement_revocation_jti_cache_max_entries = 2
    playback_entitlements.S.playback_entitlement_revocation_session_cache_max_entries = 2

    playback_entitlements.revoke_playback_entitlement(jti="jti-1", expires_at_epoch=4_100_000_100)
    playback_entitlements.revoke_playback_entitlement(jti="jti-2", expires_at_epoch=4_100_000_110)
    playback_entitlements.revoke_playback_entitlement(jti="jti-3", expires_at_epoch=4_100_000_120)
    assert set(playback_entitlements._REVOKED_JTI.keys()) == {"jti-2", "jti-3"}

    playback_entitlements.revoke_playback_entitlement(
        session_id="session-1",
        tenant_id="tenant-1",
        expires_at_epoch=4_100_000_100,
    )
    playback_entitlements.revoke_playback_entitlement(
        session_id="session-2",
        tenant_id="tenant-1",
        expires_at_epoch=4_100_000_110,
    )
    playback_entitlements.revoke_playback_entitlement(
        session_id="session-3",
        tenant_id="tenant-1",
        expires_at_epoch=4_100_000_120,
    )
    assert set(playback_entitlements._REVOKED_SESSIONS.keys()) == {"tenant-1:session-2", "tenant-1:session-3"}


def test_non_object_payload_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    tampered = _replace_payload_and_resign(issued["token"], ["not-a-dict"])

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_payload"


def test_invalid_epoch_claim_types_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    payload = _decode_payload(issued["token"])
    payload["exp"] = "not-an-epoch"
    tampered = _replace_payload_and_resign(issued["token"], payload)

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_claim_type"


def test_string_epoch_claim_rejected_even_if_numeric(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    payload = _decode_payload(issued["token"])
    payload["iat"] = "1700000000"
    tampered = _replace_payload_and_resign(issued["token"], payload)

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_claim_type"


def test_boolean_epoch_claim_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    payload = _decode_payload(issued["token"])
    payload["exp"] = True
    tampered = _replace_payload_and_resign(issued["token"], payload)

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_claim_type"


def test_empty_identity_claims_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    payload = _decode_payload(issued["token"])
    payload["tenant_id"] = "   "
    tampered = _replace_payload_and_resign(issued["token"], payload)

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_claims"


def test_non_string_identity_claim_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    payload = _decode_payload(issued["token"])
    payload["tenant_id"] = 123
    tampered = _replace_payload_and_resign(issued["token"], payload)

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_claim_type"


def test_overlong_identity_claim_rejected_on_validate(patched_settings) -> None:
    playback_entitlements.S.playback_entitlement_max_claim_length = 10
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    payload = _decode_payload(issued["token"])
    payload["session_id"] = "session-id-too-long"
    tampered = _replace_payload_and_resign(issued["token"], payload)

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_claims"


def test_non_string_audience_claim_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    payload = _decode_payload(issued["token"])
    payload["aud"] = {"name": "playback"}
    tampered = _replace_payload_and_resign(issued["token"], payload)

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_claim_type"


def test_invalid_header_alg_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    tampered = _replace_header_and_resign(issued["token"], {"alg": "none", "typ": "PLAYBACKJWT"})

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_header_alg"


def test_invalid_header_typ_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    tampered = _replace_header_and_resign(issued["token"], {"alg": "HS256", "typ": "JWT"})

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_header_typ"


def test_non_object_header_rejected(patched_settings) -> None:
    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    tampered = _replace_header_and_resign(issued["token"], ["not-a-dict"])

    with pytest.raises(playback_entitlements.PlaybackEntitlementError) as exc:
        playback_entitlements.validate_playback_entitlement(
            token=tampered,
            expected_audience="playback",
            now_epoch=1_700_000_001,
        )
    assert exc.value.code == "invalid_header"


def test_metrics_hooks_record_success_and_error(monkeypatch, patched_settings) -> None:
    events: list[tuple[str, str, str]] = []
    latencies: list[tuple[str, float]] = []

    monkeypatch.setattr(
        playback_entitlements,
        "record_playback_entitlement_event",
        lambda *, operation, outcome, reason="": events.append((operation, outcome, reason)),
    )
    monkeypatch.setattr(
        playback_entitlements,
        "record_playback_entitlement_latency",
        lambda *, operation, elapsed_seconds: latencies.append((operation, elapsed_seconds)),
    )

    issued = playback_entitlements.issue_playback_entitlement(
        tenant_id="tenant-1",
        asset_id="asset-1",
        session_id="session-1",
        device_id="device-1",
        profile="widevine",
        audience="playback",
        ttl_seconds=60,
        now_epoch=1_700_000_000,
    )
    playback_entitlements.validate_playback_entitlement(
        token=issued["token"],
        expected_audience="playback",
        now_epoch=1_700_000_001,
    )

    with pytest.raises(playback_entitlements.PlaybackEntitlementError):
        playback_entitlements.revoke_playback_entitlement(jti="jti-1", expires_at_epoch=1)

    assert ("issue", "success", "") in events
    assert ("validate", "success", "") in events
    assert ("revoke", "error", "invalid_revocation_expiry") in events
    operations_with_latency = {op for op, _ in latencies}
    assert {"issue", "validate", "revoke"} <= operations_with_latency
