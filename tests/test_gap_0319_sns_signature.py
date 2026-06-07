"""GAP-0319 — SNS notification endpoint signature verification.

Hermetic / offline. No real network: the cert-fetch and low-level verify are
patched. The router coroutine is driven directly with a fake Request (the in-repo
TestClient is unreliable per project guidance).

Fails-before / passes-after: before the fix the handler processed every payload
unconditionally; after the fix an unverifiable signature -> HTTPException(403)
and `_process_ses_notification` is NOT called.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.core.settings import S
import app.routers.ses_notifications as ses_mod
import app.services.sns_signature as sns_mod


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
class _FakeRequest:
    def __init__(self, payload: dict):
        self._payload = payload

    async def json(self):
        return self._payload


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _bounce_payload(cert_url="https://sns.us-east-1.amazonaws.com/cert.pem"):
    return {
        "Type": "Notification",
        "MessageId": "mid-1",
        "TopicArn": "arn:aws:sns:us-east-1:123:t",
        "Timestamp": "2026-06-07T00:00:00.000Z",
        "SignatureVersion": "1",
        "Signature": "QUJD",  # base64 "ABC"
        "SigningCertURL": cert_url,
        "Message": json.dumps(
            {
                "notificationType": "Bounce",
                "bounce": {
                    "bounceType": "Permanent",
                    "bounceSubType": "General",
                    "bouncedRecipients": [{"emailAddress": "victim@test.local"}],
                },
                "mail": {"messageId": "x", "source": "s", "destination": ["victim@test.local"]},
            }
        ),
    }


def _set_flag(value: bool):
    """S is a frozen dataclass -> object.__setattr__."""
    object.__setattr__(S, "ses_sns_signature_verification_enabled", value)


@pytest.fixture(autouse=True)
def _restore_flag():
    original = S.ses_sns_signature_verification_enabled
    yield
    object.__setattr__(S, "ses_sns_signature_verification_enabled", original)


# --------------------------------------------------------------------------- #
# 1. verification enabled + bad signature -> 403, NOT processed
# --------------------------------------------------------------------------- #
def test_enabled_bad_signature_rejects_403_and_does_not_process():
    _set_flag(True)
    # cert fetch returns a cert that won't match -> low-level verify raises.
    with patch.object(sns_mod, "fetch_signing_cert", return_value=b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"), \
         patch.object(ses_mod, "_process_ses_notification") as spy:
        with pytest.raises(HTTPException) as ei:
            _run(ses_mod.ses_notification(_FakeRequest(_bounce_payload())))
    assert ei.value.status_code == 403
    spy.assert_not_called()


# --------------------------------------------------------------------------- #
# 2. SSRF guard: malicious cert host -> 403 BEFORE any fetch
# --------------------------------------------------------------------------- #
def test_ssrf_guard_rejects_foreign_cert_url_before_fetch():
    _set_flag(True)
    payload = _bounce_payload(cert_url="https://evil.example/cert.pem")

    def _boom(*a, **k):  # must never be reached
        raise AssertionError("fetch_signing_cert called on a guarded URL")

    with patch.object(sns_mod, "fetch_signing_cert", side_effect=_boom), \
         patch.object(ses_mod, "_process_ses_notification") as spy:
        with pytest.raises(HTTPException) as ei:
            _run(ses_mod.ses_notification(_FakeRequest(payload)))
    assert ei.value.status_code == 403
    spy.assert_not_called()


def test_ssrf_guard_unit():
    assert sns_mod.is_allowed_aws_sns_url("https://sns.us-east-1.amazonaws.com/x.pem")
    assert sns_mod.is_allowed_aws_sns_url("https://sns.eu-west-2.amazonaws.com/c")
    # rejects
    assert not sns_mod.is_allowed_aws_sns_url("https://evil.example/cert.pem")
    assert not sns_mod.is_allowed_aws_sns_url("http://sns.us-east-1.amazonaws.com/x")  # not https
    assert not sns_mod.is_allowed_aws_sns_url("https://sns.us-east-1.amazonaws.com.evil.com/x")
    assert not sns_mod.is_allowed_aws_sns_url("https://attacker.amazonaws.com/x")  # not sns.
    assert not sns_mod.is_allowed_aws_sns_url("")


# --------------------------------------------------------------------------- #
# 3. verification DISABLED via flag -> processes (dev / back-compat)
# --------------------------------------------------------------------------- #
def test_disabled_flag_processes_without_verification():
    _set_flag(False)
    with patch.object(sns_mod, "fetch_signing_cert", side_effect=AssertionError("should not fetch")), \
         patch.object(ses_mod, "_process_ses_notification") as spy:
        resp = _run(ses_mod.ses_notification(_FakeRequest(_bounce_payload())))
    assert resp.status_code == 200
    spy.assert_called_once()


# --------------------------------------------------------------------------- #
# 4. positive: verifier accepts -> processed (verify patched to succeed)
# --------------------------------------------------------------------------- #
def test_enabled_valid_signature_processes():
    _set_flag(True)
    with patch.object(ses_mod, "verify_sns_message", return_value=None), \
         patch.object(ses_mod, "_process_ses_notification") as spy:
        resp = _run(ses_mod.ses_notification(_FakeRequest(_bounce_payload())))
    assert resp.status_code == 200
    spy.assert_called_once()


# --------------------------------------------------------------------------- #
# 5. SubscriptionConfirmation auto-confirms (best-effort) after verify
# --------------------------------------------------------------------------- #
def test_subscription_confirmation_fetches_subscribe_url():
    _set_flag(True)
    payload = {
        "Type": "SubscriptionConfirmation",
        "MessageId": "mid-2",
        "Token": "tok",
        "TopicArn": "arn:aws:sns:us-east-1:123:t",
        "Timestamp": "2026-06-07T00:00:00.000Z",
        "SubscribeURL": "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription",
        "Message": "You have chosen to subscribe",
        "SignatureVersion": "1",
        "Signature": "QUJD",
        "SigningCertURL": "https://sns.us-east-1.amazonaws.com/cert.pem",
    }
    with patch.object(ses_mod, "verify_sns_message", return_value=None), \
         patch.object(ses_mod, "confirm_subscription") as confirm_spy:
        resp = _run(ses_mod.ses_notification(_FakeRequest(payload)))
    assert resp.status_code == 200
    confirm_spy.assert_called_once_with(payload["SubscribeURL"])


# --------------------------------------------------------------------------- #
# 6. real-keypair end-to-end positive (no network: cert fetch patched)
# --------------------------------------------------------------------------- #
def test_real_keypair_signature_verifies_end_to_end():
    """Sign a canonical SNS message with a self-signed cert and verify it."""
    import base64
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sns.amazonaws.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2099, 1, 1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)

    payload = _bounce_payload()
    payload["SignatureVersion"] = "1"  # SHA1
    canonical = sns_mod._build_canonical_string(payload)
    sig = key.sign(canonical, padding.PKCS1v15(), hashes.SHA1())
    payload["Signature"] = base64.b64encode(sig).decode("ascii")

    _set_flag(True)
    with patch.object(sns_mod, "fetch_signing_cert", return_value=pem), \
         patch.object(ses_mod, "_process_ses_notification") as spy:
        resp = _run(ses_mod.ses_notification(_FakeRequest(payload)))
    assert resp.status_code == 200
    spy.assert_called_once()

    # And a tampered message with the same sig must 403.
    tampered = dict(payload)
    tampered["MessageId"] = "tampered"
    with patch.object(sns_mod, "fetch_signing_cert", return_value=pem), \
         patch.object(ses_mod, "_process_ses_notification") as spy2:
        with pytest.raises(HTTPException) as ei:
            _run(ses_mod.ses_notification(_FakeRequest(tampered)))
    assert ei.value.status_code == 403
    spy2.assert_not_called()
