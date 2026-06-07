"""AWS SNS message signature verification (PLATFORM-002 / GAP-0319).

AWS SNS signs every HTTPS push message with an RSA signature over a canonical
string built from a fixed, type-specific subset of the message fields. The
endpoint that receives these messages (``app/routers/ses_notifications.py``)
must verify this signature before acting on the payload, otherwise anyone who
can reach the endpoint can forge bounce/complaint notifications and suppress
email delivery to arbitrary addresses.

This module implements that verification with no third-party dependency beyond
``requests`` (for fetching the signing certificate) and ``cryptography`` (for
the RSA verification) — both already used elsewhere in the repo.

SECURITY: ``SigningCertURL`` is attacker-influenced. We SSRF-guard it (must be
``https://sns.<region>.amazonaws.com/...``) BEFORE any network fetch, so an
attacker cannot point the cert URL at their own RSA key.
"""
from __future__ import annotations

import base64
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Field order that SNS uses to build the string-to-sign. Order matters and
# differs by message type. Only fields actually present in the body are
# included (per the SNS spec).
_CANONICAL_FIELDS: Dict[str, List[str]] = {
    "Notification": ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"],
    "SubscriptionConfirmation": [
        "Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type",
    ],
    "UnsubscribeConfirmation": [
        "Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type",
    ],
}

# In-process cert cache keyed by URL (certs are stable per region/key rotation).
_CERT_CACHE: Dict[str, bytes] = {}

# Cert URL must be AWS SNS: https + host "sns.<something>.amazonaws.com".
_SNS_CERT_HOST_RE = re.compile(r"^sns\.[a-z0-9-]+\.amazonaws\.com$")


class SnsSignatureError(Exception):
    """Raised when an SNS message fails signature verification."""


def is_allowed_aws_sns_url(url: str) -> bool:
    """SSRF guard: only allow https URLs whose host is an AWS SNS endpoint.

    Used for both ``SigningCertURL`` and ``SubscribeURL``. Host must be
    ``sns.<region>.amazonaws.com`` (https only). Anything else is rejected so
    an attacker cannot redirect the cert fetch / confirmation to their own host.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    if not host.endswith(".amazonaws.com"):
        return False
    if not host.startswith("sns."):
        return False
    return bool(_SNS_CERT_HOST_RE.match(host))


def _build_canonical_string(body: Dict[str, Any]) -> bytes:
    """Build the canonical string-to-sign per the SNS spec for this msg type."""
    msg_type = body.get("Type", "")
    fields = _CANONICAL_FIELDS.get(msg_type)
    if not fields:
        raise SnsSignatureError(f"unsupported SNS message type: {msg_type!r}")
    parts: List[str] = []
    for field in fields:
        if field in body and body[field] is not None:
            parts.append(field)
            parts.append(str(body[field]))
    # SNS format: "<name>\n<value>\n" repeated, no trailing separator beyond it.
    return ("".join(f"{n}\n{v}\n" for n, v in zip(parts[0::2], parts[1::2]))).encode("utf-8")


def fetch_signing_cert(cert_url: str) -> bytes:
    """Fetch (and cache) the PEM signing certificate. SSRF-guarded by caller.

    Raises ``SnsSignatureError`` on any fetch failure. Isolated into its own
    function so tests can patch it without any outbound network.
    """
    cached = _CERT_CACHE.get(cert_url)
    if cached is not None:
        return cached
    try:
        import requests  # local import; keeps module import cheap/offline-safe

        resp = requests.get(cert_url, timeout=5)
        resp.raise_for_status()
        pem = resp.content
    except Exception as exc:  # noqa: BLE001
        raise SnsSignatureError(f"failed to fetch signing cert: {exc}") from exc
    _CERT_CACHE[cert_url] = pem
    return pem


def _hash_for_signature_version(sig_version: str):
    from cryptography.hazmat.primitives import hashes

    # v1 -> SHA1, v2 -> SHA256. Default to SHA1 (legacy) only for explicit "1".
    if str(sig_version) == "2":
        return hashes.SHA256()
    if str(sig_version) == "1":
        return hashes.SHA1()
    raise SnsSignatureError(f"unsupported SignatureVersion: {sig_version!r}")


def verify_sns_message(body: Dict[str, Any]) -> None:
    """Verify an SNS message signature. Raises ``SnsSignatureError`` on failure.

    Steps:
      1. SSRF-guard ``SigningCertURL`` (https + sns.<region>.amazonaws.com).
      2. Fetch the signing cert (cached).
      3. Rebuild the canonical string-to-sign for this message type.
      4. RSA-verify ``Signature`` (base64) using SignatureVersion 1 (SHA1) or
         2 (SHA256).
    """
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.x509 import load_pem_x509_certificate

    cert_url = body.get("SigningCertURL", "") or ""
    if not is_allowed_aws_sns_url(cert_url):
        # SSRF guard: reject BEFORE any network access.
        raise SnsSignatureError("SigningCertURL is not a valid AWS SNS https URL")

    signature_b64 = body.get("Signature", "") or ""
    if not signature_b64:
        raise SnsSignatureError("missing Signature")
    try:
        signature = base64.b64decode(signature_b64)
    except Exception as exc:  # noqa: BLE001
        raise SnsSignatureError(f"invalid base64 Signature: {exc}") from exc

    sig_version = body.get("SignatureVersion", "1")
    hash_alg = _hash_for_signature_version(sig_version)

    canonical = _build_canonical_string(body)

    pem = fetch_signing_cert(cert_url)
    try:
        cert = load_pem_x509_certificate(pem)
        public_key = cert.public_key()
    except Exception as exc:  # noqa: BLE001
        raise SnsSignatureError(f"failed to load signing cert: {exc}") from exc

    try:
        public_key.verify(signature, canonical, padding.PKCS1v15(), hash_alg)
    except Exception as exc:  # noqa: BLE001 - InvalidSignature etc.
        raise SnsSignatureError("SNS signature verification failed") from exc


def confirm_subscription(subscribe_url: str) -> None:
    """Best-effort auto-confirm an SNS subscription by GETting SubscribeURL.

    SSRF-guarded with the same AWS SNS host check. Raises ``SnsSignatureError``
    if the URL fails the guard; network errors are surfaced as well (the caller
    wraps this in try/except).
    """
    if not is_allowed_aws_sns_url(subscribe_url):
        raise SnsSignatureError("SubscribeURL is not a valid AWS SNS https URL")
    import requests  # local import

    resp = requests.get(subscribe_url, timeout=5)
    resp.raise_for_status()
