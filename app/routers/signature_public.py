"""Public (light-auth) signing endpoints (SUX-004 / SUX-015 / SUX-016).

A signer can open, fill required fields, acknowledge the legal notice, and
complete a signature packet using only a signed public link (SUX-002) — no
login. The link's ``signer_id`` substitutes for ``user_sub`` everywhere the
authenticated path uses it (signers are identified by ``signer_id == user_sub``
today). Owner-only operations (edit fields, send, mint link) are NOT exposed
here.

Security (SUX-015):
- scope check (``scope == "sign"``), packet+signer binding, expiry — all in
  ``verify_signing_token``;
- revocation + one-time-use on completion via the consumption store (SUX-003);
- per-token (``jti``) rate limiting using the DDB-backed ``_bucket_limit``;
- the raw token is never echoed back / logged (only ``jti`` + ``signer_id``).

The whole router is gated by ``S.signature_public_link_enabled`` (default OFF):
when disabled every endpoint returns 404 so existing behaviour is unchanged.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request, Response

from app.core.settings import S
from app.services.rate_limit import _bucket_limit
from app.services.signature_packet_flags import SignaturePdfDisabledError
from app.services.signature_public_link import (
    is_token_consumed,
    is_token_revoked,
    verify_signing_token,
)

# Reuse the authenticated handlers' logic by substituting signer_id for user_sub.
from app.routers import signature_packets as sp

router = APIRouter(prefix="/ui/sign", tags=["signature-public"])


def _require_enabled() -> None:
    if not S.signature_public_link_enabled:
        # 404 (not 503) so the public surface gives nothing away when disabled.
        raise HTTPException(status_code=404, detail={"code": "signature_public_link_disabled"})


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for") or ""
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


def _rate_limit(jti: str) -> None:
    """Per-token rate limit keyed by jti (SUX-015) to blunt brute force."""
    ok = _bucket_limit(
        f"signlink:{jti}",
        "rl#public_sign",
        S.signature_public_link_rate_max_per_window,
        S.signature_public_link_rate_window_seconds,
    )
    if not ok:
        raise HTTPException(
            status_code=429,
            detail={"code": "signing_link_rate_limited"},
            headers={"Retry-After": str(S.signature_public_link_rate_window_seconds)},
        )


def _resolve_token(token: str) -> Dict[str, Any]:
    """Verify the token + reject revoked/consumed; rate limit by jti.

    Returns the payload ``{packet_id, signer_id, jti, ...}``. Raises 403 on any
    failure with a generic code (no packet data leaked, token never echoed).
    """
    payload = verify_signing_token(token)
    if not payload:
        raise HTTPException(status_code=403, detail={"code": "signing_link_invalid"})
    jti = str(payload.get("jti") or "")
    _rate_limit(jti)
    if is_token_revoked(jti):
        raise HTTPException(status_code=403, detail={"code": "signing_link_revoked"})
    if is_token_consumed(jti):
        raise HTTPException(status_code=403, detail={"code": "signing_link_used"})
    return payload


def _audit(packet_id: str, signer_id: str, event_type: str, request: Request, extra: Optional[Dict[str, Any]] = None) -> None:
    payload: Dict[str, Any] = {"signer_id": signer_id, "source_ip": _client_ip(request)}
    if extra:
        payload.update(extra)
    try:
        sp.append_packet_event(
            packet_id=packet_id,
            actor_user_id=signer_id,
            event_type=event_type,
            event_payload=payload,
        )
    except Exception:
        pass


@router.get("/{token}", response_model=sp.SignaturePacketDetailOut)
def public_get_signing_detail(token: str, request: Request) -> Dict[str, Any]:
    _require_enabled()
    payload = _resolve_token(token)
    packet_id = str(payload["packet_id"])
    signer_id = str(payload["signer_id"])
    # Bind: the signer must actually be assigned to this packet.
    if not sp.signer_assignment_exists(packet_id, signer_id):
        raise HTTPException(status_code=403, detail={"code": "signing_link_invalid"})
    try:
        detail = sp.get_signature_packet_detail(packet_id, user_sub=signer_id)
    except SignaturePdfDisabledError as exc:
        raise HTTPException(status_code=404, detail={"code": "signature_packet_not_found"}) from exc
    _audit(packet_id, signer_id, "signing_link_opened", request)
    return detail


@router.post("/{token}/fields/{field_id}/fill", response_model=sp.SignaturePacketFieldFillOut)
def public_fill_field(
    token: str,
    field_id: str,
    inp: sp.SignaturePacketFieldFillIn,
    request: Request,
) -> Dict[str, Any]:
    _require_enabled()
    payload = _resolve_token(token)
    packet_id = str(payload["packet_id"])
    signer_id = str(payload["signer_id"])
    result = sp.fill_signature_packet_field(
        packet_id,
        field_id,
        inp,
        user_sub=signer_id,
        request_ip=_client_ip(request),
    )
    _audit(packet_id, signer_id, "public_field_filled", request, {"field_id": field_id})
    return result


@router.post("/{token}/acknowledge-legal-notice", response_model=sp.SignaturePacketLegalNoticeAckOut)
def public_acknowledge_legal_notice(token: str, request: Request) -> Dict[str, Any]:
    _require_enabled()
    payload = _resolve_token(token)
    packet_id = str(payload["packet_id"])
    signer_id = str(payload["signer_id"])
    result = sp.acknowledge_signature_packet_legal_notice(packet_id, user_sub=signer_id)
    _audit(packet_id, signer_id, "public_legal_notice_accepted", request)
    return result


@router.post("/{token}/mark-done", response_model=sp.SignaturePacketMarkDoneOut)
def public_mark_done(token: str, request: Request) -> Dict[str, Any]:
    _require_enabled()
    payload = _resolve_token(token)
    packet_id = str(payload["packet_id"])
    signer_id = str(payload["signer_id"])
    jti = str(payload["jti"])
    result = sp.mark_signature_packet_done(
        packet_id,
        user_sub=signer_id,
        request_ip=_client_ip(request),
    )
    # One-time-use: consume the token on successful completion (SUX-003).
    from app.services.signature_public_link import consume_token

    consume_token(jti)
    _audit(packet_id, signer_id, "public_signer_completed", request)
    return result
