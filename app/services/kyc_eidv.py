"""KYC-022: Electronic Identity Verification (eIDV) service.

NET-NEW feature. Integrates (MOCK, for dev) government electronic-ID (eID)
schemes that provide cryptographically-signed identity assertions. A successful
eID assertion provides government-verified identity data (name, DOB, nationality,
document number) that AUTO-FILLS / auto-verifies the KYC case for Tier 2,
bypassing manual ID-document review.

This module builds on top of the existing KYC case feature
(``app/services/kyc_cases.py``) and the tiered verification feature
(``app/services/kyc_tiers.py``) without modifying them. eID verification
sessions and assertions are stored on the *same* ``kyc_cases`` single-table item
collection under distinct sort keys -- ``EID_SESSION#...`` and ``EIDV#...`` --
mirroring the KYC-014 ``FACE_MATCH#`` style so a second table is not required.

Determinism: like the other KYC mocks, the eID assertion result is derived
deterministically from input. We use ``zlib.crc32`` / ``hashlib`` -- NOT the
builtin ``hash()`` which is salted per-process -- so the same inputs always yield
the same assertion across runs and processes. The cryptographic "signature" is a
mock HMAC-SHA256 over the canonical assertion payload keyed with
``S.kyc_eid_mock_signing_key`` (this is a MOCK -- it is not real eID crypto).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import uuid
import zlib
from typing import Any

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

# --- constants -------------------------------------------------------------

SESSION_TTL_SECONDS = 3600  # eID session valid for 1 hour
ASSERTION_TTL_SECONDS = 600  # signed assertion valid for 10 minutes

STATUS_PENDING = "pending"
STATUS_COMPLETED = "completed"
STATUS_EXPIRED = "expired"
STATUS_FAILED = "failed"

# The supported (mock) eID schemes. Mirrors the spec §1.2 table.
SUPPORTED_SCHEMES: list[dict[str, Any]] = [
    {
        "id": "eidas",
        "name": "eIDAS (EU)",
        "countries": ["DE", "FR", "ES", "IT", "NL", "SE", "PL", "BE", "AT", "FI"],
        "assurance_level": "high",
        "auth_flow": "browser_redirect",
        "description": "EU eIDAS scheme -- redirect to your national eID node.",
        "default_nationality": "DE",
    },
    {
        "id": "digid",
        "name": "DigiD",
        "countries": ["NL"],
        "assurance_level": "substantial",
        "auth_flow": "browser_redirect",
        "description": "Authenticate with your Dutch DigiD.",
        "default_nationality": "NL",
    },
    {
        "id": "bankid",
        "name": "BankID",
        "countries": ["SE", "NO"],
        "assurance_level": "high",
        "auth_flow": "mobile_app_qr",
        "description": "Authenticate with your Swedish or Norwegian BankID.",
        "default_nationality": "SE",
    },
    {
        "id": "aadhaar",
        "name": "Aadhaar",
        "countries": ["IN"],
        "assurance_level": "substantial",
        "auth_flow": "otp_biometric",
        "description": "Authenticate with your Indian Aadhaar (OTP + biometric).",
        "default_nationality": "IN",
    },
]

_ASSURANCE_RANK = {"low": 0, "substantial": 1, "high": 2}

# Tier 2 == "ID Verified" in app/services/kyc_tiers.py (KYC_TIER_NAMES[2]).
TIER_ID_VERIFIED = 2


# --- errors ----------------------------------------------------------------


class KycEidvError(ValueError):
    """Base error for eIDV operations (string code = message/code)."""


# --- helpers ---------------------------------------------------------------


def _case_pk(case_id: str) -> str:
    return f"KYC#{case_id}"


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _new_session_id() -> str:
    return f"es_{uuid.uuid4().hex[:16]}"


def _new_assertion_id() -> str:
    return f"ea_{uuid.uuid4().hex[:12]}"


def _enabled_scheme_ids() -> list[str]:
    raw = str(S.kyc_eid_schemes or "")
    return [s.strip() for s in raw.split(",") if s.strip()]


def get_supported_schemes(*, country: str | None = None) -> list[dict[str, Any]]:
    """List available eID schemes, optionally filtered by country.

    Only schemes enabled via ``S.kyc_eid_schemes`` are returned.
    """
    enabled = set(_enabled_scheme_ids())
    out: list[dict[str, Any]] = []
    country_norm = str(country or "").strip().upper() or None
    for scheme in SUPPORTED_SCHEMES:
        if scheme["id"] not in enabled:
            continue
        if country_norm and country_norm not in scheme["countries"]:
            continue
        out.append(
            {
                "id": scheme["id"],
                "name": scheme["name"],
                "countries": list(scheme["countries"]),
                "assurance_level": scheme["assurance_level"],
                "auth_flow": scheme["auth_flow"],
                "description": scheme["description"],
            }
        )
    return out


def _scheme_def(scheme: str) -> dict[str, Any]:
    sid = str(scheme or "").strip().lower()
    if sid not in set(_enabled_scheme_ids()):
        raise KycEidvError("eid_unsupported_scheme")
    found = next((s for s in SUPPORTED_SCHEMES if s["id"] == sid), None)
    if not found:
        raise KycEidvError("eid_unsupported_scheme")
    return found


# --- mock provider (deterministic signed assertion) ------------------------


def _mock_assertion_fields(*, scheme_def: dict[str, Any], session_id: str) -> dict[str, str]:
    """Deterministic mock identity fields for an eID assertion.

    crc32 is process-stable (unlike builtin hash()), so the document number --
    and therefore the whole assertion -- is reproducible for a given session.
    """
    digest = zlib.crc32(f"eidv|{session_id}".encode("utf-8"))
    nationality = str(scheme_def.get("default_nationality") or "SE")
    return {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": "1990-01-15",
        "nationality": nationality,
        "document_number": f"MOCK-{digest & 0xFFFFFFFF:08x}",
        "document_type": "national_id",
        "issuing_country": nationality,
    }


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sign_assertion(raw_payload: str) -> str:
    """Mock HMAC-SHA256 signature over the canonical assertion payload.

    Reuses the same HMAC primitive style as ``app/core/crypto.py``. This is a
    MOCK -- not real eID crypto -- it just lets the verifier detect tampering.
    """
    key = str(S.kyc_eid_mock_signing_key or "dev-mock-eid-signing-key").encode("utf-8")
    sig = hmac.new(key, raw_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return sig


def validate_assertion_signature(*, raw_assertion: str, signature: str) -> bool:
    """Verify the mock cryptographic signature of an assertion payload.

    ``raw_assertion`` is the base64-encoded canonical JSON payload; ``signature``
    is the HMAC-SHA256 hex digest. Uses constant-time comparison.
    """
    try:
        decoded = base64.b64decode(str(raw_assertion).encode("utf-8")).decode("utf-8")
    except Exception:
        return False
    expected = _sign_assertion(decoded)
    return hmac.compare_digest(expected, str(signature or ""))


def build_mock_assertion(session_id: str) -> dict[str, str]:
    """Build a signed mock assertion for a pending session (the mock provider).

    Returns ``{assertion, signature}`` where ``assertion`` is base64-encoded
    canonical JSON and ``signature`` is its HMAC-SHA256 hex digest.
    """
    session = get_verification_session(session_id)
    if not session:
        raise KycEidvError("eid_session_not_found")
    scheme_def = _scheme_def(str(session.get("scheme") or ""))
    # Determinism for a session: derive the assertion id + issued time from the
    # session (stable) rather than a fresh uuid / now_ts() per call, so repeated
    # mock verifies of the same session return an identical signed assertion.
    ts = int(session.get("created_at") or now_ts())
    fields = _mock_assertion_fields(scheme_def=scheme_def, session_id=session_id)
    payload = {
        "assertion_id": "ea_" + hashlib.sha256(f"aid|{session_id}".encode("utf-8")).hexdigest()[:12],
        "scheme": scheme_def["id"],
        "issuer": f"{scheme_def['id'].upper()}-MOCK",
        "subject_id": f"{scheme_def.get('default_nationality') or 'XX'}:{fields['document_number']}",
        "verified_fields": fields,
        "assurance_level": scheme_def["assurance_level"],
        "issued_at": ts,
        "expires_at": ts + ASSERTION_TTL_SECONDS,
        "session_id": session_id,
    }
    raw = _canonical_payload(payload)
    raw_b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    signature = _sign_assertion(raw)
    logger.info("eid.mock.assertion.built session_id=%s scheme=%s", session_id, scheme_def["id"])
    return {"assertion": raw_b64, "signature": signature}


# --- profile comparison ----------------------------------------------------


def _load_profile_fields(user_sub: str) -> dict[str, str]:
    try:
        from app.services.profile import get_profile

        profile = get_profile(user_sub)
    except Exception:  # pragma: no cover - defensive
        profile = {}
    return {
        "first_name": str(profile.get("first_name") or "").strip(),
        "last_name": str(profile.get("last_name") or "").strip(),
        "date_of_birth": str(profile.get("birthday") or "").strip(),
    }


def compare_with_profile(*, verified_fields: dict[str, str], user_sub: str) -> list[dict[str, Any]]:
    """Compare eID-verified fields with the user's profile.

    Returns a list of discrepancy records. A DOB mismatch is ``critical``; a
    name mismatch is a ``warning``. Matching fields are not included so an empty
    list means "no discrepancies".
    """
    profile = _load_profile_fields(user_sub)
    discrepancies: list[dict[str, Any]] = []

    def _cmp(field: str, severity_on_mismatch: str) -> None:
        prof_val = str(profile.get(field) or "").strip()
        eid_val = str(verified_fields.get(field) or "").strip()
        if not prof_val:
            return  # nothing to compare against
        if prof_val.casefold() != eid_val.casefold():
            discrepancies.append(
                {
                    "field": field,
                    "profile_value": prof_val,
                    "eid_value": eid_val,
                    "severity": severity_on_mismatch,
                }
            )

    _cmp("first_name", "warning")
    _cmp("last_name", "warning")
    _cmp("date_of_birth", "critical")
    return discrepancies


# --- session storage -------------------------------------------------------


def create_verification_session(
    *,
    case_id: str,
    scheme: str,
    user_sub: str,
    callback_base: str = "",
) -> dict[str, Any]:
    """Create an eID verification session for a draft case.

    Validates ownership + draft status, then writes an ``EID_SESSION#`` item and
    returns ``{session_id, redirect_url, expires_at, scheme}``.
    """
    case = T.kyc_cases.get_item(Key={"pk": _case_pk(case_id), "sk": "META"}).get("Item")
    if not case:
        raise KycEidvError("case_not_found")
    if str(case.get("user_sub") or "") != str(user_sub):
        raise KycEidvError("eid_not_owner")
    if str(case.get("status") or "") != "draft":
        raise KycEidvError("eid_case_not_draft")

    scheme_def = _scheme_def(scheme)
    sid = _new_session_id()
    ts = now_ts()
    expires_at = ts + SESSION_TTL_SECONDS
    redirect_url = f"{callback_base}/mock/eid/verify?session_id={sid}"
    item = {
        "pk": f"EID_SESSION#{sid}",
        "sk": "META",
        "entity_type": "kyc_eid_session",
        "session_id": sid,
        "case_id": case_id,
        "user_sub": user_sub,
        "scheme": scheme_def["id"],
        "redirect_url": redirect_url,
        "status": STATUS_PENDING,
        "created_at": ts,
        "expires_at": expires_at,
        "ttl": expires_at,
    }
    T.kyc_cases.put_item(Item=item)
    logger.info("eid.session.created session_id=%s case_id=%s scheme=%s", sid, case_id, scheme_def["id"])
    return {
        "session_id": sid,
        "redirect_url": redirect_url,
        "expires_at": expires_at,
        "scheme": scheme_def["id"],
    }


def get_verification_session(session_id: str) -> dict[str, Any] | None:
    return T.kyc_cases.get_item(Key={"pk": f"EID_SESSION#{session_id}", "sk": "META"}).get("Item")


def _mark_session(session_id: str, status: str) -> None:
    try:
        T.kyc_cases.update_item(
            Key={"pk": f"EID_SESSION#{session_id}", "sk": "META"},
            UpdateExpression="SET #s = :s, updated_at = :u",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": status, ":u": now_ts()},
        )
    except Exception:  # pragma: no cover - defensive
        logger.warning("eid.session.mark_failed session_id=%s status=%s", session_id, status)


# --- assertion storage -----------------------------------------------------


def _store_assertion(
    *,
    case_id: str,
    assertion_id: str,
    scheme: str,
    payload: dict[str, Any],
    raw_b64: str,
    signature_valid: bool,
    discrepancies: list[dict[str, Any]],
) -> dict[str, Any]:
    ts = now_ts()
    record = {
        "pk": _case_pk(case_id),
        "sk": f"EIDV#{ts:013d}#{assertion_id}",
        "entity_type": "kyc_eid_assertion",
        "assertion_id": assertion_id,
        "case_id": case_id,
        "scheme": scheme,
        "issuer": payload.get("issuer"),
        "subject_id": payload.get("subject_id"),
        "verified_fields": payload.get("verified_fields") or {},
        "assurance_level": payload.get("assurance_level"),
        "issued_at": _coerce_int(payload.get("issued_at"), ts),
        "raw_assertion": raw_b64,
        "signature_valid": bool(signature_valid),
        "discrepancies": discrepancies,
        "created_at": ts,
    }
    T.kyc_cases.put_item(Item=record)
    return record


def list_assertions(case_id: str) -> list[dict[str, Any]]:
    """All eID assertions for a case, newest first."""
    resp = T.kyc_cases.query(
        KeyConditionExpression=(Key("pk").eq(_case_pk(case_id)) & Key("sk").begins_with("EIDV#")),
        ScanIndexForward=False,
    )
    items = list(resp.get("Items", []))
    items.sort(key=lambda a: _coerce_int(a.get("created_at")), reverse=True)
    return items


def get_latest_assertion(case_id: str) -> dict[str, Any] | None:
    items = list_assertions(case_id)
    return items[0] if items else None


# --- case update + tier upgrade --------------------------------------------


def _write_eid_verification_to_case(case_id: str, eid_verification: dict[str, Any]) -> None:
    """Persist the ``eid_verification`` sub-object onto the KYC case item."""
    T.kyc_cases.update_item(
        Key={"pk": _case_pk(case_id), "sk": "META"},
        UpdateExpression="SET eid_verification = :e, updated_at = :u",
        ExpressionAttributeValues={":e": eid_verification, ":u": now_ts()},
    )


def _maybe_auto_upgrade_tier(
    *,
    case: dict[str, Any],
    scheme: str,
    assertion_id: str,
    assurance_level: str,
    blocked: bool,
    request: Any = None,
) -> bool:
    """Auto-upgrade the user to Tier 2 (ID Verified) on a clean high/substantial
    assertion. Never downgrades. Returns whether an upgrade was applied.
    """
    if blocked or not S.kyc_eid_auto_tier_upgrade:
        return False
    if _ASSURANCE_RANK.get(str(assurance_level), 0) < _ASSURANCE_RANK["substantial"]:
        return False
    user_sub = str(case.get("user_sub") or "")
    if not user_sub:
        return False
    try:
        from app.services.kyc_tiers import get_user_kyc_tier, upgrade_tier

        current_tier = get_user_kyc_tier(user_sub)
        if current_tier >= TIER_ID_VERIFIED:
            return False  # already at/above tier 2 -- no downgrade, no re-upgrade
        upgrade_tier(
            user_sub=user_sub,
            new_tier=TIER_ID_VERIFIED,
            reason=f"eid_verification:{scheme}",
            actor_sub=user_sub,
            case_id=str(case.get("kyc_case_id") or ""),
            request=request,
        )
        logger.info(
            "eid.tier.upgraded case_id=%s from_tier=%s to_tier=%s scheme=%s",
            case.get("kyc_case_id"),
            current_tier,
            TIER_ID_VERIFIED,
            scheme,
        )
        return True
    except Exception:  # pragma: no cover - tier upgrade is best-effort
        logger.warning("eid.tier.upgrade_failed case_id=%s", case.get("kyc_case_id"))
        return False


def process_callback(
    *,
    session_id: str,
    raw_assertion: str,
    signature: str,
    request: Any = None,
) -> dict[str, Any]:
    """Validate the eID provider's callback assertion and update the case.

    Steps: verify session, verify signature, check expiry, extract fields,
    compare with profile, store assertion, write ``eid_verification`` to the
    case, and auto-upgrade Tier 2 when eligible.

    Idempotent: a second callback for the same (already-completed) session
    returns the previously-stored result without re-processing.
    """
    session = get_verification_session(session_id)
    if not session:
        raise KycEidvError("eid_session_not_found")

    case_id = str(session.get("case_id") or "")

    # Idempotency: if this session was already completed, return the stored result.
    if str(session.get("status") or "") == STATUS_COMPLETED:
        latest = get_latest_assertion(case_id)
        if latest:
            return _public_assertion_view(latest, auto_tier_upgrade=bool(session.get("auto_tier_upgrade")))

    now = now_ts()
    if _coerce_int(session.get("expires_at"), 0) and now > _coerce_int(session.get("expires_at")):
        _mark_session(session_id, STATUS_EXPIRED)
        raise KycEidvError("eid_session_expired")

    if not validate_assertion_signature(raw_assertion=raw_assertion, signature=signature):
        _mark_session(session_id, STATUS_FAILED)
        logger.warning("eid.assertion.invalid session_id=%s reason=bad_signature", session_id)
        raise KycEidvError("eid_invalid_signature")

    try:
        payload = json.loads(base64.b64decode(raw_assertion.encode("utf-8")).decode("utf-8"))
    except Exception as exc:
        _mark_session(session_id, STATUS_FAILED)
        raise KycEidvError("eid_invalid_signature") from exc

    if _coerce_int(payload.get("expires_at"), 0) and now > _coerce_int(payload.get("expires_at")):
        _mark_session(session_id, STATUS_FAILED)
        raise KycEidvError("eid_assertion_expired")

    case = T.kyc_cases.get_item(Key={"pk": _case_pk(case_id), "sk": "META"}).get("Item")
    if not case:
        raise KycEidvError("case_not_found")

    scheme = str(payload.get("scheme") or session.get("scheme") or "")
    assertion_id = str(payload.get("assertion_id") or _new_assertion_id())
    verified_fields = dict(payload.get("verified_fields") or {})
    assurance_level = str(payload.get("assurance_level") or "")

    discrepancies = compare_with_profile(
        verified_fields=verified_fields, user_sub=str(case.get("user_sub") or "")
    )
    blocked = any(str(d.get("severity")) == "critical" for d in discrepancies)

    record = _store_assertion(
        case_id=case_id,
        assertion_id=assertion_id,
        scheme=scheme,
        payload=payload,
        raw_b64=raw_assertion,
        signature_valid=True,
        discrepancies=discrepancies,
    )

    upgraded = _maybe_auto_upgrade_tier(
        case=case,
        scheme=scheme,
        assertion_id=assertion_id,
        assurance_level=assurance_level,
        blocked=blocked,
        request=request,
    )

    eid_verification = {
        "scheme": scheme,
        "assertion_id": assertion_id,
        "assurance_level": assurance_level,
        "verified_at": now,
        "auto_tier_upgrade": bool(upgraded),
        "discrepancies": discrepancies,
        "verified_fields": verified_fields,
        "flagged_for_review": bool(blocked),
    }
    _write_eid_verification_to_case(case_id, eid_verification)

    # mark session completed + remember upgrade outcome for idempotent replays
    try:
        T.kyc_cases.update_item(
            Key={"pk": f"EID_SESSION#{session_id}", "sk": "META"},
            UpdateExpression="SET #s = :s, updated_at = :u, auto_tier_upgrade = :a, assertion_id = :i",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": STATUS_COMPLETED,
                ":u": now,
                ":a": bool(upgraded),
                ":i": assertion_id,
            },
        )
    except Exception:  # pragma: no cover - defensive
        pass

    audit_event(
        "kyc_eid_verification",
        str(case.get("user_sub") or ""),
        request,
        outcome="flagged" if blocked else "success",
        kyc_case_id=case_id,
        scheme=scheme,
        assertion_id=assertion_id,
        assurance_level=assurance_level,
        auto_tier_upgrade=bool(upgraded),
        discrepancy_count=len(discrepancies),
    )
    logger.info(
        "eid.callback.processed case_id=%s scheme=%s assertion_id=%s upgraded=%s discrepancies=%s",
        case_id,
        scheme,
        assertion_id,
        upgraded,
        len(discrepancies),
    )

    return _public_assertion_view(record, auto_tier_upgrade=bool(upgraded))


# --- public views ----------------------------------------------------------


def _public_assertion_view(record: dict[str, Any], *, auto_tier_upgrade: bool) -> dict[str, Any]:
    return {
        "scheme": record.get("scheme"),
        "assertion_id": record.get("assertion_id"),
        "assurance_level": record.get("assurance_level"),
        "verified_at": _coerce_int(record.get("created_at")),
        "auto_tier_upgrade": bool(auto_tier_upgrade),
        "discrepancies": list(record.get("discrepancies") or []),
        "verified_fields": dict(record.get("verified_fields") or {}),
    }


def get_eid_status(case_id: str) -> dict[str, Any] | None:
    """Return the current ``eid_verification`` sub-object for a case, or None."""
    case = T.kyc_cases.get_item(Key={"pk": _case_pk(case_id), "sk": "META"}).get("Item")
    if not case:
        raise KycEidvError("case_not_found")
    eid = case.get("eid_verification")
    if not eid:
        return None
    return {
        "scheme": eid.get("scheme"),
        "assertion_id": eid.get("assertion_id"),
        "assurance_level": eid.get("assurance_level"),
        "verified_at": _coerce_int(eid.get("verified_at")),
        "auto_tier_upgrade": bool(eid.get("auto_tier_upgrade")),
        "discrepancies": list(eid.get("discrepancies") or []),
        "verified_fields": dict(eid.get("verified_fields") or {}),
    }
