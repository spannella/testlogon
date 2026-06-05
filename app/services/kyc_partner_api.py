"""Third-party KYC Partner API service (KYC-021).

A thin, API-key-authenticated FACADE over the existing KYC case lifecycle.
Partners (third parties / white-label integrations) drive the KYC flow
programmatically:

* create an application  -> creates an underlying KYC case via
  ``app.services.kyc_cases.STORE.create_case``
* upload a document      -> attaches document metadata to the application
* check status           -> reads the underlying case status
* list applications      -> lists ONLY the calling partner's applications

This module deliberately does NOT reimplement case logic — it delegates to
``kyc_cases`` for the underlying case and emits ``kyc.*`` partner callbacks via
the existing ``kyc_webhooks`` (KYC-011) glue.

Storage notes
-------------
We REUSE the existing ``kyc_cases`` DynamoDB table (no new table / no DDB
re-init required). Partner-API records live under a distinct ``PARTNER#`` /
``IDEMP#`` key space so they never collide with real KYC case items
(``KYC#...``):

* Submission     pk=``PARTNER#{partner_id}``  sk=``SUB#{application_id}``
* External index  pk=``PARTNER#{partner_id}``  sk=``EXT#{external_id}``  (pointer)
* Idempotency     pk=``IDEMP#{api_key_id}``    sk=``{idempotency_key_hash}``
* Webhook         pk=``PARTNER#{partner_id}``  sk=``WH#{webhook_id}``

Partition by ``partner_id`` (the API key owner's ``user_sub``) gives natural
per-partner isolation: a partner can only ever query its own partition.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services import kyc_cases
from app.services.api_key_capabilities import expand_api_key_capabilities

# ── Constants ────────────────────────────────────────────────────────

_ALLOWED_DOCUMENT_TYPES = {"id_front", "id_back", "selfie", "proof_of_address"}
_ALLOWED_WEBHOOK_EVENTS = {"status_changed", "decision_made", "document_uploaded"}
_TIER_INTAKE_PROFILE = {
    "tier_1": "standard",
    "tier_2": "standard",
    "tier_3": "enhanced",
}
_IDEMPOTENCY_TTL_SECONDS = 24 * 3600

# Map underlying KYC case status -> partner-facing decision (None until decided).
_DECISION_FOR_STATUS = {
    "approved": "approved",
    "rejected": "rejected",
}


# ── Scope enforcement ────────────────────────────────────────────────

def require_scope(principal: Dict[str, Any], scope: str) -> None:
    """Raise 403 if the API key principal lacks ``scope``.

    ``kyc:admin`` implies every other ``kyc:*`` scope (see
    CAPABILITY_IMPLICATIONS in api_key_capabilities).
    """
    caps = expand_api_key_capabilities(principal.get("capabilities") or [])
    if scope not in caps:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "kyc_api_forbidden",
                "message": f"Key does not have {scope} scope",
                "required_scope": scope,
            },
        )


def _partner_id(principal: Dict[str, Any]) -> str:
    partner_id = str(principal.get("user_sub") or "").strip()
    if not partner_id:
        raise HTTPException(
            status_code=401,
            detail={"code": "kyc_api_unauthorized", "message": "Invalid API key principal"},
        )
    return partner_id


# ── Key helpers ──────────────────────────────────────────────────────

def _partner_pk(partner_id: str) -> str:
    return f"PARTNER#{partner_id}"


def _sub_sk(application_id: str) -> str:
    return f"SUB#{application_id}"


def _ext_sk(external_id: str) -> str:
    return f"EXT#{external_id}"


def _wh_sk(webhook_id: str) -> str:
    return f"WH#{webhook_id}"


def _idemp_pk(api_key_id: str) -> str:
    return f"IDEMP#{api_key_id}"


def _hash_idempotency(idempotency_key: str, body_fingerprint: str) -> str:
    raw = f"{idempotency_key}\x00{body_fingerprint}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _hash_key_only(idempotency_key: str) -> str:
    return hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()


# ── Idempotency guard ────────────────────────────────────────────────

def check_idempotency(
    *,
    api_key_id: str,
    idempotency_key: str,
    body_fingerprint: str,
) -> Optional[Dict[str, Any]]:
    """Return a stored response for this idempotency key, or None.

    Raises 409 (``kyc_api_idempotency_conflict``) when the same key was used
    with a DIFFERENT request body. Expired entries (past TTL) are ignored so
    the key may be re-used.
    """
    sk = _hash_key_only(idempotency_key)
    item = T.kyc_cases.get_item(Key={"pk": _idemp_pk(api_key_id), "sk": sk}).get("Item")
    if not item:
        return None
    ttl = int(item.get("ttl") or 0)
    if ttl and ttl <= now_ts():
        return None
    if str(item.get("body_fingerprint") or "") != body_fingerprint:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "kyc_api_idempotency_conflict",
                "message": "Idempotency key used with different request body",
                "original_request_hash": str(item.get("body_fingerprint") or ""),
            },
        )
    stored = item.get("response_body")
    if isinstance(stored, str):
        try:
            return json.loads(stored)
        except Exception:
            return None
    if isinstance(stored, dict):
        return stored
    return None


def store_idempotency(
    *,
    api_key_id: str,
    idempotency_key: str,
    body_fingerprint: str,
    response_status: int,
    response_body: Dict[str, Any],
) -> None:
    ts = now_ts()
    T.kyc_cases.put_item(
        Item={
            "pk": _idemp_pk(api_key_id),
            "sk": _hash_key_only(idempotency_key),
            "entity_type": "kyc_partner_idempotency",
            "body_fingerprint": body_fingerprint,
            "response_status": int(response_status),
            "response_body": json.dumps(response_body, separators=(",", ":")),
            "created_at": ts,
            "ttl": ts + _IDEMPOTENCY_TTL_SECONDS,
        }
    )


def _body_fingerprint(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── Submission serialization ─────────────────────────────────────────

def _submission_out(item: Dict[str, Any]) -> Dict[str, Any]:
    status = str(item.get("status") or "draft")
    return {
        "application_id": str(item.get("application_id") or ""),
        "external_id": str(item.get("external_id") or ""),
        "status": status,
        "decision": _DECISION_FOR_STATUS.get(status),
        "reason_codes": list(item.get("reason_codes") or []),
        "applicant": dict(item.get("applicant") or {}),
        "documents": list(item.get("documents") or []),
        "tier": str(item.get("tier") or "tier_1"),
        "created_at": int(item.get("created_at") or 0),
        "updated_at": int(item.get("updated_at") or 0),
        "sandbox": bool(item.get("sandbox", False)),
    }


def _get_submission_item(partner_id: str, application_id: str) -> Optional[Dict[str, Any]]:
    return T.kyc_cases.get_item(
        Key={"pk": _partner_pk(partner_id), "sk": _sub_sk(application_id)}
    ).get("Item")


def _require_submission(partner_id: str, application_id: str) -> Dict[str, Any]:
    item = _get_submission_item(partner_id, application_id)
    if not item or item.get("entity_type") != "kyc_partner_submission":
        raise HTTPException(
            status_code=404,
            detail={
                "code": "kyc_api_application_not_found",
                "message": "Application not found for this partner",
            },
        )
    return item


def _refresh_status_from_case(item: Dict[str, Any]) -> Dict[str, Any]:
    """Sync the partner submission status from the underlying KYC case."""
    case_id = str(item.get("kyc_case_id") or "")
    if not case_id:
        return item
    case = kyc_cases.STORE.get_case(case_id)
    if not case:
        return item
    case_status = str(case.get("status") or item.get("status") or "draft")
    review = dict(case.get("review") or {})
    reason_codes = [str(c) for c in (review.get("reason_codes") or [])]
    if case_status == str(item.get("status") or "") and reason_codes == list(item.get("reason_codes") or []):
        return item
    ts = now_ts()
    T.kyc_cases.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET #s=:s, reason_codes=:rc, updated_at=:u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": case_status, ":rc": reason_codes, ":u": ts},
    )
    item["status"] = case_status
    item["reason_codes"] = reason_codes
    item["updated_at"] = ts
    return item


# ── Application lifecycle ────────────────────────────────────────────

def create_application(
    principal: Dict[str, Any],
    *,
    external_id: str,
    applicant: Dict[str, Any],
    tier: str = "tier_1",
    metadata: Optional[Dict[str, Any]] = None,
    sandbox: bool = False,
) -> Dict[str, Any]:
    partner_id = _partner_id(principal)
    api_key_id = str(principal.get("api_key_id") or "")
    external_id = str(external_id or "").strip()

    # Reject duplicate external_id for this partner.
    existing_ptr = T.kyc_cases.get_item(
        Key={"pk": _partner_pk(partner_id), "sk": _ext_sk(external_id)}
    ).get("Item")
    if existing_ptr:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "kyc_api_duplicate_external_id",
                "message": "External ID already exists",
            },
        )

    ts = now_ts()
    application_id = f"kycapp_{uuid.uuid4().hex[:24]}"

    # Create the underlying KYC case via the EXISTING case service.
    case = kyc_cases.STORE.create_case(
        user_sub=partner_id,
        status="draft",
        intake_profile=_TIER_INTAKE_PROFILE.get(tier, "standard"),
    )
    case_id = str(case.get("kyc_case_id") or "")

    item = {
        "pk": _partner_pk(partner_id),
        "sk": _sub_sk(application_id),
        "entity_type": "kyc_partner_submission",
        "application_id": application_id,
        "partner_id": partner_id,
        "api_key_id": api_key_id,
        "external_id": external_id,
        "kyc_case_id": case_id,
        "status": "draft",
        "tier": str(tier or "tier_1"),
        "applicant": applicant,
        "metadata": metadata or {},
        "reason_codes": [],
        "documents": [],
        "sandbox": bool(sandbox),
        "created_at": ts,
        "updated_at": ts,
    }
    T.kyc_cases.put_item(Item=item)
    # external_id -> application_id pointer (for lookup + duplicate detection).
    T.kyc_cases.put_item(
        Item={
            "pk": _partner_pk(partner_id),
            "sk": _ext_sk(external_id),
            "entity_type": "kyc_partner_external_ptr",
            "application_id": application_id,
            "external_id": external_id,
            "created_at": ts,
        }
    )

    _emit_callback(
        partner_id,
        event="kyc.case.created",
        case_id=case_id,
        application_id=application_id,
        external_id=external_id,
        status="draft",
    )
    return _submission_out(item)


def get_application(principal: Dict[str, Any], application_id: str) -> Dict[str, Any]:
    partner_id = _partner_id(principal)
    item = _require_submission(partner_id, application_id)
    item = _refresh_status_from_case(item)
    return _submission_out(item)


def get_application_by_external_id(principal: Dict[str, Any], external_id: str) -> Dict[str, Any]:
    partner_id = _partner_id(principal)
    ptr = T.kyc_cases.get_item(
        Key={"pk": _partner_pk(partner_id), "sk": _ext_sk(str(external_id or "").strip())}
    ).get("Item")
    if not ptr:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "kyc_api_application_not_found",
                "message": "Application not found for this partner",
            },
        )
    return get_application(principal, str(ptr.get("application_id") or ""))


def list_applications(principal: Dict[str, Any], *, limit: int = 50) -> List[Dict[str, Any]]:
    """List ONLY the calling partner's applications (per-partner isolation)."""
    partner_id = _partner_id(principal)
    from boto3.dynamodb.conditions import Key

    resp = T.kyc_cases.query(
        KeyConditionExpression=Key("pk").eq(_partner_pk(partner_id))
        & Key("sk").begins_with("SUB#"),
        ScanIndexForward=False,
        Limit=max(1, min(int(limit or 50), 50)),
    )
    out: List[Dict[str, Any]] = []
    for row in resp.get("Items", []):
        if row.get("entity_type") != "kyc_partner_submission":
            continue
        out.append(_submission_out(_refresh_status_from_case(row)))
    return out


def submit_application(principal: Dict[str, Any], application_id: str) -> Dict[str, Any]:
    partner_id = _partner_id(principal)
    item = _require_submission(partner_id, application_id)
    case_id = str(item.get("kyc_case_id") or "")
    case = kyc_cases.STORE.get_case(case_id)
    if not case:
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_api_application_not_found", "message": "Application not found"},
        )

    current_status = str(case.get("status") or "")
    if current_status not in {"draft", "needs_more_info", "submitted"}:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "kyc_api_submission_not_ready",
                "message": f"Application is in {current_status} state",
            },
        )

    try:
        kyc_cases.STORE.submit_case(
            case_id=case_id,
            owner_sub=partner_id,
            expected_version=int(case.get("version") or 0),
            evidence_snapshot={
                "application_id": application_id,
                "external_id": str(item.get("external_id") or ""),
                "documents": [d.get("document_type") for d in (item.get("documents") or [])],
            },
        )
    except kyc_cases.KycCaseConflictError:
        raise HTTPException(
            status_code=409,
            detail={"code": "kyc_api_submission_not_ready", "message": "Application is not in a submittable state"},
        )
    except kyc_cases.KycCaseValidationError:
        raise HTTPException(
            status_code=409,
            detail={"code": "kyc_api_submission_not_ready", "message": "Application is not in a submittable state"},
        )

    item = _refresh_status_from_case(item)
    _emit_callback(
        partner_id,
        event="kyc.case.submitted",
        case_id=case_id,
        application_id=application_id,
        external_id=str(item.get("external_id") or ""),
        status="submitted",
    )
    return {"application_id": application_id, "status": str(item.get("status") or "submitted")}


def get_application_result(principal: Dict[str, Any], application_id: str) -> Dict[str, Any]:
    partner_id = _partner_id(principal)
    item = _require_submission(partner_id, application_id)
    item = _refresh_status_from_case(item)
    status = str(item.get("status") or "")
    decision = _DECISION_FOR_STATUS.get(status)
    if decision is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "kyc_api_application_not_found",
                "message": "No decision available yet for this application",
            },
        )
    case = kyc_cases.STORE.get_case(str(item.get("kyc_case_id") or "")) or {}
    review = dict(case.get("review") or {})
    return {
        "decision": decision,
        "decided_at": int(review.get("decided_at") or item.get("updated_at") or 0),
        "reason_codes": [str(c) for c in (review.get("reason_codes") or item.get("reason_codes") or [])],
        "risk_score": item.get("risk_score"),
        "verified_fields": dict(item.get("verified_fields") or {}),
    }


# ── Documents ────────────────────────────────────────────────────────

def upload_document(
    principal: Dict[str, Any],
    application_id: str,
    *,
    document_type: str,
    file_type: str,
    filename: str = "",
    size_bytes: int = 0,
) -> Dict[str, Any]:
    partner_id = _partner_id(principal)
    normalized_type = str(document_type or "").strip().lower()
    if normalized_type not in _ALLOWED_DOCUMENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "kyc_api_invalid_document_type",
                "message": "Document type must be one of: " + ", ".join(sorted(_ALLOWED_DOCUMENT_TYPES)),
            },
        )
    item = _require_submission(partner_id, application_id)
    ts = now_ts()
    document_id = f"doc_{uuid.uuid4().hex[:16]}"
    doc = {
        "document_id": document_id,
        "document_type": normalized_type,
        "file_type": str(file_type or "application/octet-stream"),
        "filename": str(filename or ""),
        "size_bytes": int(size_bytes or 0),
        "uploaded_at": ts,
    }
    documents = list(item.get("documents") or [])
    documents.append(doc)
    T.kyc_cases.update_item(
        Key={"pk": item["pk"], "sk": item["sk"]},
        UpdateExpression="SET documents=:d, updated_at=:u",
        ExpressionAttributeValues={":d": documents, ":u": ts},
    )

    _emit_callback(
        partner_id,
        event="kyc.document.verified",
        case_id=str(item.get("kyc_case_id") or ""),
        application_id=application_id,
        document_id=document_id,
        document_type=normalized_type,
    )
    return {"document_id": document_id, "file_type": doc["file_type"], "document_type": normalized_type}


# ── Webhooks ─────────────────────────────────────────────────────────

def register_webhook(
    principal: Dict[str, Any],
    *,
    url: str,
    events: List[str],
    secret: str,
) -> Dict[str, Any]:
    partner_id = _partner_id(principal)
    invalid = sorted({e for e in events if e not in _ALLOWED_WEBHOOK_EVENTS})
    if invalid:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "kyc_api_webhook_url_invalid",
                "message": f"Invalid event(s): {', '.join(invalid)}",
            },
        )
    # Encrypt secret for at-rest storage (SEC-022). Mirror the established
    # webhook_service.py pattern: KMS-encrypt, with a PLAIN: dev-mode fallback
    # when the KMS mock (port 7999, SECOPS-007) / real KMS is unavailable.
    from app.core.crypto import kms_encrypt

    try:
        stored_secret = kms_encrypt(str(secret))
    except Exception:
        stored_secret = f"PLAIN:{str(secret)}"

    ts = now_ts()
    webhook_id = f"wh_{uuid.uuid4().hex[:16]}"
    T.kyc_cases.put_item(
        Item={
            "pk": _partner_pk(partner_id),
            "sk": _wh_sk(webhook_id),
            "entity_type": "kyc_partner_webhook",
            "webhook_id": webhook_id,
            "partner_id": partner_id,
            "url": str(url),
            "events": list(events),
            "secret": stored_secret,  # encrypted at rest; never plaintext
            "created_at": ts,
        }
    )
    # Return the plaintext secret once at registration time so the partner can
    # configure their signature verification; it is never readable again.
    return {
        "webhook_id": webhook_id,
        "url": str(url),
        "events": list(events),
        "created_at": ts,
        "secret": str(secret),
    }


def _decrypt_kyc_partner_secret(stored: str) -> str:
    """Decrypt a KYC partner webhook secret stored in DynamoDB.

    Handles both the ``PLAIN:`` dev-mode fallback and KMS-encrypted ciphertext,
    mirroring ``webhook_service._decrypt_secret``. Use this anywhere the secret
    is consumed for HMAC signing of outbound partner deliveries.
    """
    if stored.startswith("PLAIN:"):
        return stored[6:]
    from app.core.crypto import kms_decrypt

    return kms_decrypt(stored).decode("utf-8")


def list_webhooks(principal: Dict[str, Any]) -> List[Dict[str, Any]]:
    partner_id = _partner_id(principal)
    from boto3.dynamodb.conditions import Key

    resp = T.kyc_cases.query(
        KeyConditionExpression=Key("pk").eq(_partner_pk(partner_id)) & Key("sk").begins_with("WH#"),
    )
    out: List[Dict[str, Any]] = []
    for row in resp.get("Items", []):
        if row.get("entity_type") != "kyc_partner_webhook":
            continue
        out.append(
            {
                "webhook_id": str(row.get("webhook_id") or ""),
                "url": str(row.get("url") or ""),
                "events": list(row.get("events") or []),
                "created_at": int(row.get("created_at") or 0),
                # "secret" intentionally omitted — never expose stored secrets
                # in list responses (SEC-022). The plaintext is returned only
                # once, from register_webhook().
            }
        )
    out.sort(key=lambda r: r["created_at"], reverse=True)
    return out


def delete_webhook(principal: Dict[str, Any], webhook_id: str) -> Dict[str, Any]:
    partner_id = _partner_id(principal)
    existing = T.kyc_cases.get_item(
        Key={"pk": _partner_pk(partner_id), "sk": _wh_sk(webhook_id)}
    ).get("Item")
    if not existing or existing.get("entity_type") != "kyc_partner_webhook":
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_api_application_not_found", "message": "Webhook not found"},
        )
    T.kyc_cases.delete_item(Key={"pk": _partner_pk(partner_id), "sk": _wh_sk(webhook_id)})
    return {"ok": True, "webhook_id": webhook_id}


def test_webhook(principal: Dict[str, Any], webhook_id: str) -> Dict[str, Any]:
    partner_id = _partner_id(principal)
    existing = T.kyc_cases.get_item(
        Key={"pk": _partner_pk(partner_id), "sk": _wh_sk(webhook_id)}
    ).get("Item")
    if not existing or existing.get("entity_type") != "kyc_partner_webhook":
        raise HTTPException(
            status_code=404,
            detail={"code": "kyc_api_application_not_found", "message": "Webhook not found"},
        )
    # Emit a sample partner callback through the existing KYC webhook glue.
    result = _emit_callback(
        partner_id,
        event="kyc.case.submitted",
        application_id="kycapp_test",
        external_id="test",
        status="submitted",
    )
    return {
        "ok": True,
        "webhook_id": webhook_id,
        "url": str(existing.get("url") or ""),
        "delivered": bool(result.get("dispatched")),
    }


# ── Webhook callback emission (REUSE kyc_webhooks / KYC-011) ──────────

def _emit_callback(partner_id: str, *, event: str, **payload: Any) -> Dict[str, Any]:
    """Emit a ``kyc.*`` partner callback via the existing KYC-011 glue.

    Never raises — a callback failure must not break the API request.
    """
    try:
        from app.services.kyc_webhooks import emit_kyc_event

        return emit_kyc_event(event=event, user_sub=partner_id, **payload)
    except Exception:  # pragma: no cover - defensive
        return {"dispatched": False, "event": event}


# ── Sandbox provider ─────────────────────────────────────────────────

def sandbox_create_application(
    principal: Dict[str, Any],
    *,
    external_id: str,
    applicant: Dict[str, Any],
    tier: str = "tier_1",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Deterministic sandbox application (no real KYC case created)."""
    partner_id = _partner_id(principal)
    h = hashlib.sha256(str(external_id or "").encode("utf-8")).hexdigest()[:12]
    application_id = f"sandbox_app_{h}"
    ts = now_ts()
    item = {
        "pk": _partner_pk(partner_id),
        "sk": _sub_sk(application_id),
        "entity_type": "kyc_partner_submission",
        "application_id": application_id,
        "partner_id": partner_id,
        "api_key_id": str(principal.get("api_key_id") or ""),
        "external_id": str(external_id or "").strip(),
        "kyc_case_id": "",
        "status": "draft",
        "tier": str(tier or "tier_1"),
        "applicant": applicant,
        "metadata": metadata or {},
        "reason_codes": [],
        "documents": [],
        "sandbox": True,
        "created_at": ts,
        "updated_at": ts,
    }
    T.kyc_cases.put_item(Item=item)
    return _submission_out(item)
