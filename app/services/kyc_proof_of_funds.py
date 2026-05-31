"""KYC-005: Proof of Funds / Source of Funds.

Users submit documentation of where their funds come from (bank statement, pay
stub, sale-of-asset, investment, business income, etc.) optionally with a
declared amount and a source category. A deterministic (mockable) verification
pipeline validates the document and amount, runs a status lifecycle, and exposes
reviewer endpoints. Results feed into the KYC case and risk score.

Mirrors KYC-004 (kyc_residency) / KYC-002 (kyc_document_verification): document
upload, deterministic mock result, ByStatus GSI, status lifecycle, reviewer
adjudication. MONEY is int cents everywhere.
"""
from __future__ import annotations

import hashlib
from decimal import Decimal
from typing import Any, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Source categories / constants
# ---------------------------------------------------------------------------

# Authoritative KNOWN source category set (from ticket NOTE).
KNOWN_SOURCE_CATEGORIES = {
    "bank_statement",
    "pay_stub",
    "sale_of_asset",
    "investment",
    "business_income",
    "inheritance",
    "gift",
    "savings",
}

VALID_STATUSES = {"pending", "verified", "rejected", "needs_more_info", "expired"}

# Threshold above which a declared amount is treated as suspicious ($10M in cents).
_SUSPICIOUS_AMOUNT_CENTS = 10_000_000_00

_DEFAULT_VALIDITY_DAYS = 365


# ---------------------------------------------------------------------------
# Verification logic (deterministic / mockable)
# ---------------------------------------------------------------------------


def _deterministic_score(
    *,
    document_s3_key: Optional[str],
    declared_amount_cents: Optional[int],
    source_category: Optional[str],
    note: Optional[str],
) -> int:
    """Deterministic 0..100 score derived from submission content.

    Implements the authoritative algorithm from the KYC-005 ticket NOTE exactly:
      score = 50 (base)
        + 20 if document_s3_key present
        + 15 if declared_amount_cents present AND > 0
        + 10 if source_category in KNOWN_SOURCE_CATEGORIES
        - 30 if declared_amount_cents present AND > $10M (suspicious)
        + 5  if note present and non-empty
      clamp 0..100
    """
    score = 50
    if document_s3_key:
        score += 20
    if declared_amount_cents is not None and declared_amount_cents > 0:
        score += 15
    if source_category in KNOWN_SOURCE_CATEGORIES:
        score += 10
    if declared_amount_cents is not None and declared_amount_cents > _SUSPICIOUS_AMOUNT_CENTS:
        score -= 30
    if note and note.strip():
        score += 5
    return max(0, min(100, score))


def _decision_for_score(score: int) -> str:
    if score >= 75:
        return "verified"
    if score >= 55:
        return "needs_more_info"
    return "rejected"


def _risk_contribution_for_status(status: str) -> int:
    return {
        "verified": -10,
        "needs_more_info": 0,
        "rejected": 15,
        "expired": 5,
        "pending": 0,
    }.get(status, 0)


def _utcnow_ts() -> int:
    return now_ts()


def _validity_days() -> int:
    from app.core.settings import S

    return getattr(S, "kyc_proof_of_funds_validity_days", _DEFAULT_VALIDITY_DAYS)


def _real_analysis_enabled() -> bool:
    from app.core.settings import S

    return getattr(S, "kyc_proof_of_funds_real_analysis_enabled", False)


def _real_analysis_score(**kwargs: Any) -> int:
    """Real (production) analysis path — gated behind a setting, off by default.

    In dev / tests the deterministic mock is always used. If real analysis is
    enabled but unimplemented, fall back to the deterministic mock rather than
    failing the request.
    """
    raise NotImplementedError("real proof-of-funds analysis is not available")


# ---------------------------------------------------------------------------
# CRUD / pipeline
# ---------------------------------------------------------------------------


def create_submission(
    *,
    user_sub: str,
    source_category: Optional[str] = None,
    declared_amount_cents: Optional[int] = None,
    currency: Optional[str] = None,
    document_s3_key: Optional[str] = None,
    note: Optional[str] = None,
    now: Optional[int] = None,
) -> dict[str, Any]:
    ts = now if now is not None else _utcnow_ts()
    submission_id = "pof_" + hashlib.sha256(
        f"{user_sub}:{ts}:{source_category}:{declared_amount_cents}".encode()
    ).hexdigest()[:24]

    if _real_analysis_enabled():
        try:
            score = _real_analysis_score(
                document_s3_key=document_s3_key,
                declared_amount_cents=declared_amount_cents,
                source_category=source_category,
                note=note,
            )
        except NotImplementedError:
            score = _deterministic_score(
                document_s3_key=document_s3_key,
                declared_amount_cents=declared_amount_cents,
                source_category=source_category,
                note=note,
            )
    else:
        score = _deterministic_score(
            document_s3_key=document_s3_key,
            declared_amount_cents=declared_amount_cents,
            source_category=source_category,
            note=note,
        )

    status = _decision_for_score(score)
    item = {
        "user_sub": user_sub,
        "submission_id": submission_id,
        "source_category": source_category,
        "declared_amount_cents": declared_amount_cents,
        "currency": currency or "USD",
        "document_s3_key": document_s3_key,
        "note": note,
        "status": status,
        "score": score,
        "risk_contribution": _risk_contribution_for_status(status),
        "created_at": ts,
        "updated_at": ts,
        "reviewer_sub": None,
        "reviewer_note": None,
        "reviewed_at": None,
    }
    T.kyc_proof_of_funds.put_item(Item=_to_ddb(item))
    return _clean(item)


def list_submissions_for_user(user_sub: str) -> list[dict[str, Any]]:
    resp = T.kyc_proof_of_funds.query(
        KeyConditionExpression=Key("user_sub").eq(user_sub),
        ScanIndexForward=False,
    )
    return [_clean(i) for i in resp.get("Items", [])]


def get_submission(submission_id: str, user_sub: Optional[str] = None) -> Optional[dict[str, Any]]:
    resp = T.kyc_proof_of_funds.query(
        IndexName="BySubmissionId",
        KeyConditionExpression=Key("submission_id").eq(submission_id),
    )
    items = resp.get("Items", [])
    if not items:
        return None
    return _clean(items[0])


def list_by_status(status: str) -> list[dict[str, Any]]:
    resp = T.kyc_proof_of_funds.query(
        IndexName="ByStatus",
        KeyConditionExpression=Key("status").eq(status),
        ScanIndexForward=False,
    )
    return [_clean(i) for i in resp.get("Items", [])]


def adjudicate(
    submission_id: str,
    *,
    decision: str,
    reviewer_sub: str,
    reviewer_note: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    sub = get_submission(submission_id)
    if not sub:
        return None
    user_sub = sub["user_sub"]
    new_status = decision
    ts = now_ts()
    upd = T.kyc_proof_of_funds.update_item(
        Key={"user_sub": user_sub, "submission_id": submission_id},
        UpdateExpression=(
            "SET #s = :s, risk_contribution = :rc, reviewer_sub = :rs, "
            "reviewer_note = :rn, reviewed_at = :ra, updated_at = :ua"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": new_status,
            ":rc": _risk_contribution_for_status(new_status),
            ":rs": reviewer_sub,
            ":rn": reviewer_note,
            ":ra": ts,
            ":ua": ts,
        },
        ReturnValues="ALL_NEW",
    )
    return _clean(upd.get("Attributes"))


# ---------------------------------------------------------------------------
# Risk / case integration
# ---------------------------------------------------------------------------


def _effective_status(sub: dict[str, Any], now: int, validity_days: int) -> str:
    st = sub.get("status")
    if st in ("verified", "needs_more_info") and sub.get("created_at"):
        if int(sub["created_at"]) + validity_days * 86400 < now:
            return "expired"
    return st


def summarize_proof_of_funds(user_sub: str, now: Optional[int] = None) -> dict[str, Any]:
    """Summary consumed by the KYC risk engine. Import-safe (no circular imports)."""
    subs = list_submissions_for_user(user_sub)
    ts = now if now is not None else _utcnow_ts()
    validity_days = _validity_days()
    count = len(subs)
    verified_count = 0
    active_risk = 0
    verified_amount_cents = 0
    categories: set[str] = set()
    for s in subs:
        st = _effective_status(s, ts, validity_days)
        if st == "verified":
            verified_count += 1
            amt = s.get("declared_amount_cents")
            if isinstance(amt, int) and amt > 0:
                verified_amount_cents += amt
            cat = s.get("source_category")
            if cat:
                categories.add(cat)
        active_risk += _risk_contribution_for_status(st)
    return {
        "count": count,
        "verified_count": verified_count,
        "active_risk_contribution": active_risk,
        "verified_amount_cents": verified_amount_cents,
        "verified_categories": sorted(categories),
        "user_sub": user_sub,
    }


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _to_ddb(item: dict[str, Any]) -> dict[str, Any]:
    """Coerce floats to Decimal; DynamoDB rejects Python float."""
    out: dict[str, Any] = {}
    for k, v in item.items():
        if isinstance(v, float):
            out[k] = Decimal(str(v))
        else:
            out[k] = v
    return out


def _clean(item: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if not item:
        return None
    out = dict(item)
    for k in (
        "score",
        "created_at",
        "updated_at",
        "reviewed_at",
        "risk_contribution",
        "declared_amount_cents",
    ):
        v = out.get(k)
        if isinstance(v, Decimal):
            out[k] = int(v)
    return out
