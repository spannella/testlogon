"""License compliance tracking, verification & flagging (LICENSE-006).

This builds the compliance layer on top of the licensing area:
  * LICENSE-001 — agreement templates + content↔agreement links
    (`app/services/license_agreements.py`)
  * LICENSE-002 — issued content licenses
    (`app/services/issued_licenses.py`)

It does NOT recreate those services. It READS the license references they
expose for a piece of content and VERIFIES each is active / unexpired /
non-revoked. The result is recorded in the dedicated `license_compliance`
single-table store and surfaced via creator + admin dashboards. A community
flag system lets viewers and creators report suspected unlicensed use.

Compliance is *non-blocking*: issues generate warnings and queue admin review
but never prevent publish/access. Statuses progress
``compliant → expiring_soon → license_expired/license_revoked → flagged →
under_review → action_required → removed`` (each admin step is explicit).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.license_agreements import (
    list_licenses_for_content as list_agreements_for_content,
)
from app.services.issued_licenses import (
    list_licenses_for_content as list_issued_for_content,
)

try:  # profile is optional in some test contexts
    from app.services.profile import get_profile
except Exception:  # pragma: no cover
    def get_profile(_sub: str) -> Dict[str, Any]:  # type: ignore
        return {}

logger = logging.getLogger(__name__)

# Reasons a viewer / creator may flag content.
FLAG_REASONS = {
    "unlicensed_music",
    "unlicensed_video",
    "unlicensed_image",
    "expired_license",
    "copyright_claim",
    "other",
}

EXPIRY_WARNING_DAYS = 30
EXPIRY_WARNING_SECONDS = EXPIRY_WARNING_DAYS * 86400

# Compliance statuses ordered by severity (low → critical). Used by
# `_escalate_compliance_status` to avoid downgrading.
_STATUS_RANK = {
    "compliant": 0,
    "resolved": 0,
    "expiring_soon": 1,
    "flagged": 2,
    "license_expired": 3,
    "license_revoked": 3,
    "under_review": 4,
    "action_required": 5,
    "removed": 6,
}

_SEVERITY_BY_STATUS = {
    "compliant": "low",
    "resolved": "low",
    "expiring_soon": "medium",
    "flagged": "medium",
    "license_expired": "high",
    "license_revoked": "high",
    "under_review": "high",
    "action_required": "critical",
    "removed": "critical",
}

# Statuses an admin may directly assign to content.
_ADMIN_STATUSES = {"compliant", "under_review", "action_required", "removed", "resolved"}
# Resolutions an admin may apply to a flag.
_FLAG_RESOLUTIONS = {"resolved", "dismissed", "action_required"}

_TABLE = lambda: T.license_compliance  # noqa: E731


# ---------------------------------------------------------------------------
# Verification — the core "is this content compliant?" check
# ---------------------------------------------------------------------------

def check_content_compliance(
    *,
    content_id: str,
    content_type: str = "",
    creator_id: str = "",
) -> Dict[str, Any]:
    """Verify every license reference on a content item and record status.

    Reads agreement links (LICENSE-001) and issued licenses (LICENSE-002),
    evaluates each (active / expired / revoked / expiring-soon / missing),
    derives an overall compliance status, persists it, updates the creator
    index, and enqueues an admin issue when non-compliant.
    """
    ts = now_ts()
    issues: List[Dict[str, Any]] = []

    # --- Agreement-based references (LICENSE-001) ---
    agreements = list_agreements_for_content(content_id=content_id)
    for agr in agreements:
        ref = _evaluate_agreement_ref(agr, ts)
        _upsert_license_ref(content_id, ref, ts)
        if ref["status"] != "active":
            issues.append({
                "type": ref["issue_type"],
                "license_id": ref["license_id"],
                "license_type": "agreement",
                "detail": ref.get("detail", ""),
                "expires_at": ref.get("expires_at"),
            })

    # --- Issued licenses (LICENSE-002) ---
    issued = list_issued_for_content(content_id=content_id)
    for lic in issued:
        ref = _evaluate_issued_ref(lic, ts)
        _upsert_license_ref(content_id, ref, ts)
        if ref["status"] != "active":
            issues.append({
                "type": ref["issue_type"],
                "license_id": ref["license_id"],
                "license_type": "issued",
                "detail": ref.get("detail", ""),
                "expires_at": ref.get("expires_at"),
            })

    has_refs = bool(agreements) or bool(issued)
    compliance_status = _determine_compliance_status(issues, has_refs)

    # Preserve admin-driven terminal states (under_review / action_required /
    # removed / resolved) — a re-check should not silently overwrite them.
    existing = _get_compliance_status(content_id)
    if existing:
        ex_status = existing.get("compliance_status", "")
        if ex_status in {"under_review", "action_required", "removed", "resolved"}:
            compliance_status = ex_status
        if not creator_id:
            creator_id = existing.get("creator_id", "")
        if not content_type:
            content_type = existing.get("content_type", "")

    _upsert_compliance_status(content_id, content_type, creator_id, compliance_status, issues, ts)
    _upsert_creator_index(creator_id, content_id, content_type, compliance_status, len(issues), ts)

    if compliance_status not in ("compliant", "resolved", "under_review", "action_required", "removed"):
        _enqueue_admin_issue(
            content_id, creator_id, compliance_status,
            _issue_type_from_status(compliance_status),
            _severity_from_status(compliance_status), ts,
        )

    return {
        "content_id": content_id,
        "compliance_status": compliance_status,
        "issues": issues,
        "checked_at": ts,
    }


# ---------------------------------------------------------------------------
# Flagging — community / creator reports
# ---------------------------------------------------------------------------

def flag_content(
    *,
    reporter_id: str,
    content_id: str,
    reason: str,
    evidence: str = "",
    reporter_type: str = "viewer",
) -> Dict[str, Any]:
    """Flag content for a potential licensing compliance issue."""
    if reason not in FLAG_REASONS:
        raise ValueError(
            f"Invalid reason: {reason}. Valid: {', '.join(sorted(FLAG_REASONS))}"
        )
    if reporter_type not in ("viewer", "creator"):
        reporter_type = "viewer"
    evidence = (evidence or "")[:2000]

    flag_id = f"flg_{uuid4().hex}"
    ts = now_ts()

    flag_item = {
        "pk": f"CONTENT#{content_id}",
        "sk": f"FLAG#{flag_id}",
        "flag_id": flag_id,
        "content_id": content_id,
        "reporter_id": reporter_id,
        "reporter_type": reporter_type,
        "reason": reason,
        "evidence": evidence,
        "status": "open",
        "created_at": ts,
        "resolved_at": None,
        "resolved_by": None,
        "resolution_notes": "",
        "GSI2PK": "FLAG_STATUS#open",
        "GSI2SK": ts,
    }
    _TABLE().put_item(Item=flag_item)

    # Admin flag queue entry.
    _TABLE().put_item(Item={
        "pk": "ADMIN_COMPLIANCE",
        "sk": f"FLAG#{ts:020d}#{flag_id}",
        "flag_id": flag_id,
        "content_id": content_id,
        "reporter_id": reporter_id,
        "reporter_type": reporter_type,
        "reason": reason,
        "status": "open",
        "created_at": ts,
    })

    # Escalate compliance status to "flagged" (if not already more severe).
    _escalate_compliance_status(content_id, "flagged", ts)

    return _flag_to_out(flag_item)


# ---------------------------------------------------------------------------
# Admin resolution / status management
# ---------------------------------------------------------------------------

def admin_resolve_flag(
    *,
    admin_sub: str,
    flag_id: str,
    resolution: str,
    notes: str = "",
    content_id: str = "",
) -> Dict[str, Any]:
    """Admin resolves a compliance flag (resolved / dismissed / action_required)."""
    if resolution not in _FLAG_RESOLUTIONS:
        raise ValueError(
            "resolution must be one of: " + ", ".join(sorted(_FLAG_RESOLUTIONS))
        )

    flag = _find_flag(flag_id, content_id)
    if not flag:
        raise LookupError("Flag not found")
    content_id = flag.get("content_id", content_id)
    ts = now_ts()

    _TABLE().update_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": f"FLAG#{flag_id}"},
        UpdateExpression=(
            "SET #s = :s, resolved_at = :t, resolved_by = :a, "
            "resolution_notes = :n, GSI2PK = :g2"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": resolution,
            ":t": ts,
            ":a": admin_sub,
            ":n": (notes or "")[:1000],
            ":g2": f"FLAG_STATUS#{resolution}",
        },
    )

    # If admin determined action is required, escalate content status.
    if resolution == "action_required":
        _escalate_compliance_status(content_id, "action_required", ts, force=True)

    # Notify the content creator.
    status_record = _get_compliance_status(content_id)
    creator_id = (status_record or {}).get("creator_id")
    if creator_id:
        try:
            write_alert(
                creator_id,
                event=f"compliance_flag_{resolution}",
                outcome="warning" if resolution == "action_required" else "info",
                title="Content Compliance Update",
                details={"content_id": content_id, "flag_id": flag_id, "notes": notes},
                action_url=f"/licenses/compliance?content={content_id}",
            )
        except Exception:
            logger.warning("Failed to write flag resolution alert", exc_info=True)

    return {"flag_id": flag_id, "content_id": content_id, "status": resolution}


def admin_update_compliance(
    *,
    admin_sub: str,
    content_id: str,
    new_status: str,
    notes: str = "",
) -> Dict[str, Any]:
    """Admin sets the compliance status of a content item directly."""
    if new_status not in _ADMIN_STATUSES:
        raise ValueError("new_status must be one of: " + ", ".join(sorted(_ADMIN_STATUSES)))

    existing = _get_compliance_status(content_id)
    if not existing:
        raise LookupError("Content compliance record not found")

    ts = now_ts()
    terminal = new_status in ("compliant", "resolved", "removed")
    _TABLE().update_item(
        Key={"pk": f"CONTENT#{content_id}", "sk": "STATUS"},
        UpdateExpression=(
            "SET compliance_status = :s, resolved_at = :t, resolved_by = :a, "
            "last_checked_at = :ts, GSI1PK = :g1, GSI1SK = :ts"
        ),
        ExpressionAttributeValues={
            ":s": new_status,
            ":t": ts if terminal else None,
            ":a": admin_sub if terminal else None,
            ":ts": ts,
            ":g1": f"COMPLIANCE_STATUS#{new_status}",
        },
    )

    # Keep creator index in sync.
    creator_id = existing.get("creator_id", "")
    if creator_id:
        _patch_creator_index(creator_id, content_id, new_status, ts)
        try:
            write_alert(
                creator_id,
                event=f"compliance_status_{new_status}",
                outcome="warning" if new_status in ("action_required", "removed") else "info",
                title="Content Compliance Status Changed",
                details={"content_id": content_id, "status": new_status, "notes": notes},
                action_url=f"/licenses/compliance?content={content_id}",
            )
        except Exception:
            logger.warning("Failed to write compliance status alert", exc_info=True)

    return {"content_id": content_id, "compliance_status": new_status}


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def get_compliance_status(*, content_id: str) -> Optional[Dict[str, Any]]:
    """Return the STATUS record for a content item (None if never checked)."""
    rec = _get_compliance_status(content_id)
    if not rec:
        return None
    return _status_to_out(rec)


def list_license_refs(*, content_id: str) -> List[Dict[str, Any]]:
    """List all verified license references on a content item."""
    resp = _TABLE().query(
        KeyConditionExpression=Key("pk").eq(f"CONTENT#{content_id}")
        & Key("sk").begins_with("LICENSE_REF#")
    )
    return [_ref_to_out(it) for it in resp.get("Items", [])]


def list_content_flags(
    *,
    content_id: str,
    status_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List compliance flags on a content item."""
    resp = _TABLE().query(
        KeyConditionExpression=Key("pk").eq(f"CONTENT#{content_id}")
        & Key("sk").begins_with("FLAG#")
    )
    out = [_flag_to_out(it) for it in resp.get("Items", [])]
    if status_filter:
        out = [f for f in out if f.get("status") == status_filter]
    out.sort(key=lambda f: f.get("created_at", 0), reverse=True)
    return out


def list_creator_compliance(
    *,
    creator_sub: str,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List compliance status for all of a creator's tracked content (GSI3)."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"CREATOR#{creator_sub}")
        & Key("sk").begins_with("COMPLIANCE#"),
        "Limit": limit,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = decode_cursor(cursor)

    resp = _TABLE().query(**kwargs)
    items = [_creator_item_to_out(it) for it in resp.get("Items", [])]
    if status_filter:
        items = [i for i in items if i.get("compliance_status") == status_filter]
    items.sort(key=lambda i: i.get("last_checked_at") or 0, reverse=True)

    result: Dict[str, Any] = {"items": items, "summary": _creator_summary(items)}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def admin_list_issues(
    *,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Admin: list compliance issues platform-wide."""
    if status_filter:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI1",
            "KeyConditionExpression": Key("GSI1PK").eq(f"COMPLIANCE_STATUS#{status_filter}"),
            "Limit": limit,
            "ScanIndexForward": False,
        }
        if cursor:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        resp = _TABLE().query(**kwargs)
        items = [_status_record_to_admin_issue(it) for it in resp.get("Items", [])]
    else:
        kwargs = {
            "KeyConditionExpression": Key("pk").eq("ADMIN_COMPLIANCE")
            & Key("sk").begins_with("ISSUE#"),
            "Limit": limit,
            "ScanIndexForward": False,
        }
        if cursor:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        resp = _TABLE().query(**kwargs)
        items = [_admin_issue_to_out(it) for it in resp.get("Items", [])]

    _enrich_display_names(items)
    result: Dict[str, Any] = {"items": items}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


def admin_list_flags(
    *,
    status_filter: Optional[str] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Admin: list compliance flags."""
    if status_filter:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI2",
            "KeyConditionExpression": Key("GSI2PK").eq(f"FLAG_STATUS#{status_filter}"),
            "Limit": limit,
            "ScanIndexForward": False,
        }
        if cursor:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        resp = _TABLE().query(**kwargs)
        items = [_flag_to_out(it) for it in resp.get("Items", [])]
    else:
        kwargs = {
            "KeyConditionExpression": Key("pk").eq("ADMIN_COMPLIANCE")
            & Key("sk").begins_with("FLAG#"),
            "Limit": limit,
            "ScanIndexForward": False,
        }
        if cursor:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        resp = _TABLE().query(**kwargs)
        items = [_flag_to_out(it) for it in resp.get("Items", [])]

    result: Dict[str, Any] = {"items": items}
    if resp.get("LastEvaluatedKey"):
        result["next_cursor"] = encode_cursor(resp["LastEvaluatedKey"])
    return result


# ---------------------------------------------------------------------------
# Background scan
# ---------------------------------------------------------------------------

def run_compliance_scan() -> Dict[str, Any]:
    """Re-verify all tracked content and surface newly discovered issues.

    Iterates the STATUS records currently marked compliant / expiring_soon and
    re-runs `check_content_compliance` on each. Returns scan summary counts.
    """
    checked = 0
    issues_found = 0
    alerts_sent = 0
    seen: set[str] = set()

    for status in ("compliant", "expiring_soon"):
        last_key = None
        while True:
            kwargs: Dict[str, Any] = {
                "IndexName": "GSI1",
                "KeyConditionExpression": Key("GSI1PK").eq(f"COMPLIANCE_STATUS#{status}"),
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            try:
                resp = _TABLE().query(**kwargs)
            except Exception:
                logger.warning("Compliance scan query failed for %s", status, exc_info=True)
                break
            for it in resp.get("Items", []):
                content_id = it.get("content_id", "")
                if not content_id or content_id in seen:
                    continue
                seen.add(content_id)
                prev = it.get("compliance_status", "")
                result = check_content_compliance(
                    content_id=content_id,
                    content_type=it.get("content_type", ""),
                    creator_id=it.get("creator_id", ""),
                )
                checked += 1
                new_status = result["compliance_status"]
                if new_status not in ("compliant", "resolved"):
                    issues_found += 1
                    if new_status != prev:
                        creator_id = it.get("creator_id", "")
                        if creator_id:
                            try:
                                write_alert(
                                    creator_id,
                                    event="compliance_issue_detected",
                                    outcome="warning",
                                    title="Content Compliance Issue Detected",
                                    details={
                                        "content_id": content_id,
                                        "status": new_status,
                                    },
                                    action_url=f"/licenses/compliance?content={content_id}",
                                )
                                alerts_sent += 1
                            except Exception:
                                logger.warning("Scan alert failed", exc_info=True)
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

    return {"checked": checked, "issues_found": issues_found, "alerts_sent": alerts_sent}


# ---------------------------------------------------------------------------
# Reference evaluation
# ---------------------------------------------------------------------------

def _evaluate_agreement_ref(agr: Dict[str, Any], ts: int) -> Dict[str, Any]:
    """Evaluate an agreement link by reading its current META status."""
    license_id = agr.get("license_id", "")
    meta = _agreement_meta(license_id)
    status = meta.get("status", "")
    expires_at = meta.get("expires_at")
    expires_at = int(expires_at) if expires_at is not None else None
    return _classify_ref(license_id, "agreement", status, expires_at, ts)


def _evaluate_issued_ref(lic: Dict[str, Any], ts: int) -> Dict[str, Any]:
    """Evaluate an issued license reference."""
    license_id = lic.get("issued_license_id", "")
    status = lic.get("status", "")
    expires_at = lic.get("expires_at")
    expires_at = int(expires_at) if expires_at is not None else None
    return _classify_ref(license_id, "issued", status, expires_at, ts)


def _classify_ref(
    license_id: str,
    license_type: str,
    status: str,
    expires_at: Optional[int],
    ts: int,
) -> Dict[str, Any]:
    """Map a license's raw status + expiry to a compliance reference verdict."""
    ref: Dict[str, Any] = {
        "license_id": license_id,
        "license_type": license_type,
        "expires_at": expires_at,
    }
    if status in ("revoked",):
        ref.update(status="revoked", issue_type="license_revoked", license_status="revoked",
                   detail="License has been revoked by the licensor")
        return ref
    if status in ("expired",):
        ref.update(status="expired", issue_type="license_expired", license_status="expired",
                   detail="License has expired")
        return ref
    if status in ("", "deleted", "rejected", "archived"):
        ref.update(status="missing", issue_type="license_missing", license_status=status or "missing",
                   detail="Referenced license is not active")
        return ref
    # status is active / pending_review — check expiry.
    if expires_at is not None and expires_at <= ts:
        ref.update(status="expired", issue_type="license_expired", license_status="expired",
                   detail="License expiry date has passed")
        return ref
    if expires_at is not None and 0 < (expires_at - ts) <= EXPIRY_WARNING_SECONDS:
        ref.update(status="active", issue_type="expiring_soon", license_status="expiring_soon",
                   detail="License expires within 30 days")
        return ref
    ref.update(status="active", issue_type="", license_status="active", detail="")
    return ref


def _determine_compliance_status(issues: List[Dict[str, Any]], has_refs: bool) -> str:
    """Derive the overall compliance status from per-reference issues."""
    if not has_refs:
        # No license references at all → nothing licensed to verify.
        return "compliant"
    types = {i.get("type") for i in issues}
    if "license_revoked" in types:
        return "license_revoked"
    if "license_expired" in types or "license_missing" in types:
        return "license_expired"
    if "expiring_soon" in types:
        return "expiring_soon"
    return "compliant"


def _issue_type_from_status(status: str) -> str:
    return {
        "expiring_soon": "expiring_soon",
        "license_expired": "expired_license",
        "license_revoked": "revoked_license",
        "flagged": "community_flag",
    }.get(status, status)


def _severity_from_status(status: str) -> str:
    return _SEVERITY_BY_STATUS.get(status, "medium")


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def _upsert_license_ref(content_id: str, ref: Dict[str, Any], ts: int) -> None:
    item = {
        "pk": f"CONTENT#{content_id}",
        "sk": f"LICENSE_REF#{ref['license_id']}",
        "license_id": ref["license_id"],
        "license_type": ref["license_type"],
        "license_status": ref.get("license_status", ""),
        "expires_at": ref.get("expires_at"),
        "verified_at": ts,
    }
    _TABLE().put_item(Item=item)


def _upsert_compliance_status(
    content_id: str,
    content_type: str,
    creator_id: str,
    status: str,
    issues: List[Dict[str, Any]],
    ts: int,
) -> None:
    item = {
        "pk": f"CONTENT#{content_id}",
        "sk": "STATUS",
        "content_id": content_id,
        "content_type": content_type or "",
        "creator_id": creator_id or "",
        "compliance_status": status,
        "last_checked_at": ts,
        "issues": issues,
        "GSI1PK": f"COMPLIANCE_STATUS#{status}",
        "GSI1SK": ts,
    }
    # Preserve resolution fields if already present.
    existing = _get_compliance_status(content_id)
    if existing:
        item["resolved_at"] = existing.get("resolved_at")
        item["resolved_by"] = existing.get("resolved_by")
    else:
        item["resolved_at"] = None
        item["resolved_by"] = None
    _TABLE().put_item(Item=item)


def _upsert_creator_index(
    creator_id: str,
    content_id: str,
    content_type: str,
    status: str,
    issue_count: int,
    ts: int,
) -> None:
    if not creator_id:
        return
    _TABLE().put_item(Item={
        "pk": f"CREATOR#{creator_id}",
        "sk": f"COMPLIANCE#{content_id}",
        "content_id": content_id,
        "content_type": content_type or "",
        "compliance_status": status,
        "issue_count": issue_count,
        "last_checked_at": ts,
        "GSI3PK": f"CREATOR_COMPLIANCE#{creator_id}",
        "GSI3SK": ts,
    })


def _patch_creator_index(creator_id: str, content_id: str, status: str, ts: int) -> None:
    if not creator_id:
        return
    try:
        _TABLE().update_item(
            Key={"pk": f"CREATOR#{creator_id}", "sk": f"COMPLIANCE#{content_id}"},
            UpdateExpression="SET compliance_status = :s, last_checked_at = :t, GSI3SK = :t",
            ExpressionAttributeValues={":s": status, ":t": ts},
        )
    except Exception:
        logger.warning("Failed to patch creator compliance index", exc_info=True)


def _enqueue_admin_issue(
    content_id: str,
    creator_id: str,
    status: str,
    issue_type: str,
    severity: str,
    ts: int,
) -> None:
    _TABLE().put_item(Item={
        "pk": "ADMIN_COMPLIANCE",
        "sk": f"ISSUE#{severity}#{ts:020d}#{content_id}",
        "content_id": content_id,
        "creator_id": creator_id or "",
        "compliance_status": status,
        "issue_type": issue_type,
        "severity": severity,
        "created_at": ts,
    })


def _escalate_compliance_status(
    content_id: str,
    new_status: str,
    ts: int,
    *,
    force: bool = False,
) -> None:
    """Set compliance status to `new_status` only if more severe (or `force`)."""
    existing = _get_compliance_status(content_id)
    if existing:
        cur = existing.get("compliance_status", "compliant")
        if not force and _STATUS_RANK.get(new_status, 0) <= _STATUS_RANK.get(cur, 0):
            return
        creator_id = existing.get("creator_id", "")
        content_type = existing.get("content_type", "")
        issues = existing.get("issues", [])
    else:
        creator_id = ""
        content_type = ""
        issues = []

    _upsert_compliance_status(content_id, content_type, creator_id, new_status, issues, ts)
    _upsert_creator_index(creator_id, content_id, content_type, new_status, len(issues), ts)
    _enqueue_admin_issue(
        content_id, creator_id, new_status,
        _issue_type_from_status(new_status),
        _severity_from_status(new_status), ts,
    )


def _get_compliance_status(content_id: str) -> Optional[Dict[str, Any]]:
    resp = _TABLE().get_item(Key={"pk": f"CONTENT#{content_id}", "sk": "STATUS"})
    return resp.get("Item")


def _agreement_meta(license_id: str) -> Dict[str, Any]:
    """Read the LICENSE-001 reverse-lookup META record for an agreement."""
    if not license_id:
        return {}
    try:
        resp = T.license_agreements.get_item(
            Key={"pk": f"LICENSE#{license_id}", "sk": "META"}
        )
        return resp.get("Item") or {}
    except Exception:
        return {}


def _find_flag(flag_id: str, content_id: str = "") -> Optional[Dict[str, Any]]:
    if content_id:
        resp = _TABLE().get_item(
            Key={"pk": f"CONTENT#{content_id}", "sk": f"FLAG#{flag_id}"}
        )
        if resp.get("Item"):
            return resp["Item"]
    # Fall back: scan admin flag queue for the flag_id (small in practice).
    resp = _TABLE().query(
        KeyConditionExpression=Key("pk").eq("ADMIN_COMPLIANCE")
        & Key("sk").begins_with("FLAG#")
    )
    for it in resp.get("Items", []):
        if it.get("flag_id") == flag_id:
            cid = it.get("content_id", "")
            full = _TABLE().get_item(
                Key={"pk": f"CONTENT#{cid}", "sk": f"FLAG#{flag_id}"}
            ).get("Item")
            return full or it
    return None


# ---------------------------------------------------------------------------
# Output shaping
# ---------------------------------------------------------------------------

def _coerce_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _status_to_out(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "content_id": rec.get("content_id", ""),
        "content_type": rec.get("content_type", ""),
        "creator_id": rec.get("creator_id", ""),
        "compliance_status": rec.get("compliance_status", ""),
        "issues": rec.get("issues", []) or [],
        "last_checked_at": _coerce_int(rec.get("last_checked_at")),
        "resolved_at": _coerce_int(rec.get("resolved_at")),
        "resolved_by": rec.get("resolved_by"),
    }


def _ref_to_out(it: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "license_id": it.get("license_id", ""),
        "license_type": it.get("license_type", ""),
        "license_status": it.get("license_status", ""),
        "expires_at": _coerce_int(it.get("expires_at")),
        "verified_at": _coerce_int(it.get("verified_at")),
    }


def _flag_to_out(it: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "flag_id": it.get("flag_id", ""),
        "content_id": it.get("content_id", ""),
        "reporter_id": it.get("reporter_id", ""),
        "reporter_type": it.get("reporter_type", "viewer"),
        "reason": it.get("reason", ""),
        "evidence": it.get("evidence", ""),
        "status": it.get("status", "open"),
        "created_at": _coerce_int(it.get("created_at")) or 0,
        "resolved_at": _coerce_int(it.get("resolved_at")),
        "resolved_by": it.get("resolved_by"),
        "resolution_notes": it.get("resolution_notes", ""),
    }


def _creator_item_to_out(it: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "content_id": it.get("content_id", ""),
        "content_type": it.get("content_type", ""),
        "compliance_status": it.get("compliance_status", ""),
        "issue_count": _coerce_int(it.get("issue_count")) or 0,
        "last_checked_at": _coerce_int(it.get("last_checked_at")),
    }


def _admin_issue_to_out(it: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "content_id": it.get("content_id", ""),
        "creator_id": it.get("creator_id", ""),
        "creator_display_name": "",
        "compliance_status": it.get("compliance_status", ""),
        "issue_type": it.get("issue_type", ""),
        "severity": it.get("severity", ""),
        "created_at": _coerce_int(it.get("created_at")) or 0,
    }


def _status_record_to_admin_issue(it: Dict[str, Any]) -> Dict[str, Any]:
    status = it.get("compliance_status", "")
    return {
        "content_id": it.get("content_id", ""),
        "creator_id": it.get("creator_id", ""),
        "creator_display_name": "",
        "compliance_status": status,
        "issue_type": _issue_type_from_status(status),
        "severity": _severity_from_status(status),
        "created_at": _coerce_int(it.get("last_checked_at")) or 0,
    }


def _enrich_display_names(items: List[Dict[str, Any]]) -> None:
    cache: Dict[str, str] = {}
    for it in items:
        cid = it.get("creator_id", "")
        if not cid:
            continue
        if cid not in cache:
            try:
                profile = get_profile(cid) or {}
            except Exception:
                profile = {}
            cache[cid] = profile.get("display_name") or ""
        it["creator_display_name"] = cache[cid]


def _creator_summary(items: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {
        "total": len(items),
        "compliant": 0,
        "expiring_soon": 0,
        "issues": 0,
        "flagged": 0,
    }
    for it in items:
        st = it.get("compliance_status", "")
        if st == "compliant" or st == "resolved":
            summary["compliant"] += 1
        elif st == "expiring_soon":
            summary["expiring_soon"] += 1
        elif st == "flagged":
            summary["flagged"] += 1
        elif st in ("license_expired", "license_revoked", "under_review",
                    "action_required", "removed"):
            summary["issues"] += 1
    return summary
