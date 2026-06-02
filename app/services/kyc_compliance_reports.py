"""KYC compliance reporting & export (KYC-012).

A reporting + export layer ON TOP of the existing KYC data (it does NOT run a
new KYC pipeline).  It aggregates the operational KYC tables/services into
compliance reports and renders them as CSV / PDF.

Reports:
  - volume_report()            -> case counts by status, approval/rejection rates
  - screening_report()         -> sanctions/PEP hit-rate + resolution breakdown
  - processing_time_report()   -> submission->decision distribution (percentiles)
  - deadline_tracker()         -> cases pending beyond thresholds
  - retention_report()         -> PII inventory + purge schedule
  - audit_trail_for_user()     -> KYC audit events for a user
  - generate_sar()             -> Suspicious Activity Report

Exports:
  - render_report_csv()        -> RFC-4180 CSV string (reuses csv_export sanitizer)
  - render_report_pdf()        -> minimal PDF bytes (reuses questionnaire PDF helper)

IMPORTANT (DDB gotcha): scans that filter a sparse attribute on a busy table
must loop on ``LastEvaluatedKey`` because DynamoDB applies FilterExpression
*after* reading up to 1MB — a single ``scan()``/``query()`` call silently
misses items beyond the first page.  ``_scan_all`` / ``_query_all`` below do
this looping.
"""

from __future__ import annotations

import csv
import io
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.csv_export import _sanitize_csv_field
from app.services.kyc_cases import STORE, _status_pk, _updated_sk
from app.services.questionnaire_response_pdf import html_to_pdf_bytes

logger = logging.getLogger(__name__)

# Page sizes for paginated reads (kept modest; loops cover the rest).
_PAGE_LIMIT = 500
# Hard ceiling on items pulled per report so a huge table can't hang a request.
_MAX_ITEMS = 5000

_ALL_STATUSES = [
    "draft",
    "submitted",
    "under_review",
    "needs_more_info",
    "approved",
    "rejected",
    "expired",
]
_PENDING_STATUSES = ["submitted", "under_review", "needs_more_info"]


# --------------------------------------------------------------------------- #
# DDB helpers — always loop on LastEvaluatedKey                                #
# --------------------------------------------------------------------------- #
def _query_all(table: Any, *, max_items: int = _MAX_ITEMS, **kwargs: Any) -> list[dict]:
    """Run a paginated query, following LastEvaluatedKey until exhausted."""
    items: list[dict] = []
    start_key: dict | None = None
    while True:
        if start_key is not None:
            kwargs["ExclusiveStartKey"] = start_key
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key or len(items) >= max_items:
            break
    return items


def _scan_all(table: Any, *, max_items: int = _MAX_ITEMS, **kwargs: Any) -> list[dict]:
    """Run a paginated scan, following LastEvaluatedKey until exhausted.

    NB: DynamoDB FilterExpression does NOT reduce the per-page read size, so a
    single scan() call would miss filtered items beyond the first 1MB page on a
    busy table — hence the loop.
    """
    items: list[dict] = []
    start_key: dict | None = None
    while True:
        if start_key is not None:
            kwargs["ExclusiveStartKey"] = start_key
        resp = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key or len(items) >= max_items:
            break
    return items


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _query_cases_by_status_date_range(status: str, start_ts: int, end_ts: int) -> list[dict]:
    """Query cases in a status within [start_ts, end_ts] via the status GSI.

    The status GSI sort key is ``UPDATED#{ts:013d}#KYC#{case_id}``; we build an
    inclusive BETWEEN range using a ``~`` suffix that sorts after every hex
    char of the case-id suffix.
    """
    start_sk = _updated_sk(start_ts, "")
    end_sk = f"UPDATED#{end_ts:013d}#KYC#~"
    items = _query_all(
        T.kyc_cases,
        IndexName=S.kyc_cases_status_index_name,
        KeyConditionExpression=(
            Key("gsi_status_pk").eq(_status_pk(status))
            & Key("gsi_status_sk").between(start_sk, end_sk)
        ),
        ScanIndexForward=False,
    )
    return [row for row in items if row.get("entity_type") == "kyc_case"]


def _case_files(case: dict) -> list[dict]:
    files = case.get("files") or []
    return [f for f in files if isinstance(f, dict)]


def _file_type(f: dict) -> str:
    # Seeded cases use "type"; some paths use "file_type".
    return str(f.get("file_type") or f.get("type") or "")


def _percentile(sorted_values: list[int], q: float) -> int | None:
    if not sorted_values:
        return None
    idx = min(int(len(sorted_values) * q), len(sorted_values) - 1)
    return int(sorted_values[idx])


def _normalize_range(start_date: int | None, end_date: int | None) -> tuple[int, int]:
    end = _coerce_int(end_date) if end_date is not None else now_ts()
    start = _coerce_int(start_date) if start_date is not None else (end - 30 * 86400)
    return start, end


# --------------------------------------------------------------------------- #
# Reports                                                                      #
# --------------------------------------------------------------------------- #
def volume_report(*, start_date: int | None = None, end_date: int | None = None) -> dict[str, Any]:
    """KYC volume: case counts by status, approval/rejection rates for a period."""
    start, end = _normalize_range(start_date, end_date)
    counts: dict[str, int] = {}
    total = 0
    for status in _ALL_STATUSES:
        cases = _query_cases_by_status_date_range(status, start, end)
        counts[status] = len(cases)
        total += len(cases)

    approved = counts.get("approved", 0)
    rejected = counts.get("rejected", 0)
    decided = approved + rejected

    return {
        "report_type": "volume",
        "period_start": start,
        "period_end": end,
        "total_cases": total,
        "counts_by_status": counts,
        "approval_rate": round(approved / max(decided, 1) * 100, 1),
        "rejection_rate": round(rejected / max(decided, 1) * 100, 1),
        "generated_at": now_ts(),
    }


def processing_time_report(*, start_date: int | None = None, end_date: int | None = None) -> dict[str, Any]:
    """Distribution of submission->decision time for decided cases in the period."""
    start, end = _normalize_range(start_date, end_date)
    decided = (
        _query_cases_by_status_date_range("approved", start, end)
        + _query_cases_by_status_date_range("rejected", start, end)
    )

    durations: list[int] = []
    for case in decided:
        submitted_at = (case.get("submission") or {}).get("submitted_at")
        decided_at = (case.get("review") or {}).get("decided_at")
        if submitted_at and decided_at:
            delta = _coerce_int(decided_at) - _coerce_int(submitted_at)
            if delta >= 0:
                durations.append(delta)
    durations.sort()

    return {
        "report_type": "processing_time",
        "period_start": start,
        "period_end": end,
        "total_decided": len(decided),
        "avg_seconds": round(sum(durations) / max(len(durations), 1)) if durations else 0,
        "p50_seconds": _percentile(durations, 0.50),
        "p90_seconds": _percentile(durations, 0.90),
        "p95_seconds": _percentile(durations, 0.95),
        "min_seconds": durations[0] if durations else None,
        "max_seconds": durations[-1] if durations else None,
        "generated_at": now_ts(),
    }


def screening_report(*, start_date: int | None = None, end_date: int | None = None) -> dict[str, Any]:
    """Sanctions/PEP screening hit-rate + resolution breakdown for a period.

    Reads the existing ``kyc_screening_results`` table.  ``result`` is one of
    ``clear`` / ``potential_match`` / ``confirmed_match``; ``review_decision``
    is the adjudication (``clear`` / ``confirm`` / ``escalate``).
    """
    start, end = _normalize_range(start_date, end_date)
    results = _scan_all(
        T.kyc_screening_results,
        FilterExpression=Attr("created_at").between(start, end),
        Limit=_PAGE_LIMIT,
    )

    total = len(results)
    hits = [r for r in results if str(r.get("result")) in ("potential_match", "confirmed_match")]

    resolutions: dict[str, int] = defaultdict(int)
    for hit in hits:
        decision = str(hit.get("review_decision") or "pending")
        resolutions[decision] += 1

    confirmed = sum(1 for r in hits if str(r.get("result")) == "confirmed_match")

    return {
        "report_type": "screening",
        "period_start": start,
        "period_end": end,
        "total_screenings": total,
        "total_hits": len(hits),
        "hit_rate_pct": round(len(hits) / max(total, 1) * 100, 2),
        "resolutions": dict(resolutions),
        "false_positive_count": resolutions.get("clear", 0),
        "escalated_count": resolutions.get("escalate", 0),
        "confirmed_count": confirmed,
        "generated_at": now_ts(),
    }


def deadline_tracker(*, warn_after_hours: int = 48, critical_after_hours: int = 120) -> dict[str, Any]:
    """List pending cases beyond warn/critical age thresholds."""
    now = now_ts()
    warn_threshold = now - (warn_after_hours * 3600)
    critical_threshold = now - (critical_after_hours * 3600)

    overdue: list[dict] = []
    for status in _PENDING_STATUSES:
        for case in STORE.list_cases_by_status(status=status, limit=100):
            submitted_at = _coerce_int(
                (case.get("submission") or {}).get("submitted_at") or case.get("created_at", 0)
            )
            if submitted_at < critical_threshold:
                severity = "critical"
            elif submitted_at < warn_threshold:
                severity = "warning"
            else:
                continue
            overdue.append(
                {
                    "case_id": str(case.get("kyc_case_id") or ""),
                    "user_sub": str(case.get("user_sub") or ""),
                    "status": str(case.get("status") or status),
                    "submitted_at": submitted_at,
                    "age_hours": round((now - submitted_at) / 3600, 1),
                    "severity": severity,
                    "assigned_admin": (case.get("review") or {}).get("assigned_admin_sub"),
                }
            )

    overdue.sort(key=lambda c: c["age_hours"], reverse=True)
    return {
        "report_type": "deadlines",
        "warn_after_hours": warn_after_hours,
        "critical_after_hours": critical_after_hours,
        "total_overdue": len(overdue),
        "critical_count": sum(1 for c in overdue if c["severity"] == "critical"),
        "warning_count": sum(1 for c in overdue if c["severity"] == "warning"),
        "cases": overdue,
        "generated_at": now_ts(),
    }


def retention_report() -> dict[str, Any]:
    """PII inventory + purge schedule + compliance status."""
    now = now_ts()
    policies = {
        "rejected": int(S.kyc_retention_rejected_days),
        "expired": int(S.kyc_retention_expired_days),
        "approved": int(S.kyc_retention_approved_days),
    }

    inventory: list[dict] = []
    for status, retention_days in policies.items():
        for case in STORE.list_cases_by_status(status=status, limit=100):
            review = case.get("review") or {}
            decided_at = _coerce_int(review.get("decided_at") or case.get("updated_at", 0))
            purge_due = decided_at + (retention_days * 86400)
            files = _case_files(case)
            purged = bool(review.get("purged_at"))
            inventory.append(
                {
                    "case_id": str(case.get("kyc_case_id") or ""),
                    "user_sub": str(case.get("user_sub") or ""),
                    "status": status,
                    "decided_at": decided_at,
                    "retention_days": retention_days,
                    "purge_due_at": purge_due,
                    "purge_overdue": (purge_due < now) and not purged,
                    "file_count": len(files),
                    "has_selfie": any(_file_type(f) == "selfie" for f in files),
                    "has_id_document": any(_file_type(f) in ("id_front", "id_back") for f in files),
                    "has_proof_of_address": any(
                        _file_type(f) in ("proof_of_address", "proof_of_funds") for f in files
                    ),
                    "purged": purged,
                }
            )

    inventory.sort(key=lambda c: c["purge_due_at"])
    return {
        "report_type": "retention",
        "policies": {k: f"{v} days" for k, v in policies.items()},
        "total_records": len(inventory),
        "overdue_purge_count": sum(1 for c in inventory if c["purge_overdue"]),
        "already_purged_count": sum(1 for c in inventory if c["purged"]),
        "inventory": inventory,
        "generated_at": now_ts(),
    }


def audit_trail_for_user(user_sub: str) -> dict[str, Any]:
    """KYC audit events for a user, derived from their cases' review/submission timeline.

    The platform's audit_log table is keyed by event-id (not user), so for a
    stable, user-scoped trail we reconstruct events from the user's own KYC
    cases (creation / submission / decision).
    """
    events: list[dict] = []
    for case in STORE.list_cases_by_owner(user_sub=user_sub, limit=50):
        case_id = str(case.get("kyc_case_id") or "")
        created_at = _coerce_int(case.get("created_at", 0))
        if created_at:
            events.append(
                {
                    "event_name": "kyc.case.created",
                    "actor_sub": user_sub,
                    "timestamp": created_at,
                    "outcome": "success",
                    "details": {"case_id": case_id, "status": case.get("status")},
                }
            )
        submission = case.get("submission") or {}
        submitted_at = _coerce_int(submission.get("submitted_at", 0))
        if submitted_at:
            events.append(
                {
                    "event_name": "kyc.case.submitted",
                    "actor_sub": user_sub,
                    "timestamp": submitted_at,
                    "outcome": "success",
                    "details": {"case_id": case_id},
                }
            )
        review = case.get("review") or {}
        decided_at = _coerce_int(review.get("decided_at", 0))
        if decided_at:
            events.append(
                {
                    "event_name": "kyc.case.decided",
                    "actor_sub": str(review.get("assigned_admin_sub") or "system"),
                    "timestamp": decided_at,
                    "outcome": str(review.get("decision") or "decided"),
                    "details": {"case_id": case_id, "reason_codes": review.get("reason_codes") or []},
                }
            )

    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return {
        "report_type": "audit_trail",
        "user_sub": user_sub,
        "total_events": len(events),
        "events": events,
        "generated_at": now_ts(),
    }


def generate_sar(
    *,
    user_sub: str,
    reason: str,
    transaction_ids: list[str] | None = None,
    admin_sub: str,
) -> dict[str, Any]:
    """Generate (and persist) a Suspicious Activity Report for a user."""
    ts = now_ts()
    sar_id = f"SAR_{uuid.uuid4().hex[:12]}"

    cases = STORE.list_cases_by_owner(user_sub=user_sub, limit=10)
    flagged: list[dict[str, Any]] = [{"transaction_id": tid} for tid in (transaction_ids or [])]
    audit = audit_trail_for_user(user_sub).get("events", [])

    sar = {
        "sar_id": sar_id,
        "generated_at": ts,
        "generated_by": admin_sub,
        "subject_user_sub": user_sub,
        "reason": reason,
        "kyc_cases": [
            {
                "case_id": str(c.get("kyc_case_id") or ""),
                "status": str(c.get("status") or ""),
                "created_at": _coerce_int(c.get("created_at", 0)),
                "decided_at": (c.get("review") or {}).get("decided_at"),
            }
            for c in cases
        ],
        "flagged_transactions": flagged,
        "audit_trail": audit,
    }

    T.kyc_cases.put_item(
        Item={
            "pk": f"SAR#{sar_id}",
            "sk": "META",
            "entity_type": "sar",
            **sar,
        }
    )
    logger.warning(
        "kyc.sar.generated sar_id=%s subject=%s admin=%s case_count=%s txn_count=%s",
        sar_id,
        user_sub,
        admin_sub,
        len(sar["kyc_cases"]),
        len(flagged),
    )
    return sar


# --------------------------------------------------------------------------- #
# Export rendering                                                             #
# --------------------------------------------------------------------------- #
def _report_rows(report_data: dict[str, Any]) -> list[dict]:
    """Pick the tabular list out of a report for row-based export."""
    for key in ("cases", "inventory", "events", "kyc_cases"):
        rows = report_data.get(key)
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            return rows
    return []


def render_report_csv(report_data: dict[str, Any]) -> str:
    """Render a report's tabular rows as an RFC-4180 CSV string.

    For reports that are purely scalar summaries (volume, screening, processing
    time) we emit a two-column key/value CSV so the export is never empty.
    """
    rows = _report_rows(report_data)
    output = io.StringIO()
    writer = csv.writer(output)

    if rows:
        headers = list(rows[0].keys())
        writer.writerow(headers)
        for item in rows:
            writer.writerow([_sanitize_csv_field(str(item.get(h, ""))) for h in headers])
        return output.getvalue()

    # Scalar summary -> key/value rows (skip nested containers).
    writer.writerow(["metric", "value"])
    for key, value in report_data.items():
        if isinstance(value, (list, dict)):
            continue
        writer.writerow([_sanitize_csv_field(str(key)), _sanitize_csv_field(str(value))])
    return output.getvalue()


def _ts_to_iso(ts: Any) -> str:
    n = _coerce_int(ts, -1)
    if n < 0:
        return ""
    return datetime.fromtimestamp(n, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_report_pdf(report_data: dict[str, Any]) -> bytes:
    """Render a formatted PDF for a report (reuses the questionnaire PDF helper)."""
    report_type = str(report_data.get("report_type") or "report")
    parts: list[str] = [
        "<html><body>",
        f"<h1>KYC Compliance Report — {report_type}</h1>",
        f"<p>Generated: {_ts_to_iso(report_data.get('generated_at'))}</p>",
    ]
    if report_data.get("period_start") is not None:
        parts.append(f"<p>Period: {_ts_to_iso(report_data.get('period_start'))} to "
                     f"{_ts_to_iso(report_data.get('period_end'))}</p>")

    parts.append("<h2>Summary</h2><ul>")
    for key, value in report_data.items():
        if isinstance(value, (list, dict)):
            continue
        parts.append(f"<li>{key}: {value}</li>")
    parts.append("</ul>")

    rows = _report_rows(report_data)
    if rows:
        parts.append(f"<h2>Records ({len(rows)})</h2><ul>")
        for item in rows[:200]:
            line = " | ".join(f"{k}={item.get(k)}" for k in list(item.keys())[:8])
            parts.append(f"<li>{line}</li>")
        parts.append("</ul>")

    parts.append("</body></html>")
    return html_to_pdf_bytes("".join(parts))


# Report generators keyed by the path slug used in the export endpoint.
REPORT_GENERATORS: dict[str, Callable[..., dict[str, Any]]] = {
    "volume": lambda start_date=None, end_date=None: volume_report(
        start_date=start_date, end_date=end_date
    ),
    "screening": lambda start_date=None, end_date=None: screening_report(
        start_date=start_date, end_date=end_date
    ),
    "processing-time": lambda start_date=None, end_date=None: processing_time_report(
        start_date=start_date, end_date=end_date
    ),
    "deadlines": lambda start_date=None, end_date=None: deadline_tracker(),
    "retention": lambda start_date=None, end_date=None: retention_report(),
}
