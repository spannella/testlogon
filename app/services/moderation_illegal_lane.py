from __future__ import annotations

"""MODX-8: illegal / CSAM escalation lane.

The gravest category cannot ride the normal report -> 30-day public hold ->
reinstate-eligible lifecycle. Illegal content (CSAM in particular) demands a
DISTINCT lane:

  * IMMEDIATE restricted hide on the FIRST report (no distinct-reporter gate, no
    trust floor, no waiting for corroboration — legal preservation duty);
  * NEVER the public 30-day hold; the poster cannot reinstate or self-delete
    (evidence must be preserved, not destroyed);
  * a preservation record + a mandated-reporting event (NCMEC / hotline STUB +
    ops runbook) is written;
  * routed to a LOCKED senior-only queue, separate from the general board.

This module is the seam. ``escalate`` is called from ``on_report_filed`` when the
report carries an illegal category; ``assert_reinstate_allowed`` / ``assert_delete_allowed``
are the guards the lifecycle calls before any reinstate or hard-delete.
"""

import logging
import os
import time
from typing import Any, Dict, Iterable, List, Optional

from app.core.aws import ddb

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")

# Report topics / categories that trigger the locked lane. ``csam`` normalises to
# ``illegal`` for the case category set but is preserved verbatim in the report.
ILLEGAL_CATEGORIES = {"illegal", "csam"}
ILLEGAL_QUEUE = "illegal"


class IllegalContentError(ValueError):
    """Raised when an operation is forbidden on an illegal-lane case (e.g. a
    poster/admin attempt to reinstate or self-delete preserved evidence)."""


def is_illegal_category(categories: Iterable[str]) -> bool:
    for c in categories or []:
        if str(c or "").strip().lower() in ILLEGAL_CATEGORIES:
            return True
    return False


def is_illegal_case(case: Dict[str, Any]) -> bool:
    if not case:
        return False
    if bool(case.get("illegal_lane")):
        return True
    return is_illegal_category(case.get("categories") or [])


def _preserve_record(case_id: str, *, content_type: str, content_id: str, owner_user_id: str, categories: List[str], reporter_user_id: str, ts: int) -> str:
    """Write an immutable preservation record (evidence must survive any later
    delete). Idempotent on (case_id) via a stable sort key."""
    preserve_id = f"preserve_{case_id}"
    try:
        ddb.Table(APP_TABLE).put_item(
            Item={
                "pk": f"ILLEGALPRESERVE#{case_id}",
                "sk": "RECORD",
                "entity_type": "illegal_preservation",
                "preserve_id": preserve_id,
                "case_id": case_id,
                "content_type": content_type,
                "content_id": content_id,
                "owner_user_id": owner_user_id or "",
                "categories": ",".join(sorted(set(categories or []))),
                "first_reporter_user_id": reporter_user_id or "",
                "preserved_at": ts,
                "status": "preserved",
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
    except Exception as exc:  # noqa: BLE001 - ConditionalCheckFailed => already preserved
        if "ConditionalCheckFailed" not in str(type(exc).__name__) and "ConditionalCheckFailed" not in str(exc):
            logger.exception("illegal_lane: preservation write failed for %s", case_id)
    return preserve_id


def _mandated_report_event(case_id: str, *, content_type: str, content_id: str, owner_user_id: str, categories: List[str], ts: int) -> str:
    """Fire the mandated-reporting hook. STUB: writes an auditable event + logs a
    CRITICAL line for the ops runbook to pick up and file with NCMEC / the
    relevant hotline. Real integration replaces the body of this function."""
    report_event_id = f"mandrpt_{case_id}"
    try:
        ddb.Table(APP_TABLE).put_item(
            Item={
                "pk": f"MANDATEDREPORT#{case_id}",
                "sk": f"EVENT#{ts}",
                "entity_type": "mandated_report_event",
                "report_event_id": report_event_id,
                "case_id": case_id,
                "content_type": content_type,
                "content_id": content_id,
                "owner_user_id": owner_user_id or "",
                "categories": ",".join(sorted(set(categories or []))),
                "channel": "ncmec_stub",
                "status": "queued",
                "created_at": ts,
            }
        )
    except Exception:
        logger.exception("illegal_lane: mandated-report event write failed for %s", case_id)
    logger.critical(
        "MANDATED_REPORT_REQUIRED case_id=%s content=%s#%s categories=%s — file with NCMEC/hotline per runbook",
        case_id, content_type, content_id, ",".join(sorted(set(categories or []))),
    )
    return report_event_id


def escalate(
    *,
    case_id: str,
    content_type: str,
    content_id: str,
    owner_user_id: Optional[str],
    categories: Iterable[str],
    reporter_user_id: str,
    ticket_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Immediate restricted-hide + preserve + mandated-report + senior-queue route.

    Called from ``on_report_filed`` on the FIRST illegal report. Bypasses the
    distinct-reporter / trust auto-hide gate entirely. Returns a summary dict.
    """
    from app.services import moderation_case as mc
    from app.services import moderation_hide as mhide

    ts = int(now_ts or time.time())
    cats = sorted(set(mc.normalize_categories(categories) or ["illegal"]))
    md = metadata or {}

    # 1. Restricted hide (reuse the byte-for-byte non-destructive hide primitive).
    resolved_owner = mhide.hide_content(
        content_type=content_type, content_id=content_id, metadata=md,
        case_id=case_id, state=mc.STATE_UNDER_REVIEW,
    ) or (owner_user_id or "")

    # 2. Mark the case as an illegal-lane, restricted, reinstate-blocked case.
    try:
        mc.mark_under_review(case_id, hide_reason="illegal_content", now_ts=ts)
    except Exception:
        logger.exception("illegal_lane: mark_under_review failed for %s", case_id)
    try:
        from app.core.tables import T
        # NB: ``hidden`` is a DynamoDB reserved keyword -> alias every name. The
        # hidden flag itself is already set True by mark_under_review above.
        T.moderation_cases.update_item(
            Key={"case_id": case_id},
            UpdateExpression=(
                "SET #il = :t, #rs = :t, #rb = :t, #ea = :ts, #mq = :q, #h = :t"
            ),
            ExpressionAttributeNames={
                "#il": "illegal_lane", "#rs": "restricted", "#rb": "reinstate_blocked",
                "#ea": "escalated_at", "#mq": "moderation_queue", "#h": "hidden",
            },
            ExpressionAttributeValues={":t": True, ":ts": ts, ":q": ILLEGAL_QUEUE},
        )
    except Exception:
        logger.exception("illegal_lane: case flagging failed for %s", case_id)

    # 3. Preserve evidence + fire the mandated-reporting hook.
    preserve_id = _preserve_record(
        case_id, content_type=content_type, content_id=content_id,
        owner_user_id=resolved_owner or "", categories=cats,
        reporter_user_id=reporter_user_id, ts=ts,
    )
    report_event_id = _mandated_report_event(
        case_id, content_type=content_type, content_id=content_id,
        owner_user_id=resolved_owner or "", categories=cats, ts=ts,
    )

    # 4. Route the linked ticket to the LOCKED senior-only queue (critical).
    if ticket_id:
        try:
            from app.core.tables import T
            T.moderation_tickets.update_item(
                Key={"ticket_id": ticket_id},
                UpdateExpression="SET queue = :q, priority = :p, restricted = :t, updated_at = :ts",
                ExpressionAttributeValues={":q": ILLEGAL_QUEUE, ":p": "critical", ":t": True, ":ts": str(ts)},
            )
        except Exception:
            logger.exception("illegal_lane: ticket routing failed for %s", ticket_id)

    return {
        "illegal_lane": True,
        "restricted": True,
        "state": mc.STATE_UNDER_REVIEW,
        "owner_user_id": resolved_owner,
        "preserve_id": preserve_id,
        "mandated_report_event_id": report_event_id,
        "queue": ILLEGAL_QUEUE,
        "categories": cats,
    }


def assert_reinstate_allowed(case: Dict[str, Any]) -> None:
    if is_illegal_case(case):
        raise IllegalContentError("illegal_content_no_reinstate")


def assert_delete_allowed(case: Dict[str, Any]) -> None:
    """Poster-initiated hard delete of preserved illegal content is forbidden
    (evidence). Admin senior final-call handles disposition separately."""
    if is_illegal_case(case):
        raise IllegalContentError("illegal_content_preserved")
