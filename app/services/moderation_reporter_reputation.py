from __future__ import annotations

"""MODX-5: reporter reputation loop + self/COI guards.

The moderation case store (``moderation_case``) already *reads* three reporter
reputation signals off ``account_state`` — ``trusted_reporter`` (bool),
``report_trust_score`` (float) and ``report_false_rate`` (float) — but NOTHING
ever wrote them, so the trust gate for auto-hide could never legitimately fire
and serial false-reporters were never penalised.

This module closes that loop. When an admin (or a lifecycle terminal) resolves a
case we feed the outcome back onto every distinct reporter of that case:

  - a **dismiss / reinstate** (the report did NOT hold up) DECREMENTS trust and
    bumps the reporter's false-report rate;
  - a **confirm / delete** (the report was upheld) INCREMENTS trust.

``report_trust_score`` and ``report_false_rate`` are recomputed from durable
counters (``reports_total`` / ``reports_upheld`` / ``reports_dismissed``) so the
derived signals are always consistent and ``is_trusted_reporter`` becomes real.

Self / conflict-of-interest guards live here too: a report whose reporter is the
content owner must never count toward auto-hide, and an admin may not adjudicate
a case where they are the owner or the sole reporter.
"""

import logging
import time
from typing import Any, Dict, Iterable, List, Optional, Set

from botocore.exceptions import ClientError

from app.core.tables import T

logger = logging.getLogger(__name__)

# A reporter is "trusted" once upheld-heavy; false at/above this rate is capped out.
TRUST_SCORE_TRUSTED_FLOOR = 1.0
FALSE_RATE_TRUSTED_CEILING = 0.2


def _f(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _i(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _recompute_and_store(reporter_user_id: str, now_ts: int) -> None:
    """Read back the durable counters and store derived score + false-rate.

    ``report_trust_score = upheld - dismissed`` (a simple signed reputation),
    ``report_false_rate  = dismissed / total``  (0..1). Both are clamped.
    """
    try:
        st = T.account_state.get_item(Key={"user_sub": reporter_user_id}).get("Item") or {}
    except ClientError:
        logger.exception("reporter_reputation: read-back failed for %s", reporter_user_id)
        return
    total = max(0, _i(st.get("reports_total")))
    upheld = max(0, _i(st.get("reports_upheld")))
    dismissed = max(0, _i(st.get("reports_dismissed")))
    score = float(upheld - dismissed)
    false_rate = (float(dismissed) / float(total)) if total > 0 else 0.0
    false_rate = max(0.0, min(1.0, false_rate))
    try:
        # The T wrapper coerces float -> Decimal on update ExpressionAttributeValues.
        T.account_state.update_item(
            Key={"user_sub": reporter_user_id},
            UpdateExpression="SET report_trust_score = :sc, report_false_rate = :fr, reputation_updated_at = :ts",
            ExpressionAttributeValues={":sc": round(score, 4), ":fr": round(false_rate, 4), ":ts": now_ts},
        )
    except ClientError:
        logger.exception("reporter_reputation: store failed for %s", reporter_user_id)


def _bump(reporter_user_id: str, *, upheld: bool, now_ts: int) -> None:
    if not reporter_user_id:
        return
    names = {"#t": "reports_total"}
    add_parts = ["#t :one"]
    if upheld:
        names["#u"] = "reports_upheld"
        add_parts.append("#u :one")
    else:
        names["#d"] = "reports_dismissed"
        add_parts.append("#d :one")
    try:
        T.account_state.update_item(
            Key={"user_sub": reporter_user_id},
            UpdateExpression="ADD " + ", ".join(add_parts),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues={":one": 1},
        )
    except ClientError:
        logger.exception("reporter_reputation: counter bump failed for %s", reporter_user_id)
        return
    _recompute_and_store(reporter_user_id, now_ts)


def distinct_reporter_ids(case: Dict[str, Any]) -> List[str]:
    raw = case.get("reporter_ids")
    if isinstance(raw, (set, frozenset)):
        return sorted(str(x) for x in raw if x)
    if isinstance(raw, (list, tuple)):
        return sorted({str(x) for x in raw if x})
    return []


def apply_outcome(case: Dict[str, Any], *, upheld: bool, now_ts: Optional[int] = None) -> int:
    """Feed a case resolution back onto every distinct reporter.

    ``upheld=True``  -> the report(s) held up (confirm/delete): trust up.
    ``upheld=False`` -> dismissed/reinstated: trust down + false-rate up.
    Returns the number of reporters adjusted. Never raises (best-effort).
    """
    ts = int(now_ts or time.time())
    owner = str(case.get("owner_user_id") or "")
    reporters = [r for r in distinct_reporter_ids(case) if r and r != owner]
    for r in reporters:
        try:
            _bump(r, upheld=upheld, now_ts=ts)
        except Exception:
            logger.exception("reporter_reputation.apply_outcome failed for %s", r)
    return len(reporters)


def sole_reporter(case: Dict[str, Any]) -> Optional[str]:
    reporters = distinct_reporter_ids(case)
    return reporters[0] if len(reporters) == 1 else None


def is_conflicted_admin(case: Dict[str, Any], admin_user_id: str) -> bool:
    """MODX-5 (A13): an admin may not adjudicate a case where they are the content
    owner or the sole reporter (conflict of interest)."""
    aid = str(admin_user_id or "")
    if not aid:
        return False
    if aid == str(case.get("owner_user_id") or ""):
        return True
    if aid == (sole_reporter(case) or "__none__"):
        return True
    return False
