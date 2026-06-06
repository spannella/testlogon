"""KYC-003: Liveness Video Verification Call service.

Standalone liveness-call feature that builds alongside the existing KYC case
feature (``app/services/kyc_cases.py``) and the other KYC verification services
(document / residency / proof-of-funds) WITHOUT modifying them.

A user (case owner) schedules a live video verification call for a KYC case.
A verifier (admin/root) conducts the call and records the outcome. The result
feeds the KYC risk-scoring engine (``app/services/kyc_risk_scoring.py`` reads
``case.verification_call.result``) the same way residency / funds factors do.

Call records live in the ``kyc_liveness_calls`` DynamoDB table (PK ``call_id``)
with a ``ByStatus`` GSI for verifier listing. Status lifecycle::

    scheduled  -> in_progress  -> passed
                              -> failed
               -> cancelled
               -> expired

Scheduling when an active (scheduled / in_progress) call already exists for the
case raises a conflict -> 409 ``kyc_call_already_scheduled``.

There is no real video: ``conduct`` flips the call to ``in_progress`` and
``record_outcome`` stores ``passed`` / ``failed`` with notes and an optional
recording reference (``/mock/s3/...`` in dev). All time logic accepts an
injectable ``now`` so E2E tests are deterministic.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# --- constants -------------------------------------------------------------

# Call lifecycle / status values
STATUS_SCHEDULED = "scheduled"
STATUS_IN_PROGRESS = "in_progress"
STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_EXPIRED = "expired"

_ALL_STATUSES = {
    STATUS_SCHEDULED,
    STATUS_IN_PROGRESS,
    STATUS_PASSED,
    STATUS_FAILED,
    STATUS_CANCELLED,
    STATUS_EXPIRED,
}

# statuses that can be listed via the ByStatus GSI for verifier / admin work
LISTABLE_STATUSES = set(_ALL_STATUSES)

# statuses considered "active" (block re-scheduling for the same case)
ACTIVE_STATUSES = {STATUS_SCHEDULED, STATUS_IN_PROGRESS}

# terminal statuses (call is finished)
TERMINAL_STATUSES = {STATUS_PASSED, STATUS_FAILED, STATUS_CANCELLED, STATUS_EXPIRED}

# allowed verifier-recorded outcomes
ALLOWED_OUTCOMES = {STATUS_PASSED, STATUS_FAILED}


# --- errors ----------------------------------------------------------------


class KycLivenessCallValidationError(ValueError):
    """Invalid input supplied for a KYC liveness-call operation."""


class KycLivenessCallNotFoundError(LookupError):
    """A referenced KYC liveness call does not exist."""


class KycLivenessCallStateError(RuntimeError):
    """A call is in a state that does not permit the requested operation."""


class KycLivenessCallConflictError(RuntimeError):
    """An active liveness call already exists for the case."""


# --- helpers ---------------------------------------------------------------


def _new_call_id() -> str:
    return f"kyccall_{uuid.uuid4().hex[:16]}"


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _resolve_now(now: Any = None) -> int:
    """Return the reference "now" as an integer Unix timestamp.

    ``now`` may be an int/float timestamp or ``None`` (current time). Injectable
    for deterministic tests.
    """
    if isinstance(now, (int, float)):
        return int(now)
    return now_ts()


# --- service ---------------------------------------------------------------


@dataclass
class KycLivenessCallStore:
    """Persistence + lifecycle for KYC liveness video verification calls."""

    _table: Any = field(default=T.kyc_liveness_calls)

    # -- S3 recording ref --------------------------------------------------

    def _recording_ref(self, *, call_id: str) -> str:
        """Return a (mock) S3 reference for the call recording."""
        prefix = S.kyc_liveness_call_s3_prefix
        key = f"{prefix}{call_id}/recording.webm"
        bucket = S.kyc_liveness_call_bucket or "local-uploads"
        if S.dev_mode:
            return f"/mock/s3/{bucket}/{key}"
        return key

    # -- public API --------------------------------------------------------

    def schedule_call(
        self,
        *,
        case_id: str,
        user_sub: str,
        scheduled_at: int,
        duration_minutes: int = 15,
        verifier_sub: str | None = None,
        note: str | None = None,
        now: Any = None,
    ) -> dict[str, Any]:
        """Schedule a liveness call for a case (owner action).

        Raises ``KycLivenessCallConflictError`` if an active call already exists
        for the case (-> 409 ``kyc_call_already_scheduled``).
        """
        ref_now = _resolve_now(now)
        sched = _coerce_int(scheduled_at)
        if sched <= 0:
            raise KycLivenessCallValidationError("kyc_invalid_schedule_time")
        if sched < ref_now + max(0, int(S.kyc_liveness_call_min_lead_seconds)):
            raise KycLivenessCallValidationError("kyc_invalid_schedule_time")

        existing = self.get_active_call_for_case(case_id)
        if existing is not None:
            raise KycLivenessCallConflictError("kyc_call_already_scheduled")

        call_id = _new_call_id()
        ts = ref_now
        item: dict[str, Any] = {
            "call_id": call_id,
            "case_id": case_id,
            "user_sub": user_sub,
            "status": STATUS_SCHEDULED,
            "scheduled_at": sched,
            "duration_minutes": max(5, min(60, int(duration_minutes or 15))),
            "verifier_sub": verifier_sub or "_unassigned",
            "note": (note or None),
            "result": None,
            "result_notes": None,
            "result_set_at": None,
            "recording_ref": None,
            "started_at": None,
            "conducted_by": None,
            "created_at": ts,
            "updated_at": ts,
        }
        self._table.put_item(Item=item)
        logger.info(
            "kyc.liveness_call.scheduled call_id=%s case_id=%s scheduled_at=%s",
            call_id,
            case_id,
            sched,
        )
        return item

    def get_call(self, call_id: str) -> dict[str, Any] | None:
        resp = self._table.get_item(Key={"call_id": call_id})
        return resp.get("Item")

    def get_active_call_for_case(self, case_id: str) -> dict[str, Any] | None:
        """Return the active (scheduled / in_progress) call for a case, if any."""
        for item in self.list_calls_for_case(case_id):
            if str(item.get("status") or "") in ACTIVE_STATUSES:
                return item
        return None

    def get_latest_call_for_case(self, case_id: str) -> dict[str, Any] | None:
        """Return the most recently created call for a case (any status)."""
        items = self.list_calls_for_case(case_id)
        return items[0] if items else None

    def list_calls_for_case(self, case_id: str) -> list[dict[str, Any]]:
        try:
            resp = self._table.query(
                IndexName="ByCase",
                KeyConditionExpression=Key("case_id").eq(case_id),
                ScanIndexForward=False,
            )
            return list(resp.get("Items", []))
        except Exception:
            resp = self._table.scan()
            items = [i for i in resp.get("Items", []) if i.get("case_id") == case_id]
            items.sort(key=lambda i: _coerce_int(i.get("created_at")), reverse=True)
            return items

    def list_calls_for_owner(self, user_sub: str) -> list[dict[str, Any]]:
        try:
            resp = self._table.query(
                IndexName="ByOwner",
                KeyConditionExpression=Key("user_sub").eq(user_sub),
                ScanIndexForward=False,
            )
            return list(resp.get("Items", []))
        except Exception:
            resp = self._table.scan()
            items = [i for i in resp.get("Items", []) if i.get("user_sub") == user_sub]
            items.sort(key=lambda i: _coerce_int(i.get("created_at")), reverse=True)
            return items

    def list_by_status(self, status: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """List calls by status via the ByStatus GSI (PK=status, SK=created_at)."""
        st = str(status or "").strip()
        if st not in LISTABLE_STATUSES:
            raise KycLivenessCallValidationError("invalid_status")
        items: list[dict[str, Any]] = []
        last_key: dict | None = None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": S.kyc_liveness_call_status_index_name,
                "KeyConditionExpression": Key("status").eq(st),
                "ScanIndexForward": False,
                "Limit": min(limit, 500),
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = self._table.query(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key or len(items) >= limit:
                break
        return items[:limit]

    def cancel_call(self, *, call_id: str, actor_sub: str, now: Any = None) -> dict[str, Any]:
        """Cancel a scheduled / in-progress call (owner or verifier action)."""
        item = self.get_call(call_id)
        if not item:
            raise KycLivenessCallNotFoundError(call_id)
        if str(item.get("status") or "") not in ACTIVE_STATUSES:
            raise KycLivenessCallStateError("kyc_call_not_active")
        ts = _resolve_now(now)
        update = {
            "status": STATUS_CANCELLED,
            "cancelled_by": actor_sub,
            "updated_at": ts,
        }
        self._apply_update(call_id, update)
        logger.info("kyc.liveness_call.cancelled call_id=%s by=%s", call_id, actor_sub)
        return {**item, **update}

    def conduct_call(self, *, call_id: str, verifier_sub: str, now: Any = None) -> dict[str, Any]:
        """Verifier marks the call as in progress (joins / begins the call)."""
        item = self.get_call(call_id)
        if not item:
            raise KycLivenessCallNotFoundError(call_id)
        status = str(item.get("status") or "")
        if status == STATUS_IN_PROGRESS:
            return item
        if status != STATUS_SCHEDULED:
            raise KycLivenessCallStateError("kyc_call_not_scheduled")
        ts = _resolve_now(now)
        update = {
            "status": STATUS_IN_PROGRESS,
            "started_at": ts,
            "conducted_by": verifier_sub,
            "verifier_sub": verifier_sub,
            "updated_at": ts,
        }
        self._apply_update(call_id, update)
        logger.info("kyc.liveness_call.conducting call_id=%s verifier=%s", call_id, verifier_sub)
        return {**item, **update}

    def record_outcome(
        self,
        *,
        call_id: str,
        verifier_sub: str,
        result: str,
        notes: str,
        recording_linked: bool = True,
        now: Any = None,
    ) -> dict[str, Any]:
        """Verifier records the pass/fail outcome of a conducted call.

        The call must be scheduled or in_progress. Stores the result + notes +
        optional recording reference and feeds the KYC case / risk engine.
        """
        outcome = str(result or "").strip().lower()
        if outcome not in ALLOWED_OUTCOMES:
            raise KycLivenessCallValidationError("kyc_invalid_result")
        if not str(notes or "").strip():
            raise KycLivenessCallValidationError("kyc_result_notes_required")

        item = self.get_call(call_id)
        if not item:
            raise KycLivenessCallNotFoundError(call_id)
        status = str(item.get("status") or "")
        if status not in (STATUS_SCHEDULED, STATUS_IN_PROGRESS):
            raise KycLivenessCallStateError("kyc_call_not_recordable")

        ts = _resolve_now(now)
        recording_ref = self._recording_ref(call_id=call_id) if recording_linked else None
        update = {
            "status": outcome,
            "result": outcome,
            "result_notes": str(notes),
            "result_set_at": ts,
            "recording_ref": recording_ref,
            "conducted_by": verifier_sub,
            "verifier_sub": verifier_sub,
            "updated_at": ts,
        }
        if item.get("started_at") is None:
            update["started_at"] = ts
        self._apply_update(call_id, update)
        merged = {**item, **update}

        # Feed the KYC case / risk-scoring engine (import-safe, best effort).
        self._feed_case_result(case_id=str(item.get("case_id") or ""), call=merged)

        logger.info(
            "kyc.liveness_call.recorded call_id=%s result=%s verifier=%s",
            call_id,
            outcome,
            verifier_sub,
        )
        return merged

    def expire_due_calls(self, *, now: Any = None, limit: int = 200) -> list[str]:
        """Expire scheduled calls past their expiry window (deterministic ``now``)."""
        ref_now = _resolve_now(now)
        cutoff_seconds = max(0, int(S.kyc_liveness_call_expiry_seconds))
        expired: list[str] = []
        for item in self.list_by_status(STATUS_SCHEDULED, limit=limit):
            sched = _coerce_int(item.get("scheduled_at"))
            if sched and ref_now >= sched + cutoff_seconds:
                call_id = str(item.get("call_id") or "")
                self._apply_update(call_id, {"status": STATUS_EXPIRED, "updated_at": ref_now})
                expired.append(call_id)
        return expired

    # -- internals ---------------------------------------------------------

    def _feed_case_result(self, *, case_id: str, call: dict[str, Any]) -> None:
        """Mirror the call result onto the KYC case ``verification_call`` field so
        the risk-scoring engine (which reads ``case.verification_call.result``)
        picks it up. Best-effort + import-safe; never raises into the caller."""
        if not case_id:
            return
        try:
            existing = T.kyc_cases.get_item(
                Key={"pk": f"KYC#{case_id}", "sk": "META"}
            ).get("Item")
        except Exception:  # pragma: no cover - defensive
            existing = None
        if not existing:
            return

        verification_call = {
            "call_id": call.get("call_id"),
            "status": call.get("status"),
            "result": call.get("result"),
            "result_notes": call.get("result_notes"),
            "result_set_at": call.get("result_set_at"),
            "recording_ref": call.get("recording_ref"),
            "verifier_sub": call.get("verifier_sub"),
            "scheduled_at": call.get("scheduled_at"),
        }
        try:
            T.kyc_cases.update_item(
                Key={"pk": f"KYC#{case_id}", "sk": "META"},
                UpdateExpression="SET verification_call = :vc, updated_at = :ts",
                ExpressionAttributeValues={
                    ":vc": verification_call,
                    ":ts": _coerce_int(call.get("result_set_at")) or now_ts(),
                },
            )
        except Exception:  # pragma: no cover - defensive
            logger.warning("kyc.liveness_call.case_feed_failed case_id=%s", case_id)
            return

        # Recompute the risk score (lazy import keeps module import-safe).
        try:
            from app.services.kyc_risk_scoring import KycRiskScoringService

            KycRiskScoringService().compute_score(
                case_id=case_id,
                user_sub=str(existing.get("user_sub") or ""),
                trigger="verification_call",
            )
        except Exception:  # pragma: no cover - best effort
            logger.warning("kyc.liveness_call.risk_rescore_failed case_id=%s", case_id)

    def _apply_update(self, call_id: str, update: dict[str, Any]) -> None:
        expr_names: dict[str, str] = {}
        expr_values: dict[str, Any] = {}
        sets: list[str] = []
        for i, (k, v) in enumerate(update.items()):
            nk = f"#k{i}"
            vk = f":v{i}"
            expr_names[nk] = k
            expr_values[vk] = v
            sets.append(f"{nk} = {vk}")
        self._table.update_item(
            Key={"call_id": call_id},
            UpdateExpression="SET " + ", ".join(sets),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )


STORE = KycLivenessCallStore()


def _join_url(item: dict[str, Any], *, now: Any = None) -> str | None:
    """Return the join URL when within the active join window, else None."""
    status = str(item.get("status") or "")
    if status not in (STATUS_SCHEDULED, STATUS_IN_PROGRESS):
        return None
    ref_now = _resolve_now(now)
    sched = _coerce_int(item.get("scheduled_at"))
    window = max(0, int(S.kyc_liveness_call_join_window_seconds))
    if status == STATUS_IN_PROGRESS or (sched and ref_now >= sched - window):
        return f"/call/{item.get('call_id')}"
    return None


def public_call_view(item: dict[str, Any], *, include_verifier: bool = True, now: Any = None) -> dict[str, Any]:
    """Shape a stored item into the full (verifier/admin) API response fields."""
    out: dict[str, Any] = {
        "call_id": item.get("call_id"),
        "case_id": item.get("case_id"),
        "user_sub": item.get("user_sub"),
        "status": item.get("status"),
        "scheduled_at": _coerce_int(item.get("scheduled_at")),
        "duration_minutes": _coerce_int(item.get("duration_minutes")),
        "note": item.get("note"),
        "result": item.get("result"),
        "result_notes": item.get("result_notes"),
        "result_set_at": _coerce_int(item.get("result_set_at")) or None,
        "recording_ref": item.get("recording_ref"),
        "started_at": _coerce_int(item.get("started_at")) or None,
        "join_url": _join_url(item, now=now),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
    }
    if include_verifier:
        verifier = item.get("verifier_sub")
        out["verifier_sub"] = None if verifier == "_unassigned" else verifier
    return out


def owner_call_view(item: dict[str, Any], *, now: Any = None) -> dict[str, Any]:
    """Owner-facing view: omits internal verifier identity, keeps result/status."""
    return {
        "call_id": item.get("call_id"),
        "case_id": item.get("case_id"),
        "status": item.get("status"),
        "scheduled_at": _coerce_int(item.get("scheduled_at")),
        "duration_minutes": _coerce_int(item.get("duration_minutes")),
        "result": item.get("result"),
        "join_url": _join_url(item, now=now),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
    }


# -- background expiry task (GAP-0249 / KYC-003) ---------------------------

_EXPIRY_INTERVAL_SECONDS = 60  # run every minute


async def kyc_liveness_expiry_loop(interval_seconds: int = _EXPIRY_INTERVAL_SECONDS) -> None:
    """Every ``interval_seconds``: expire scheduled liveness calls past their
    window so missed calls don't remain ``scheduled`` forever (which blocks
    re-scheduling and grows the ByStatus GSI). Never raises out of the loop."""
    import asyncio

    while True:
        try:
            expired = STORE.expire_due_calls()
            if expired:
                logger.info(
                    "kyc.liveness_call.expiry_loop.expired count=%d call_ids=%s",
                    len(expired),
                    expired[:10],
                )
        except Exception:  # pragma: no cover - defensive
            logger.exception("kyc.liveness_call.expiry_loop.error")
        await asyncio.sleep(max(5, int(interval_seconds)))


def start_kyc_liveness_expiry_task() -> None:
    """Register the KYC liveness-call expiry background task at app startup."""
    import asyncio

    if S.kyc_liveness_call_enabled:
        asyncio.ensure_future(kyc_liveness_expiry_loop())
        logger.info("KYC liveness-call expiry task started")
