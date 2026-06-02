"""KYC-019 — Case Assignment & Workload Management.

Net-new service that layers assignment, SLA enforcement, escalation, and
workload visibility on top of the existing KYC case store
(``app/services/kyc_cases.py``). It READS the admin queue / case items and
WRITES assignment + SLA metadata back onto the case ``review`` sub-object; it
does not rewrite the queue itself.

Storage (single-table design on the existing ``kyc_cases`` table, keyed by the
table's ``pk``/``sk``):

  Admin availability   PK ``ADMIN#{sub}``        SK ``AVAILABILITY``
  SLA config           PK ``CONFIG``             SK ``SLA#{tier}``
  Assignment audit log PK ``AUDIT#ASSIGN#{cid}`` SK ``{ts}#{event_id}``

Case items keep ``review.assigned_admin_sub`` (existing field), plus the new
``review.assigned_at``, ``review.sla_due_at`` and ``review.escalation_level``.

Tier vocabulary: cases use the queue's risk model (low / medium / high derived
from ``intake_profile``); these map to the ticket's SLA tiers tier_1 / tier_2 /
tier_3 respectively.
"""
from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("app.kyc.assignment")

# SLA tiers used by this feature.
SLA_TIERS: tuple[str, ...] = ("tier_1", "tier_2", "tier_3")

# Map the queue's coarse risk band (from intake_profile) to an SLA tier.
_RISK_BAND_TO_TIER: dict[str, str] = {
    "low": "tier_1",
    "medium": "tier_2",
    "high": "tier_3",
}

# Default SLA config (target hours + warning %) seeded on first read.
_DEFAULT_SLA: dict[str, dict[str, int]] = {
    "tier_1": {"target_hours": 24, "warning_pct": 75, "escalation_pct": 100},
    "tier_2": {"target_hours": 48, "warning_pct": 75, "escalation_pct": 100},
    "tier_3": {"target_hours": 120, "warning_pct": 80, "escalation_pct": 100},
}

# Escalation chain — index == escalation_level reached AFTER escalating.
_MAX_ESCALATION_LEVEL = 3


def _admin_pk(admin_sub: str) -> str:
    return f"ADMIN#{admin_sub}"


def _audit_pk(case_id: str) -> str:
    return f"AUDIT#ASSIGN#{case_id}"


def _sla_sk(tier: str) -> str:
    return f"SLA#{tier}"


def risk_band_for_case(case: dict[str, Any]) -> str:
    """Mirror of kyc_cases.list_admin_queue's ``_risk`` helper."""
    intake = str(case.get("intake_profile") or "").strip().lower()
    if intake in {"enhanced", "high_risk"}:
        return "high"
    if intake in {"standard", "medium_risk"}:
        return "medium"
    return "low"


def tier_for_case(case: dict[str, Any]) -> str:
    return _RISK_BAND_TO_TIER.get(risk_band_for_case(case), "tier_1")


@dataclass
class AdminAvailability:
    admin_sub: str
    on_duty: bool = False
    current_case_count: int = 0
    avg_processing_hours: float = 0.0
    expertise_tiers: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    seniority_level: int = 0
    max_cases: int = 20
    last_assigned_at: int | None = None
    updated_at: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "admin_sub": self.admin_sub,
            "on_duty": self.on_duty,
            "current_case_count": self.current_case_count,
            "avg_processing_hours": round(float(self.avg_processing_hours), 2),
            "expertise_tiers": list(self.expertise_tiers),
            "languages": list(self.languages),
            "seniority_level": self.seniority_level,
            "max_cases": self.max_cases,
            "last_assigned_at": self.last_assigned_at,
            "updated_at": self.updated_at,
        }


class KycCaseAssignmentError(ValueError):
    """Raised for assignment validation failures (mapped to HTTP by router)."""

    def __init__(self, code: str, *, status_code: int = 400, message: str | None = None):
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.message = message or code


@dataclass
class KycCaseAssignmentService:
    _table: Any = field(default=T.kyc_cases)

    # ── case lookup helpers ─────────────────────────────────────────

    def _case_key(self, case_id: str) -> dict[str, str]:
        return {"pk": f"KYC#{case_id}", "sk": "META"}

    def _get_case(self, case_id: str) -> dict[str, Any] | None:
        return self._table.get_item(Key=self._case_key(case_id)).get("Item")

    def _scan_active_cases(self) -> list[dict[str, Any]]:
        """All cases in actively-reviewed statuses, looping LastEvaluatedKey."""
        statuses = ("submitted", "under_review", "needs_more_info")
        out: list[dict[str, Any]] = []
        for status in statuses:
            ekey: dict[str, Any] | None = None
            while True:
                kwargs: dict[str, Any] = {
                    "IndexName": S.kyc_cases_status_index_name,
                    "KeyConditionExpression": "gsi_status_pk = :pk",
                    "ExpressionAttributeValues": {":pk": f"STATUS#{status}"},
                }
                if ekey:
                    kwargs["ExclusiveStartKey"] = ekey
                resp = self._table.query(**kwargs)
                out.extend(
                    row for row in resp.get("Items", []) if row.get("entity_type") == "kyc_case"
                )
                ekey = resp.get("LastEvaluatedKey")
                if not ekey:
                    break
        return out

    # ── admin availability ──────────────────────────────────────────

    def _scan_availability_items(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        ekey: dict[str, Any] | None = None
        while True:
            kwargs: dict[str, Any] = {
                "FilterExpression": "begins_with(pk, :p) AND sk = :s",
                "ExpressionAttributeValues": {":p": "ADMIN#", ":s": "AVAILABILITY"},
            }
            if ekey:
                kwargs["ExclusiveStartKey"] = ekey
            resp = self._table.scan(**kwargs)
            out.extend(resp.get("Items", []))
            ekey = resp.get("LastEvaluatedKey")
            if not ekey:
                break
        return out

    def _item_to_availability(self, item: dict[str, Any], *, case_count: int = 0) -> AdminAvailability:
        return AdminAvailability(
            admin_sub=str(item.get("admin_sub") or str(item.get("pk") or "").removeprefix("ADMIN#")),
            on_duty=bool(item.get("on_duty", False)),
            current_case_count=case_count,
            avg_processing_hours=float(item.get("avg_processing_hours") or 0.0),
            expertise_tiers=[str(t) for t in (item.get("expertise_tiers") or [])],
            languages=[str(l) for l in (item.get("languages") or [])],
            seniority_level=int(item.get("seniority_level") or 0),
            max_cases=int(item.get("max_cases") or S.kyc_assignment_default_max_cases),
            last_assigned_at=(int(item["last_assigned_at"]) if item.get("last_assigned_at") is not None else None),
            updated_at=(int(item["updated_at"]) if item.get("updated_at") is not None else None),
        )

    def get_admin_availability(self, admin_sub: str) -> AdminAvailability:
        item = self._table.get_item(Key={"pk": _admin_pk(admin_sub), "sk": "AVAILABILITY"}).get("Item")
        counts = self._active_case_counts()
        if not item:
            return AdminAvailability(
                admin_sub=admin_sub,
                on_duty=False,
                current_case_count=counts.get(admin_sub, 0),
                max_cases=S.kyc_assignment_default_max_cases,
            )
        return self._item_to_availability(item, case_count=counts.get(admin_sub, 0))

    def set_admin_availability(
        self,
        *,
        admin_sub: str,
        on_duty: bool,
        expertise_tiers: list[str] | None = None,
        languages: list[str] | None = None,
        max_cases: int | None = None,
        seniority_level: int | None = None,
    ) -> AdminAvailability:
        existing = self._table.get_item(Key={"pk": _admin_pk(admin_sub), "sk": "AVAILABILITY"}).get("Item") or {}
        ts = now_ts()
        item = {
            "pk": _admin_pk(admin_sub),
            "sk": "AVAILABILITY",
            "entity_type": "kyc_admin_availability",
            "admin_sub": admin_sub,
            "on_duty": bool(on_duty),
            "expertise_tiers": [str(t) for t in (expertise_tiers if expertise_tiers is not None else existing.get("expertise_tiers") or [])],
            "languages": [str(l) for l in (languages if languages is not None else existing.get("languages") or [])],
            "max_cases": int(max_cases if max_cases is not None else existing.get("max_cases") or S.kyc_assignment_default_max_cases),
            "seniority_level": int(seniority_level if seniority_level is not None else existing.get("seniority_level") or 0),
            "avg_processing_hours": Decimal(str(round(float(existing.get("avg_processing_hours") or 0.0), 2))),
            "last_assigned_at": existing.get("last_assigned_at"),
            "updated_at": ts,
        }
        if item["last_assigned_at"] is None:
            item.pop("last_assigned_at")
        self._table.put_item(Item=item)
        counts = self._active_case_counts()
        return self._item_to_availability(item, case_count=counts.get(admin_sub, 0))

    # ── workload aggregation ────────────────────────────────────────

    def _active_case_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for case in self._scan_active_cases():
            assigned = str((case.get("review") or {}).get("assigned_admin_sub") or "").strip()
            if assigned:
                counts[assigned] = counts.get(assigned, 0) + 1
        return counts

    def list_admin_workloads(self) -> list[AdminAvailability]:
        counts = self._active_case_counts()
        out: list[AdminAvailability] = []
        for item in self._scan_availability_items():
            sub = str(item.get("admin_sub") or str(item.get("pk") or "").removeprefix("ADMIN#"))
            out.append(self._item_to_availability(item, case_count=counts.get(sub, 0)))
        out.sort(key=lambda a: a.admin_sub)
        return out

    def workload_dashboard(self) -> dict[str, Any]:
        admins = self.list_admin_workloads()
        sla = self.get_sla_config()
        return {
            "admins": [a.to_dict() for a in admins],
            "sla_config": sla,
            "total_active_cases": sum(a.current_case_count for a in admins),
            "total_on_duty_admins": sum(1 for a in admins if a.on_duty),
        }

    # ── scoring + auto-assignment ───────────────────────────────────

    def _score_admin(self, admin: AdminAvailability, *, case_tier: str, language: str) -> float:
        max_cases = max(1, admin.max_cases)
        workload_score = max(0.0, 1.0 - (admin.current_case_count / max_cases))
        expertise_score = 1.0 if case_tier in admin.expertise_tiers else 0.3
        language_score = 1.0 if language in admin.languages else 0.5
        if admin.last_assigned_at is None:
            recency_score = 1.0
        else:
            hours_since = max(0.0, (now_ts() - admin.last_assigned_at) / 3600.0)
            recency_score = 1.0 - min(1.0, hours_since / 8.0)
            recency_score = max(0.0, recency_score)
        return (
            workload_score * 0.4
            + expertise_score * 0.3
            + language_score * 0.2
            + recency_score * 0.1
        )

    def _eligible_admins(self, exclude_sub: str | None = None) -> list[AdminAvailability]:
        out: list[AdminAvailability] = []
        for admin in self.list_admin_workloads():
            if exclude_sub and admin.admin_sub == exclude_sub:
                continue
            if not admin.on_duty:
                continue
            if admin.current_case_count >= max(1, admin.max_cases):
                continue
            out.append(admin)
        return out

    def auto_assign(
        self,
        *,
        case_id: str,
        applicant_language: str = "en",
        actor_sub: str = "SYSTEM",
    ) -> dict[str, Any]:
        case = self._get_case(case_id)
        if not case:
            raise KycCaseAssignmentError("case_not_found", status_code=404, message="KYC case not found")
        case_tier = tier_for_case(case)
        eligible = self._eligible_admins()
        if not eligible:
            return {
                "assigned_admin_sub": None,
                "score": 0.0,
                "tier": case_tier,
                "reason": "No eligible admins: all off-duty or at capacity",
            }
        scored = [
            (self._score_admin(a, case_tier=case_tier, language=applicant_language), a)
            for a in eligible
        ]
        scored.sort(key=lambda pair: (-pair[0], pair[1].admin_sub))
        best_score, best = scored[0]
        previous = str((case.get("review") or {}).get("assigned_admin_sub") or "").strip() or None
        reason = (
            f"Auto-assigned: score={best_score:.2f} (highest eligible of {len(eligible)})"
        )
        self._write_assignment(
            case=case,
            new_admin_sub=best.admin_sub,
            tier=case_tier,
            event_type="auto_assign",
            from_admin=previous,
            reason=reason,
            actor_sub=actor_sub,
            escalation_level=0,
        )
        logger.info(
            "kyc.assignment.auto_assigned case_id=%s admin_sub=%s score=%.2f tier=%s",
            case_id, best.admin_sub, best_score, case_tier,
        )
        return {
            "assigned_admin_sub": best.admin_sub,
            "score": round(best_score, 4),
            "tier": case_tier,
            "reason": reason,
        }

    def auto_assign_batch(self, *, case_ids: list[str], applicant_language: str = "en", actor_sub: str = "SYSTEM") -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for cid in case_ids:
            try:
                res = self.auto_assign(case_id=cid, applicant_language=applicant_language, actor_sub=actor_sub)
            except KycCaseAssignmentError as exc:
                res = {"assigned_admin_sub": None, "score": 0.0, "reason": exc.message, "error": exc.code}
            results.append({"kyc_case_id": cid, **res})
        return results

    # ── manual (re)assign / claim ───────────────────────────────────

    def manual_reassign(
        self,
        *,
        case_id: str,
        new_admin_sub: str,
        reason: str,
        actor_sub: str,
    ) -> dict[str, Any]:
        case = self._get_case(case_id)
        if not case:
            raise KycCaseAssignmentError("case_not_found", status_code=404, message="KYC case not found")
        new_admin_sub = str(new_admin_sub or "").strip()
        if not new_admin_sub:
            raise KycCaseAssignmentError("admin_not_found", status_code=404, message="Admin not found")
        avail = self._table.get_item(Key={"pk": _admin_pk(new_admin_sub), "sk": "AVAILABILITY"}).get("Item")
        if not avail:
            raise KycCaseAssignmentError("admin_not_found", status_code=404, message="Admin not found")
        previous = str((case.get("review") or {}).get("assigned_admin_sub") or "").strip() or None
        tier = tier_for_case(case)
        self._write_assignment(
            case=case,
            new_admin_sub=new_admin_sub,
            tier=tier,
            event_type="manual_reassign",
            from_admin=previous,
            reason=reason,
            actor_sub=actor_sub,
            escalation_level=int((case.get("review") or {}).get("escalation_level") or 0),
        )
        logger.info(
            "kyc.assignment.manual_reassigned case_id=%s from=%s to=%s actor=%s",
            case_id, previous, new_admin_sub, actor_sub,
        )
        return {
            "ok": True,
            "previous_admin_sub": previous,
            "new_admin_sub": new_admin_sub,
            "reason": reason,
        }

    def claim(self, *, case_id: str, admin_sub: str) -> dict[str, Any]:
        case = self._get_case(case_id)
        if not case:
            raise KycCaseAssignmentError("case_not_found", status_code=404, message="KYC case not found")
        previous = str((case.get("review") or {}).get("assigned_admin_sub") or "").strip() or None
        if previous and previous != admin_sub:
            raise KycCaseAssignmentError(
                "case_already_claimed", status_code=409, message="Case already assigned to another admin"
            )
        tier = tier_for_case(case)
        self._write_assignment(
            case=case,
            new_admin_sub=admin_sub,
            tier=tier,
            event_type="claim",
            from_admin=previous,
            reason=f"Claimed by {admin_sub}",
            actor_sub=admin_sub,
            escalation_level=int((case.get("review") or {}).get("escalation_level") or 0),
        )
        return {"ok": True, "assigned_admin_sub": admin_sub, "previous_admin_sub": previous}

    def unclaim(self, *, case_id: str, admin_sub: str) -> dict[str, Any]:
        case = self._get_case(case_id)
        if not case:
            raise KycCaseAssignmentError("case_not_found", status_code=404, message="KYC case not found")
        previous = str((case.get("review") or {}).get("assigned_admin_sub") or "").strip() or None
        self._write_assignment(
            case=case,
            new_admin_sub=None,
            tier=tier_for_case(case),
            event_type="unclaim",
            from_admin=previous,
            reason=f"Unclaimed by {admin_sub}",
            actor_sub=admin_sub,
            escalation_level=int((case.get("review") or {}).get("escalation_level") or 0),
        )
        return {"ok": True, "previous_admin_sub": previous}

    def list_my_assigned(self, *, admin_sub: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        now = now_ts()
        for case in self._scan_active_cases():
            review = case.get("review") or {}
            if str(review.get("assigned_admin_sub") or "").strip() != admin_sub:
                continue
            sla_due_at = review.get("sla_due_at")
            out.append(
                {
                    "kyc_case_id": str(case.get("kyc_case_id") or ""),
                    "status": str(case.get("status") or ""),
                    "tier": tier_for_case(case),
                    "assigned_at": (int(review["assigned_at"]) if review.get("assigned_at") is not None else None),
                    "sla_due_at": (int(sla_due_at) if sla_due_at is not None else None),
                    "overdue": bool(sla_due_at is not None and int(sla_due_at) < now),
                    "escalation_level": int(review.get("escalation_level") or 0),
                }
            )
        out.sort(key=lambda r: (r["sla_due_at"] is None, r["sla_due_at"] or 0))
        return out

    # ── assignment write + audit ────────────────────────────────────

    def _write_assignment(
        self,
        *,
        case: dict[str, Any],
        new_admin_sub: str | None,
        tier: str,
        event_type: str,
        from_admin: str | None,
        reason: str,
        actor_sub: str,
        escalation_level: int,
    ) -> dict[str, Any]:
        case_id = str(case.get("kyc_case_id") or "")
        ts = now_ts()
        review = dict(case.get("review") or {})
        review["assigned_admin_sub"] = new_admin_sub
        review["assigned_at"] = ts if new_admin_sub else None
        review["escalation_level"] = int(escalation_level)
        # SLA due-time anchored at assignment time using the tier target.
        sla = self.get_sla_config().get(tier, _DEFAULT_SLA["tier_1"])
        if new_admin_sub:
            review["sla_due_at"] = ts + int(sla["target_hours"]) * 3600
        else:
            review["sla_due_at"] = None
        self._table.update_item(
            Key=self._case_key(case_id),
            UpdateExpression="SET review = :review, updated_at = :u",
            ExpressionAttributeValues={":review": review, ":u": ts},
        )
        # Bump the assignee's last_assigned_at to spread future load.
        if new_admin_sub:
            try:
                self._table.update_item(
                    Key={"pk": _admin_pk(new_admin_sub), "sk": "AVAILABILITY"},
                    UpdateExpression="SET last_assigned_at = :t",
                    ExpressionAttributeValues={":t": ts},
                    ConditionExpression="attribute_exists(pk)",
                )
            except ClientError:
                pass
        self._write_audit_event(
            case_id=case_id,
            event_type=event_type,
            from_admin=from_admin,
            to_admin=new_admin_sub,
            reason=reason,
            actor_sub=actor_sub,
            escalation_level=escalation_level,
            ts=ts,
        )
        return review

    def _write_audit_event(
        self,
        *,
        case_id: str,
        event_type: str,
        from_admin: str | None,
        to_admin: str | None,
        reason: str,
        actor_sub: str,
        escalation_level: int | None,
        ts: int,
    ) -> None:
        event_id = uuid.uuid4().hex[:10]
        self._table.put_item(
            Item={
                "pk": _audit_pk(case_id),
                "sk": f"{ts:013d}#{event_id}",
                "entity_type": "kyc_assignment_audit",
                "kyc_case_id": case_id,
                "event_type": event_type,
                "from_admin": from_admin,
                "to_admin": to_admin,
                "reason": reason,
                "actor_sub": actor_sub,
                "escalation_level": escalation_level,
                "created_at": ts,
            }
        )

    def get_assignment_history(self, *, case_id: str) -> list[dict[str, Any]]:
        resp = self._table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": _audit_pk(case_id)},
            ScanIndexForward=False,
        )
        events: list[dict[str, Any]] = []
        for item in resp.get("Items", []):
            events.append(
                {
                    "event_type": str(item.get("event_type") or ""),
                    "from_admin": item.get("from_admin"),
                    "to_admin": item.get("to_admin"),
                    "reason": str(item.get("reason") or ""),
                    "actor_sub": item.get("actor_sub"),
                    "escalation_level": (int(item["escalation_level"]) if item.get("escalation_level") is not None else None),
                    "created_at": int(item.get("created_at") or 0),
                }
            )
        return events

    # ── SLA config ──────────────────────────────────────────────────

    def get_sla_config(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        resp = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :s)",
            ExpressionAttributeValues={":pk": "CONFIG", ":s": "SLA#"},
        )
        stored = {
            str(item.get("sk") or "").removeprefix("SLA#"): item
            for item in resp.get("Items", [])
        }
        for tier in SLA_TIERS:
            if tier in stored:
                item = stored[tier]
                out[tier] = {
                    "target_hours": int(item.get("target_hours") or _DEFAULT_SLA[tier]["target_hours"]),
                    "warning_pct": int(item.get("warning_pct") or _DEFAULT_SLA[tier]["warning_pct"]),
                    "escalation_pct": int(item.get("escalation_pct") or 100),
                }
            else:
                out[tier] = dict(_DEFAULT_SLA[tier])
        return out

    def update_sla_config(self, *, tier: str, target_hours: int, warning_pct: int, actor_sub: str) -> dict[str, Any]:
        if tier not in SLA_TIERS:
            raise KycCaseAssignmentError("invalid_tier", status_code=400, message=f"Tier '{tier}' is not recognized")
        ts = now_ts()
        item = {
            "pk": "CONFIG",
            "sk": _sla_sk(tier),
            "entity_type": "kyc_sla_config",
            "tier": tier,
            "target_hours": int(target_hours),
            "warning_pct": int(warning_pct),
            "escalation_pct": 100,
            "updated_at": ts,
            "updated_by": actor_sub,
        }
        self._table.put_item(Item=item)
        return {
            "tier": tier,
            "target_hours": int(target_hours),
            "warning_pct": int(warning_pct),
            "escalation_pct": 100,
            "updated_at": ts,
            "updated_by": actor_sub,
        }

    # ── SLA compliance + escalation ─────────────────────────────────

    def check_sla_compliance(self) -> list[dict[str, Any]]:
        """Return active cases whose SLA due-time has passed (breached)."""
        now = now_ts()
        breached: list[dict[str, Any]] = []
        for case in self._scan_active_cases():
            review = case.get("review") or {}
            assigned = str(review.get("assigned_admin_sub") or "").strip()
            sla_due_at = review.get("sla_due_at")
            if not assigned or sla_due_at is None:
                continue
            sla_due_at = int(sla_due_at)
            if sla_due_at >= now:
                continue
            hours_overdue = (now - sla_due_at) / 3600.0
            breached.append(
                {
                    "kyc_case_id": str(case.get("kyc_case_id") or ""),
                    "assigned_admin_sub": assigned,
                    "tier": tier_for_case(case),
                    "sla_due_at": sla_due_at,
                    "hours_overdue": round(hours_overdue, 2),
                    "escalation_level": int(review.get("escalation_level") or 0),
                }
            )
        breached.sort(key=lambda r: -r["hours_overdue"])
        return breached

    def escalate_case(self, *, case_id: str, current_level: int, reason: str) -> dict[str, Any]:
        case = self._get_case(case_id)
        if not case:
            raise KycCaseAssignmentError("case_not_found", status_code=404, message="KYC case not found")
        review = case.get("review") or {}
        previous = str(review.get("assigned_admin_sub") or "").strip() or None
        next_level = min(_MAX_ESCALATION_LEVEL, int(current_level) + 1)
        tier = tier_for_case(case)

        # Choose a more senior on-duty admin (seniority >= next_level if possible),
        # excluding the current assignee.
        candidates = [
            a for a in self._eligible_admins(exclude_sub=previous)
        ]
        senior = [a for a in candidates if a.seniority_level >= next_level]
        pool = senior or candidates
        pool.sort(key=lambda a: (-a.seniority_level, a.current_case_count, a.admin_sub))
        new_admin = pool[0].admin_sub if pool else previous

        ts = now_ts()
        new_review = dict(review)
        new_review["assigned_admin_sub"] = new_admin
        new_review["assigned_at"] = ts
        new_review["escalation_level"] = next_level
        sla = self.get_sla_config().get(tier, _DEFAULT_SLA["tier_1"])
        new_review["sla_due_at"] = ts + int(sla["target_hours"]) * 3600
        self._table.update_item(
            Key=self._case_key(case_id),
            UpdateExpression="SET review = :review, updated_at = :u",
            ExpressionAttributeValues={":review": new_review, ":u": ts},
        )
        if new_admin:
            try:
                self._table.update_item(
                    Key={"pk": _admin_pk(new_admin), "sk": "AVAILABILITY"},
                    UpdateExpression="SET last_assigned_at = :t",
                    ExpressionAttributeValues={":t": ts},
                    ConditionExpression="attribute_exists(pk)",
                )
            except ClientError:
                pass
        self._write_audit_event(
            case_id=case_id,
            event_type="escalation",
            from_admin=previous,
            to_admin=new_admin,
            reason=reason,
            actor_sub="SYSTEM",
            escalation_level=next_level,
            ts=ts,
        )
        logger.warning(
            "kyc.assignment.escalated case_id=%s from_level=%s to_level=%s from=%s to=%s",
            case_id, current_level, next_level, previous, new_admin,
        )
        return {
            "ok": True,
            "kyc_case_id": case_id,
            "escalation_level": next_level,
            "previous_admin_sub": previous,
            "new_admin_sub": new_admin,
            "reason": reason,
        }

    def run_sla_escalation_sweep(self) -> dict[str, Any]:
        """One pass of: detect breaches → escalate. Returns a summary."""
        breached = self.check_sla_compliance()
        escalated = 0
        for case in breached:
            try:
                self.escalate_case(
                    case_id=case["kyc_case_id"],
                    current_level=case.get("escalation_level", 0),
                    reason=f"SLA breached: {case['hours_overdue']:.1f}h overdue",
                )
                escalated += 1
            except Exception:  # pragma: no cover - defensive
                logger.exception("kyc.assignment.escalate_failed case_id=%s", case.get("kyc_case_id"))
        return {"checked": len(breached), "escalated": escalated}


# Module-level singleton for router + background task reuse.
ASSIGNMENT_SERVICE = KycCaseAssignmentService()


# ── Background SLA checker (registered from app/main.py at startup) ──


async def kyc_sla_checker_loop(interval_seconds: int = 300) -> None:
    """Every ``interval_seconds`` (5 min default): detect SLA breaches and
    escalate. Never raises out of the loop."""
    import asyncio

    while True:
        try:
            ASSIGNMENT_SERVICE.run_sla_escalation_sweep()
        except Exception:  # pragma: no cover - defensive
            logger.exception("kyc.assignment.sla_checker_error")
        await asyncio.sleep(max(5, int(interval_seconds)))


def start_kyc_sla_checker_task() -> None:
    """Register the KYC SLA checker background task at app startup."""
    import asyncio

    if S.kyc_assignment_enabled and S.kyc_sla_checker_enabled:
        asyncio.ensure_future(kyc_sla_checker_loop())
        logger.info("KYC SLA checker started")
