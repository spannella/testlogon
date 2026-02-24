from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional, Tuple

ErrorCode = Literal[
    "denied",
    "expired",
    "exhausted",
    "idempotency_conflict",
]


@dataclass(frozen=True)
class CheckAccessResponse:
    allowed: bool
    entitlement_id: Optional[str]
    reason_code: Optional[ErrorCode] = None
    message: Optional[str] = None


@dataclass(frozen=True)
class ConsumeUsageResponse:
    consumed: bool
    entitlement_id: Optional[str]
    usage_consumed: int
    usage_limit: int
    replayed: bool = False
    reason_code: Optional[ErrorCode] = None
    message: Optional[str] = None


@dataclass
class EntitlementGrant:
    entitlement_id: str
    subject: str
    status: Literal["pending_payment", "active", "expired", "revoked", "consumed"]
    starts_at: datetime
    ends_at: Optional[datetime]
    allowed_actions: set[str] = field(default_factory=set)
    scope: Dict[str, Any] = field(default_factory=dict)
    usage_limit: int = 0
    usage_consumed: int = 0


class EntitlementPolicyContract:
    """Shared policy contract for entitlement access checks and usage consumption.

    This in-memory implementation defines deterministic behavior for:
    - check_access(subject, action, resource)
    - consume_usage(subject, meter, amount, idempotency_key)
    """

    def __init__(self) -> None:
        self._grants: Dict[str, EntitlementGrant] = {}
        self._idempotency: Dict[str, Tuple[str, str, int, ConsumeUsageResponse]] = {}

    @staticmethod
    def _utc(value: datetime) -> datetime:
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def upsert_grant(self, grant: EntitlementGrant) -> None:
        grant.starts_at = self._utc(grant.starts_at)
        grant.ends_at = self._utc(grant.ends_at) if grant.ends_at else None
        self._grants[grant.entitlement_id] = grant

    def _scope_matches(self, grant_scope: Dict[str, Any], resource: Dict[str, Any]) -> bool:
        for key, expected in grant_scope.items():
            actual = resource.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    def _candidate_for_subject(self, subject: str) -> Optional[EntitlementGrant]:
        matches = [g for g in self._grants.values() if g.subject == subject]
        matches.sort(key=lambda x: x.entitlement_id)
        return matches[0] if matches else None

    def check_access(self, *, subject: str, action: str, resource: Dict[str, Any], now: Optional[datetime] = None) -> CheckAccessResponse:
        ts = self._utc(now or datetime.now(timezone.utc))
        grant = self._candidate_for_subject(subject)
        if grant is None:
            return CheckAccessResponse(allowed=False, entitlement_id=None, reason_code="denied", message="No entitlement for subject")
        if grant.status != "active":
            if grant.status == "expired" or (grant.ends_at is not None and ts >= grant.ends_at):
                return CheckAccessResponse(allowed=False, entitlement_id=grant.entitlement_id, reason_code="expired", message="Entitlement expired")
            return CheckAccessResponse(allowed=False, entitlement_id=grant.entitlement_id, reason_code="denied", message="Entitlement not active")
        if grant.ends_at is not None and ts >= grant.ends_at:
            return CheckAccessResponse(allowed=False, entitlement_id=grant.entitlement_id, reason_code="expired", message="Entitlement expired")
        if action not in grant.allowed_actions:
            return CheckAccessResponse(allowed=False, entitlement_id=grant.entitlement_id, reason_code="denied", message="Action denied by entitlement scope")
        if not self._scope_matches(grant.scope, resource):
            return CheckAccessResponse(allowed=False, entitlement_id=grant.entitlement_id, reason_code="denied", message="Resource denied by entitlement scope")
        if grant.usage_limit > 0 and grant.usage_consumed >= grant.usage_limit:
            return CheckAccessResponse(allowed=False, entitlement_id=grant.entitlement_id, reason_code="exhausted", message="Entitlement usage exhausted")
        return CheckAccessResponse(allowed=True, entitlement_id=grant.entitlement_id)

    def consume_usage(
        self,
        *,
        subject: str,
        meter: str,
        amount: int,
        idempotency_key: str,
        now: Optional[datetime] = None,
    ) -> ConsumeUsageResponse:
        if amount <= 0:
            raise ValueError("amount must be > 0")
        grant = self._candidate_for_subject(subject)
        if grant is None:
            return ConsumeUsageResponse(consumed=False, entitlement_id=None, usage_consumed=0, usage_limit=0, reason_code="denied", message="No entitlement for subject")

        replay = self._idempotency.get(idempotency_key)
        if replay is not None:
            prior_entitlement_id, prior_meter, prior_amount, prior_resp = replay
            if prior_entitlement_id != grant.entitlement_id or prior_meter != meter or prior_amount != amount:
                return ConsumeUsageResponse(
                    consumed=False,
                    entitlement_id=grant.entitlement_id,
                    usage_consumed=grant.usage_consumed,
                    usage_limit=grant.usage_limit,
                    reason_code="idempotency_conflict",
                    message="idempotency_key replay with different payload",
                )
            return ConsumeUsageResponse(**{**prior_resp.__dict__, "replayed": True})

        access = self.check_access(subject=subject, action=meter, resource={}, now=now)
        if not access.allowed:
            return ConsumeUsageResponse(
                consumed=False,
                entitlement_id=access.entitlement_id,
                usage_consumed=grant.usage_consumed,
                usage_limit=grant.usage_limit,
                reason_code=access.reason_code,
                message=access.message,
            )

        new_total = grant.usage_consumed + amount
        if grant.usage_limit > 0 and new_total > grant.usage_limit:
            resp = ConsumeUsageResponse(
                consumed=False,
                entitlement_id=grant.entitlement_id,
                usage_consumed=grant.usage_consumed,
                usage_limit=grant.usage_limit,
                reason_code="exhausted",
                message="Usage amount exceeds remaining entitlement balance",
            )
            self._idempotency[idempotency_key] = (grant.entitlement_id, meter, amount, resp)
            return resp

        grant.usage_consumed = new_total
        resp = ConsumeUsageResponse(
            consumed=True,
            entitlement_id=grant.entitlement_id,
            usage_consumed=grant.usage_consumed,
            usage_limit=grant.usage_limit,
        )
        self._idempotency[idempotency_key] = (grant.entitlement_id, meter, amount, resp)
        return resp
