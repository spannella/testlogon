from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from app.core.settings import S


_DEFAULT_RETENTION_CLASS_DAYS: dict[str, int] = {
    "short": 30,
    "standard": 365,
    "regulatory": 2555,  # ~7 years
}

_DEFAULT_EVENT_RETENTION_CLASSES: dict[str, str] = {
    "message.sent": "regulatory",
    "message.edited": "regulatory",
    "message.deleted": "regulatory",
    "message.revoked": "regulatory",
    "attachment.added": "regulatory",
    "attachment.removed": "regulatory",
    "conversation.member_joined": "regulatory",
    "conversation.member_left": "regulatory",
    "conversation.role_changed": "regulatory",
    "report.submitted": "regulatory",
    "report.status_changed": "regulatory",
}


@dataclass(frozen=True)
class RetentionDecision:
    tenant_id: str
    product: str
    event_type: str
    retention_class: str
    retention_days: int
    event_ts: int
    retain_until_ts: int
    now_ts: int
    purge_eligible: bool
    legal_hold_active: bool
    decision_version: int
    policy_fingerprint: str
    evaluated_at_ts: int

    def as_audit_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "product": self.product,
            "event_type": self.event_type,
            "retention_class": self.retention_class,
            "retention_days": self.retention_days,
            "event_ts": self.event_ts,
            "retain_until_ts": self.retain_until_ts,
            "now_ts": self.now_ts,
            "purge_eligible": self.purge_eligible,
            "legal_hold_active": self.legal_hold_active,
            "decision_version": self.decision_version,
            "policy_fingerprint": self.policy_fingerprint,
            "evaluated_at_ts": self.evaluated_at_ts,
        }



def _parse_json_object(raw: str, *, fallback: Mapping[str, Any]) -> dict[str, Any]:
    text = (raw or "").strip()
    if not text:
        return dict(fallback)
    try:
        loaded = json.loads(text)
    except Exception:  # noqa: BLE001
        return dict(fallback)
    if not isinstance(loaded, dict):
        return dict(fallback)
    return dict(loaded)



def _retention_class_days() -> dict[str, int]:
    configured = _parse_json_object(
        getattr(S, "messaging_archive_retention_class_days_json", ""),
        fallback=_DEFAULT_RETENTION_CLASS_DAYS,
    )
    out: dict[str, int] = {}
    for k, v in configured.items():
        key = str(k).strip().lower()
        if not key:
            continue
        try:
            days = int(v)
        except Exception:  # noqa: BLE001
            continue
        if days <= 0:
            continue
        out[key] = days
    if not out:
        return dict(_DEFAULT_RETENTION_CLASS_DAYS)
    return out



def _event_retention_classes() -> dict[str, str]:
    configured = _parse_json_object(
        getattr(S, "messaging_archive_retention_event_class_overrides_json", ""),
        fallback=_DEFAULT_EVENT_RETENTION_CLASSES,
    )
    out = dict(_DEFAULT_EVENT_RETENTION_CLASSES)
    for k, v in configured.items():
        ek = str(k).strip()
        ev = str(v).strip().lower()
        if not ek or not ev:
            continue
        out[ek] = ev
    return out



def _tenant_retention_overrides() -> dict[str, str]:
    configured = _parse_json_object(
        getattr(S, "messaging_archive_retention_tenant_overrides_json", ""),
        fallback={},
    )
    out: dict[str, str] = {}
    for k, v in configured.items():
        tenant = str(k).strip()
        klass = str(v).strip().lower()
        if tenant and klass:
            out[tenant] = klass
    return out



def _default_retention_class() -> str:
    return str(getattr(S, "messaging_archive_retention_default_class", "regulatory")).strip().lower() or "regulatory"



def _policy_fingerprint(*, class_days: Mapping[str, int], event_classes: Mapping[str, str], tenant_overrides: Mapping[str, str]) -> str:
    canonical = json.dumps(
        {
            "decision_version": 1,
            "class_days": {k: int(v) for k, v in sorted(class_days.items())},
            "event_classes": {k: event_classes[k] for k in sorted(event_classes.keys())},
            "tenant_overrides": {k: tenant_overrides[k] for k in sorted(tenant_overrides.keys())},
            "default_class": _default_retention_class(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()



def evaluate_archive_retention_decision(
    *,
    tenant_id: str,
    event_type: str,
    event_ts: int,
    now_ts: int,
    product: str = "messaging",
    explicit_retention_class: str | None = None,
    legal_hold_active: bool = False,
) -> RetentionDecision:
    class_days = _retention_class_days()
    event_classes = _event_retention_classes()
    tenant_overrides = _tenant_retention_overrides()

    retention_class = (
        (explicit_retention_class or "").strip().lower()
        or tenant_overrides.get(tenant_id)
        or event_classes.get(event_type)
        or _default_retention_class()
    )
    if retention_class not in class_days:
        retention_class = _default_retention_class()
        if retention_class not in class_days:
            retention_class = "regulatory" if "regulatory" in class_days else sorted(class_days.keys())[0]

    retention_days = int(class_days[retention_class])
    retain_until_ts = int(event_ts) + retention_days * 86400
    purge_eligible = (int(now_ts) >= retain_until_ts) and (not bool(legal_hold_active))

    return RetentionDecision(
        tenant_id=tenant_id,
        product=product,
        event_type=event_type,
        retention_class=retention_class,
        retention_days=retention_days,
        event_ts=int(event_ts),
        retain_until_ts=retain_until_ts,
        now_ts=int(now_ts),
        purge_eligible=purge_eligible,
        legal_hold_active=bool(legal_hold_active),
        decision_version=1,
        policy_fingerprint=_policy_fingerprint(
            class_days=class_days,
            event_classes=event_classes,
            tenant_overrides=tenant_overrides,
        ),
        evaluated_at_ts=int(now_ts),
    )



def evaluate_archive_purge_eligibility(
    *,
    tenant_id: str,
    event_type: str,
    event_ts: int,
    now_ts: int,
    explicit_retention_class: str | None = None,
    legal_hold_active: bool = False,
) -> bool:
    decision = evaluate_archive_retention_decision(
        tenant_id=tenant_id,
        event_type=event_type,
        event_ts=event_ts,
        now_ts=now_ts,
        explicit_retention_class=explicit_retention_class,
        legal_hold_active=legal_hold_active,
    )
    return decision.purge_eligible



def format_retain_until_iso(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")
