from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr

from app.core.tables import T
from app.services.subscription_entitlement_templates import (
    map_plan_to_entitlement_template,
    map_subscription_state_to_entitlement,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stable_entitlement_id(subscription_id: str, period_start: Any) -> str:
    token = f"sub_backfill:{subscription_id}:{period_start}"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]


def _owner_fields(product_type: str) -> Dict[str, str]:
    if product_type == "api_package":
        return {"owner_team": "api", "owner_contact": "api-oncall"}
    if product_type == "internal_api_package":
        return {"owner_team": "messaging_filemanager", "owner_contact": "internal-api-oncall"}
    return {"owner_team": "billing", "owner_contact": "billing-oncall"}


def build_entitlement_from_subscription(
    *,
    subscription: Dict[str, Any],
    plan: Dict[str, Any],
    batch_id: str,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    template = map_plan_to_entitlement_template(plan, now=now)
    mapped = map_subscription_state_to_entitlement(subscription, template, now=now)
    ent_id = _stable_entitlement_id(str(subscription.get("subscription_id") or ""), subscription.get("current_period_start") or mapped.get("starts_at"))

    scope = dict(mapped.get("scope") or {})
    sub_scope = dict(scope.get("subscription") or {})
    sub_scope["subscription_id"] = subscription.get("subscription_id")
    sub_scope["invoice_anchor"] = subscription.get("current_period_start")
    scope["subscription"] = sub_scope

    return {
        "user_id": str(subscription.get("subscriber_id") or ""),
        "entitlement_id": ent_id,
        "sku": str(template.get("sku") or f"subscription_plan:{subscription.get('plan_id') or 'unknown'}"),
        "product_type": str(template.get("product_type") or "internal_api_package"),
        "status": str(mapped.get("status") or "pending_payment"),
        "starts_at": mapped.get("starts_at"),
        "ends_at": mapped.get("ends_at"),
        "scope": scope,
        "usage_limit": int((scope.get("limits") or {}).get("monthly_call_limit") or 0),
        "usage_consumed": 0,
        "created_at": (_utc_now()).isoformat(),
        "updated_at": (_utc_now()).isoformat(),
        "created_by": "subscription_backfill",
        "backfill_batch_id": batch_id,
    }


def _index_entitlements(existing: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for ent in existing:
        sub_id = str((((ent.get("scope") or {}).get("subscription") or {}).get("subscription_id") or "")).strip()
        if sub_id:
            idx[sub_id] = ent
    return idx


def plan_subscription_entitlement_backfill(
    *,
    subscriptions: List[Dict[str, Any]],
    plans_by_id: Dict[str, Dict[str, Any]],
    existing_entitlements: List[Dict[str, Any]],
    batch_id: str,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    now = now or _utc_now()
    existing_idx = _index_entitlements(existing_entitlements)
    drifts: List[Dict[str, Any]] = []
    operations: List[Dict[str, Any]] = []

    for sub in subscriptions:
        status = str(sub.get("status") or "").lower()
        if status not in {"active", "trialing"}:
            continue
        sub_id = str(sub.get("subscription_id") or "")
        plan = plans_by_id.get(str(sub.get("plan_id") or ""), {})
        desired = build_entitlement_from_subscription(subscription=sub, plan=plan, batch_id=batch_id, now=now)
        owner = _owner_fields(desired["product_type"])

        current = existing_idx.get(sub_id)
        if not current:
            drifts.append(
                {
                    "subscription_id": sub_id,
                    "entitlement_id": desired["entitlement_id"],
                    "drift_type": "missing_entitlement",
                    "severity": "high",
                    "recommended_action": "create_entitlement",
                    **owner,
                }
            )
            operations.append({"op": "upsert", "item": desired})
            continue

        current_status = str(current.get("status") or "")
        if current_status != desired["status"] or str(current.get("ends_at") or "") != str(desired.get("ends_at") or ""):
            drifts.append(
                {
                    "subscription_id": sub_id,
                    "entitlement_id": desired["entitlement_id"],
                    "drift_type": "state_or_window_mismatch",
                    "severity": "medium",
                    "recommended_action": "update_entitlement",
                    **owner,
                }
            )
            operations.append({"op": "upsert", "item": {**current, **desired}})

    return {
        "batch_id": batch_id,
        "generated_at": now.isoformat(),
        "subscription_count": len(subscriptions),
        "drift_count": len(drifts),
        "operations_count": len(operations),
        "drifts": drifts,
        "operations": operations,
    }


@dataclass
class BackfillApplyResult:
    batch_id: str
    applied: int
    skipped: int


def apply_subscription_entitlement_backfill(report: Dict[str, Any]) -> BackfillApplyResult:
    applied = 0
    skipped = 0
    for op in report.get("operations", []):
        if op.get("op") != "upsert":
            skipped += 1
            continue
        item = dict(op.get("item") or {})
        if not item.get("user_id") or not item.get("entitlement_id"):
            skipped += 1
            continue
        T.entitlements.put_item(Item=item)
        applied += 1
    return BackfillApplyResult(batch_id=str(report.get("batch_id") or ""), applied=applied, skipped=skipped)


def rollback_subscription_entitlement_backfill(batch_id: str) -> Dict[str, Any]:
    resp = T.entitlements.scan(FilterExpression=Attr("backfill_batch_id").eq(batch_id))
    items = list(resp.get("Items", []))
    revoked = 0
    for ent in items:
        if str(ent.get("status") or "") == "revoked":
            continue
        T.entitlements.update_item(
            Key={"user_id": ent.get("user_id"), "entitlement_id": ent.get("entitlement_id")},
            UpdateExpression="SET #st = :rev, rollback_batch_id = :b, updated_at = :ts",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":rev": "revoked",
                ":b": batch_id,
                ":ts": _utc_now().isoformat(),
            },
        )
        revoked += 1
    return {"batch_id": batch_id, "scanned": len(items), "revoked": revoked}
