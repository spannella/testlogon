"""CRM Workflow Rules service — WFL-002.

Authoritative data-layer service for persisting, retrieving, and mutating
CRM workflow rule definitions in DynamoDB. Pure data layer — no router,
no executor, no background worker.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from boto3.dynamodb.conditions import Attr, Key

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRIGGER_TYPES: list[str] = ["on_save", "on_schedule", "on_time_elapsed"]
TARGET_MODULES: list[str] = ["ticket", "contact", "order", "subscription", "lead"]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require_flag() -> None:
    if not S.crm_workflow_enabled:
        raise RuntimeError("crm_workflow is disabled")


def _rule_pk(rule_id: str) -> str:
    return f"RULE#{rule_id}"


def _rule_out(item: dict) -> dict:
    """Normalise a raw DDB item into a clean rule dict (int timestamps)."""
    return {
        "rule_id": item.get("rule_id", ""),
        "name": item.get("name", ""),
        "description": item.get("description", ""),
        "target_module": item.get("target_module", ""),
        "trigger_type": item.get("trigger_type", ""),
        "trigger_config": item.get("trigger_config") or {},
        "conditions": item.get("conditions") or [],
        "actions": item.get("actions") or [],
        "enabled": bool(item.get("enabled", True)),
        "created_by": item.get("created_by", ""),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "next_run_at": int(item["next_run_at"]) if "next_run_at" in item else None,
        "GSI_MODULE_PK": item.get("GSI_MODULE_PK", ""),
        "GSI_MODULE_SK": int(item.get("GSI_MODULE_SK", 0)),
    }


# ---------------------------------------------------------------------------
# CRUD functions
# ---------------------------------------------------------------------------

def create_rule(
    *,
    created_by: str,
    name: str,
    description: str = "",
    target_module: str,
    trigger_type: str,
    trigger_config: dict | None = None,
    conditions: list[dict] | None = None,
    actions: list[dict] | None = None,
    enabled: bool = True,
) -> dict:
    """Create a new workflow rule. Returns the created rule dict."""
    _require_flag()
    if trigger_config is None:
        trigger_config = {}
    if conditions is None:
        conditions = []
    if actions is None:
        actions = []

    if target_module not in TARGET_MODULES:
        raise ValueError(f"invalid_target_module: {target_module!r}")
    if trigger_type not in TRIGGER_TYPES:
        raise ValueError(f"invalid_trigger_type: {trigger_type!r}")
    if len(conditions) > S.crm_workflow_max_conditions_per_rule:
        raise OverflowError(
            f"Too many conditions: {len(conditions)} > {S.crm_workflow_max_conditions_per_rule}"
        )
    if len(actions) > S.crm_workflow_max_actions_per_rule:
        raise OverflowError(
            f"Too many actions: {len(actions)} > {S.crm_workflow_max_actions_per_rule}"
        )

    rule_id = "wfl_" + uuid.uuid4().hex[:12]
    ts = now_ts()
    item: dict[str, Any] = {
        "pk": _rule_pk(rule_id),
        "sk": "META",
        "rule_id": rule_id,
        "name": name,
        "description": description,
        "target_module": target_module,
        "trigger_type": trigger_type,
        "trigger_config": trigger_config,
        "conditions": conditions,
        "actions": actions,
        "enabled": enabled,
        "created_by": created_by,
        "created_at": ts,
        "updated_at": ts,
        "GSI_MODULE_PK": f"MODULE#{target_module}",
        "GSI_MODULE_SK": ts,
    }
    T.crm_workflow_rules.put_item(Item=item)

    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_workflow_rule.created",
            created_by,
            rule_id=rule_id,
            name=name,
            target_module=target_module,
        )
    except Exception:
        logger.warning("crm_workflow_rule: audit_event failed on create", exc_info=True)

    return get_rule(rule_id)  # type: ignore[return-value]


def get_rule(rule_id: str) -> dict | None:
    """Return the rule dict or None if not found."""
    resp = T.crm_workflow_rules.get_item(
        Key={"pk": _rule_pk(rule_id), "sk": "META"}
    )
    item = resp.get("Item")
    if not item:
        return None
    return _rule_out(item)


def list_rules(
    *,
    target_module: str | None = None,
    enabled_only: bool = False,
    limit: int = 25,
    cursor: str | None = None,
) -> dict:
    """List rules with optional module filter and pagination.

    Returns {"rules": [...], "cursor": str | None}.
    """
    _require_flag()

    exclusive_start = decode_cursor(cursor)
    kwargs: dict[str, Any] = {"Limit": limit}
    if exclusive_start:
        kwargs["ExclusiveStartKey"] = exclusive_start
    if enabled_only:
        kwargs["FilterExpression"] = Attr("enabled").eq(True)

    if target_module is not None:
        kwargs["IndexName"] = "ByModule"
        kwargs["KeyConditionExpression"] = Key("GSI_MODULE_PK").eq(f"MODULE#{target_module}")
        kwargs["ScanIndexForward"] = True
        resp = T.crm_workflow_rules.query(**kwargs)
    else:
        resp = T.crm_workflow_rules.scan(**kwargs)

    items = [_rule_out(i) for i in resp.get("Items", []) if i.get("sk") == "META"]
    return {
        "rules": items,
        "cursor": encode_cursor(resp.get("LastEvaluatedKey")),
    }


def update_rule(
    rule_id: str,
    *,
    updated_by: str,
    name: str | None = None,
    description: str | None = None,
    trigger_config: dict | None = None,
    conditions: list[dict] | None = None,
    actions: list[dict] | None = None,
    enabled: bool | None = None,
) -> dict | None:
    """Partial update of a rule. Returns updated dict or None if not found."""
    _require_flag()
    existing = get_rule(rule_id)
    if existing is None:
        return None

    ts = now_ts()
    set_parts: list[str] = ["#updated_at = :updated_at"]
    names: dict[str, str] = {"#updated_at": "updated_at"}
    values: dict[str, Any] = {":updated_at": ts}

    if name is not None:
        set_parts.append("#name = :name")
        names["#name"] = "name"
        values[":name"] = name
    if description is not None:
        set_parts.append("#description = :description")
        names["#description"] = "description"
        values[":description"] = description
    if trigger_config is not None:
        set_parts.append("#trigger_config = :trigger_config")
        names["#trigger_config"] = "trigger_config"
        values[":trigger_config"] = trigger_config
    if conditions is not None:
        set_parts.append("#conditions = :conditions")
        names["#conditions"] = "conditions"
        values[":conditions"] = conditions
    if actions is not None:
        set_parts.append("#actions = :actions")
        names["#actions"] = "actions"
        values[":actions"] = actions
    if enabled is not None:
        set_parts.append("#enabled = :enabled")
        names["#enabled"] = "enabled"
        values[":enabled"] = enabled

    T.crm_workflow_rules.update_item(
        Key={"pk": _rule_pk(rule_id), "sk": "META"},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )

    changed = [k for k in ["name", "description", "trigger_config", "conditions", "actions", "enabled"]
               if locals()[k] is not None]
    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_workflow_rule.updated",
            updated_by,
            rule_id=rule_id,
            changed_fields=changed,
        )
    except Exception:
        logger.warning("crm_workflow_rule: audit_event failed on update", exc_info=True)

    return get_rule(rule_id)


def delete_rule(rule_id: str, *, deleted_by: str) -> bool:
    """Hard-delete the rule META row. Returns False if not found."""
    _require_flag()
    existing = get_rule(rule_id)
    if existing is None:
        return False

    T.crm_workflow_rules.delete_item(Key={"pk": _rule_pk(rule_id), "sk": "META"})

    try:
        from app.services.alerts import audit_event
        audit_event("crm_workflow_rule.deleted", deleted_by, rule_id=rule_id)
    except Exception:
        logger.warning("crm_workflow_rule: audit_event failed on delete", exc_info=True)

    return True


def enable_rule(rule_id: str, *, actor: str) -> dict | None:
    """Set enabled=True on the rule. Returns updated dict or None if not found."""
    _require_flag()
    existing = get_rule(rule_id)
    if existing is None:
        return None

    ts = now_ts()
    T.crm_workflow_rules.update_item(
        Key={"pk": _rule_pk(rule_id), "sk": "META"},
        UpdateExpression="SET #enabled = :enabled, #updated_at = :updated_at",
        ExpressionAttributeNames={"#enabled": "enabled", "#updated_at": "updated_at"},
        ExpressionAttributeValues={":enabled": True, ":updated_at": ts},
    )
    try:
        from app.services.alerts import audit_event
        audit_event("crm_workflow_rule.enabled", actor, rule_id=rule_id)
    except Exception:
        pass
    return get_rule(rule_id)


def disable_rule(rule_id: str, *, actor: str) -> dict | None:
    """Set enabled=False on the rule. Returns updated dict or None if not found."""
    _require_flag()
    existing = get_rule(rule_id)
    if existing is None:
        return None

    ts = now_ts()
    T.crm_workflow_rules.update_item(
        Key={"pk": _rule_pk(rule_id), "sk": "META"},
        UpdateExpression="SET #enabled = :enabled, #updated_at = :updated_at",
        ExpressionAttributeNames={"#enabled": "enabled", "#updated_at": "updated_at"},
        ExpressionAttributeValues={":enabled": False, ":updated_at": ts},
    )
    try:
        from app.services.alerts import audit_event
        audit_event("crm_workflow_rule.disabled", actor, rule_id=rule_id)
    except Exception:
        pass
    return get_rule(rule_id)


def list_rules_for_module(target_module: str) -> list[dict]:
    """Return all enabled on_save/on_schedule/on_time_elapsed rules for a module.

    Used internally by on-save hook and scheduler. Never raises.
    Returns [] when flag is off.
    """
    if not S.crm_workflow_enabled:
        return []
    try:
        items: list[dict] = []
        last_key: Any = None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": "ByModule",
                "KeyConditionExpression": Key("GSI_MODULE_PK").eq(f"MODULE#{target_module}"),
                "FilterExpression": Attr("enabled").eq(True),
                "ScanIndexForward": True,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.crm_workflow_rules.query(**kwargs)
            items.extend(
                _rule_out(i) for i in resp.get("Items", []) if i.get("sk") == "META"
            )
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return sorted(items, key=lambda r: r["created_at"])
    except Exception:
        logger.warning("crm_workflow: list_rules_for_module failed", exc_info=True)
        return []


def list_all_enabled_rules(*, trigger_type: str | None = None) -> list[dict]:
    """Return all enabled rules across all modules (used by scheduler).

    Optionally filter by trigger_type. Never raises; returns [] on error.
    """
    if not S.crm_workflow_enabled:
        return []
    try:
        items: list[dict] = []
        last_key: Any = None
        filter_expr = Attr("enabled").eq(True) & Attr("sk").eq("META")
        if trigger_type:
            filter_expr = filter_expr & Attr("trigger_type").eq(trigger_type)
        while True:
            kwargs: dict[str, Any] = {"FilterExpression": filter_expr}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.crm_workflow_rules.scan(**kwargs)
            for i in resp.get("Items", []):
                if i.get("sk") == "META" and i.get("pk", "").startswith("RULE#"):
                    items.append(_rule_out(i))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
        return items
    except Exception:
        logger.warning("crm_workflow: list_all_enabled_rules failed", exc_info=True)
        return []


def update_rule_next_run_at(rule_id: str, next_run_at: int) -> None:
    """Persist next_run_at on the rule META row (used by scheduler)."""
    try:
        T.crm_workflow_rules.update_item(
            Key={"pk": _rule_pk(rule_id), "sk": "META"},
            UpdateExpression="SET next_run_at = :nra",
            ExpressionAttributeValues={":nra": next_run_at},
        )
    except Exception:
        logger.warning("crm_workflow: update_rule_next_run_at failed", exc_info=True)
