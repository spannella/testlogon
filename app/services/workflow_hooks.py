"""CRM Workflow On-Save Hook — WFL-004.

Fire-and-forget hook that fires after any successful record write.
Evaluates on_save workflow rules and enqueues matched rules as
crm_workflow action items in T.scheduled_actions for async dispatch.

Never raises — all exceptions are caught so this cannot break the primary
write path. Returns the number of rules matched and enqueued.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from app.core.settings import S
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def fire_on_save_hook(
    *,
    module: str,
    record: dict[str, Any],
    event: str,  # "create" | "update"
) -> int:
    """Evaluate and enqueue on_save workflow rules for a saved record.

    Must be called AFTER the write commits. Returns the count of rules
    matched and enqueued. Returns 0 immediately when the flag is off.

    Never raises.
    """
    if not S.crm_workflow_enabled:
        return 0

    try:
        return _fire_on_save_hook_impl(module=module, record=record, event=event)
    except Exception as exc:
        logger.warning("crm_workflow on_save hook error: %s", exc, exc_info=True)
        return 0


def _fire_on_save_hook_impl(
    *,
    module: str,
    record: dict[str, Any],
    event: str,
) -> int:
    from app.services.workflow_rules import list_rules_for_module
    from app.services.workflow_condition_evaluator import evaluate_conditions
    from app.core.tables import T
    from app.services.alerts import audit_event

    rules = list_rules_for_module(module)

    # Filter to on_save rules that include this event type
    on_save_rules = [
        r for r in rules
        if r.get("trigger_type") == "on_save"
        and event in (r.get("trigger_config") or {}).get("events", [])
    ]

    if not on_save_rules:
        return 0

    # Resolve record_id
    if module == "ticket":
        record_id = record.get("ticket_id", "")
    elif module == "contact":
        record_id = record.get("contact_id", "")
    else:
        record_id = record.get("id", record.get("record_id", ""))

    owner_sub = record.get("owner_sub") or record.get("user_sub") or record.get("owner_id", "")

    enqueued = 0
    for rule in on_save_rules:
        try:
            matched, _details = evaluate_conditions(rule.get("conditions", []), record)
            if not matched:
                continue

            # Enqueue as crm_workflow action
            action_id = "sa_" + uuid.uuid4().hex
            # Bypass the min-lead-time guard by writing put_item directly
            scheduled_at = now_ts() + S.scheduled_actions_min_lead_time_seconds + 1
            now = now_ts()
            item: dict[str, Any] = {
                "pk": "USER#system",
                "sk": f"ACTION#{scheduled_at}#{action_id}",
                "action_id": action_id,
                "user_sub": "system",
                "action_type": "crm_workflow",
                "status": "pending",
                "scheduled_at": scheduled_at,
                "created_at": now,
                "updated_at": now,
                "title": f"WFL on_save: {rule.get('name', rule['rule_id'])}",
                "payload": {
                    "rule_id": rule["rule_id"],
                    "module": module,
                    "record_id": record_id,
                    "event": event,
                    "owner_sub": owner_sub,
                },
                "GSI_DUE_PK": "DUE",
                "GSI_DUE_SK": scheduled_at,
                "GSI_TYPE_PK": f"USER#system#TYPE#crm_workflow",
                "GSI_TYPE_SK": scheduled_at,
                "ttl_epoch": scheduled_at + S.scheduled_actions_ttl_days * 86400,
                "retry_count": 0,
                "max_retries": S.scheduled_actions_max_retries,
                "reminder_sent": False,
                "notify_before_seconds": 0,
            }
            T.scheduled_actions.put_item(Item=item)

            try:
                audit_event(
                    "crm_workflow.on_save_enqueued",
                    "system",
                    rule_id=rule["rule_id"],
                    module=module,
                    record_id=record_id,
                    event=event,
                )
            except Exception:
                pass

            enqueued += 1
        except Exception as exc:
            logger.warning(
                "crm_workflow on_save hook: failed for rule_id=%s: %s",
                rule.get("rule_id"),
                exc,
                exc_info=True,
            )

    return enqueued
