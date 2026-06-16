"""CRM Workflow Action Executor — WFL-006 + WFL-007.

Registered in unified_scheduler._EXECUTORS as "crm_workflow".
Executes matched workflow rules' action lists against target records.

Action types implemented:
  - modify_field  (WFL-006)
  - create_record (WFL-006)
  - send_email    (WFL-007)
  - drip_sequence (WFL-008 — dispatched from here; logic in workflow_drip_sequences.py)
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from app.core.settings import S
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ID helpers
# ---------------------------------------------------------------------------

def _new_run_id() -> str:
    return "run_" + uuid.uuid4().hex[:12]


# ---------------------------------------------------------------------------
# Top-level executor (registered in _EXECUTORS)
# ---------------------------------------------------------------------------

async def execute_crm_workflow_action(user_sub: str, payload: dict) -> None:
    """Entry point called by the unified scheduler for action_type='crm_workflow'."""
    if not S.crm_workflow_enabled:
        return

    from app.services.workflow_rules import get_rule
    from app.services.alerts import audit_event

    rule_id = payload.get("rule_id", "")
    module = payload.get("module", "")
    record_id = payload.get("record_id", "")
    trigger_type = payload.get("trigger_type", payload.get("event", "on_save"))

    rule = get_rule(rule_id)
    if not rule or not rule.get("enabled"):
        logger.info(
            "crm_workflow executor: rule not found or disabled rule_id=%s", rule_id
        )
        return

    run_id = _new_run_id()
    started_at = now_ts()
    actions_fired: list[dict] = []

    try:
        # Hydrate the record for action execution
        record = _fetch_record(module, record_id) or {}

        for action in rule.get("actions", []):
            result = await _execute_action(
                action, module=module, record_id=record_id, record=record
            )
            if isinstance(result, str):
                actions_fired.append({
                    "action_type": action.get("action_type", ""),
                    "result": result,
                })
            else:
                actions_fired.append(result)

        finished_at = now_ts()
        _write_run(
            rule_id=rule_id,
            run_id=run_id,
            module=module,
            record_id=record_id,
            trigger_type=trigger_type,
            outcome="matched",
            actions_fired=actions_fired,
            started_at=started_at,
            finished_at=finished_at,
        )
        try:
            audit_event(
                "crm_workflow.execute",
                "system",
                rule_id=rule_id,
                module=module,
                record_id=record_id,
            )
        except Exception:
            pass

    except Exception as exc:
        finished_at = now_ts()
        _write_run(
            rule_id=rule_id,
            run_id=run_id,
            module=module,
            record_id=record_id,
            trigger_type=trigger_type,
            outcome="error",
            actions_fired=actions_fired,
            started_at=started_at,
            finished_at=finished_at,
            error_message=str(exc),
        )
        raise  # Let unified scheduler apply retry logic


# ---------------------------------------------------------------------------
# Drip stage executor (registered in _EXECUTORS as "crm_workflow_drip_stage")
# ---------------------------------------------------------------------------

async def execute_drip_stage_action(user_sub: str, payload: dict) -> None:
    """Entry point for drip stage dispatch."""
    if not S.crm_workflow_enabled:
        return

    from app.services.workflow_drip_sequences import (
        get_enrolment,
        get_sequence,
        advance_enrolment,
        complete_enrolment,
    )
    from app.services.alerts import audit_event

    sequence_id = payload.get("sequence_id", "")
    stage_number = int(payload.get("stage_number", 1))
    module = payload.get("module", "")
    record_id = payload.get("record_id", "")
    template_id = payload.get("template_id", "")
    to_field = payload.get("to_field", "")
    enrolled_at = int(payload.get("enrolled_at", 0))

    enrolment = get_enrolment(sequence_id, module, record_id)
    if not enrolment or enrolment.get("stopped"):
        logger.info(
            "drip_stage: skipping stopped/missing enrolment seq=%s record=%s",
            sequence_id,
            record_id,
        )
        return

    record = _fetch_record(module, record_id)
    if record is None:
        logger.warning(
            "drip_stage: record not found module=%s record_id=%s", module, record_id
        )
        return

    # Send email using shared WFL-007 helper
    action_config = {"template_id": template_id, "to_field": to_field}
    result = _execute_send_email(
        {"action_type": "send_email", "config": action_config},
        module=module,
        record=record,
    )
    if result.get("result") == "skipped":
        logger.warning(
            "drip_stage: email skipped seq=%s stage=%d reason=%s",
            sequence_id,
            stage_number,
            result.get("skip_reason"),
        )

    _now = now_ts()
    try:
        audit_event(
            "crm_workflow.drip_stage_sent",
            "system",
            sequence_id=sequence_id,
            stage_number=stage_number,
            module=module,
            record_id=record_id,
            result=result.get("result"),
        )
    except Exception:
        pass

    advance_enrolment(sequence_id, module, record_id, stage_number=stage_number, now=_now)

    seq = get_sequence(sequence_id)
    if not seq:
        complete_enrolment(sequence_id, module, record_id, now=_now)
        return

    stages = sorted(seq.get("stages") or [], key=lambda s: int(s.get("stage_number", 0)))
    next_stages = [s for s in stages if int(s.get("stage_number", 0)) > stage_number]
    if next_stages:
        next_stage = next_stages[0]
        from app.services.workflow_drip_sequences import _schedule_drip_stage
        _schedule_drip_stage(seq, next_stage, module=module, record_id=record_id, enrolled_at=_now)
    else:
        complete_enrolment(sequence_id, module, record_id, now=_now)
        try:
            audit_event(
                "crm_workflow.drip_completed",
                "system",
                sequence_id=sequence_id,
                module=module,
                record_id=record_id,
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Action dispatcher
# ---------------------------------------------------------------------------

async def _execute_action(
    action: dict,
    *,
    module: str,
    record_id: str,
    record: dict,
) -> dict:
    """Dispatch a single action step. Returns an actions_fired entry dict."""
    action_type = action.get("action_type", "")
    config = action.get("config") or {}

    try:
        if action_type == "modify_field":
            result = _dispatch_modify_field(module, record_id, config)
            return {"action_type": action_type, "result": result}

        elif action_type == "create_record":
            result = _dispatch_create_record(config)
            return {"action_type": action_type, "result": result}

        elif action_type == "send_email":
            return _execute_send_email(action, module=module, record=record)

        elif action_type == "drip_sequence":
            result_dict = await _execute_drip_sequence(config, module=module, record_id=record_id)
            return {"action_type": action_type, **result_dict}

        else:
            logger.warning(
                "crm_workflow: unknown action_type=%r — skipping", action_type
            )
            return {"action_type": action_type, "result": "skipped", "reason": "unknown_action_type"}

    except Exception as exc:
        logger.warning(
            "crm_workflow _execute_action failed type=%s: %s", action_type, exc, exc_info=True
        )
        return {"action_type": action_type, "result": f"error:{exc}"}


# ---------------------------------------------------------------------------
# modify_field
# ---------------------------------------------------------------------------

def _dispatch_modify_field(module: str, record_id: str, config: dict) -> str:
    field = config.get("field", "")
    value = config.get("value")

    if module == "ticket":
        return _modify_field_ticket(record_id, field, value)
    elif module == "contact":
        owner_sub = config.get("owner_sub", "")
        return _modify_field_contact(owner_sub, record_id, field, value)
    return "skipped:unsupported_module"


def _modify_field_ticket(ticket_id: str, field: str, value: Any) -> str:
    from app.services.tickets import TicketStore, TicketStateError
    from app.core.tables import T
    from app.services.alerts import audit_event

    store = TicketStore(T.tickets)

    if field == "status":
        try:
            result = store.update_status(
                ticket_id=ticket_id, actor_sub="system", status=value or ""
            )
            if result is None:
                return "skipped:record_not_found"
        except (TicketStateError, Exception) as exc:
            return f"error:{exc}"
        try:
            audit_event(
                "crm_workflow.modify_field",
                "system",
                module="ticket",
                record_id=ticket_id,
                field=field,
                value=value,
            )
        except Exception:
            pass
        return "ok"

    elif field in ("assignee_sub", "assigned_to_sub"):
        if not value:
            return "skipped:empty_value"
        try:
            result = store.assign_ticket(
                ticket_id=ticket_id, actor_sub="system", assignee_sub=value
            )
            if result is None:
                return "skipped:record_not_found"
        except Exception as exc:
            return f"error:{exc}"
        try:
            audit_event(
                "crm_workflow.modify_field",
                "system",
                module="ticket",
                record_id=ticket_id,
                field=field,
                value=value,
            )
        except Exception:
            pass
        return "ok"

    elif field in ("priority", "subject", "title"):
        ddb_field = "subject" if field in ("title", "subject") else field
        try:
            T.tickets.update_item(
                Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
                UpdateExpression="SET #f = :v",
                ExpressionAttributeNames={"#f": ddb_field},
                ExpressionAttributeValues={":v": value},
            )
        except Exception as exc:
            return f"error:{exc}"
        try:
            audit_event(
                "crm_workflow.modify_field",
                "system",
                module="ticket",
                record_id=ticket_id,
                field=field,
                value=value,
            )
        except Exception:
            pass
        return "ok"

    return "skipped:unsupported_field"


def _modify_field_contact(owner_sub: str, contact_id: str, field: str, value: Any) -> str:
    from app.core.tables import T
    from app.services.alerts import audit_event

    if field == "is_favorite":
        bool_val = bool(value) if not isinstance(value, bool) else value
    elif field == "is_blocked":
        bool_val = bool(value) if not isinstance(value, bool) else value
    else:
        return "skipped:unsupported_contact_field"

    try:
        T.contacts.update_item(
            Key={"owner_id": owner_sub, "contact_id": contact_id},
            UpdateExpression="SET #f = :v",
            ExpressionAttributeNames={"#f": field},
            ExpressionAttributeValues={":v": bool_val},
            ConditionExpression="attribute_exists(owner_id)",
        )
    except Exception as exc:
        code = getattr(getattr(exc, "response", {}), "get", lambda k, d=None: d)(
            "Error", {}
        ).get("Code", "")
        if "ConditionalCheckFailed" in str(exc) or code == "ConditionalCheckFailedException":
            return "skipped:record_not_found"
        return f"error:{exc}"

    try:
        audit_event(
            "crm_workflow.modify_field",
            "system",
            module="contact",
            record_id=contact_id,
            field=field,
        )
    except Exception:
        pass
    return "ok"


# ---------------------------------------------------------------------------
# create_record
# ---------------------------------------------------------------------------

def _dispatch_create_record(config: dict) -> str:
    module = config.get("module", "ticket")
    fields = config.get("fields") or {}

    if module == "ticket":
        return _create_record_ticket(fields)
    return "skipped:unsupported_module"


def _create_record_ticket(fields: dict) -> str:
    from app.services.tickets import TicketStore
    from app.core.tables import T
    from app.services.alerts import audit_event

    subject = fields.get("subject") or fields.get("title") or ""
    if not subject:
        return "skipped:missing_subject"

    description = fields.get("description", "")
    space_id = fields.get("space_id") or None
    labels = fields.get("labels") or []

    store = TicketStore(T.tickets)
    try:
        new_ticket = store.create_ticket(
            owner_sub="system",
            subject=subject,
            description=description,
            space_id=space_id,
            labels=labels,
        )
    except Exception as exc:
        return f"error:{exc}"

    try:
        audit_event(
            "crm_workflow.create_record",
            "system",
            module="ticket",
            new_record_id=new_ticket.get("ticket_id", ""),
            triggered_by=fields.get("_triggered_by_record_id", ""),
        )
    except Exception:
        pass
    return f"ok:ticket_id={new_ticket.get('ticket_id', '')}"


# ---------------------------------------------------------------------------
# send_email (WFL-007)
# ---------------------------------------------------------------------------

def _execute_send_email(action: dict, *, module: str, record: dict) -> dict:
    """Execute a send_email action step.

    Returns an actions_fired entry dict with keys:
      action_type, result, skip_reason, template_id, to_address.
    Never raises.
    """
    config = action.get("config") or {}
    template_id = config.get("template_id", "")
    to_field = config.get("to_field", "")
    extra_vars = config.get("extra_vars") or {}

    def _skipped(reason: str, to_address: str | None = None) -> dict:
        return {
            "action_type": "send_email",
            "result": "skipped",
            "skip_reason": reason,
            "template_id": template_id,
            "to_address": to_address,
        }

    if not template_id or not to_field:
        return _skipped("bad_config")

    try:
        # 1. Resolve to_address
        to_address: str | None
        if to_field == "owner_sub":
            owner_sub = record.get("owner_sub") or record.get("user_sub")
            if not owner_sub:
                return _skipped("to_address_unresolvable")
            try:
                from app.services.profile import get_profile_identity
                identity = get_profile_identity(owner_sub)
                to_address = identity.get("email")
            except Exception:
                return _skipped("unexpected_error")
        else:
            to_address = record.get(to_field)

        if not to_address:
            return _skipped("to_address_unresolvable")

        # 2. Load and validate template
        from app.services.notification_templates import get_template, _render
        tpl = get_template(template_id)
        if tpl is None:
            return _skipped("template_not_found", to_address)
        if not tpl.get("active", True):
            return _skipped("template_inactive", to_address)
        if tpl.get("channel", "email") != "email":
            return _skipped("channel_mismatch", to_address)

        # 3. Build context and render
        context: dict[str, str] = {
            str(k): str(v) for k, v in record.items() if v is not None
        }
        context.update({str(k): str(v) for k, v in extra_vars.items()})

        rendered_subject, _ = _render(tpl.get("subject") or "", context)
        rendered_body, _ = _render(tpl.get("body") or "", context)

        # 4. Dispatch
        from app.services.alerts import send_alert_email, audit_event
        send_alert_email(
            to_emails=[to_address],
            subject=rendered_subject or "",
            body_text=rendered_body or "",
        )

        # 5. Audit
        try:
            audit_event(
                "crm_workflow.send_email",
                "system",
                template_id=template_id,
                module=module,
                record_id=record.get(f"{module}_id") or record.get("id", ""),
                to=to_address,
            )
        except Exception:
            pass

        return {
            "action_type": "send_email",
            "result": "sent",
            "skip_reason": None,
            "template_id": template_id,
            "to_address": to_address,
        }

    except Exception as exc:
        logger.warning("crm_workflow send_email unexpected error: %s", exc, exc_info=True)
        return _skipped("unexpected_error")


# ---------------------------------------------------------------------------
# drip_sequence (WFL-008)
# ---------------------------------------------------------------------------

async def _execute_drip_sequence(config: dict, *, module: str, record_id: str) -> dict:
    """Enrol a record in a drip sequence and schedule stage 1."""
    if not S.crm_workflow_enabled:
        return {"status": "skipped", "reason": "flag_off"}

    from app.services.workflow_drip_sequences import (
        get_sequence,
        enrol_record,
        _schedule_drip_stage,
    )
    from app.services.alerts import audit_event

    sequence_id = config.get("sequence_id", "")
    seq = get_sequence(sequence_id)
    if not seq:
        logger.warning("drip_sequence: sequence_id=%s not found", sequence_id)
        return {"status": "skipped", "reason": "sequence_not_found"}

    stages = sorted(
        seq.get("stages") or [], key=lambda s: int(s.get("stage_number", 0))
    )
    if not stages:
        return {"status": "skipped", "reason": "sequence_has_no_stages"}

    _now = now_ts()
    enrolment = enrol_record(sequence_id, module, record_id, enrolled_at=_now)

    if int(enrolment.get("current_stage", 0)) > 0:
        return {"status": "already_enrolled", "sequence_id": sequence_id}

    stage = stages[0]
    _schedule_drip_stage(seq, stage, module=module, record_id=record_id, enrolled_at=_now)

    try:
        audit_event(
            "crm_workflow.drip_enrolled",
            "system",
            sequence_id=sequence_id,
            module=module,
            record_id=record_id,
        )
    except Exception:
        pass

    return {
        "status": "enrolled",
        "sequence_id": sequence_id,
        "stage_scheduled": stage.get("stage_number"),
    }


# ---------------------------------------------------------------------------
# Run log writer
# ---------------------------------------------------------------------------

def _write_run(
    *,
    rule_id: str,
    run_id: str,
    module: str,
    record_id: str,
    trigger_type: str,
    outcome: str,
    actions_fired: list[dict],
    started_at: int,
    finished_at: int,
    error_message: str | None = None,
) -> None:
    """Write a run log row to T.crm_workflow_runs."""
    from app.core.tables import T

    item: dict[str, Any] = {
        "pk": f"RULE#{rule_id}",
        "sk": f"RUN#{started_at:010d}#{run_id}",
        "run_id": run_id,
        "rule_id": rule_id,
        "target_module": module,
        "record_id": record_id,
        "trigger_type": trigger_type,
        "outcome": outcome,
        "actions_fired": actions_fired,
        "started_at": started_at,
        "finished_at": finished_at,
        "GSI_RECORD_PK": f"{module}#{record_id}",
        "GSI_RECORD_SK": started_at,
    }
    if error_message:
        item["error_message"] = error_message[:2000]

    try:
        T.crm_workflow_runs.put_item(Item=item)
    except Exception as exc:
        logger.warning("crm_workflow: _write_run failed: %s", exc, exc_info=True)


# ---------------------------------------------------------------------------
# Record fetcher (thin adapter)
# ---------------------------------------------------------------------------

def _fetch_record(module: str, record_id: str) -> dict | None:
    """Fetch a single record by module + record_id."""
    try:
        from app.services.workflow_record_fetcher import fetch_single_record
        return fetch_single_record(module, record_id)
    except Exception as exc:
        logger.warning(
            "crm_workflow: _fetch_record failed module=%s record_id=%s: %s",
            module,
            record_id,
            exc,
            exc_info=True,
        )
        return None
