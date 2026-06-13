"""CRM Workflow Drip Sequences — WFL-008.

Service for drip sequence definition CRUD and enrolment state management.
All definitions and enrolment rows live in T.crm_workflow_rules using dedicated
PK prefixes (DRIP# for definitions, ENROL# for enrolments).
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ID / key helpers
# ---------------------------------------------------------------------------

def _new_sequence_id() -> str:
    return "drip_" + uuid.uuid4().hex


def _seq_pk(sequence_id: str) -> str:
    return f"DRIP#{sequence_id}"


def _enrol_pk(sequence_id: str) -> str:
    return f"ENROL#{sequence_id}"


def _enrol_sk(module: str, record_id: str) -> str:
    return f"RECORD#{module}#{record_id}"


# ---------------------------------------------------------------------------
# Sequence definition CRUD
# ---------------------------------------------------------------------------

def _validate_stages(stages: list[dict]) -> None:
    """Validate stage list: must be non-empty, stage_numbers contiguous from 1."""
    if not stages:
        raise ValueError("stages list must not be empty")
    nums = sorted(int(s.get("stage_number", 0)) for s in stages)
    expected = list(range(1, len(nums) + 1))
    if nums != expected:
        raise ValueError("stage_number values must be contiguous starting from 1")
    for s in stages:
        if int(s.get("delay_hours", -1)) < 0:
            raise ValueError("delay_hours must be >= 0")
        if not s.get("template_id", ""):
            raise ValueError("template_id must not be blank")


def _seq_out(item: dict) -> dict:
    return {
        "sequence_id": item.get("sequence_id", ""),
        "name": item.get("name", ""),
        "description": item.get("description", ""),
        "stages": item.get("stages") or [],
        "created_by": item.get("created_by", ""),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def create_sequence(
    *,
    created_by: str,
    name: str,
    description: str = "",
    stages: list[dict],
) -> dict:
    """Persist a new drip sequence definition."""
    _validate_stages(stages)
    sequence_id = _new_sequence_id()
    ts = now_ts()
    # Sort stages by stage_number for canonical storage
    sorted_stages = sorted(stages, key=lambda s: int(s.get("stage_number", 0)))
    item: dict[str, Any] = {
        "pk": _seq_pk(sequence_id),
        "sk": "META",
        "sequence_id": sequence_id,
        "name": name,
        "description": description,
        "stages": sorted_stages,
        "created_by": created_by,
        "created_at": ts,
        "updated_at": ts,
    }
    T.crm_workflow_rules.put_item(Item=item)
    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_workflow.drip_sequence.created",
            created_by,
            sequence_id=sequence_id,
            name=name,
        )
    except Exception:
        pass
    return get_sequence(sequence_id)  # type: ignore[return-value]


def get_sequence(sequence_id: str) -> dict | None:
    """Return the sequence definition or None."""
    resp = T.crm_workflow_rules.get_item(
        Key={"pk": _seq_pk(sequence_id), "sk": "META"}
    )
    item = resp.get("Item")
    if not item:
        return None
    return _seq_out(item)


def list_sequences(*, limit: int = 50, cursor: str | None = None) -> dict:
    """Return {sequences: [...], cursor: str|None}."""
    from boto3.dynamodb.conditions import Attr

    exclusive_start = decode_cursor(cursor)
    kwargs: dict[str, Any] = {
        "FilterExpression": Attr("pk").begins_with("DRIP#") & Attr("sk").eq("META"),
        "Limit": limit,
    }
    if exclusive_start:
        kwargs["ExclusiveStartKey"] = exclusive_start
    resp = T.crm_workflow_rules.scan(**kwargs)
    seqs = [_seq_out(i) for i in resp.get("Items", [])]
    return {
        "sequences": seqs,
        "cursor": encode_cursor(resp.get("LastEvaluatedKey")),
    }


def update_sequence(
    sequence_id: str,
    *,
    updated_by: str,
    name: str | None = None,
    description: str | None = None,
    stages: list[dict] | None = None,
) -> dict | None:
    """Partial update. Returns updated dict or None if not found."""
    existing = get_sequence(sequence_id)
    if existing is None:
        return None

    if stages is not None:
        _validate_stages(stages)

    ts = now_ts()
    set_parts = ["#updated_at = :updated_at"]
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
    if stages is not None:
        sorted_stages = sorted(stages, key=lambda s: int(s.get("stage_number", 0)))
        set_parts.append("#stages = :stages")
        names["#stages"] = "stages"
        values[":stages"] = sorted_stages

    T.crm_workflow_rules.update_item(
        Key={"pk": _seq_pk(sequence_id), "sk": "META"},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )
    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_workflow.drip_sequence.updated",
            updated_by,
            sequence_id=sequence_id,
        )
    except Exception:
        pass
    return get_sequence(sequence_id)


def delete_sequence(sequence_id: str, *, deleted_by: str) -> bool:
    """Hard-delete the sequence definition row. Returns True if existed."""
    existing = get_sequence(sequence_id)
    if existing is None:
        return False
    T.crm_workflow_rules.delete_item(Key={"pk": _seq_pk(sequence_id), "sk": "META"})
    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_workflow.drip_sequence.deleted",
            deleted_by,
            sequence_id=sequence_id,
        )
    except Exception:
        pass
    return True


# ---------------------------------------------------------------------------
# Enrolment state
# ---------------------------------------------------------------------------

def enrol_record(
    sequence_id: str,
    module: str,
    record_id: str,
    *,
    enrolled_at: int,
) -> dict:
    """Create or return the enrolment row.

    Uses conditional put (attribute_not_exists(pk)) so the second call for
    the same triple returns the existing enrolment unchanged.
    """
    from botocore.exceptions import ClientError

    pk = _enrol_pk(sequence_id)
    sk = _enrol_sk(module, record_id)
    item: dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "sequence_id": sequence_id,
        "module": module,
        "record_id": record_id,
        "current_stage": 0,
        "enrolled_at": enrolled_at,
        "last_stage_sent_at": None,
        "completed": False,
        "stopped": False,
    }
    try:
        T.crm_workflow_rules.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk)",
        )
        return item
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            # Already exists — return the existing row
            return get_enrolment(sequence_id, module, record_id) or item
        raise


def get_enrolment(sequence_id: str, module: str, record_id: str) -> dict | None:
    """Return the current enrolment state row or None."""
    resp = T.crm_workflow_rules.get_item(
        Key={"pk": _enrol_pk(sequence_id), "sk": _enrol_sk(module, record_id)}
    )
    item = resp.get("Item")
    if not item:
        return None
    return {
        "sequence_id": item.get("sequence_id", sequence_id),
        "module": item.get("module", module),
        "record_id": item.get("record_id", record_id),
        "current_stage": int(item.get("current_stage", 0)),
        "enrolled_at": int(item.get("enrolled_at", 0)),
        "last_stage_sent_at": int(item["last_stage_sent_at"]) if item.get("last_stage_sent_at") else None,
        "completed": bool(item.get("completed", False)),
        "stopped": bool(item.get("stopped", False)),
        "stopped_at": int(item["stopped_at"]) if item.get("stopped_at") else None,
        "stop_reason": item.get("stop_reason", ""),
    }


def advance_enrolment(
    sequence_id: str,
    module: str,
    record_id: str,
    *,
    stage_number: int,
    now: int,
) -> None:
    """Update current_stage and last_stage_sent_at after a stage send."""
    T.crm_workflow_rules.update_item(
        Key={"pk": _enrol_pk(sequence_id), "sk": _enrol_sk(module, record_id)},
        UpdateExpression="SET current_stage = :stage, last_stage_sent_at = :ts",
        ExpressionAttributeValues={":stage": stage_number, ":ts": now},
    )


def complete_enrolment(
    sequence_id: str, module: str, record_id: str, *, now: int
) -> None:
    """Mark enrolment completed=True."""
    T.crm_workflow_rules.update_item(
        Key={"pk": _enrol_pk(sequence_id), "sk": _enrol_sk(module, record_id)},
        UpdateExpression="SET completed = :t",
        ExpressionAttributeValues={":t": True},
    )


def stop_drip_sequence(
    sequence_id: str,
    module: str,
    record_id: str,
    *,
    reason: str = "manual",
    now: int | None = None,
) -> bool:
    """Set stopped=True on the enrolment row."""
    existing = get_enrolment(sequence_id, module, record_id)
    if existing is None:
        return False

    _now = now if now is not None else now_ts()
    T.crm_workflow_rules.update_item(
        Key={"pk": _enrol_pk(sequence_id), "sk": _enrol_sk(module, record_id)},
        UpdateExpression="SET stopped = :t, stopped_at = :ts, stop_reason = :reason",
        ExpressionAttributeValues={":t": True, ":ts": _now, ":reason": reason},
    )
    try:
        from app.services.alerts import audit_event
        audit_event(
            "crm_workflow.drip_stopped",
            "system",
            sequence_id=sequence_id,
            module=module,
            record_id=record_id,
            reason=reason,
        )
    except Exception:
        pass
    return True


# ---------------------------------------------------------------------------
# Internal stage scheduler (used by executor)
# ---------------------------------------------------------------------------

def _schedule_drip_stage(
    seq: dict,
    stage: dict,
    *,
    module: str,
    record_id: str,
    enrolled_at: int,
) -> None:
    """Write one crm_workflow_drip_stage row to T.scheduled_actions.

    Bypasses create_action min-lead-time guard by direct put_item.
    """
    from app.core.tables import T as _T

    action_id = "sa_" + uuid.uuid4().hex
    scheduled_at = enrolled_at + int(stage.get("delay_hours", 0)) * 3600
    _now = now_ts()
    item: dict[str, Any] = {
        "pk": "USER#system",
        "sk": f"ACTION#{scheduled_at}#{action_id}",
        "action_id": action_id,
        "user_sub": "system",
        "action_type": "crm_workflow_drip_stage",
        "status": "pending",
        "scheduled_at": scheduled_at,
        "created_at": _now,
        "updated_at": _now,
        "title": f"Drip {seq.get('name', seq.get('sequence_id', ''))} stage {stage.get('stage_number')}",
        "payload": {
            "sequence_id": seq["sequence_id"],
            "stage_number": stage["stage_number"],
            "module": module,
            "record_id": record_id,
            "template_id": stage.get("template_id", ""),
            "to_field": stage.get("to_field", ""),
            "enrolled_at": enrolled_at,
        },
        "GSI_DUE_PK": "DUE",
        "GSI_DUE_SK": scheduled_at,
        "GSI_TYPE_PK": "USER#system#TYPE#crm_workflow_drip_stage",
        "GSI_TYPE_SK": scheduled_at,
        "ttl_epoch": scheduled_at + S.scheduled_actions_ttl_days * 86400,
        "retry_count": 0,
        "max_retries": S.scheduled_actions_max_retries,
        "reminder_sent": False,
        "notify_before_seconds": 0,
    }
    _T.scheduled_actions.put_item(Item=item)
