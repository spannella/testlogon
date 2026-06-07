"""DevOps/SRE Agent service (AGENT-010).

The DevOps Agent is an *agent type config* that plugs into the Worker Agent
Framework (AGENT-003), mirroring the Coder Agent (AGENT-008) pattern. It owns:

* ``devops_config`` storage/validation on the shared ``agent_types`` table
  (reused from AGENT-008 — one CONFIG item per type id)
* ticket label filtering (deployment / infrastructure / incident) + atomic
  claiming on the ``tickets`` table
* a deterministic, mockable deployment state machine
  (plan -> approval? -> execute -> health -> smoke -> monitor -> rollback?)
* a per-deployment, command-level audit log on the ``deployment_log`` table
* structured ``devops_output`` storage on the shared ``agent_runs`` table
* automatic rollback + incident ticket auto-filing
* runbook matching/execution
* deployment frequency / success rate / MTTR metrics aggregation

Real command/infra execution is gated behind ``S.agent_devops_execute_commands``.
When disabled (the default, and always in E2E), the workflow is generated and
its transitions are driven in-memory so tests are fully deterministic. The
agent may optionally integrate with the compute launchers
(``app/services/ec2_launcher.py`` / ``k8s_launcher.py``) when execution is on.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services import agent_coder as coder_svc
from app.services import tickets as tickets_svc

logger = logging.getLogger("app.agent_devops")

DEVOPS_AGENT_TYPE = "devops"

_DEFAULT_DEPLOY_LABELS = ["type:deployment"]
_DEFAULT_INFRA_LABELS = ["type:infrastructure"]
_DEFAULT_INCIDENT_LABELS = ["type:incident"]

_OUTPUT_TAIL_MAX = 10_000  # 10KB cap per stdout/stderr tail (security §7)
_STDOUT_TAIL_LINES = 500
_STDERR_TAIL_LINES = 200
_APPROVAL_TIMEOUT_SECONDS = 24 * 3600  # auto-reject after 24h (§7.1)
_MUTEX_TTL_SECONDS = 3600  # deployment mutex auto-expires after 1h

# Crude secret-scrubbing patterns for deployment log scrubbing (§10).
_SECRET_KEYS = ("password", "secret", "token", "api_key", "apikey", "aws_secret")


# ---------------------------------------------------------------------------
# Table bootstrap (idempotent; additive per AGENT-008/010)
# ---------------------------------------------------------------------------

_BOOTSTRAPPED = False


def ensure_tables() -> None:
    """Create the deployment_log table on first use if absent.

    agent_types / agent_runs are created by the coder service bootstrap (shared).
    The canonical definitions also live in ``scripts/local-ddb-init.py`` but the
    devops feature is self-contained so it works in any environment without a
    stack re-init.
    """
    global _BOOTSTRAPPED
    # Reuse the coder bootstrap for the shared agent_types / agent_runs tables.
    coder_svc.ensure_tables()
    if _BOOTSTRAPPED:
        return
    client = ddb.meta.client
    try:
        client.create_table(
            TableName=S.deployment_log_table_name,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "gsi_env_pk", "AttributeType": "S"},
                {"AttributeName": "gsi_env_sk", "AttributeType": "N"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "ByEnv",
                    "KeySchema": [
                        {"AttributeName": "gsi_env_pk", "KeyType": "HASH"},
                        {"AttributeName": "gsi_env_sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("ResourceInUseException",):
            logger.warning("ensure_tables: could not create deployment_log: %s", exc)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("ensure_tables: deployment_log create error: %s", exc)
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def _type_pk(type_id: str) -> str:
    return f"TYPE#{type_id}"


def _run_pk(run_id: str) -> str:
    return f"RUN#{run_id}"


def _deploy_pk(deployment_id: str) -> str:
    return f"DEPLOY#{deployment_id}"


def _step_sk(step_number: int) -> str:
    return f"STEP#{step_number:04d}"


def _mutex_pk(environment: str) -> str:
    return f"MUTEX#ENV#{environment}"


# ---------------------------------------------------------------------------
# Config validation + normalization
# ---------------------------------------------------------------------------


def _is_http_url(url: str) -> bool:
    return isinstance(url, str) and (url.startswith("http://") or url.startswith("https://"))


def validate_devops_config(config: Dict[str, Any]) -> List[str]:
    """Return list of validation errors (empty = valid).

    Rules (§4.3): at least one environment, unique env names, valid HTTP(S)
    health check URLs, rollback commands required for production, approval
    required for production.
    """
    errors: List[str] = []

    environments = config.get("environments") or []
    if not environments:
        errors.append("At least one environment is required")
        return errors

    names_seen: set[str] = set()
    for env in environments:
        name = str(env.get("name", "") or "").strip()
        if not name:
            errors.append("Environment name is required")
            continue
        if name in names_seen:
            errors.append("Environment names must be unique")
        names_seen.add(name)

        deploy_commands = env.get("deploy_commands") or []
        if not deploy_commands:
            errors.append(f"Environment '{name}' must have at least one deploy command")

        for url in env.get("health_check_urls") or []:
            if not _is_http_url(url):
                errors.append("Health check URLs must be valid HTTP or HTTPS URLs")
                break
            # GAP-0092: reject shell-injectable URLs at config-write time too.
            try:
                _validate_health_check_url(url)
            except ValueError as exc:
                errors.append(f"Invalid health_check_url: {exc}")
                break

        is_prod = "prod" in name.lower()
        if is_prod and not (env.get("rollback_commands") or []):
            errors.append("Production environment must have rollback commands")
        if is_prod and not env.get("requires_approval", False):
            errors.append("Production environment must require approval")

    coding_tool = config.get("coding_tool", "claude_code")
    if coding_tool not in ("claude_code", "codex"):
        errors.append("Coding tool must be claude_code or codex")

    return errors


def _normalize_env(env: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": env.get("name", ""),
        "requires_approval": bool(env.get("requires_approval", False)),
        "deploy_commands": list(env.get("deploy_commands") or []),
        "rollback_commands": list(env.get("rollback_commands") or []),
        "health_check_urls": list(env.get("health_check_urls") or []),
        "health_check_timeout_seconds": int(env.get("health_check_timeout_seconds", 120) or 120),
        "smoke_test_command": env.get("smoke_test_command"),
        "rollback_window_seconds": int(env.get("rollback_window_seconds", 300) or 300),
        "env_vars": dict(env.get("env_vars") or {}) if env.get("env_vars") else None,
    }


def _normalize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "environments": [_normalize_env(e) for e in (config.get("environments") or [])],
        "deploy_ticket_labels": list(config.get("deploy_ticket_labels") or _DEFAULT_DEPLOY_LABELS),
        "infra_ticket_labels": list(config.get("infra_ticket_labels") or _DEFAULT_INFRA_LABELS),
        "incident_ticket_labels": list(config.get("incident_ticket_labels") or _DEFAULT_INCIDENT_LABELS),
        "auto_deploy_on_qa_approved": bool(config.get("auto_deploy_on_qa_approved", False)),
        "coding_tool": config.get("coding_tool", "claude_code"),
        "max_operation_time_seconds": int(config.get("max_operation_time_seconds", 1800) or 1800),
        "incident_space_id": config.get("incident_space_id"),
    }
    if config.get("monitoring_endpoints"):
        out["monitoring_endpoints"] = [
            {
                "name": m.get("name", ""),
                "url": m.get("url", ""),
                "metric_type": m.get("metric_type", ""),
                "threshold": float(m.get("threshold", 0) or 0),
            }
            for m in config["monitoring_endpoints"]
        ]
    if config.get("runbooks"):
        out["runbooks"] = [
            {
                "trigger_label": r.get("trigger_label", ""),
                "name": r.get("name", ""),
                "steps": list(r.get("steps") or []),
            }
            for r in config["runbooks"]
        ]
    return out


def _coerce_numbers(config: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(config)
    if "max_operation_time_seconds" in out and out["max_operation_time_seconds"] is not None:
        try:
            out["max_operation_time_seconds"] = int(out["max_operation_time_seconds"])
        except (TypeError, ValueError):
            pass
    for env in out.get("environments") or []:
        for f in ("health_check_timeout_seconds", "rollback_window_seconds"):
            if env.get(f) is not None:
                try:
                    env[f] = int(env[f])
                except (TypeError, ValueError):
                    pass
    return out


# ---------------------------------------------------------------------------
# Config CRUD (reuses the shared agent_types table)
# ---------------------------------------------------------------------------


def get_agent_type(*, agent_type_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _type_pk(agent_type_id), "sk": "META"})
    return resp.get("Item")


def get_devops_config(*, agent_type_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _type_pk(agent_type_id), "sk": "CONFIG"})
    item = resp.get("Item")
    if not item:
        return None
    config = item.get("devops_config")
    if not config:
        return None
    return _coerce_numbers(config)


def update_devops_config(
    *, agent_type_id: str, owner_sub: str, config: Dict[str, Any]
) -> Dict[str, Any]:
    """Validate and persist devops_config. Auto-creates the type META if absent."""
    ensure_tables()
    if get_agent_type(agent_type_id=agent_type_id) is None:
        coder_svc.create_agent_type(
            agent_type_id=agent_type_id, owner_sub=owner_sub, agent_type=DEVOPS_AGENT_TYPE
        )
    normalized = _normalize_config(config)
    ts = now_ts()
    T.agent_types.put_item(
        Item={
            "pk": _type_pk(agent_type_id),
            "sk": "CONFIG",
            "agent_type_id": agent_type_id,
            "agent_type": DEVOPS_AGENT_TYPE,
            "owner_sub": owner_sub,
            "devops_config": normalized,
            "updated_at": ts,
        }
    )
    T.agent_types.update_item(
        Key={"pk": _type_pk(agent_type_id), "sk": "META"},
        UpdateExpression="SET agent_type = :t, updated_at = :u",
        ExpressionAttributeValues={":t": DEVOPS_AGENT_TYPE, ":u": ts},
    )
    return {"type_id": agent_type_id, "devops_config": normalized, "updated_at": ts}


def config_schema() -> Dict[str, Any]:
    return {
        "fields": {
            "environments": {"type": "array", "required": True, "min": 1, "max": 10},
            "deploy_ticket_labels": {"type": "array", "default": _DEFAULT_DEPLOY_LABELS},
            "infra_ticket_labels": {"type": "array", "default": _DEFAULT_INFRA_LABELS},
            "incident_ticket_labels": {"type": "array", "default": _DEFAULT_INCIDENT_LABELS},
            "auto_deploy_on_qa_approved": {"type": "boolean", "default": False},
            "coding_tool": {"type": "enum", "values": ["claude_code", "codex"], "default": "claude_code"},
            "max_operation_time_seconds": {"type": "integer", "min": 300, "max": 14400, "default": 1800},
            "incident_space_id": {"type": "string"},
            "monitoring_endpoints": {"type": "array"},
            "runbooks": {"type": "array"},
        }
    }


def _find_environment(config: Dict[str, Any], env_name: str) -> Optional[Dict[str, Any]]:
    for env in config.get("environments") or []:
        if env.get("name") == env_name:
            return env
    return None


# ---------------------------------------------------------------------------
# Ticket filtering & claiming
# ---------------------------------------------------------------------------


def find_devops_eligible_tickets(
    *,
    label_sets: Dict[str, List[str]],
    auto_deploy_on_qa: bool = False,
    limit: int = 10,
) -> List[Dict[str, Any]]:
    """Return open/unassigned tickets matching deployment/infra/incident labels.

    ``label_sets`` is {"deployment": [...], "infrastructure": [...],
    "incident": [...]}. Queries the label index partitions, merges, drops
    already-claimed tickets, classifies each by which label set matched, and
    returns oldest-first (FIFO).
    """
    ensure_tables()
    all_labels: Dict[str, str] = {}
    for op_type, labels in label_sets.items():
        for label in labels or []:
            all_labels[label] = op_type

    seen: dict[str, Dict[str, Any]] = {}
    for label, op_type in all_labels.items():
        resp = tickets_svc.STORE._table.query(  # noqa: SLF001 - internal reuse
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": tickets_svc.label_index_pk(label)},
            ScanIndexForward=True,
        )
        for row in resp.get("Items", []):
            tid = row.get("ticket_id")
            if not tid or tid in seen:
                continue
            ticket = tickets_svc.STORE.get_ticket(tid)
            if not ticket:
                continue
            status = ticket.get("status")
            # Eligible statuses: open, plus qa_approved/code_complete when auto-deploy.
            eligible_statuses = {"open"}
            if auto_deploy_on_qa:
                eligible_statuses |= {"qa_approved", "code_complete"}
            if status not in eligible_statuses:
                continue
            if ticket.get("assigned_to_sub"):
                continue
            seen[tid] = {
                "ticket_id": tid,
                "subject": ticket.get("subject", ""),
                "labels": sorted(set(ticket.get("labels", []))),
                "operation_type": op_type,
                "status": status,
                "created_at": int(ticket.get("created_at", 0) or 0),
            }
    out = sorted(seen.values(), key=lambda t: (t["created_at"], t["ticket_id"]))
    return out[:limit]


def classify_operation(*, ticket: Dict[str, Any], config: Dict[str, Any]) -> str:
    """Determine operation type from a ticket's labels and the config label sets."""
    labels = set(ticket.get("labels", []))
    if labels & set(config.get("incident_ticket_labels") or _DEFAULT_INCIDENT_LABELS):
        return "incident_response"
    if labels & set(config.get("infra_ticket_labels") or _DEFAULT_INFRA_LABELS):
        return "infrastructure"
    # Runbook match takes precedence when configured.
    if match_runbook(ticket=ticket, runbooks=config.get("runbooks") or []):
        return "runbook"
    return "deployment"


def claim_devops_ticket(*, ticket_id: str, agent_sub: str, operation_type: str) -> Dict[str, Any]:
    """Atomically claim a ticket. Sets status to deploying / investigating."""
    ticket = tickets_svc.STORE.get_ticket(ticket_id)
    if not ticket:
        raise LookupError("Ticket not found")
    new_status = "investigating" if operation_type == "incident_response" else "deploying"
    table = tickets_svc.STORE._table  # noqa: SLF001
    ts = now_ts()
    try:
        table.update_item(
            Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
            UpdateExpression=(
                "SET assigned_to_sub = :sub, #st = :status, assigned_at = :ts, updated_at = :ts"
            ),
            ConditionExpression=(
                "attribute_not_exists(assigned_to_sub) OR assigned_to_sub = :none"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":sub": agent_sub,
                ":status": new_status,
                ":ts": ts,
                ":none": None,
            },
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            raise ValueError("already_claimed") from exc
        raise
    return {
        "ok": True,
        "ticket_id": ticket_id,
        "status": new_status,
        "assigned_to_sub": agent_sub,
        "claimed_at": ts,
    }


# ---------------------------------------------------------------------------
# Auto-deploy-on-QA-approved dispatch (GAP-0093)
#
# The ``auto_deploy_on_qa_approved`` config flag was stored and widened the
# eligible-ticket statuses, but nothing ever dispatched a deployment when a
# ticket reached ``qa_approved``. The functions below provide the dispatch
# hooks. They are pure-DynamoDB (moto-friendly) and never run real shell
# commands in dev (``S.agent_devops_execute_commands`` stays False), so the
# whole QA-approve -> auto-deploy pipeline is exercisable offline.
#
# Wiring (outside this module): the event-driven hook
# ``dispatch_auto_deploy_for_ticket`` is intended to be called from
# ``agent_qa.mark_ticket_qa_approved`` (non-blocking), and ``poll_auto_deploy_once``
# is intended as the body of a background catch-up loop in ``app/main.py``.
# ---------------------------------------------------------------------------


def _config_label_sets(config: Dict[str, Any]) -> Dict[str, List[str]]:
    """Build the {operation_type: [labels]} map used by find_devops_eligible_tickets."""
    return {
        "deployment": config.get("deploy_ticket_labels") or list(_DEFAULT_DEPLOY_LABELS),
        "infrastructure": config.get("infra_ticket_labels") or list(_DEFAULT_INFRA_LABELS),
        "incident_response": config.get("incident_ticket_labels") or list(_DEFAULT_INCIDENT_LABELS),
    }


def list_agent_types_with_auto_deploy() -> List[Dict[str, Any]]:
    """Return all DevOps agent types with ``auto_deploy_on_qa_approved=True``.

    Scans the shared ``agent_types`` table for CONFIG items of type ``devops``.
    The number of agent types is small and this is only called from dispatch /
    background paths, so a paginating scan is acceptable.
    """
    ensure_tables()
    out: List[Dict[str, Any]] = []
    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": "sk = :sk AND agent_type = :t",
        "ExpressionAttributeValues": {":sk": "CONFIG", ":t": DEVOPS_AGENT_TYPE},
    }
    while True:
        resp = T.agent_types.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            cfg = item.get("devops_config") or {}
            if cfg.get("auto_deploy_on_qa_approved"):
                out.append(
                    {
                        "agent_type_id": item.get("agent_type_id", ""),
                        "config": _coerce_numbers(cfg),
                    }
                )
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        scan_kwargs["ExclusiveStartKey"] = lek
    return out


def _dispatch_auto_deploy(
    *, ticket: Dict[str, Any], agent_type_id: str, config: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Dispatch a deployment workflow for an eligible qa_approved ticket.

    Runs the deterministic mock workflow (the same path manual deploys use).
    Returns the persisted devops_output, or ``None`` if the ticket was already
    claimed by another process. Never raises on already-claimed.
    """
    ticket_id = ticket.get("ticket_id", "")
    agent_sub = f"auto_deploy@{agent_type_id}"
    operation_type = classify_operation(ticket=ticket, config=config)
    # Claim first so a concurrent dispatch/poll cannot double-deploy.
    try:
        claim_devops_ticket(
            ticket_id=ticket_id, agent_sub=agent_sub, operation_type=operation_type
        )
    except ValueError:
        # already_claimed — another dispatcher won the race.
        logger.info("auto_deploy.skipped ticket=%s reason=already_claimed", ticket_id)
        return None
    except LookupError:
        logger.info("auto_deploy.skipped ticket=%s reason=ticket_not_found", ticket_id)
        return None
    run_id = f"auto_{uuid.uuid4().hex[:12]}"
    logger.info(
        "auto_deploy.dispatched ticket=%s agent_type=%s run=%s",
        ticket_id, agent_type_id, run_id,
    )
    return run_mock_workflow(
        run_id=run_id,
        agent_type_id=agent_type_id,
        ticket=ticket,
        config=config,
        agent_sub=agent_sub,
    )


def dispatch_auto_deploy_for_ticket(*, ticket_id: str) -> Optional[Dict[str, Any]]:
    """Event-driven auto-deploy hook for a single ticket.

    Intended to be called (non-blocking, best-effort) from
    ``agent_qa.mark_ticket_qa_approved`` right after a ticket is set to
    ``qa_approved``. Finds the first DevOps agent type configured with
    ``auto_deploy_on_qa_approved=True`` whose label sets match this ticket and
    dispatches a deployment. Returns the devops_output of the dispatched run,
    or ``None`` when no agent type matches / the ticket is not eligible.
    """
    ticket = tickets_svc.STORE.get_ticket(ticket_id)
    if not ticket:
        return None
    for at in list_agent_types_with_auto_deploy():
        config = at["config"]
        eligible = find_devops_eligible_tickets(
            label_sets=_config_label_sets(config),
            auto_deploy_on_qa=True,
            limit=100,
        )
        if any(t["ticket_id"] == ticket_id for t in eligible):
            return _dispatch_auto_deploy(
                ticket=ticket, agent_type_id=at["agent_type_id"], config=config
            )
    return None


def poll_auto_deploy_once() -> List[Dict[str, Any]]:
    """Catch-up pass: dispatch every currently-eligible qa_approved ticket.

    Intended as the body of a background polling loop. For each DevOps agent
    type with ``auto_deploy_on_qa_approved=True`` it dispatches all eligible,
    unclaimed tickets. Best-effort: a failure dispatching one ticket is logged
    and does not abort the rest. Returns the list of dispatched devops_outputs.
    """
    dispatched: List[Dict[str, Any]] = []
    for at in list_agent_types_with_auto_deploy():
        config = at["config"]
        agent_type_id = at["agent_type_id"]
        try:
            eligible = find_devops_eligible_tickets(
                label_sets=_config_label_sets(config),
                auto_deploy_on_qa=True,
                limit=100,
            )
        except Exception:  # noqa: BLE001 - background loop must not die
            logger.exception("auto_deploy.error agent_type=%s during eligibility", agent_type_id)
            continue
        for t in eligible:
            ticket = tickets_svc.STORE.get_ticket(t["ticket_id"])
            if not ticket:
                continue
            try:
                output = _dispatch_auto_deploy(
                    ticket=ticket, agent_type_id=agent_type_id, config=config
                )
            except Exception:  # noqa: BLE001 - one bad ticket must not stop the loop
                logger.exception("auto_deploy.error ticket=%s", t["ticket_id"])
                continue
            if output is not None:
                dispatched.append(output)
    return dispatched


# ---------------------------------------------------------------------------
# Deployment mutex (one active deployment per environment)
# ---------------------------------------------------------------------------


def acquire_env_mutex(*, environment: str, deployment_id: str, agent_run_id: str) -> bool:
    """Conditionally claim the per-environment deployment mutex. False on conflict."""
    ensure_tables()
    ts = now_ts()
    try:
        T.deployment_log.put_item(
            Item={
                "pk": _mutex_pk(environment),
                "sk": "ACTIVE",
                "deployment_id": deployment_id,
                "agent_run_id": agent_run_id,
                "started_at": ts,
                "ttl": ts + _MUTEX_TTL_SECONDS,
            },
            ConditionExpression="attribute_not_exists(pk) OR #ttl < :now",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={":now": ts},
        )
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            return False
        raise


def release_env_mutex(*, environment: str) -> None:
    ensure_tables()
    try:
        T.deployment_log.delete_item(Key={"pk": _mutex_pk(environment), "sk": "ACTIVE"})
    except ClientError:  # pragma: no cover - defensive
        pass


# ---------------------------------------------------------------------------
# Deployment plan generation
# ---------------------------------------------------------------------------


def generate_deployment_plan(
    *, ticket: Dict[str, Any], environment: Dict[str, Any], version: Optional[str] = None
) -> Dict[str, Any]:
    """Generate a structured deployment plan for review or direct execution."""
    env_name = environment.get("name", "")
    deploy_commands = list(environment.get("deploy_commands") or [])
    if version:
        deploy_commands = [c.replace("${VERSION}", version) for c in deploy_commands]
    return {
        "environment": env_name,
        "version": version,
        "requires_approval": bool(environment.get("requires_approval", False)),
        "deploy_commands": deploy_commands,
        "rollback_commands": list(environment.get("rollback_commands") or []),
        "health_check_urls": list(environment.get("health_check_urls") or []),
        "health_check_timeout_seconds": int(environment.get("health_check_timeout_seconds", 120)),
        "smoke_test_command": environment.get("smoke_test_command"),
        "rollback_window_seconds": int(environment.get("rollback_window_seconds", 300)),
        "ticket_id": ticket.get("ticket_id", ""),
        "ticket_subject": ticket.get("subject", ""),
    }


def render_plan_markdown(plan: Dict[str, Any]) -> str:
    lines = [
        f"# Deployment Plan — {plan.get('environment', '')}",
        "",
        f"**Ticket:** {plan.get('ticket_id', '')} — {plan.get('ticket_subject', '')}",
        f"**Version:** {plan.get('version') or '(latest)'}",
        "",
        "## Deploy commands",
    ]
    for c in plan.get("deploy_commands", []):
        lines.append(f"- `{c}`")
    lines += ["", "## Health checks"]
    for u in plan.get("health_check_urls", []):
        lines.append(f"- {u}")
    lines += ["", "## Rollback plan"]
    for c in plan.get("rollback_commands", []):
        lines.append(f"- `{c}`")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Deployment log (command-level audit trail)
# ---------------------------------------------------------------------------


def _scrub_secrets(text: str) -> str:
    if not text:
        return text
    out = text
    lowered = out.lower()
    for key in _SECRET_KEYS:
        if key in lowered:
            # Replace values after key= or key: with [REDACTED]
            import re as _re

            out = _re.sub(
                rf"({key}[=:\s]+)\S+", r"\1[REDACTED]", out, flags=_re.IGNORECASE
            )
            lowered = out.lower()
    return out


def _tail(text: str, max_lines: int) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    tail = "\n".join(lines[-max_lines:])
    return _scrub_secrets(tail)[-_OUTPUT_TAIL_MAX:]


def create_deployment_log(
    *, deployment_id: str, agent_run_id: str, ticket_id: str, environment: str
) -> None:
    """Write the deployment header row (STEP#9999 reserved as a meta marker)."""
    ensure_tables()
    ts = now_ts()
    T.deployment_log.put_item(
        Item={
            "pk": _deploy_pk(deployment_id),
            "sk": "META",
            "deployment_id": deployment_id,
            "agent_run_id": agent_run_id,
            "ticket_id": ticket_id,
            "environment": environment,
            "created_at": ts,
            "gsi_env_pk": f"ENV#{environment}",
            "gsi_env_sk": ts,
        }
    )


def log_deployment_step(
    *,
    deployment_id: str,
    agent_run_id: str,
    ticket_id: str,
    environment: str,
    step_number: int,
    step_type: str,
    command: str,
    exit_code: Optional[int],
    stdout_tail: str,
    stderr_tail: str,
    started_at: int,
    completed_at: int,
    status: str,
) -> Dict[str, Any]:
    ensure_tables()
    item = {
        "pk": _deploy_pk(deployment_id),
        "sk": _step_sk(step_number),
        "deployment_id": deployment_id,
        "agent_run_id": agent_run_id,
        "ticket_id": ticket_id,
        "environment": environment,
        "step_number": step_number,
        "step_type": step_type,
        "command": command,
        "exit_code": exit_code,
        "stdout_tail": _tail(stdout_tail, _STDOUT_TAIL_LINES),
        "stderr_tail": _tail(stderr_tail, _STDERR_TAIL_LINES),
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": max(0, int(completed_at) - int(started_at)),
        "status": status,
        "gsi_env_pk": f"ENV#{environment}",
        "gsi_env_sk": started_at,
    }
    T.deployment_log.put_item(Item={k: v for k, v in item.items() if v is not None})
    return item


def get_deployment_log(*, deployment_id: str) -> List[Dict[str, Any]]:
    """Return all STEP# rows for a deployment, sorted by step number."""
    ensure_tables()
    resp = T.deployment_log.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
        ExpressionAttributeValues={":pk": _deploy_pk(deployment_id), ":sk": "STEP#"},
        ScanIndexForward=True,
    )
    steps = []
    for it in resp.get("Items", []):
        steps.append(
            {
                "step_number": int(it.get("step_number", 0) or 0),
                "step_type": it.get("step_type", "command"),
                "command": it.get("command", ""),
                "exit_code": (int(it["exit_code"]) if it.get("exit_code") is not None else None),
                "stdout_tail": it.get("stdout_tail", ""),
                "stderr_tail": it.get("stderr_tail", ""),
                "started_at": int(it.get("started_at", 0) or 0),
                "completed_at": int(it.get("completed_at", 0) or 0),
                "duration_seconds": int(it.get("duration_seconds", 0) or 0),
                "status": it.get("status", "success"),
            }
        )
    steps.sort(key=lambda s: s["step_number"])
    return steps


# ---------------------------------------------------------------------------
# Health checks / smoke test / monitoring (mock-friendly)
# ---------------------------------------------------------------------------


# Shell metacharacters (and control chars) that must never appear in a health
# check URL. Mirrors app/core/validate_url._SHELL_META_RE but permits spaces are
# still rejected (a URL must not contain whitespace).
_HEALTH_URL_SHELL_META_RE = re.compile(r"[;&|`$<>(){}\[\]'\"\\\s]|[\x00-\x1f]")
_HEALTH_URL_PCT_NEWLINE_RE = re.compile(r"%0[09adAD]", re.IGNORECASE)


def _validate_health_check_url(url: str) -> str:
    """Validate a health-check URL for safe use as a ``curl`` argument.

    Allows only ``http://`` / ``https://`` URLs free of shell metacharacters,
    control characters and percent-encoded newlines. Returns the URL unchanged
    when valid; raises ``ValueError`` otherwise.

    This is the GAP-0092 remediation: ``health_check_urls`` come from
    admin-supplied deployment config and were previously interpolated verbatim
    into a ``curl -sf {url}`` command string. Validation here (plus argv-style
    execution / JSON-argv logging) closes the latent shell-injection path that
    would open when ``S.agent_devops_execute_commands`` is enabled.
    """
    if not url or not isinstance(url, str):
        raise ValueError("health_check_url must be a non-empty string")
    if len(url) > 500:
        raise ValueError("health_check_url too long (max 500)")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"health_check_url scheme must be http or https, got: {parsed.scheme!r}"
        )
    if _HEALTH_URL_PCT_NEWLINE_RE.search(url):
        raise ValueError(
            "health_check_url contains forbidden percent-encoded control characters"
        )
    if _HEALTH_URL_SHELL_META_RE.search(url):
        raise ValueError(
            f"health_check_url contains forbidden shell metacharacters: {url!r}"
        )
    return url


def _health_check_argv(url: str) -> List[str]:
    """Build the safe argv list for a health-check ``curl`` invocation.

    Never used with ``shell=True``. The returned list is also what is recorded
    (as JSON) in the deployment-step ``command`` field so the audit record is
    always parseable and never shell-interpretable.
    """
    return ["curl", "--silent", "--fail", _validate_health_check_url(url)]


def run_health_checks(
    *, health_check_urls: List[str], timeout_seconds: int = 120, force_unhealthy: bool = False
) -> List[Dict[str, Any]]:
    """Run health checks against each URL.

    Real HTTP execution is gated; in mock mode all checks pass (or all fail when
    ``force_unhealthy`` is set so rollback paths are testable).

    Every URL is validated up front (GAP-0092): a URL containing shell
    metacharacters raises ``ValueError`` before it can reach any execution or
    logging path. When ``S.agent_devops_execute_commands`` is enabled the check
    runs ``curl`` via an argv list with ``shell=False`` (no shell parsing).
    """
    results: List[Dict[str, Any]] = []
    for url in health_check_urls:
        argv = _health_check_argv(url)  # validates url; raises on shell metachars
        if S.agent_devops_execute_commands:
            try:
                proc = subprocess.run(  # noqa: S603 - argv list, shell=False, validated url
                    argv + ["--max-time", str(int(timeout_seconds))],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=int(timeout_seconds) + 5,
                )
                healthy = proc.returncode == 0 and not force_unhealthy
            except (subprocess.SubprocessError, OSError):
                healthy = False
        else:
            healthy = not force_unhealthy
        results.append(
            {
                "url": url,
                "status_code": 200 if healthy else 503,
                "response_time_ms": 25 if healthy else 0,
                "healthy": healthy,
            }
        )
    return results


def run_smoke_test(*, command: Optional[str], force_fail: bool = False) -> Optional[Dict[str, Any]]:
    if not command:
        return None
    passed = not force_fail
    return {"command": command, "exit_code": 0 if passed else 1, "passed": passed}


def monitor_post_deployment(
    *, monitoring_endpoints: List[Dict[str, Any]], window_seconds: int = 300
) -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {"window_seconds": window_seconds, "endpoints": []}
    anomaly = False
    for ep in monitoring_endpoints or []:
        snapshot["endpoints"].append(
            {"name": ep.get("name"), "value": 0.0, "threshold": ep.get("threshold", 0), "ok": True}
        )
    snapshot["anomaly_detected"] = anomaly
    return snapshot


def should_auto_rollback(
    *,
    health_results: List[Dict[str, Any]],
    smoke_result: Optional[Dict[str, Any]] = None,
    monitoring: Optional[Dict[str, Any]] = None,
) -> bool:
    if any(not h.get("healthy", False) for h in (health_results or [])):
        return True
    if smoke_result is not None and not smoke_result.get("passed", True):
        return True
    if monitoring is not None and monitoring.get("anomaly_detected"):
        return True
    return False


# ---------------------------------------------------------------------------
# Incident management
# ---------------------------------------------------------------------------


def build_incident_ticket(
    *,
    source_ticket: Optional[Dict[str, Any]],
    deployment_id: Optional[str],
    agent_run_id: str,
    environment: str,
    diagnosis: Dict[str, Any],
    error_logs: str,
    metrics_snapshot: Dict[str, Any],
    rollback_status: str,
    severity: str = "P2",
) -> Dict[str, Any]:
    timeline = diagnosis.get("timeline") or f"Deployment {deployment_id} health checks failed."
    return {
        "subject": f"[Incident] Deployment failure in {environment}",
        "labels": ["type:incident"],
        "metadata": {
            "incident_source": "devops_agent",
            "severity": severity,
            "affected_environment": environment,
            "affected_services": diagnosis.get("affected_services", []),
            "timeline": timeline,
            "deployment_id": deployment_id or "",
            "agent_run_id": agent_run_id,
            "error_logs": (error_logs or "")[:10000],
            "metrics_snapshot": json.dumps(metrics_snapshot or {})[:10000],
            "rollback_status": rollback_status,
            "remediation_steps": diagnosis.get("remediation_steps", ""),
        },
    }


def file_incident_ticket(
    *, incident_data: Dict[str, Any], space_id: Optional[str], agent_sub: str
) -> str:
    """Create the incident ticket and return its id."""
    ticket = tickets_svc.STORE.create_ticket(
        owner_sub=agent_sub,
        subject=incident_data["subject"],
        description=incident_data.get("metadata", {}).get("timeline", ""),
        space_id=space_id,
        labels=incident_data.get("labels", ["type:incident"]),
        metadata=incident_data.get("metadata"),
    )
    return ticket["ticket_id"]


def investigate_incident(*, ticket: Dict[str, Any], coding_tool: str = "claude_code") -> Dict[str, Any]:
    """Mock investigation: produces a diagnosis stub. Real LLM call is gated."""
    return {
        "timeline": f"Investigated incident on ticket {ticket.get('ticket_id', '')}.",
        "affected_services": [],
        "remediation_steps": "Automated diagnosis collected logs and metrics.",
        "coding_tool": coding_tool,
    }


# ---------------------------------------------------------------------------
# Runbook matching / execution
# ---------------------------------------------------------------------------


def match_runbook(
    *, ticket: Dict[str, Any], runbooks: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    labels = set(ticket.get("labels", []))
    for rb in runbooks or []:
        if rb.get("trigger_label") in labels:
            return rb
    return None


# ---------------------------------------------------------------------------
# Workflow orchestration (state machine)
# ---------------------------------------------------------------------------

WORKFLOW_STEP_TYPES = (
    "claim_ticket",
    "generate_plan",
    "request_approval",
    "execute_deployment",
    "run_health_checks",
    "run_smoke_test",
    "monitor_post_deploy",
    "auto_rollback",
    "update_ticket",
)


def build_devops_workflow(
    *, agent_run_id: str, config: Dict[str, Any], ticket: Dict[str, Any], operation_type: str
) -> Dict[str, Any]:
    """Generate ordered workflow steps. Pure / no I/O (dry-run preview + mock basis)."""
    cfg = _coerce_numbers(config)
    # Pick the first environment by default (staging-first). Production envs are
    # included but approval-gated.
    environments = cfg.get("environments") or []
    environment = environments[0] if environments else {}
    env_name = environment.get("name", "")
    requires_approval = bool(environment.get("requires_approval", False))
    max_time = int(cfg.get("max_operation_time_seconds", 1800))

    steps: List[Dict[str, Any]] = [
        {"step_id": 1, "type": "claim_ticket", "command": None, "timeout_seconds": 30, "on_failure": "escalate"},
        {"step_id": 2, "type": "generate_plan", "command": None, "timeout_seconds": 30, "on_failure": "escalate"},
    ]
    step_id = 3
    if requires_approval:
        steps.append(
            {"step_id": step_id, "type": "request_approval", "command": None, "timeout_seconds": _APPROVAL_TIMEOUT_SECONDS, "on_failure": "block"}
        )
        step_id += 1
    for cmd in environment.get("deploy_commands") or []:
        steps.append(
            {"step_id": step_id, "type": "execute_deployment", "command": cmd, "timeout_seconds": max_time, "on_failure": "rollback"}
        )
        step_id += 1
    if environment.get("health_check_urls"):
        steps.append(
            {"step_id": step_id, "type": "run_health_checks", "command": None, "timeout_seconds": int(environment.get("health_check_timeout_seconds", 120)), "on_failure": "rollback"}
        )
        step_id += 1
    if environment.get("smoke_test_command"):
        steps.append(
            {"step_id": step_id, "type": "run_smoke_test", "command": environment.get("smoke_test_command"), "timeout_seconds": 300, "on_failure": "rollback"}
        )
        step_id += 1
    steps.append(
        {"step_id": step_id, "type": "monitor_post_deploy", "command": None, "timeout_seconds": int(environment.get("rollback_window_seconds", 300)), "on_failure": "rollback"}
    )
    step_id += 1
    steps.append(
        {"step_id": step_id, "type": "update_ticket", "command": None, "timeout_seconds": 30, "on_failure": "next"}
    )
    return {
        "steps": steps,
        "environment": env_name,
        "operation_type": operation_type,
        "requires_approval": requires_approval,
        "total_timeout_seconds": max_time,
    }


# ---------------------------------------------------------------------------
# Output assembly & storage (reuses the shared agent_runs table)
# ---------------------------------------------------------------------------


def store_devops_output(*, run_id: str, agent_type_id: str, output: Dict[str, Any]) -> Dict[str, Any]:
    ensure_tables()
    ts = now_ts()
    T.agent_runs.put_item(
        Item={
            "pk": _run_pk(run_id),
            "sk": "DEVOPS_OUTPUT",
            "run_id": run_id,
            "agent_type_id": agent_type_id,
            "devops_output": output,
            "created_at": ts,
            "gsi_type_date_pk": f"DEVOPS#{agent_type_id}",
            "gsi_type_date_sk": f"DATE#{ts}",
        }
    )
    return output


def get_devops_output(*, run_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_runs.get_item(Key={"pk": _run_pk(run_id), "sk": "DEVOPS_OUTPUT"})
    item = resp.get("Item")
    if not item:
        return None
    return _coerce_output_numbers(item.get("devops_output"))


def _coerce_output_numbers(output: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not output:
        return output
    out = dict(output)
    for f in ("steps_total", "steps_completed", "total_duration_seconds", "approval_received_at"):
        if out.get(f) is not None:
            try:
                out[f] = int(out[f])
            except (TypeError, ValueError):
                pass
    return out


# ---------------------------------------------------------------------------
# Approval / rejection
# ---------------------------------------------------------------------------


def _update_output_field(*, run_id: str, updates: Dict[str, Any]) -> None:
    output = get_devops_output(run_id=run_id) or {}
    output.update(updates)
    item = T.agent_runs.get_item(Key={"pk": _run_pk(run_id), "sk": "DEVOPS_OUTPUT"}).get("Item") or {}
    agent_type_id = item.get("agent_type_id", "")
    store_devops_output(run_id=run_id, agent_type_id=agent_type_id, output=output)


def approve_deployment(*, run_id: str, approver_sub: str, notes: Optional[str]) -> Dict[str, Any]:
    output = get_devops_output(run_id=run_id)
    if output is None:
        raise LookupError("run_not_found")
    ts = now_ts()
    deployment_id = output.get("deployment_id", "")
    environment = output.get("environment", "")
    # Resume execution: run health checks, finalize.
    health_results = run_health_checks(
        health_check_urls=output.get("_health_check_urls", []),
        force_unhealthy=False,
    )
    output.update(
        {
            "status": "success",
            "approval_received_at": ts,
            "approval_status": "approved",
            "approved_by": approver_sub,
            "health_check_results": health_results,
            "steps_completed": output.get("steps_total", 0),
        }
    )
    _update_output_field(run_id=run_id, updates=output)
    ticket_id = output.get("ticket_id")
    if ticket_id:
        try:
            _set_ticket_status(ticket_id=ticket_id, status="deployed", actor_sub=approver_sub)
        except LookupError:
            pass
    return {
        "run_id": run_id,
        "deployment_id": deployment_id,
        "approval_status": "approved",
        "approved_by": approver_sub,
        "approved_at": ts,
        "notes": notes,
    }


def reject_deployment(*, run_id: str, approver_sub: str, notes: Optional[str]) -> Dict[str, Any]:
    output = get_devops_output(run_id=run_id)
    if output is None:
        raise LookupError("run_not_found")
    ts = now_ts()
    deployment_id = output.get("deployment_id", "")
    environment = output.get("environment", "")
    output.update(
        {"status": "rejected", "approval_status": "rejected", "approved_by": approver_sub}
    )
    _update_output_field(run_id=run_id, updates=output)
    release_env_mutex(environment=environment)
    ticket_id = output.get("ticket_id")
    if ticket_id:
        try:
            _set_ticket_status(ticket_id=ticket_id, status="blocked", actor_sub=approver_sub, reason=notes or "Deployment rejected")
        except LookupError:
            pass
    return {
        "run_id": run_id,
        "deployment_id": deployment_id,
        "approval_status": "rejected",
        "approved_by": approver_sub,
        "approved_at": ts,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Ticket status helpers (direct table writes — bypass strict transition machine)
# ---------------------------------------------------------------------------


def _set_ticket_status(
    *, ticket_id: str, status: str, actor_sub: str, reason: Optional[str] = None
) -> None:
    ticket = tickets_svc.STORE.get_ticket(ticket_id)
    if not ticket:
        raise LookupError("Ticket not found")
    table = tickets_svc.STORE._table  # noqa: SLF001
    ts = now_ts()
    meta = dict(ticket.get("metadata") or {})
    if reason:
        meta["devops_reason"] = reason
    table.update_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
        UpdateExpression="SET #st = :s, metadata = :m, updated_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":s": status, ":m": meta, ":ts": ts},
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def get_devops_metrics(*, agent_type_id: Optional[str] = None, period_days: int = 30) -> Dict[str, Any]:
    """Aggregate deployment frequency / success rate / MTTR / rollback rate."""
    ensure_tables()
    now = now_ts()
    period_start = now - period_days * 86400
    items: List[Dict[str, Any]] = []
    if agent_type_id:
        pk_val = f"DEVOPS#{agent_type_id}"
        try:
            resp = T.agent_runs.query(
                IndexName="ByTypeDate",
                KeyConditionExpression="gsi_type_date_pk = :pk",
                ExpressionAttributeValues={":pk": pk_val},
            )
            items = resp.get("Items", [])
        except ClientError:
            resp = T.agent_runs.scan(
                FilterExpression="gsi_type_date_pk = :pk",
                ExpressionAttributeValues={":pk": pk_val},
            )
            items = resp.get("Items", [])
    else:
        resp = T.agent_runs.scan(
            FilterExpression="sk = :sk",
            ExpressionAttributeValues={":sk": "DEVOPS_OUTPUT"},
        )
        items = resp.get("Items", [])

    total = 0
    successes = 0
    rollbacks = 0
    incidents = 0
    recovery_times: List[int] = []
    for it in items:
        if int(it.get("created_at", 0) or 0) < period_start:
            continue
        output = it.get("devops_output") or {}
        status = output.get("status")
        if status == "awaiting_approval":
            continue
        total += 1
        if status == "success":
            successes += 1
        if output.get("rollback_executed"):
            rollbacks += 1
            recovery_times.append(int(output.get("total_duration_seconds", 0) or 0))
        if output.get("incident_ticket_id"):
            incidents += 1

    success_rate = (successes / total) if total else 0.0
    rollback_rate = (rollbacks / total) if total else 0.0
    mttr = (sum(recovery_times) / len(recovery_times)) if recovery_times else 0.0
    frequency = (total / period_days) if period_days else 0.0
    return {
        "deployment_frequency": round(frequency, 4),
        "success_rate": round(success_rate, 4),
        "mttr_seconds": round(mttr, 2),
        "rollback_rate": round(rollback_rate, 4),
        "incidents_count": incidents,
        "period_start": period_start,
        "period_end": now,
    }


def list_recent_deployments(*, limit: int = 50) -> List[Dict[str, Any]]:
    """List recent deployments across all agents (scan DEVOPS_OUTPUT rows)."""
    ensure_tables()
    resp = T.agent_runs.scan(
        FilterExpression="sk = :sk",
        ExpressionAttributeValues={":sk": "DEVOPS_OUTPUT"},
    )
    rows = []
    for it in resp.get("Items", []):
        output = it.get("devops_output") or {}
        rows.append(
            {
                "run_id": it.get("run_id", ""),
                "agent_type_id": it.get("agent_type_id", ""),
                "deployment_id": output.get("deployment_id", ""),
                "ticket_id": output.get("ticket_id", ""),
                "environment": output.get("environment", ""),
                "status": output.get("status", ""),
                "version_deployed": output.get("version_deployed"),
                "total_duration_seconds": int(output.get("total_duration_seconds", 0) or 0),
                "created_at": int(it.get("created_at", 0) or 0),
            }
        )
    rows.sort(key=lambda r: r["created_at"], reverse=True)
    return rows[:limit]


# ---------------------------------------------------------------------------
# Mock lifecycle driver (deterministic E2E transitions)
# ---------------------------------------------------------------------------


def run_mock_workflow(
    *,
    run_id: str,
    agent_type_id: str,
    ticket: Dict[str, Any],
    config: Dict[str, Any],
    agent_sub: str,
    environment_name: Optional[str] = None,
    version: Optional[str] = None,
    force_health_failure: bool = False,
) -> Dict[str, Any]:
    """Drive the full deployment lifecycle in mock mode (no real execution).

    Gated: when ``S.agent_devops_execute_commands`` is true this would dispatch
    to the real Worker Agent Framework / compute launchers instead. Mock is the
    only path here so the state machine is fully driveable/testable.

    Returns the persisted devops_output. Handles three terminal outcomes:
      * production env w/ approval -> status="awaiting_approval" (blocks)
      * health failure -> rollback + incident ticket -> status="rolled_back"
      * otherwise -> status="success"
    """
    cfg = _coerce_numbers(config)
    environments = cfg.get("environments") or []
    environment = (
        _find_environment(cfg, environment_name) if environment_name else (environments[0] if environments else {})
    )
    if environment is None:
        environment = environments[0] if environments else {}
    env_name = environment.get("name", "")
    operation_type = classify_operation(ticket=ticket, config=cfg)
    deployment_id = f"dep-{uuid.uuid4().hex[:12]}"
    ticket_id = ticket.get("ticket_id", "")
    start_ts = now_ts()

    # Claim the ticket (best-effort; ignore if already claimed in tests).
    try:
        claim_devops_ticket(ticket_id=ticket_id, agent_sub=agent_sub, operation_type=operation_type)
    except (LookupError, ValueError):
        pass

    # Mutex (best-effort in mock).
    acquire_env_mutex(environment=env_name, deployment_id=deployment_id, agent_run_id=run_id)
    create_deployment_log(
        deployment_id=deployment_id, agent_run_id=run_id, ticket_id=ticket_id, environment=env_name
    )

    plan = generate_deployment_plan(ticket=ticket, environment=environment, version=version)
    deploy_commands = plan["deploy_commands"]

    # --- Approval gate (production) ---
    if environment.get("requires_approval", False):
        log_deployment_step(
            deployment_id=deployment_id, agent_run_id=run_id, ticket_id=ticket_id,
            environment=env_name, step_number=0, step_type="approval_wait",
            command="(awaiting human approval)", exit_code=None, stdout_tail="",
            stderr_tail="", started_at=start_ts, completed_at=start_ts, status="pending",
        )
        output = {
            "deployment_id": deployment_id,
            "ticket_id": ticket_id,
            "environment": env_name,
            "operation_type": operation_type,
            "status": "awaiting_approval",
            "version_deployed": version,
            "steps_total": len(deploy_commands) + 2,
            "steps_completed": 1,
            "health_check_results": [],
            "smoke_test_result": None,
            "rollback_executed": False,
            "rollback_success": None,
            "incident_ticket_id": None,
            "total_duration_seconds": 0,
            "approval_received_at": None,
            "monitoring_snapshot": None,
            # Internal carry-over for resume-on-approval.
            "_health_check_urls": environment.get("health_check_urls", []),
        }
        store_devops_output(run_id=run_id, agent_type_id=agent_type_id, output=output)
        return output

    # --- Execute deploy commands ---
    step_no = 0
    for cmd in deploy_commands:
        ts0 = now_ts()
        log_deployment_step(
            deployment_id=deployment_id, agent_run_id=run_id, ticket_id=ticket_id,
            environment=env_name, step_number=step_no, step_type="command",
            command=cmd, exit_code=0, stdout_tail="ok", stderr_tail="",
            started_at=ts0, completed_at=ts0 + 2, status="success",
        )
        step_no += 1

    # --- Health checks ---
    health_results = run_health_checks(
        health_check_urls=environment.get("health_check_urls", []),
        timeout_seconds=int(environment.get("health_check_timeout_seconds", 120)),
        force_unhealthy=force_health_failure,
    )
    for h in health_results:
        ts0 = now_ts()
        log_deployment_step(
            deployment_id=deployment_id, agent_run_id=run_id, ticket_id=ticket_id,
            environment=env_name, step_number=step_no, step_type="health_check",
            command=json.dumps(_health_check_argv(h["url"])), exit_code=0 if h["healthy"] else 1,
            stdout_tail=json.dumps({"status": "ok" if h["healthy"] else "fail"}),
            stderr_tail="", started_at=ts0, completed_at=ts0 + 1,
            status="success" if h["healthy"] else "failed",
        )
        step_no += 1

    # --- Smoke test ---
    smoke_result = run_smoke_test(
        command=environment.get("smoke_test_command"), force_fail=False
    )

    # --- Monitoring ---
    monitoring = monitor_post_deployment(
        monitoring_endpoints=cfg.get("monitoring_endpoints", []),
        window_seconds=int(environment.get("rollback_window_seconds", 300)),
    )

    rollback_executed = False
    rollback_success: Optional[bool] = None
    incident_ticket_id: Optional[str] = None
    status = "success"

    if should_auto_rollback(
        health_results=health_results, smoke_result=smoke_result, monitoring=monitoring
    ):
        rollback_executed = True
        status = "rolled_back"
        rb_ok = True
        for cmd in environment.get("rollback_commands") or []:
            ts0 = now_ts()
            log_deployment_step(
                deployment_id=deployment_id, agent_run_id=run_id, ticket_id=ticket_id,
                environment=env_name, step_number=step_no, step_type="rollback",
                command=cmd, exit_code=0, stdout_tail="rolled back", stderr_tail="",
                started_at=ts0, completed_at=ts0 + 2, status="rolled_back",
            )
            step_no += 1
        rollback_success = rb_ok
        # File an incident ticket with diagnostic data (§4.1.4).
        diagnosis = investigate_incident(ticket=ticket, coding_tool=cfg.get("coding_tool", "claude_code"))
        incident_data = build_incident_ticket(
            source_ticket=ticket,
            deployment_id=deployment_id,
            agent_run_id=run_id,
            environment=env_name,
            diagnosis=diagnosis,
            error_logs="health check failed: 503",
            metrics_snapshot=monitoring,
            rollback_status="success" if rollback_success else "failed",
            severity="P1",
        )
        incident_ticket_id = file_incident_ticket(
            incident_data=incident_data,
            space_id=cfg.get("incident_space_id"),
            agent_sub=agent_sub,
        )

    end_ts = now_ts()
    output = {
        "deployment_id": deployment_id,
        "ticket_id": ticket_id,
        "environment": env_name,
        "operation_type": operation_type,
        "status": status,
        "version_deployed": version,
        "steps_total": step_no,
        "steps_completed": step_no,
        "health_check_results": health_results,
        "smoke_test_result": smoke_result,
        "rollback_executed": rollback_executed,
        "rollback_success": rollback_success,
        "incident_ticket_id": incident_ticket_id,
        "total_duration_seconds": max(0, end_ts - start_ts),
        "approval_received_at": None,
        "monitoring_snapshot": monitoring,
    }
    store_devops_output(run_id=run_id, agent_type_id=agent_type_id, output=output)
    release_env_mutex(environment=env_name)

    # Update ticket status.
    try:
        _set_ticket_status(
            ticket_id=ticket_id,
            status="deployed" if status == "success" else "blocked",
            actor_sub=agent_sub,
        )
    except LookupError:
        pass
    return output
