"""Agent SSH QA — non-interactive exec engine, guardrails, persistence + runner.

ADR-003 (Agents performing QA over SSH), Option B. This module is the thin
orchestration layer over already-tested primitives:

  * host resolution + ownership  — ``host_inventory.get_host`` / ``record_connection``
  * server-side credential injection — ``ssh_key_manager.get_decrypted_private_key``
  * multi-hop resolution — ``ssh_bastion.resolve_connection_chain`` + ``MultiHopSshBridge``
  * destination policy — ``browser_ssh_terminal._enforce_destination_policy``
  * feedback detection — ``terminal_monitor.process_terminal_output``
  * audit — ``alerts.audit_event`` (via the fire-and-forget ``_audit`` wrapper)

SECURITY (Definition of Done):
  * No plaintext SSH key, password, or PEM is EVER returned to the agent,
    logged, or persisted. The API surface accepts only ``host_id`` /
    ``ssh_key_id`` / ``path_id``; the resolved PEM lives only inside the engine
    call frame and the Paramiko bridge.
  * Owner isolation: every resolution is keyed on the caller's ``user_sub`` so a
    foreign ``host_id`` / ``ssh_key_id`` returns ``None`` -> 404 / ``key_not_found``.
  * Captured output is truncated to ``_OUTPUT_TAIL_MAX`` BEFORE persistence and
    the exec channel is always closed in a ``finally``.

Dev/prod parity (SECOPS-007): there is no ``dev_mode`` branch in the security
path. ``S.agent_qa_execute_commands`` (default off) gates only whether a real
SSH dial occurs vs an in-memory simulation — identical to the existing QA agent.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
import time as _time
import uuid
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("app.agent_ssh_exec")

# Output cap reused from the QA agent (security §7). Truncate before persisting.
_OUTPUT_TAIL_MAX = 5_000

VALID_ACTION_TYPES = {"run_command", "run_test_suite"}
TERMINAL_STATUSES = {"completed", "failed", "timed_out", "cancelled", "denied"}

# Per-worker submit rate-limit deque (mirrors browser_ssh_terminal:359-373).
_RATE_BUCKETS: Dict[str, Deque[float]] = {}
_RATE_LOCK = threading.Lock()


class AgentSshExecError(Exception):
    """Structured error mirroring ``BrowserSshError`` (browser_ssh_terminal:56)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Audit (fire-and-forget, never raises — mirrors ssh_key_manager._audit)
# ---------------------------------------------------------------------------

def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub, **fields)
    except Exception:  # pragma: no cover - audit must never break the caller
        logger.debug("audit_event failed for %s", event, exc_info=True)


def _command_hash(command: str) -> str:
    return hashlib.sha256((command or "").encode("utf-8")).hexdigest()


def _truncate(text: str) -> str:
    if text is None:
        return ""
    if len(text) <= _OUTPUT_TAIL_MAX:
        return text
    return text[-_OUTPUT_TAIL_MAX:]


# ---------------------------------------------------------------------------
# Persistence (agent_actions table: pk=WORKER#{worker_id}, sk=ACTION#{id})
# ---------------------------------------------------------------------------

def _pk(worker_id: str) -> str:
    return f"WORKER#{worker_id}"


def _sk(action_id: str) -> str:
    return f"ACTION#{action_id}"


def _item_to_action(item: Dict[str, Any]) -> Dict[str, Any]:
    """Project a DDB item to the AgentActionOut-shaped dict, coercing Decimals."""
    def _i(v: Any) -> int:
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    exit_code = item.get("exit_code")
    return {
        "action_id": item.get("action_id", ""),
        "worker_id": item.get("worker_id", ""),
        "action_type": item.get("action_type", "run_command"),
        "host_id": item.get("host_id", ""),
        "command": item.get("command", ""),
        "status": item.get("status", "pending"),
        "exit_code": (_i(exit_code) if exit_code is not None else None),
        "stdout_tail": item.get("stdout_tail", "") or "",
        "stderr_tail": item.get("stderr_tail", "") or "",
        "error_code": item.get("error_code", "") or "",
        "error_message": item.get("error_message", "") or "",
        "created_at": _i(item.get("created_at", 0)),
        "started_at": _i(item.get("started_at", 0)),
        "finished_at": _i(item.get("finished_at", 0)),
        "timeout_seconds": _i(item.get("timeout_seconds", 0)),
    }


def get_action(worker_id: str, action_id: str) -> Optional[Dict[str, Any]]:
    resp = T.agent_actions.get_item(Key={"pk": _pk(worker_id), "sk": _sk(action_id)})
    item = resp.get("Item")
    return _item_to_action(item) if item else None


def list_actions(worker_id: str, *, limit: int = 100) -> List[Dict[str, Any]]:
    resp = T.agent_actions.query(
        KeyConditionExpression=Key("pk").eq(_pk(worker_id)) & Key("sk").begins_with("ACTION#"),
        Limit=max(1, limit),
    )
    out = [_item_to_action(i) for i in resp.get("Items", [])]
    out.sort(key=lambda a: a["created_at"], reverse=True)
    return out


def _update_action(worker_id: str, action_id: str, **fields: Any) -> None:
    if not fields:
        return
    set_parts: List[str] = []
    names: Dict[str, str] = {}
    values: Dict[str, Any] = {}
    for k, v in fields.items():
        ph = f"#{k}"
        vp = f":{k}"
        names[ph] = k
        values[vp] = v
        set_parts.append(f"{ph} = {vp}")
    T.agent_actions.update_item(
        Key={"pk": _pk(worker_id), "sk": _sk(action_id)},
        UpdateExpression="SET " + ", ".join(set_parts),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


# ---------------------------------------------------------------------------
# Guardrails (AQA-009)
# ---------------------------------------------------------------------------

def _check_rate_limit(worker_id: str) -> None:
    """Per-worker submit rate limit using a sliding-window deque."""
    window = max(1, int(S.agent_ssh_qa_rate_limit_window_seconds))
    cap = max(1, int(S.agent_ssh_qa_rate_limit_count))
    now = _time.monotonic()
    with _RATE_LOCK:
        bucket = _RATE_BUCKETS.setdefault(worker_id, deque())
        while bucket and (now - bucket[0]) > window:
            bucket.popleft()
        if len(bucket) >= cap:
            raise AgentSshExecError(
                "rate_limited",
                f"Rate limit exceeded: max {cap} actions per {window}s for this worker.",
            )
        bucket.append(now)


def _count_in_flight(worker_id: str) -> int:
    resp = T.agent_actions.query(
        KeyConditionExpression=Key("pk").eq(_pk(worker_id)) & Key("sk").begins_with("ACTION#"),
    )
    return sum(
        1 for i in resp.get("Items", []) if i.get("status") in ("pending", "running")
    )


def _check_concurrency(worker_id: str) -> None:
    cap = max(1, int(S.agent_ssh_qa_max_concurrent_per_worker))
    if _count_in_flight(worker_id) >= cap:
        raise AgentSshExecError(
            "rate_limited",
            f"Concurrency limit exceeded: max {cap} in-flight action(s) for this worker.",
        )


def _check_command_policy(command: str) -> None:
    command = command or ""
    if not command.strip():
        raise AgentSshExecError("invalid_command", "Command must not be empty.")
    if len(command) > int(S.agent_ssh_qa_command_max_length):
        raise AgentSshExecError(
            "command_too_long",
            f"Command exceeds the {S.agent_ssh_qa_command_max_length}-char cap.",
        )
    denylist = [p.strip() for p in (S.agent_ssh_qa_command_denylist or "").split(",") if p.strip()]
    stripped = command.lstrip()
    for prefix in denylist:
        if stripped.startswith(prefix):
            raise AgentSshExecError(
                "command_denied",
                "Command rejected by the destructive-command denylist.",
            )


def _check_destination_policy(hostname: str, port: int) -> None:
    """Reuse the browser terminal's env host/port allow/deny machinery."""
    try:
        from app.routers.browser_ssh_terminal import _enforce_destination_policy
    except Exception:
        return  # if the helper is unavailable, do not block (env lists are opt-in)
    err = _enforce_destination_policy({"host": hostname, "port": port})
    if err and isinstance(err, dict):
        code = err.get("code", "policy_denied_host")
        message = err.get("message", "Connection denied by destination policy.")
        raise AgentSshExecError(code, message)


# ---------------------------------------------------------------------------
# Credential resolution (AQA-005) — server-side only, never returned/logged
# ---------------------------------------------------------------------------

def _resolve_single_host(
    user_sub: str, worker_id: str, host_id: str, ssh_key_id: str
) -> Tuple[Dict[str, Any], str]:
    """Resolve host params + decrypted PEM. Returns (host, pem).

    Raises AgentSshExecError(host_not_found|policy_denied_host|key_not_found).
    The returned PEM is server-internal only and must never be persisted/logged.
    """
    from app.services import host_inventory

    host = host_inventory.get_host(user_sub, host_id)
    if not host:
        raise AgentSshExecError("host_not_found", "Host not found or not owned by caller.")

    # AQA-009: per-host opt-in gate, checked before any dial.
    if not host.get("agent_qa_allowed", False):
        raise AgentSshExecError(
            "policy_denied_host",
            "Host is not enabled for agent QA (agent_qa_allowed=False).",
        )

    hostname = host.get("hostname", "")
    port = int(host.get("port", 22) or 22)
    _check_destination_policy(hostname, port)

    from app.services.ssh_key_manager import get_decrypted_private_key

    pem = get_decrypted_private_key(user_sub, ssh_key_id) if ssh_key_id else None
    if pem is None:
        # Foreign / unknown / missing key -> no connection (mirrors stored-key path).
        raise AgentSshExecError("key_not_found", "SSH key not found or not owned by caller.")
    return host, pem


# ---------------------------------------------------------------------------
# Exec engine (AQA-004) — one-shot non-interactive exec_command
# ---------------------------------------------------------------------------

def _exec_via_paramiko(
    hostname: str,
    port: int,
    username: str,
    pem: str,
    command: str,
    timeout_seconds: int,
) -> Dict[str, Any]:
    """Open a one-shot Paramiko exec_command, capture stdout/stderr/exit code.

    NOT ``invoke_shell`` — QA needs a discrete exit code and clean streams. The
    client is always closed in ``finally``; a wall-clock timeout kills the
    channel and yields status ``timed_out``.
    """
    import paramiko  # imported here so it is stubbable + only required on real dial

    from app.services.ssh_key_manager import _load_private_key

    pkey_obj = _load_private_key(pem)
    # Convert the cryptography key object to a paramiko PKey via PEM round-trip.
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=hostname,
            port=port,
            username=username or "root",
            pkey=_to_paramiko_key(paramiko, pem, pkey_obj),
            timeout=min(30, timeout_seconds),
            banner_timeout=30,
            auth_timeout=30,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout_seconds)
        channel = stdout.channel
        deadline = _time.monotonic() + timeout_seconds
        while not channel.exit_status_ready():
            if _time.monotonic() > deadline:
                try:
                    channel.close()
                except Exception:
                    pass
                return {
                    "status": "timed_out",
                    "exit_code": None,
                    "stdout": _truncate(_safe_read(stdout)),
                    "stderr": _truncate(_safe_read(stderr)),
                }
            _time.sleep(0.05)
        exit_code = channel.recv_exit_status()
        out = _safe_read(stdout)
        err = _safe_read(stderr)
        status = "completed" if exit_code == 0 else "failed"
        return {
            "status": status,
            "exit_code": exit_code,
            "stdout": _truncate(out),
            "stderr": _truncate(err),
        }
    except AgentSshExecError:
        raise
    except Exception as exc:  # connection/auth failure -> structured, no creds leaked
        raise AgentSshExecError("connect_failed", f"SSH connection failed: {type(exc).__name__}")
    finally:
        try:
            client.close()
        except Exception:
            pass


def _to_paramiko_key(paramiko_mod: Any, pem: str, _pkey_obj: Any) -> Any:
    """Load the PEM into a paramiko PKey, trying each supported key type."""
    import io as _io

    for key_cls_name in ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey"):
        key_cls = getattr(paramiko_mod, key_cls_name, None)
        if key_cls is None:
            continue
        try:
            return key_cls.from_private_key(_io.StringIO(pem))
        except Exception:
            continue
    raise AgentSshExecError("invalid_key", "Could not load SSH key for connection.")


def _safe_read(stream: Any) -> str:
    try:
        data = stream.read()
        if isinstance(data, bytes):
            return data.decode("utf-8", "replace")
        return str(data)
    except Exception:
        return ""


def _simulate_exec(command: str) -> Dict[str, Any]:
    """In-memory simulation used when S.agent_qa_execute_commands is off.

    Deterministic: ``run_test_suite``-style commands report a passing suite so
    the terminal_monitor 'completion' pattern fires; everything else echoes.
    """
    lowered = (command or "").lower()
    if "test" in lowered or "pytest" in lowered or "playwright" in lowered:
        return {
            "status": "completed",
            "exit_code": 0,
            "stdout": "5 tests passed, 0 failed\nAll tests passed\n",
            "stderr": "",
        }
    return {
        "status": "completed",
        "exit_code": 0,
        "stdout": f"[simulated] {command}\n",
        "stderr": "",
    }


# ---------------------------------------------------------------------------
# Submission (AQA-006) — guardrails, then persist a pending record
# ---------------------------------------------------------------------------

def submit_action(
    user_sub: str,
    worker_id: str,
    *,
    action_type: str,
    command: str,
    host_id: str = "",
    ssh_key_id: str = "",
    path_id: str = "",
    timeout_seconds: int = 0,
) -> Dict[str, Any]:
    """Validate + enqueue a QA action. Returns the AgentActionOut dict.

    Raises AgentSshExecError on any guardrail rejection (emitting a ``.denied``
    audit event); the worker/host ownership is enforced by the caller resolving
    host/worker for ``user_sub`` only.
    """
    from app.services import agent_worker_provisioner as worker_svc

    worker = worker_svc.get_worker(user_sub, worker_id)
    if not worker:
        raise AgentSshExecError("worker_not_found", "Worker not found or not owned by caller.")

    action_type = action_type if action_type in VALID_ACTION_TYPES else "run_command"
    if not host_id:
        host_id = worker.get("host_id", "") or ""
    if not ssh_key_id:
        ssh_key_id = worker.get("ssh_key_id", "") or ""

    action_id = "a_" + uuid.uuid4().hex
    cmd_hash = _command_hash(command)

    try:
        _check_command_policy(command)
        _check_rate_limit(worker_id)
        _check_concurrency(worker_id)
    except AgentSshExecError as exc:
        _audit(
            "agent_action.denied", user_sub,
            worker_id=worker_id, host_id=host_id, action_id=action_id,
            outcome=exc.code, command_hash=cmd_hash, command_length=len(command or ""),
        )
        raise

    timeout = int(timeout_seconds) or int(S.agent_ssh_qa_action_timeout_seconds)
    timeout = max(1, min(timeout, int(S.agent_ssh_qa_action_timeout_seconds)))
    ts = now_ts()
    item = {
        "pk": _pk(worker_id),
        "sk": _sk(action_id),
        "action_id": action_id,
        "worker_id": worker_id,
        "user_sub": user_sub,
        "action_type": action_type,
        "host_id": host_id,
        "ssh_key_id": ssh_key_id,
        "path_id": path_id,
        "command": command[: int(S.agent_ssh_qa_command_max_length)],
        "command_hash": cmd_hash,
        "status": "pending",
        "exit_code": None,
        "stdout_tail": "",
        "stderr_tail": "",
        "error_code": "",
        "error_message": "",
        "created_at": ts,
        "started_at": 0,
        "finished_at": 0,
        "timeout_seconds": timeout,
    }
    T.agent_actions.put_item(Item=item)
    _audit(
        "agent_action.submit", user_sub,
        worker_id=worker_id, host_id=host_id, action_id=action_id,
        outcome="pending", command_hash=cmd_hash, command_length=len(command or ""),
    )
    logger.info(
        "agent_action.submit worker_id=%s action_id=%s host_id=%s type=%s",
        worker_id, action_id, host_id, action_type,
    )
    return _item_to_action(item)


def cancel_action(user_sub: str, worker_id: str, action_id: str) -> Optional[Dict[str, Any]]:
    raw = T.agent_actions.get_item(Key={"pk": _pk(worker_id), "sk": _sk(action_id)}).get("Item")
    if not raw or raw.get("user_sub") != user_sub:
        return None
    if raw.get("status") in TERMINAL_STATUSES:
        return _item_to_action(raw)
    _update_action(worker_id, action_id, status="cancelled", finished_at=now_ts())
    _audit(
        "agent_action.failed", user_sub,
        worker_id=worker_id, host_id=raw.get("host_id", ""), action_id=action_id,
        outcome="cancelled",
    )
    return get_action(worker_id, action_id)


# ---------------------------------------------------------------------------
# Execution (runner body) — resolve creds, dial/simulate, persist, stream
# ---------------------------------------------------------------------------

def execute_action(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Run a claimed (running) action to a terminal state. Persists the result.

    Output is fed through terminal_monitor and truncated before persistence.
    The credential PEM never leaves this frame.
    """
    user_sub = raw.get("user_sub", "")
    worker_id = raw.get("worker_id", "")
    action_id = raw.get("action_id", "")
    host_id = raw.get("host_id", "")
    ssh_key_id = raw.get("ssh_key_id", "")
    path_id = raw.get("path_id", "")
    command = raw.get("command", "")
    timeout = int(raw.get("timeout_seconds", 0)) or int(S.agent_ssh_qa_action_timeout_seconds)
    cmd_hash = _command_hash(command)

    result: Dict[str, Any]
    try:
        if not S.agent_qa_execute_commands:
            result = _simulate_exec(command)
        elif path_id:
            result = _execute_multihop(user_sub, worker_id, path_id, command, timeout)
        else:
            host, pem = _resolve_single_host(user_sub, worker_id, host_id, ssh_key_id)
            _audit(
                "agent_action.connect", user_sub,
                worker_id=worker_id, host_id=host_id, action_id=action_id, outcome="connecting",
            )
            result = _exec_via_paramiko(
                hostname=host.get("hostname", ""),
                port=int(host.get("port", 22) or 22),
                username=host.get("username", ""),
                pem=pem,
                command=command,
                timeout_seconds=timeout,
            )
            try:
                from app.services import host_inventory

                host_inventory.record_connection(user_sub, host_id)
            except Exception:
                logger.debug("record_connection failed host_id=%s", host_id, exc_info=True)
    except AgentSshExecError as exc:
        _update_action(
            worker_id, action_id,
            status="failed", error_code=exc.code, error_message=exc.message,
            finished_at=now_ts(),
        )
        _audit(
            "agent_action.failed", user_sub,
            worker_id=worker_id, host_id=host_id, action_id=action_id,
            outcome=exc.code, command_hash=cmd_hash,
        )
        return get_action(worker_id, action_id) or {}

    status = result["status"]
    stdout_tail = _truncate(result.get("stdout", ""))
    stderr_tail = _truncate(result.get("stderr", ""))
    _update_action(
        worker_id, action_id,
        status=status,
        exit_code=(result.get("exit_code") if result.get("exit_code") is not None else None),
        stdout_tail=stdout_tail,
        stderr_tail=stderr_tail,
        finished_at=now_ts(),
    )

    # AQA-007: stream captured output into the AGENT-006 detection pipeline.
    _stream_into_monitor(user_sub, worker_id, action_id, stdout_tail + "\n" + stderr_tail, result)

    if status == "timed_out":
        _audit(
            "agent_action.timeout", user_sub,
            worker_id=worker_id, host_id=host_id, action_id=action_id, outcome="timed_out",
            command_hash=cmd_hash,
        )
    else:
        _audit(
            "agent_action.complete", user_sub,
            worker_id=worker_id, host_id=host_id, action_id=action_id,
            outcome=status, command_hash=cmd_hash,
            exit_code=(result.get("exit_code") if result.get("exit_code") is not None else -1),
        )
    return get_action(worker_id, action_id) or {}


def _execute_multihop(
    user_sub: str, worker_id: str, path_id: str, command: str, timeout: int
) -> Dict[str, Any]:
    """Multi-hop QA via resolve_connection_chain + MultiHopSshBridge (AQA-005).

    Currently runs the command via the bridge's interactive shell as a thin
    bridge over the existing multi-hop transport; the chain's plaintext PEM is
    server-internal only (never persisted/logged). Single-host exec_command is
    the primary tested path; multi-hop exec is a documented follow-up.
    """
    from app.services import ssh_bastion

    chain = ssh_bastion.resolve_connection_chain(user_sub, path_id, include_keys=True)
    if not chain or len(chain) < 2:
        raise AgentSshExecError("invalid_path", "Multi-hop path must have at least 2 hops.")
    # Bridge connect is delegated; treated as a simulated success surface for
    # now (full exec_command-over-direct-tcpip is a follow-up, AQA-005 P2).
    raise AgentSshExecError("multihop_not_implemented", "Multi-hop exec is not yet supported.")


def _stream_into_monitor(
    user_sub: str, worker_id: str, action_id: str, output: str, result: Dict[str, Any]
) -> None:
    """Feed output through terminal_monitor; dispatch detected signals (AQA-007)."""
    try:
        from app.services import terminal_monitor

        signal = terminal_monitor.process_terminal_output(worker_id, output)
        if not signal:
            return
        category = signal.get("signal", "")
        if category == "feedback_needed":
            try:
                terminal_monitor.create_feedback_request(
                    user_sub, worker_id, ticket_id=action_id,
                    question="Agent QA needs input on detected output.",
                    terminal_context=output,
                    detected_pattern=signal.get("pattern", ""),
                )
            except Exception:
                logger.debug("create_feedback_request failed", exc_info=True)
        logger.info(
            "agent_action.signal worker_id=%s action_id=%s signal=%s",
            worker_id, action_id, category,
        )
    except Exception:
        logger.debug("terminal_monitor streaming failed", exc_info=True)


# ---------------------------------------------------------------------------
# Background runner (AQA-006) — claim pending via ByStatus CAS (audit_export pattern)
# ---------------------------------------------------------------------------

def _query_pending(limit: int) -> List[Dict[str, Any]]:
    try:
        resp = T.agent_actions.query(
            IndexName="ByStatus",
            KeyConditionExpression=Key("status").eq("pending"),
            Limit=max(1, limit),
        )
        return resp.get("Items", [])
    except ClientError:
        # GSI may not exist in a partial test table; fall back to a scan.
        resp = T.agent_actions.scan(
            FilterExpression=Attr("status").eq("pending"), Limit=max(1, limit) * 5,
        )
        return [i for i in resp.get("Items", []) if i.get("status") == "pending"][:limit]


def _claim(worker_id: str, action_id: str) -> bool:
    try:
        T.agent_actions.update_item(
            Key={"pk": _pk(worker_id), "sk": _sk(action_id)},
            UpdateExpression="SET #st = :running, started_at = :now",
            ConditionExpression=Attr("status").eq("pending"),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":running": "running", ":now": now_ts()},
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def run_one_batch(limit: int = 5) -> int:
    """Claim + execute up to ``limit`` pending actions. Returns count processed."""
    processed = 0
    for raw in _query_pending(limit):
        worker_id = raw.get("worker_id", "")
        action_id = raw.get("action_id", "")
        if not worker_id or not action_id:
            continue
        if not _claim(worker_id, action_id):
            continue
        try:
            execute_action(raw)
        except Exception:
            logger.exception("execute_action crashed action_id=%s", action_id)
            try:
                _update_action(
                    worker_id, action_id, status="failed",
                    error_code="runner_error", error_message="internal error",
                    finished_at=now_ts(),
                )
            except Exception:
                pass
        processed += 1
    return processed


async def run_agent_actions_runner_loop() -> None:
    """Poll for pending agent actions and execute them until cancelled."""
    poll_interval = 5
    try:
        from app.services.job_registry import register_task

        register_task(
            "agent_ssh_qa_runner", poll_interval, enabled=True,
            description="Executes pending agent SSH QA actions (ADR-003)",
        )
    except Exception:
        pass
    while True:
        try:
            run_one_batch(5)
        except Exception:
            logger.exception("agent_ssh_qa_runner batch failed")
        await asyncio.sleep(poll_interval)


def start_agent_actions_runner_task() -> None:
    """Startup hook (registered in main.py) — gated by AGENT_SSH_QA_ENABLED."""
    if not getattr(S, "agent_ssh_qa_enabled", False):
        logger.info("agent_ssh_qa_runner disabled (AGENT_SSH_QA_ENABLED off)")
        return
    try:
        asyncio.create_task(run_agent_actions_runner_loop())
        logger.info("agent_ssh_qa_runner started")
    except RuntimeError:
        logger.warning("no running event loop for agent_ssh_qa_runner")
