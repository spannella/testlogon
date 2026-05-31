"""Agent Worker Provisioner (AGENT-002).

Provisions compute infrastructure, installs AI coding tools,
injects LLM API keys, and registers workers for orchestration.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.ec2_launcher import (
    launch_instance,
    stop_instance,
    start_instance,
    terminate_instance,
)
from app.services.k8s_launcher import launch_pod, delete_pod
from app.services.llm_provider_keys import get_key

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool installation metadata
# ---------------------------------------------------------------------------

TOOL_INSTALL_SCRIPTS: Dict[str, Dict[str, Any]] = {
    "claude_code": {
        "install_commands": [
            "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -",
            "sudo apt-get install -y nodejs git",
            "sudo npm install -g @anthropic-ai/claude-code",
        ],
        "env_var": "ANTHROPIC_API_KEY",
        "verify_command": "claude --version",
        "verify_pattern": r"\d+\.\d+\.\d+",
    },
    "codex": {
        "install_commands": [
            "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -",
            "sudo apt-get install -y nodejs git",
            "sudo npm install -g @openai/codex",
        ],
        "env_var": "OPENAI_API_KEY",
        "verify_command": "codex --version",
        "verify_pattern": r"\d+\.\d+\.\d+",
    },
    "custom": {
        "install_commands": [],
        "env_var": "",
        "verify_command": "",
        "verify_pattern": "",
    },
}

TOOL_INFO_LIST = [
    {
        "tool": "claude_code",
        "display_name": "Claude Code",
        "description": "Anthropic's autonomous coding CLI",
        "install_time_seconds": 45,
        "required_provider": "anthropic",
    },
    {
        "tool": "codex",
        "display_name": "OpenAI Codex",
        "description": "OpenAI's code generation CLI",
        "install_time_seconds": 40,
        "required_provider": "openai",
    },
    {
        "tool": "custom",
        "display_name": "Custom Tool",
        "description": "User-provided tool with custom install script",
        "install_time_seconds": 0,
        "required_provider": "",
    },
]

COMPUTE_OPTIONS = [
    {"compute_type": "ec2", "instance_type": "t3.medium", "vcpu": 2, "memory_gb": 4.0, "cost_cents_per_min": 0.7, "startup_seconds": 45},
    {"compute_type": "ec2", "instance_type": "t3.large", "vcpu": 2, "memory_gb": 8.0, "cost_cents_per_min": 1.4, "startup_seconds": 45},
    {"compute_type": "ec2", "instance_type": "m5.xlarge", "vcpu": 4, "memory_gb": 16.0, "cost_cents_per_min": 3.2, "startup_seconds": 60},
    {"compute_type": "k8s", "instance_type": "standard-2cpu-4gb", "vcpu": 2, "memory_gb": 4.0, "cost_cents_per_min": 0.5, "startup_seconds": 8},
    {"compute_type": "k8s", "instance_type": "standard-4cpu-8gb", "vcpu": 4, "memory_gb": 8.0, "cost_cents_per_min": 1.0, "startup_seconds": 8},
]

# Provider required for each tool (for provider mismatch validation)
TOOL_REQUIRED_PROVIDER: Dict[str, str] = {
    "claude_code": "anthropic",
    "codex": "openai",
    "custom": "",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _item_to_worker(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DDB item to a clean worker dict, coercing Decimals."""
    out: Dict[str, Any] = {}
    for k, v in item.items():
        if k in ("pk", "sk"):
            continue
        if isinstance(v, Decimal):
            out[k] = int(v)
        elif isinstance(v, list):
            out[k] = [
                {kk: (int(vv) if isinstance(vv, Decimal) else vv) for kk, vv in entry.items()}
                if isinstance(entry, dict) else entry
                for entry in v
            ]
        else:
            out[k] = v
    return out


def _count_active_workers(user_id: str) -> int:
    """Count non-terminated workers for limit enforcement."""
    resp = T.agent_workers.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": f"USER#{user_id}", ":prefix": "WORKER#"},
    )
    items = resp.get("Items", [])
    active_statuses = {"provisioning", "installing", "ready", "running"}
    return sum(1 for item in items if item.get("worker_status") in active_statuses)


def _append_provision_step(
    user_id: str,
    worker_id: str,
    step: str,
    status: str,
    detail: str = "",
) -> None:
    """Append a step to the worker's provision log."""
    entry = {"step": step, "status": status, "ts": now_ts(), "detail": detail}
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET provision_log = list_append(if_not_exists(provision_log, :empty), :entry)",
        ExpressionAttributeValues={":entry": [entry], ":empty": []},
    )


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def create_worker(
    *,
    user_id: str,
    label: str,
    agent_type: str,
    tool: str,
    compute_type: str,
    instance_type: str,
    llm_key_id: str,
    repo_url: str = "",
    branch_convention: str = "agent/{worker_id}/{ticket_id}",
    idle_timeout_seconds: int = 7200,
    template_id: str = "",
    custom_install_commands: Optional[List[str]] = None,
    custom_env_var: str = "",
    custom_verify_command: str = "",
) -> Dict[str, Any]:
    """Create and provision a new agent worker.

    In dev mode, provisioning completes instantly (mock).
    """
    # 1. Validate LLM key
    key_data = get_key(user_id, llm_key_id)
    if not key_data:
        raise ValueError("LLM key not found")

    # 2. Provider mismatch check
    required_provider = TOOL_REQUIRED_PROVIDER.get(tool, "")
    if required_provider and key_data.get("provider") != required_provider:
        raise ValueError(
            f"The selected key is for {key_data.get('provider')}, "
            f"but {tool} requires {required_provider}."
        )

    # 3. Custom tool validation
    if tool == "custom" and not custom_install_commands:
        raise ValueError("Custom tool requires at least one install command.")

    # 4. Check worker limit
    max_workers = S.agent_max_workers_per_user
    active_count = _count_active_workers(user_id)
    if active_count >= max_workers:
        raise LookupError(
            f"You have reached the maximum of {max_workers} active workers. "
            "Terminate an existing worker first."
        )

    # 5. Create worker record
    worker_id = f"w_{uuid4().hex}"
    ts = now_ts()
    llm_provider = key_data.get("provider", "")

    item: Dict[str, Any] = {
        "pk": f"USER#{user_id}",
        "sk": f"WORKER#{worker_id}",
        "worker_id": worker_id,
        "user_id": user_id,
        "label": label,
        "agent_type": agent_type,
        "tool": tool,
        "tool_version": "",
        "compute_type": compute_type,
        "compute_instance_id": "",
        "instance_type": instance_type,
        "llm_key_id": llm_key_id,
        "llm_provider": llm_provider,
        "host_id": "",
        "public_ip": "",
        "worker_status": "provisioning",
        "provision_log": [],
        "repo_url": repo_url,
        "branch_convention": branch_convention,
        "idle_timeout_seconds": idle_timeout_seconds,
        "last_activity_at": 0,
        "created_at": ts,
        "started_at": 0,
        "stopped_at": 0,
        "terminated_at": 0,
        "template_id": template_id,
        "error_message": "",
    }

    T.agent_workers.put_item(Item=item)
    logger.info(
        "worker.created worker_id=%s user_id=%s tool=%s compute_type=%s instance_type=%s",
        worker_id, user_id, tool, compute_type, instance_type,
    )

    # 6. Dev mode: complete provisioning synchronously
    if S.dev_mode:
        _provision_worker_dev(user_id, worker_id, compute_type, instance_type, tool)

    return _item_to_worker(get_worker_raw(user_id, worker_id) or item)


def _provision_worker_dev(
    user_id: str,
    worker_id: str,
    compute_type: str,
    instance_type: str,
    tool: str,
) -> None:
    """Dev mode provisioning — complete all steps instantly in-memory."""
    try:
        # Step 1: Launch compute
        _append_provision_step(user_id, worker_id, "compute_launch", "running")
        if compute_type == "ec2":
            result = launch_instance(user_id, instance_type=instance_type)
            compute_id = result["ec2_instance_id"]
            public_ip = result.get("public_ip", "")
        else:
            result = launch_pod(user_id)
            compute_id = result["pod_name"]
            public_ip = result.get("pod_ip", "")

        host_id = f"h_{uuid4().hex[:16]}"
        _append_provision_step(user_id, worker_id, "compute_launch", "done", compute_id)

        T.agent_workers.update_item(
            Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
            UpdateExpression="SET compute_instance_id = :cid, public_ip = :ip, host_id = :hid",
            ExpressionAttributeValues={":cid": compute_id, ":ip": public_ip, ":hid": host_id},
        )

        # Step 2: Install tool
        _append_provision_step(user_id, worker_id, "tool_install", "running")
        tool_config = TOOL_INSTALL_SCRIPTS.get(tool, TOOL_INSTALL_SCRIPTS["custom"])
        tool_version = "1.0.23" if tool == "claude_code" else ("0.9.5" if tool == "codex" else "1.0.0")
        _append_provision_step(
            user_id, worker_id, "tool_install", "done",
            f"{tool}@{tool_version}",
        )

        # Step 3: Inject key
        _append_provision_step(user_id, worker_id, "key_inject", "running")
        _append_provision_step(user_id, worker_id, "key_inject", "done")

        # Step 4: Verify
        _append_provision_step(user_id, worker_id, "verify", "running")
        _append_provision_step(user_id, worker_id, "verify", "done", f"v{tool_version}")

        # Mark ready
        ts = now_ts()
        T.agent_workers.update_item(
            Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
            UpdateExpression="SET worker_status = :st, started_at = :ts, tool_version = :tv",
            ExpressionAttributeValues={":st": "ready", ":ts": ts, ":tv": tool_version},
        )
        logger.info("worker.ready worker_id=%s tool_version=%s", worker_id, tool_version)

    except Exception as e:
        logger.error("worker.provision.error worker_id=%s error=%s", worker_id, str(e))
        T.agent_workers.update_item(
            Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
            UpdateExpression="SET worker_status = :st, error_message = :msg",
            ExpressionAttributeValues={":st": "error", ":msg": str(e)},
        )


def get_worker_raw(user_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
    """Get a single worker by ID (raw DDB item)."""
    resp = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    )
    return resp.get("Item")


def get_worker(user_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
    """Get a single worker by ID (cleaned for API output)."""
    item = get_worker_raw(user_id, worker_id)
    return _item_to_worker(item) if item else None


def list_workers(
    user_id: str,
    *,
    status: Optional[str] = None,
    agent_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List user's agent workers with optional filters."""
    if status:
        resp = T.agent_workers.query(
            IndexName="ByStatus",
            KeyConditionExpression="pk = :pk AND worker_status = :st",
            ExpressionAttributeValues={":pk": f"USER#{user_id}", ":st": status},
        )
    elif agent_type:
        resp = T.agent_workers.query(
            IndexName="ByAgentType",
            KeyConditionExpression="pk = :pk AND agent_type = :at",
            ExpressionAttributeValues={":pk": f"USER#{user_id}", ":at": agent_type},
        )
    else:
        resp = T.agent_workers.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={":pk": f"USER#{user_id}", ":prefix": "WORKER#"},
        )

    return [_item_to_worker(item) for item in resp.get("Items", [])]


def stop_worker(user_id: str, worker_id: str) -> Dict[str, Any]:
    """Stop a running worker. Preserves state for restart."""
    item = get_worker_raw(user_id, worker_id)
    if not item:
        raise ValueError("Worker not found")
    status = item["worker_status"]
    if status not in ("ready", "running"):
        raise ValueError(f"Cannot stop worker in state: {status}")

    # Stop underlying compute
    if item["compute_type"] == "ec2" and item.get("compute_instance_id"):
        stop_instance(user_id, item["compute_instance_id"])
    # K8s pods are stateless — stopping means deleting
    elif item["compute_type"] == "k8s" and item.get("compute_instance_id"):
        delete_pod(user_id, item["compute_instance_id"])

    ts = now_ts()
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET worker_status = :st, stopped_at = :ts",
        ExpressionAttributeValues={":st": "stopped", ":ts": ts},
    )
    return get_worker(user_id, worker_id)  # type: ignore


def start_worker(user_id: str, worker_id: str) -> Dict[str, Any]:
    """Restart a stopped worker."""
    item = get_worker_raw(user_id, worker_id)
    if not item:
        raise ValueError("Worker not found")
    status = item["worker_status"]
    if status != "stopped":
        raise ValueError(f"Cannot start worker in state: {status}")

    # Restart underlying compute
    if item["compute_type"] == "ec2" and item.get("compute_instance_id"):
        start_instance(user_id, item["compute_instance_id"])

    ts = now_ts()
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET worker_status = :st, started_at = :ts",
        ExpressionAttributeValues={":st": "ready", ":ts": ts},
    )
    return get_worker(user_id, worker_id)  # type: ignore


def terminate_worker(user_id: str, worker_id: str) -> Dict[str, Any]:
    """Terminate a worker permanently. Cleans up compute resources."""
    item = get_worker_raw(user_id, worker_id)
    if not item:
        raise ValueError("Worker not found")
    status = item["worker_status"]
    if status == "terminated":
        raise ValueError("Worker is already terminated.")

    # Terminate underlying compute
    if item["compute_type"] == "ec2" and item.get("compute_instance_id"):
        terminate_instance(user_id, item["compute_instance_id"])
    elif item["compute_type"] == "k8s" and item.get("compute_instance_id"):
        delete_pod(user_id, item["compute_instance_id"])

    ts = now_ts()
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET worker_status = :st, terminated_at = :ts",
        ExpressionAttributeValues={":st": "terminated", ":ts": ts},
    )
    return get_worker(user_id, worker_id)  # type: ignore


def get_provision_log(user_id: str, worker_id: str) -> List[Dict[str, Any]]:
    """Get the provisioning log for a worker."""
    item = get_worker_raw(user_id, worker_id)
    if not item:
        return []
    log = item.get("provision_log", [])
    # Coerce Decimals in log entries
    out = []
    for entry in log:
        clean: Dict[str, Any] = {}
        for k, v in entry.items():
            clean[k] = int(v) if isinstance(v, Decimal) else v
        out.append(clean)
    return out


def check_idle_workers() -> int:
    """Background task: find and stop workers where
    now() - last_activity_at > idle_timeout_seconds.
    Returns count of workers stopped."""
    # Simplified implementation — in production this would scan all users
    return 0
