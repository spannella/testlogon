# AGENT-002: Terminal Worker Provisioning

**Ticket**: AGENT-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 8-10 days
**Dependencies**: AGENT-001 (LLM Provider Key Management), INFRA-003 (EC2 Instance Launcher), INFRA-004 (Kubernetes Container Launcher)

---

## 1. Overview & Motivation

### 1.1 Purpose

AGENT-002 bridges compute infrastructure (EC2 instances / K8s pods) and AI coding tools (Claude Code CLI, OpenAI Codex CLI) into a single provisioning flow. When a user creates a new agent worker, the system provisions a compute instance, automatically installs the selected AI coding tool, injects the user's LLM API key from AGENT-001, verifies the tool is operational, and registers the worker in DynamoDB for orchestration by AGENT-003.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| User | As a user, I want to create a new agent worker with one click so that I don't have to manually provision infrastructure and install tools. | Click "Create Worker"; system provisions EC2/K8s, installs Claude Code, injects API key, reports ready. |
| User | As a user, I want to select which AI tool to install (Claude Code, Codex) so that I can use my preferred agent. | Worker creation form has tool selector; selected tool is installed and verified on the instance. |
| User | As a user, I want my LLM API key automatically injected so that I don't have to paste secrets into terminals. | Worker references AGENT-001 key_id; provisioner decrypts key and sets environment variable on instance. |
| User | As a user, I want to SSH into my worker instance via the web terminal so that I can inspect or debug what the agent is doing. | Worker detail page has "Open Terminal" button; opens SSH session to the worker instance. |
| User | As a user, I want workers to auto-shutdown after being idle to save money. | Configurable idle timeout; worker stops/terminates when no ticket activity for the timeout period. |
| User | As a user, I want to start, stop, and terminate workers so that I control costs. | Lifecycle buttons on worker detail; state changes reflected in DynamoDB and on compute. |
| User | As a user, I want to use a worker template so that I can quickly recreate a known-good configuration. | Save current worker config as template; "Create from Template" button. |

### 1.3 Why This Is Needed

Manual agent setup is a multi-step process: launch an EC2 instance, SSH in, install Node.js, install Claude Code CLI (`npm install -g @anthropic-ai/claude-code`), export the API key, clone the repo, and run `claude`. This takes 10-15 minutes and is error-prone. AGENT-002 reduces this to a single API call that completes in under 60 seconds, enabling the fleet management (AGENT-004) and autonomous agent loop (AGENT-003) that follow.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| EC2 launcher | `app/services/ec2_launcher.py` (INFRA-003) | `launch_instance()`, `stop_instance()`, `terminate_instance()`; provides compute VMs |
| K8s launcher | `app/services/k8s_launcher.py` (INFRA-004) | `launch_pod()`, `delete_pod()`; provides lightweight containers |
| SSH key manager | `app/services/ssh_key_manager.py` (INFRA-002) | Key generation and host association for SSH access |
| Host inventory | `app/services/remote_hosts.py` (INFRA-001) | Auto-registered hosts from EC2/K8s launches |
| LLM key store | `app/services/llm_provider_keys.py` (AGENT-001) | `get_decrypted_api_key()` for injecting LLM credentials |
| Web terminal | `app/routers/terminal.py` | WebSocket-based SSH terminal in the browser |
| Mock EC2 store | `app/services/ec2_launcher.py` | `_MockEc2Store` for dev mode |
| Mock K8s store | `app/services/k8s_launcher.py` | `_MockK8sStore` for dev mode |
| Settings | `app/core/settings.py` | `S.dev_mode`, table names, etc. |
| Crypto | `app/core/crypto.py` | KMS decrypt for API keys |

### 2.2 Gaps

1. **No tool installer** -- no automation for installing Claude Code CLI, Codex CLI, or other AI tools on provisioned instances.
2. **No credential injection** -- no mechanism to set environment variables (API keys) on remote instances without manual terminal interaction.
3. **No worker registry** -- no DynamoDB table tracking which instances are designated as agent workers vs. general-purpose instances.
4. **No tool verification** -- no automated check that the installed tool is functional (`claude --version`, test prompt).
5. **No startup script templates** -- no pre-built cloud-init / user-data scripts for AI tool installation.
6. **No worker-to-key binding** -- no link between a compute instance and its assigned LLM key.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `agent_workers`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.agent_workers_table_name, "agent_workers"),
    "pk",              # USER#{user_id}
    "sk",              # WORKER#{worker_id}
    gsis=[
        {"index_name": "ByStatus", "partition_key": "pk", "sort_key": "worker_status"},
        {"index_name": "ByCreatedAt", "partition_key": "pk", "sort_key": "created_at"},
        {"index_name": "ByAgentType", "partition_key": "pk", "sort_key": "agent_type"},
    ],
    attr_types={"created_at": "N"},
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `pk` | S (PK) | `USER#{user_id}` |
| `sk` | S (SK) | `WORKER#{worker_id}` |
| `worker_id` | S | UUID hex identifier |
| `user_id` | S | Owner user_sub |
| `label` | S | User-assigned name (e.g., "Coder Agent #1") |
| `agent_type` | S | `coder`, `qa`, `reviewer`, `devops`, `custom` |
| `tool` | S | `claude_code`, `codex`, `custom` |
| `tool_version` | S | Installed tool version (e.g., "1.0.23") |
| `compute_type` | S | `ec2` or `k8s` |
| `compute_instance_id` | S | Reference to EC2 instance_id or K8s pod_id |
| `instance_type` | S | EC2 instance type or K8s preset (e.g., `t3.medium`) |
| `llm_key_id` | S | Reference to AGENT-001 key |
| `llm_provider` | S | Denormalized from key: `openai`, `anthropic`, etc. |
| `host_id` | S | Reference to host inventory for SSH access |
| `public_ip` | S | Denormalized from compute instance |
| `worker_status` | S | `provisioning`, `installing`, `ready`, `running`, `stopped`, `error`, `terminated` |
| `provision_log` | L | List of provisioning step entries: `{step, status, ts, detail}` |
| `repo_url` | S | Git repository URL cloned on the instance |
| `branch_convention` | S | Branch naming convention (e.g., `agent/{worker_id}/{ticket_id}`) |
| `idle_timeout_seconds` | N | Auto-shutdown after this many seconds of inactivity (default 7200) |
| `last_activity_at` | N | Unix timestamp of last agent action |
| `created_at` | N | Unix timestamp |
| `started_at` | N | Unix timestamp when worker reached `ready` |
| `stopped_at` | N | Unix timestamp of last stop |
| `terminated_at` | N | Unix timestamp of termination |
| `template_id` | S | Worker template used for creation (optional) |
| `error_message` | S | Last error message if status=error |

### 3.2 Tool Installation Scripts

```python
# In app/services/agent_worker_provisioner.py

TOOL_INSTALL_SCRIPTS = {
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
        "install_commands": [],  # User-provided
        "env_var": "",           # User-provided
        "verify_command": "",    # User-provided
        "verify_pattern": "",
    },
}
```

### 3.3 Backend Service

**New file**: `app/services/agent_worker_provisioner.py` (~500 lines)

```python
"""Agent Worker Provisioner (AGENT-002).

Provisions compute infrastructure, installs AI coding tools,
injects LLM API keys, and registers workers for orchestration.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.tables import T
from app.core.time import now_ts
from app.services.ec2_launcher import launch_instance, stop_instance, start_instance, terminate_instance
from app.services.llm_provider_keys import get_decrypted_api_key, get_key

logger = logging.getLogger(__name__)

MAX_WORKERS_PER_USER = 5


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
    custom_install_commands: List[str] | None = None,
    custom_env_var: str = "",
    custom_verify_command: str = "",
) -> Dict[str, Any]:
    """Create and provision a new agent worker.

    Orchestrates the full provisioning flow:
    1. Validate inputs (agent_type, tool, compute_type, LLM key exists)
    2. Check worker limit
    3. Build startup script (tool install + key injection + repo clone)
    4. Launch compute instance (EC2 or K8s)
    5. Register worker in DDB with status=provisioning
    6. Return worker record (provisioning continues asynchronously)
    """


def _build_startup_script(
    *,
    tool: str,
    api_key: str,
    env_var: str,
    repo_url: str,
    custom_commands: List[str] | None = None,
) -> str:
    """Build cloud-init / startup script for tool installation."""
    lines = ["#!/bin/bash", "set -e", ""]
    
    # Install tool
    tool_config = TOOL_INSTALL_SCRIPTS.get(tool, TOOL_INSTALL_SCRIPTS["custom"])
    commands = custom_commands or tool_config["install_commands"]
    lines.extend(commands)
    
    # Inject API key as environment variable
    actual_env_var = env_var or tool_config["env_var"]
    if actual_env_var and api_key:
        lines.append(f'echo "export {actual_env_var}={api_key}" >> ~/.bashrc')
        lines.append(f'export {actual_env_var}="{api_key}"')
    
    # Clone repo
    if repo_url:
        lines.append(f"git clone {repo_url} ~/workspace")
        lines.append("cd ~/workspace")
    
    # Verify tool
    verify_cmd = tool_config.get("verify_command")
    if verify_cmd:
        lines.append(f"{verify_cmd}")
    
    return "\n".join(lines)


def get_worker(user_id: str, worker_id: str) -> Dict[str, Any] | None:
    """Get a single worker by ID."""
    resp = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    )
    return resp.get("Item")


def list_workers(
    user_id: str,
    *,
    status: str | None = None,
    agent_type: str | None = None,
) -> List[Dict[str, Any]]:
    """List user's agent workers with optional filters."""


def stop_worker(user_id: str, worker_id: str) -> Dict[str, Any]:
    """Stop a running worker. Preserves state for restart."""
    worker = get_worker(user_id, worker_id)
    if not worker:
        raise ValueError("Worker not found")
    if worker["worker_status"] not in ("ready", "running"):
        raise ValueError(f"Cannot stop worker in state: {worker['worker_status']}")
    
    # Stop underlying compute
    if worker["compute_type"] == "ec2":
        stop_instance(user_id, worker["compute_instance_id"])
    # K8s pods are stateless — stopping means deleting
    
    ts = now_ts()
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET worker_status = :st, stopped_at = :ts",
        ExpressionAttributeValues={":st": "stopped", ":ts": ts},
    )
    return get_worker(user_id, worker_id)


def start_worker(user_id: str, worker_id: str) -> Dict[str, Any]:
    """Restart a stopped worker."""


def terminate_worker(user_id: str, worker_id: str) -> Dict[str, Any]:
    """Terminate a worker permanently. Cleans up compute resources."""
    worker = get_worker(user_id, worker_id)
    if not worker:
        raise ValueError("Worker not found")
    
    # Terminate underlying compute
    if worker["compute_type"] == "ec2":
        terminate_instance(user_id, worker["compute_instance_id"])
    
    ts = now_ts()
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET worker_status = :st, terminated_at = :ts",
        ExpressionAttributeValues={":st": "terminated", ":ts": ts},
    )
    return get_worker(user_id, worker_id)


def get_provision_log(user_id: str, worker_id: str) -> List[Dict[str, Any]]:
    """Get the provisioning log for a worker."""
    worker = get_worker(user_id, worker_id)
    return worker.get("provision_log", []) if worker else []


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


def check_idle_workers() -> int:
    """Background task: find and stop workers where
    now() - last_activity_at > idle_timeout_seconds.
    Returns count of workers stopped."""
```

### 3.4 Backend Router

**New file**: `app/routers/agent_workers.py` (~250 lines)

Prefix: `/ui/agent/workers`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/agent/workers` | `require_ui_session` | Create a new agent worker |
| `GET` | `/ui/agent/workers` | `require_ui_session` | List user's workers |
| `GET` | `/ui/agent/workers/{worker_id}` | `require_ui_session` | Get worker details |
| `POST` | `/ui/agent/workers/{worker_id}/stop` | `require_ui_session` | Stop a worker |
| `POST` | `/ui/agent/workers/{worker_id}/start` | `require_ui_session` | Start a stopped worker |
| `DELETE` | `/ui/agent/workers/{worker_id}` | `require_ui_session` | Terminate a worker |
| `GET` | `/ui/agent/workers/{worker_id}/provision-log` | `require_ui_session` | Get provisioning log |
| `GET` | `/ui/agent/workers/tools` | `require_ui_session` | List available AI tools |
| `GET` | `/ui/agent/workers/compute-options` | `require_ui_session` | List compute options (EC2 types + K8s presets) |

### 3.5 Pydantic Models

**Add to `app/models.py`**:

```python
# -- Agent Worker Provisioning (AGENT-002) --

class CreateWorkerIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=200)
    agent_type: str = Field(..., pattern="^(coder|qa|reviewer|devops|custom)$")
    tool: str = Field(..., pattern="^(claude_code|codex|custom)$")
    compute_type: str = Field(..., pattern="^(ec2|k8s)$")
    instance_type: str = Field(..., min_length=1)
    llm_key_id: str = Field(..., min_length=1)
    repo_url: str = Field(default="", max_length=500)
    branch_convention: str = Field(default="agent/{worker_id}/{ticket_id}", max_length=200)
    idle_timeout_seconds: int = Field(default=7200, ge=600, le=86400)
    template_id: str = Field(default="", max_length=100)
    custom_install_commands: Optional[List[str]] = None
    custom_env_var: str = Field(default="", max_length=100)
    custom_verify_command: str = Field(default="", max_length=500)

class ProvisionStepOut(BaseModel):
    step: str
    status: str
    ts: int
    detail: str = ""

class WorkerOut(BaseModel):
    worker_id: str
    user_id: str
    label: str
    agent_type: str
    tool: str
    tool_version: str = ""
    compute_type: str
    compute_instance_id: str = ""
    instance_type: str
    llm_key_id: str
    llm_provider: str = ""
    host_id: str = ""
    public_ip: str = ""
    worker_status: str
    provision_log: List[ProvisionStepOut] = Field(default_factory=list)
    repo_url: str = ""
    branch_convention: str = ""
    idle_timeout_seconds: int = 7200
    last_activity_at: int = 0
    created_at: int = 0
    started_at: int = 0
    stopped_at: int = 0
    terminated_at: int = 0
    template_id: str = ""
    error_message: str = ""

class WorkerListOut(BaseModel):
    workers: List[WorkerOut]
    count: int

class ToolInfo(BaseModel):
    tool: str
    display_name: str
    description: str
    install_time_seconds: int
    required_provider: str

class ToolListOut(BaseModel):
    tools: List[ToolInfo]

class ComputeOption(BaseModel):
    compute_type: str
    instance_type: str
    vcpu: int
    memory_gb: float
    cost_cents_per_min: float
    startup_seconds: int

class ComputeOptionListOut(BaseModel):
    options: List[ComputeOption]
```

### 3.6 Provisioning Flow (Async)

The `create_worker` endpoint returns immediately with `worker_status: "provisioning"`. The actual provisioning runs as a background task:

```python
async def _provision_worker_background(user_id: str, worker_id: str):
    """Background provisioning task.

    Steps:
    1. provisioning  — Launch compute instance (EC2 or K8s)
    2. installing    — Run tool installation script via SSH/exec
    3. verifying     — Run verify command (claude --version)
    4. configuring   — Set up repo, branch conventions, agent identity
    5. ready         — Worker is ready for ticket assignment
    """
    try:
        _append_provision_step(user_id, worker_id, "compute_launch", "running")
        # Launch compute...
        _append_provision_step(user_id, worker_id, "compute_launch", "done", "Instance i-mock...")
        
        _append_provision_step(user_id, worker_id, "tool_install", "running")
        # Install tool via startup script...
        _append_provision_step(user_id, worker_id, "tool_install", "done", "claude-code@1.0.23")
        
        _append_provision_step(user_id, worker_id, "key_inject", "running")
        # Inject API key as env var...
        _append_provision_step(user_id, worker_id, "key_inject", "done")
        
        _append_provision_step(user_id, worker_id, "verify", "running")
        # Verify tool works...
        _append_provision_step(user_id, worker_id, "verify", "done", "v1.0.23")
        
        # Mark ready
        T.agent_workers.update_item(
            Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
            UpdateExpression="SET worker_status = :st, started_at = :ts",
            ExpressionAttributeValues={":st": "ready", ":ts": now_ts()},
        )
    except Exception as e:
        T.agent_workers.update_item(
            Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
            UpdateExpression="SET worker_status = :st, error_message = :msg",
            ExpressionAttributeValues={":st": "error", ":msg": str(e)},
        )
```

### 3.7 Frontend Components

#### WorkerCreateWizard (`frontend/src/pages/agents/WorkerCreateWizard.tsx`)

Dialog/page (~350 lines):

- **Step 1**: Agent type selector (card grid: Coder, QA, Reviewer, DevOps, Custom)
- **Step 2**: AI tool selector (Claude Code, Codex, Custom)
- **Step 3**: Compute selector (EC2 instance types + K8s presets with cost/performance info)
- **Step 4**: LLM key selector (dropdown of keys from AGENT-001, filtered by tool compatibility)
- **Step 5**: Configuration -- label, repo URL, branch convention, idle timeout
- **Create button**: Shows estimated cost per hour

#### Route & Navigation

```tsx
<Route path="/agents/workers" element={<WorkersPage />} />
```

Sidebar: "Workers" with `Bot` icon under "AI Agents" group.

---

## 4. Implementation Plan

### Phase 1: DDB + Service Layer (3-4 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `agent_workers_table_name`, `agent_max_workers_per_user` |
| `app/core/tables.py` | Add `agent_workers` table handle |
| `scripts/local-ddb-init.py` | Add `agent_workers` TableDef with 3 GSIs |
| `app/services/agent_worker_provisioner.py` | New file: create, list, get, stop, start, terminate, idle checker |
| `app/models.py` | Add Worker Pydantic models |

### Phase 2: Router + Background Task (2 days)

| File | Change |
|------|--------|
| `app/routers/agent_workers.py` | New file: 9 endpoints |
| `app/main.py` | Register router + idle worker checker background task |

### Phase 3: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add Worker TypeScript types |
| `frontend/src/api/endpoints/agentWorkers.ts` | New file: API wrappers |
| `frontend/src/pages/agents/WorkerCreateWizard.tsx` | New file: creation wizard |
| `frontend/src/App.tsx` | Add `/agents/workers` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Workers" nav item |

### Phase 4: E2E Tests (1-2 days)

| File | Change |
|------|--------|
| `frontend/e2e/agent-workers.spec.ts` | New file: ~16 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/agent-workers.spec.ts`)

**Test setup**: Uses `e2e_admin_session_setup.py` sessions. Alice is the primary test user. `beforeAll` creates an LLM key via AGENT-001 API for use in worker creation tests.

**Section 627: Compute & Tool Options API (3 tests)**

1. `List available AI tools` -- GET `/ui/agent/workers/tools`. Verify at least 2 tools: `claude_code` with `display_name: "Claude Code"`, `codex` with `display_name: "OpenAI Codex"`. Each has `install_time_seconds > 0`.
2. `List compute options` -- GET `/ui/agent/workers/compute-options`. Verify at least 2 EC2 options and at least 1 K8s option. Each has `vcpu`, `memory_gb`, `cost_cents_per_min`.
3. `Compute options include startup time` -- Verify K8s options have `startup_seconds < 10` and EC2 options have `startup_seconds > 20`.

**Section 628: Worker CRUD API (5 tests)**

4. `Alice creates a Claude Code worker on EC2` -- POST `/ui/agent/workers` with `agent_type: "coder"`, `tool: "claude_code"`, `compute_type: "ec2"`, `instance_type: "t3.medium"`, `llm_key_id` from setup. Verify 201 with `worker_id`, `worker_status` in `["provisioning", "installing", "ready"]`, `tool: "claude_code"`, `compute_type: "ec2"`.
5. `Worker provisioning completes to ready` -- Poll GET `/ui/agent/workers/{worker_id}` until `worker_status === "ready"` (max 10s). Verify `provision_log` has at least 3 entries, `public_ip` is non-empty, `host_id` is non-empty.
6. `Alice lists workers` -- GET `/ui/agent/workers`. Verify `count >= 1`, first worker has matching `worker_id`.
7. `Alice cannot exceed worker limit` -- Create workers until hitting `MAX_WORKERS_PER_USER`. Attempt one more, verify 409 or 400 with message about limit.
8. `Invalid LLM key_id returns 400` -- POST with `llm_key_id: "nonexistent_key"`. Verify 400 error about LLM key not found.

**Section 629: Worker Lifecycle API (5 tests)**

9. `Alice stops a running worker` -- POST `/ui/agent/workers/{worker_id}/stop`. Verify `worker_status: "stopped"`, `stopped_at > 0`.
10. `Alice starts a stopped worker` -- POST `/ui/agent/workers/{worker_id}/start`. Verify `worker_status` transitions to `ready`.
11. `Alice terminates a worker` -- DELETE `/ui/agent/workers/{worker_id}`. Verify `worker_status: "terminated"`, `terminated_at > 0`.
12. `Cannot stop an already terminated worker` -- POST `/stop` on terminated worker. Verify 400/409.
13. `Provision log shows all steps` -- GET `/ui/agent/workers/{worker_id}/provision-log`. Verify list with entries for `compute_launch`, `tool_install`, `key_inject`, `verify`. Each entry has `step`, `status`, `ts`.

**Section 630: Worker Creation UI (5 tests)**

14. `Workers page renders empty state` -- Navigate to `/agents/workers`. Verify "No workers" empty state message visible.
15. `Create Worker wizard shows agent type selector` -- Click "Create Worker" button. Verify cards for "Coder", "QA", "Reviewer", "DevOps" are visible.
16. `Wizard progresses through all steps` -- Select "Coder" agent type, click Next. Select "Claude Code" tool, click Next. Select compute option, click Next. Verify LLM key dropdown is visible.
17. `Complete wizard creates worker` -- Fill all steps, submit. Verify new row appears in workers table with status badge.
18. `Worker row shows provisioning progress` -- Verify status badge transitions (provisioning → installing → ready) with polling.

---

## 6. Security Considerations

### 6.1 API Key Injection

LLM API keys are decrypted from KMS only during provisioning and injected as environment variables in the instance's `.bashrc`. The decrypted key is never stored in DynamoDB, never logged, and is available only within the instance's shell environment.

### 6.2 Worker Isolation

Each worker runs on a separate EC2 instance or K8s pod with its own network namespace. Workers cannot access each other's environments or API keys.

### 6.3 Startup Script Validation

Custom install commands are limited to 16KB total. Shell metacharacter injection is mitigated by writing commands to a script file rather than passing via command-line arguments.

### 6.4 Worker Limit

Per-user maximum (default: 5) prevents resource abuse. Configurable via `S.agent_max_workers_per_user`.

### 6.5 Idle Auto-Shutdown

Workers automatically stop after `idle_timeout_seconds` of inactivity to prevent cost accumulation. The background checker runs every 5 minutes.

---

## 7. Dependencies

| Dependency | Type | Description |
|------------|------|-------------|
| AGENT-001 | Upstream | `get_decrypted_api_key()` for injecting LLM credentials |
| INFRA-003 | Upstream | `launch_instance()`, `stop_instance()`, etc. for EC2 compute |
| INFRA-004 | Upstream | `launch_pod()`, `delete_pod()` for K8s compute |
| INFRA-001 | Upstream | Auto-registered hosts for SSH terminal access |
| INFRA-002 | Upstream | SSH key injection during instance launch |
| AGENT-003 | Downstream | Agent framework uses worker records for orchestration |
| AGENT-004 | Downstream | Fleet management UI displays worker status |

---

## 8. Acceptance Criteria

1. Users can create agent workers with a single API call specifying agent type, tool, compute, and LLM key.
2. Provisioning automatically installs the selected AI tool (Claude Code or Codex) on the compute instance.
3. LLM API keys from AGENT-001 are automatically injected as environment variables.
4. Tool installation is verified (version check) before marking the worker as `ready`.
5. Workers can be stopped, started, and terminated.
6. Per-user worker limits are enforced.
7. Provisioning log tracks each step with status and timestamp.
8. Workers auto-shutdown after configurable idle timeout.
9. Web terminal access to worker instances is available via the existing SSH infrastructure.
10. Compute options (EC2 types, K8s presets) and tool options are listed via API for the creation wizard.
