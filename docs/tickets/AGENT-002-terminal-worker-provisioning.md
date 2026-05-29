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

### 1.4 Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND (React)                               │
│                                                                              │
│  ┌──────────────────────┐  ┌────────────────────┐  ┌─────────────────────┐  │
│  │  WorkerCreateWizard  │  │   WorkersPage      │  │  WorkerDetailPanel  │  │
│  │  ┌────────────────┐  │  │  ┌──────────────┐  │  │  ┌───────────────┐  │  │
│  │  │ AgentTypeSelect│  │  │  │ WorkerTable  │  │  │  │ StatusBadge   │  │  │
│  │  │ ToolSelector   │  │  │  │ StatusFilter │  │  │  │ ProvisionLog  │  │  │
│  │  │ ComputeSelect  │  │  │  │ CreateButton │  │  │  │ LifecycleBar  │  │  │
│  │  │ LlmKeyPicker   │  │  │  └──────────────┘  │  │  │ TerminalLink  │  │  │
│  │  │ ConfigForm     │  │  │                     │  │  └───────────────┘  │  │
│  │  └────────────────┘  │  └────────────────────┘  └─────────────────────┘  │
│  └──────────────────────┘                                                    │
│                              │  Axios + CSRF                                 │
└──────────────────────────────┼───────────────────────────────────────────────┘
                               │
                        Vite Proxy :3000 → :8000
                               │
┌──────────────────────────────┼───────────────────────────────────────────────┐
│                      BACKEND (FastAPI :8000)                                 │
│                               │                                              │
│  ┌────────────────────────────▼─────────────────────────────────────────┐    │
│  │         app/routers/agent_workers.py  (9 endpoints)                  │    │
│  │  POST /ui/agent/workers          — create worker                     │    │
│  │  GET  /ui/agent/workers          — list workers                      │    │
│  │  GET  /ui/agent/workers/{id}     — get worker                        │    │
│  │  POST /ui/agent/workers/{id}/stop   — stop                           │    │
│  │  POST /ui/agent/workers/{id}/start  — restart                        │    │
│  │  DELETE /ui/agent/workers/{id}      — terminate                      │    │
│  │  GET  /ui/agent/workers/{id}/provision-log — log                     │    │
│  │  GET  /ui/agent/workers/tools       — tool list                      │    │
│  │  GET  /ui/agent/workers/compute-options — compute options            │    │
│  └────────┬──────────────┬───────────────┬──────────────────────────────┘    │
│           │              │               │                                   │
│  ┌────────▼──────────┐  │  ┌────────────▼──────────────────────────┐        │
│  │ agent_worker_     │  │  │  Background: _provision_worker_bg()   │        │
│  │ provisioner.py    │  │  │  1. launch compute                     │        │
│  │                   │  │  │  2. install tool (SSH/cloud-init)      │        │
│  │  create_worker()  │  │  │  3. inject API key                     │        │
│  │  list_workers()   │  │  │  4. verify tool                        │        │
│  │  stop_worker()    │  │  │  5. mark ready                         │        │
│  │  start_worker()   │  │  └────────────┬──────────────────────────┘        │
│  │  terminate_worker │  │               │                                   │
│  └───────┬───────────┘  │               │                                   │
│          │              │               │                                   │
│  ┌───────▼──────────────▼───────────────▼──────────────────────────────┐    │
│  │                    DEPENDENCY SERVICES                               │    │
│  │  ┌──────────────┐  ┌───────────────┐  ┌───────────────────────┐     │    │
│  │  │ ec2_launcher  │  │ k8s_launcher  │  │ llm_provider_keys    │     │    │
│  │  │ (INFRA-003)   │  │ (INFRA-004)   │  │ (AGENT-001)          │     │    │
│  │  │ launch/stop/  │  │ launch_pod/   │  │ get_decrypted_api_   │     │    │
│  │  │ terminate     │  │ delete_pod    │  │ key()                │     │    │
│  │  └───────┬───────┘  └──────┬────────┘  └──────────┬────────────┘     │    │
│  │          │                 │                       │                  │    │
│  │  ┌───────▼───────┐  ┌─────▼─────┐   ┌────────────▼────────────┐     │    │
│  │  │ ssh_key_mgr   │  │ remote_   │   │ crypto.py               │     │    │
│  │  │ (INFRA-002)   │  │ hosts.py  │   │ KMS decrypt             │     │    │
│  │  └───────────────┘  │ (INFRA-001│   └─────────────────────────┘     │    │
│  │                      └───────────┘                                   │    │
│  └──────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└──────────────────────────────┼───────────────────────────────────────────────┘
                               │
┌──────────────────────────────┼───────────────────────────────────────────────┐
│                     INFRASTRUCTURE LAYER                                     │
│                               │                                              │
│  ┌────────────────────────────▼──────────────────────────────────────────┐   │
│  │                    DynamoDB (:8001)                                    │   │
│  │   Table: agent_workers                                                │   │
│  │   ┌──────────────────────────────────────────────────────────────┐    │   │
│  │   │ PK: USER#{user_id}   SK: WORKER#{worker_id}                 │    │   │
│  │   │ GSI: ByStatus (pk + worker_status)                          │    │   │
│  │   │ GSI: ByCreatedAt (pk + created_at)                          │    │   │
│  │   │ GSI: ByAgentType (pk + agent_type)                          │    │   │
│  │   └──────────────────────────────────────────────────────────────┘    │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌──────────────────────┐  ┌──────────────────────┐                         │
│  │  EC2 (or Moto mock)  │  │  K8s (or mock store)  │                        │
│  │  Compute instances   │  │  Ephemeral pods       │                        │
│  └──────────────────────┘  └──────────────────────┘                         │
│                                                                              │
│  ┌──────────────────────┐                                                   │
│  │  KMS (or mock KMS)   │  API key decrypt-at-provision-time                │
│  └──────────────────────┘                                                   │
└──────────────────────────────────────────────────────────────────────────────┘

Data Flow — Create Worker:
  1. User fills WorkerCreateWizard (agent type, tool, compute, LLM key)
  2. POST /ui/agent/workers with CSRF token
  3. Router validates session, calls create_worker()
  4. Service checks worker limit, validates LLM key exists via AGENT-001
  5. Decrypts API key from KMS for injection into startup script
  6. Launches EC2/K8s via INFRA-003/INFRA-004 with startup user-data script
  7. Writes WORKER item to DDB with status="provisioning"
  8. Returns 201 immediately; background task continues provisioning
  9. Background: SSH into instance, run install, verify tool, mark ready
 10. Frontend polls GET /ui/agent/workers/{id} until status="ready"

Data Flow — Stop/Terminate Worker:
  1. User clicks Stop/Terminate on WorkerDetailPanel
  2. POST ../stop or DELETE ../{id} with CSRF
  3. Service calls ec2 stop_instance/terminate_instance (or k8s delete_pod)
  4. Updates DDB worker_status to "stopped" or "terminated"
  5. Downstream: AGENT-003 agent loop detects status change and exits
```

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| EC2 launcher | `app/services/ec2_launcher.py` (INFRA-003) | <!-- NOTE: `app/services/ec2_launcher.py` does not exist yet — requires INFRA-003 implementation --> `launch_instance()`, `stop_instance()`, `terminate_instance()`; provides compute VMs |
| K8s launcher | `app/services/k8s_launcher.py` (INFRA-004) | <!-- NOTE: `app/services/k8s_launcher.py` does not exist yet — requires INFRA-004 implementation --> `launch_pod()`, `delete_pod()`; provides lightweight containers |
| SSH key manager | `app/services/ssh_key_manager.py` (INFRA-002) | <!-- NOTE: `app/services/ssh_key_manager.py` does not exist yet — requires INFRA-002 implementation --> Key generation and host association for SSH access |
| Host inventory | `app/services/remote_hosts.py` (INFRA-001) | <!-- NOTE: `app/services/remote_hosts.py` does not exist yet — requires INFRA-001 implementation --> Auto-registered hosts from EC2/K8s launches |
| LLM key store | `app/services/llm_provider_keys.py` (AGENT-001) | <!-- NOTE: `app/services/llm_provider_keys.py` does not exist yet — requires AGENT-001 implementation --> `get_decrypted_api_key()` for injecting LLM credentials |
| Web terminal | `app/routers/browser_ssh_terminal.py` | <!-- NOTE: The ticket referenced `app/routers/terminal.py` which does not exist. The actual SSH terminal router is `app/routers/browser_ssh_terminal.py` (registered in main.py:404) --> WebSocket-based SSH terminal in the browser |
| Mock EC2 store | `app/services/ec2_launcher.py` (INFRA-003) | <!-- NOTE: does not exist yet --> `_MockEc2Store` for dev mode |
| Mock K8s store | `app/services/k8s_launcher.py` (INFRA-004) | <!-- NOTE: does not exist yet --> `_MockK8sStore` for dev mode |
| Settings | `app/core/settings.py` | `S.dev_mode` (line 254), table names, etc. (verified) |
| Crypto | `app/core/crypto.py` | KMS decrypt for API keys — `kms_decrypt()` at line 22 (verified) |

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

### 3.1.2 DynamoDB Access Patterns

| # | Operation | Table / Index | PK | SK / Condition | Projection | Frequency |
|---|-----------|---------------|----|----|------------|-----------|
| AP-1 | Get worker by ID | `agent_workers` (base) | `USER#{user_id}` | `WORKER#{worker_id}` | Full item | Every API call |
| AP-2 | List all workers for user | `agent_workers` (base) | `USER#{user_id}` | `begins_with(sk, "WORKER#")` | All fields | Workers page load |
| AP-3 | List workers by status | `ByStatus` GSI | `USER#{user_id}` | `worker_status = :status` | worker_id, label, agent_type, tool | Filter dropdown |
| AP-4 | List workers by creation date | `ByCreatedAt` GSI | `USER#{user_id}` | `created_at BETWEEN :start AND :end` | All fields | Sort by newest |
| AP-5 | List workers by agent type | `ByAgentType` GSI | `USER#{user_id}` | `agent_type = :type` | worker_id, label, status | Type filter |
| AP-6 | Count active workers (limit check) | `ByStatus` GSI | `USER#{user_id}` | `worker_status IN (provisioning, installing, ready, running)` | worker_id only | Before create |
| AP-7 | Update worker status | `agent_workers` (base) | `USER#{user_id}` | `WORKER#{worker_id}` | N/A (update) | State transitions |
| AP-8 | Append provision log entry | `agent_workers` (base) | `USER#{user_id}` | `WORKER#{worker_id}` | N/A (list_append) | During provisioning |
| AP-9 | Find idle workers for auto-shutdown | `ByStatus` GSI | `USER#{user_id}` | `worker_status = "ready"` then filter `last_activity_at < threshold` | worker_id, last_activity_at, idle_timeout | Background task (every 5 min) |

#### Example DynamoDB Items

**Worker item — Ready EC2 Claude Code worker:**

```json
{
  "pk": {"S": "USER#a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  "sk": {"S": "WORKER#w_8f3a1b2c4d5e6f7890abcdef12345678"},
  "worker_id": {"S": "w_8f3a1b2c4d5e6f7890abcdef12345678"},
  "user_id": {"S": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  "label": {"S": "Coder Agent #1"},
  "agent_type": {"S": "coder"},
  "tool": {"S": "claude_code"},
  "tool_version": {"S": "1.0.23"},
  "compute_type": {"S": "ec2"},
  "compute_instance_id": {"S": "i-0abcdef1234567890"},
  "instance_type": {"S": "t3.medium"},
  "llm_key_id": {"S": "k_abc123def456"},
  "llm_provider": {"S": "anthropic"},
  "host_id": {"S": "h_fedcba0987654321"},
  "public_ip": {"S": "54.123.45.67"},
  "worker_status": {"S": "ready"},
  "provision_log": {"L": [
    {"M": {"step": {"S": "compute_launch"}, "status": {"S": "done"}, "ts": {"N": "1748520000"}, "detail": {"S": "i-0abcdef1234567890"}}},
    {"M": {"step": {"S": "tool_install"}, "status": {"S": "done"}, "ts": {"N": "1748520045"}, "detail": {"S": "claude-code@1.0.23"}}},
    {"M": {"step": {"S": "key_inject"}, "status": {"S": "done"}, "ts": {"N": "1748520048"}, "detail": {"S": ""}}},
    {"M": {"step": {"S": "verify"}, "status": {"S": "done"}, "ts": {"N": "1748520052"}, "detail": {"S": "v1.0.23"}}}
  ]},
  "repo_url": {"S": "https://github.com/acme/webapp.git"},
  "branch_convention": {"S": "agent/{worker_id}/{ticket_id}"},
  "idle_timeout_seconds": {"N": "7200"},
  "last_activity_at": {"N": "1748520120"},
  "created_at": {"N": "1748519990"},
  "started_at": {"N": "1748520052"},
  "stopped_at": {"N": "0"},
  "terminated_at": {"N": "0"},
  "template_id": {"S": ""},
  "error_message": {"S": ""}
}
```

**Worker item — Error state (provisioning failed):**

```json
{
  "pk": {"S": "USER#a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  "sk": {"S": "WORKER#w_99887766aabbccdd11223344eeff5566"},
  "worker_id": {"S": "w_99887766aabbccdd11223344eeff5566"},
  "user_id": {"S": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  "label": {"S": "QA Agent #2"},
  "agent_type": {"S": "qa"},
  "tool": {"S": "codex"},
  "tool_version": {"S": ""},
  "compute_type": {"S": "ec2"},
  "compute_instance_id": {"S": "i-0fedcba9876543210"},
  "instance_type": {"S": "t3.large"},
  "llm_key_id": {"S": "k_xyz789"},
  "llm_provider": {"S": "openai"},
  "host_id": {"S": ""},
  "public_ip": {"S": ""},
  "worker_status": {"S": "error"},
  "provision_log": {"L": [
    {"M": {"step": {"S": "compute_launch"}, "status": {"S": "done"}, "ts": {"N": "1748521000"}, "detail": {"S": "i-0fedcba9876543210"}}},
    {"M": {"step": {"S": "tool_install"}, "status": {"S": "error"}, "ts": {"N": "1748521060"}, "detail": {"S": "npm install failed: ENOSPC no space left on device"}}}
  ]},
  "repo_url": {"S": ""},
  "branch_convention": {"S": "agent/{worker_id}/{ticket_id}"},
  "idle_timeout_seconds": {"N": "3600"},
  "last_activity_at": {"N": "0"},
  "created_at": {"N": "1748521000"},
  "started_at": {"N": "0"},
  "stopped_at": {"N": "0"},
  "terminated_at": {"N": "0"},
  "template_id": {"S": ""},
  "error_message": {"S": "npm install failed: ENOSPC no space left on device"}
}
```

**Worker item — K8s Codex worker (stopped):**

```json
{
  "pk": {"S": "USER#a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  "sk": {"S": "WORKER#w_aabbccdd11223344eeff556677889900"},
  "worker_id": {"S": "w_aabbccdd11223344eeff556677889900"},
  "user_id": {"S": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
  "label": {"S": "Codex Fast Worker"},
  "agent_type": {"S": "coder"},
  "tool": {"S": "codex"},
  "tool_version": {"S": "0.9.5"},
  "compute_type": {"S": "k8s"},
  "compute_instance_id": {"S": "pod-agent-a1b2c3d4"},
  "instance_type": {"S": "standard-2cpu-4gb"},
  "llm_key_id": {"S": "k_openai_prod"},
  "llm_provider": {"S": "openai"},
  "host_id": {"S": "h_k8s_pod_a1b2c3d4"},
  "public_ip": {"S": "10.0.5.42"},
  "worker_status": {"S": "stopped"},
  "provision_log": {"L": [
    {"M": {"step": {"S": "compute_launch"}, "status": {"S": "done"}, "ts": {"N": "1748510000"}, "detail": {"S": "pod-agent-a1b2c3d4"}}},
    {"M": {"step": {"S": "tool_install"}, "status": {"S": "done"}, "ts": {"N": "1748510008"}, "detail": {"S": "codex@0.9.5"}}},
    {"M": {"step": {"S": "key_inject"}, "status": {"S": "done"}, "ts": {"N": "1748510009"}, "detail": {"S": ""}}},
    {"M": {"step": {"S": "verify"}, "status": {"S": "done"}, "ts": {"N": "1748510011"}, "detail": {"S": "v0.9.5"}}}
  ]},
  "repo_url": {"S": "https://github.com/acme/api-service.git"},
  "branch_convention": {"S": "agent/{worker_id}/{ticket_id}"},
  "idle_timeout_seconds": {"N": "1800"},
  "last_activity_at": {"N": "1748515000"},
  "created_at": {"N": "1748510000"},
  "started_at": {"N": "1748510011"},
  "stopped_at": {"N": "1748518000"},
  "terminated_at": {"N": "0"},
  "template_id": {"S": "tmpl_fast_codex"},
  "error_message": {"S": ""}
}
```

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

## 6. API Request/Response Examples

### 6.1 Create Worker

```bash
curl -s -X POST http://localhost:3000/ui/agent/workers \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1" \
  -d '{
    "label": "Coder Agent #1",
    "agent_type": "coder",
    "tool": "claude_code",
    "compute_type": "ec2",
    "instance_type": "t3.medium",
    "llm_key_id": "k_abc123def456",
    "repo_url": "https://github.com/acme/webapp.git",
    "branch_convention": "agent/{worker_id}/{ticket_id}",
    "idle_timeout_seconds": 7200
  }'
```

**Response (201 Created):**

```json
{
  "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
  "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "label": "Coder Agent #1",
  "agent_type": "coder",
  "tool": "claude_code",
  "tool_version": "",
  "compute_type": "ec2",
  "compute_instance_id": "i-0abcdef1234567890",
  "instance_type": "t3.medium",
  "llm_key_id": "k_abc123def456",
  "llm_provider": "anthropic",
  "host_id": "",
  "public_ip": "",
  "worker_status": "provisioning",
  "provision_log": [
    {"step": "compute_launch", "status": "running", "ts": 1748520000, "detail": ""}
  ],
  "repo_url": "https://github.com/acme/webapp.git",
  "branch_convention": "agent/{worker_id}/{ticket_id}",
  "idle_timeout_seconds": 7200,
  "last_activity_at": 0,
  "created_at": 1748520000,
  "started_at": 0,
  "stopped_at": 0,
  "terminated_at": 0,
  "template_id": "",
  "error_message": ""
}
```

### 6.2 List Workers

```bash
curl -s http://localhost:3000/ui/agent/workers \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..."
```

**Response (200 OK):**

```json
{
  "workers": [
    {
      "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
      "label": "Coder Agent #1",
      "agent_type": "coder",
      "tool": "claude_code",
      "tool_version": "1.0.23",
      "compute_type": "ec2",
      "instance_type": "t3.medium",
      "worker_status": "ready",
      "created_at": 1748520000,
      "last_activity_at": 1748520120
    }
  ],
  "count": 1
}
```

### 6.3 Get Worker Details

```bash
curl -s http://localhost:3000/ui/agent/workers/w_8f3a1b2c4d5e6f7890abcdef12345678 \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..."
```

**Response (200 OK):** Full `WorkerOut` object (see create response above with all fields populated).

### 6.4 Stop Worker

```bash
curl -s -X POST http://localhost:3000/ui/agent/workers/w_8f3a1b2c4d5e6f7890abcdef12345678/stop \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1"
```

**Response (200 OK):**

```json
{
  "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
  "worker_status": "stopped",
  "stopped_at": 1748525000,
  "label": "Coder Agent #1"
}
```

### 6.5 Start (Restart) Worker

```bash
curl -s -X POST http://localhost:3000/ui/agent/workers/w_8f3a1b2c4d5e6f7890abcdef12345678/start \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1"
```

**Response (200 OK):**

```json
{
  "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
  "worker_status": "ready",
  "started_at": 1748526000
}
```

### 6.6 Terminate Worker

```bash
curl -s -X DELETE http://localhost:3000/ui/agent/workers/w_8f3a1b2c4d5e6f7890abcdef12345678 \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..." \
  -H "x-csrf-token: csrf_tok_1"
```

**Response (200 OK):**

```json
{
  "worker_id": "w_8f3a1b2c4d5e6f7890abcdef12345678",
  "worker_status": "terminated",
  "terminated_at": 1748530000
}
```

### 6.7 Get Provision Log

```bash
curl -s http://localhost:3000/ui/agent/workers/w_8f3a1b2c4d5e6f7890abcdef12345678/provision-log \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..."
```

**Response (200 OK):**

```json
[
  {"step": "compute_launch", "status": "done", "ts": 1748520000, "detail": "i-0abcdef1234567890"},
  {"step": "tool_install", "status": "done", "ts": 1748520045, "detail": "claude-code@1.0.23"},
  {"step": "key_inject", "status": "done", "ts": 1748520048, "detail": ""},
  {"step": "verify", "status": "done", "ts": 1748520052, "detail": "v1.0.23"}
]
```

### 6.8 List Available AI Tools

```bash
curl -s http://localhost:3000/ui/agent/workers/tools \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..."
```

**Response (200 OK):**

```json
{
  "tools": [
    {
      "tool": "claude_code",
      "display_name": "Claude Code",
      "description": "Anthropic's autonomous coding CLI",
      "install_time_seconds": 45,
      "required_provider": "anthropic"
    },
    {
      "tool": "codex",
      "display_name": "OpenAI Codex",
      "description": "OpenAI's code generation CLI",
      "install_time_seconds": 40,
      "required_provider": "openai"
    },
    {
      "tool": "custom",
      "display_name": "Custom Tool",
      "description": "User-provided tool with custom install script",
      "install_time_seconds": 0,
      "required_provider": ""
    }
  ]
}
```

### 6.9 List Compute Options

```bash
curl -s http://localhost:3000/ui/agent/workers/compute-options \
  -H "Cookie: ui_session=ses_abc123; ui_csrf=csrf_tok_1; ui_access_token=eyJ..."
```

**Response (200 OK):**

```json
{
  "options": [
    {"compute_type": "ec2", "instance_type": "t3.medium", "vcpu": 2, "memory_gb": 4.0, "cost_cents_per_min": 0.7, "startup_seconds": 45},
    {"compute_type": "ec2", "instance_type": "t3.large", "vcpu": 2, "memory_gb": 8.0, "cost_cents_per_min": 1.4, "startup_seconds": 45},
    {"compute_type": "ec2", "instance_type": "m5.xlarge", "vcpu": 4, "memory_gb": 16.0, "cost_cents_per_min": 3.2, "startup_seconds": 60},
    {"compute_type": "k8s", "instance_type": "standard-2cpu-4gb", "vcpu": 2, "memory_gb": 4.0, "cost_cents_per_min": 0.5, "startup_seconds": 8},
    {"compute_type": "k8s", "instance_type": "standard-4cpu-8gb", "vcpu": 4, "memory_gb": 8.0, "cost_cents_per_min": 1.0, "startup_seconds": 8}
  ]
}
```

---

## 7. Error Handling Matrix

| # | Error Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|---|---------------|-------------|------------|---------------------|----------------|
| E-1 | LLM key not found | 400 | `llm_key_not_found` | "The selected LLM key does not exist. Please select another key." | User selects a different key in the wizard |
| E-2 | LLM key belongs to wrong provider | 400 | `llm_key_provider_mismatch` | "The selected key is for {provider}, but {tool} requires {required_provider}." | User selects a compatible key |
| E-3 | Worker limit reached | 409 | `worker_limit_reached` | "You have reached the maximum of {limit} active workers. Terminate an existing worker first." | User terminates an existing worker |
| E-4 | Invalid agent type | 422 | `validation_error` | "Invalid agent_type. Must be one of: coder, qa, reviewer, devops, custom." | Fix request body |
| E-5 | Invalid tool | 422 | `validation_error` | "Invalid tool. Must be one of: claude_code, codex, custom." | Fix request body |
| E-6 | Invalid compute type | 422 | `validation_error` | "Invalid compute_type. Must be ec2 or k8s." | Fix request body |
| E-7 | EC2 launch failure | 500 | `compute_launch_failed` | "Failed to launch compute instance. Please try again." | Retry; check AWS quotas if persistent |
| E-8 | K8s pod launch failure | 500 | `compute_launch_failed` | "Failed to launch container. Please try again." | Retry; check K8s cluster capacity |
| E-9 | Tool installation timeout | 500 | `tool_install_timeout` | "Tool installation timed out after 120 seconds." | Retry with different instance type; check network |
| E-10 | Tool verification failed | 500 | `tool_verify_failed` | "Tool installed but verification failed. Check worker provision log for details." | Inspect provision log; may need different instance AMI |
| E-11 | KMS decryption failure | 500 | `key_decrypt_failed` | "Failed to decrypt LLM API key. Please re-add the key." | User re-adds the key in AGENT-001 |
| E-12 | Stop non-running worker | 400 | `invalid_worker_state` | "Cannot stop worker in state: {state}. Worker must be 'ready' or 'running'." | Wait for provisioning to complete first |
| E-13 | Start non-stopped worker | 400 | `invalid_worker_state` | "Cannot start worker in state: {state}. Worker must be 'stopped'." | Stop the worker first |
| E-14 | Terminate already terminated | 400 | `invalid_worker_state` | "Worker is already terminated." | No action needed |
| E-15 | Worker not found | 404 | `worker_not_found` | "Worker not found." | Check worker_id |
| E-16 | Session expired | 401 | `unauthorized` | "Session expired. Please log in again." | Re-login |
| E-17 | Missing CSRF token | 403 | `csrf_missing` | "CSRF token required." | Include x-csrf-token header |
| E-18 | Custom tool missing install commands | 400 | `custom_tool_no_commands` | "Custom tool requires at least one install command." | Provide custom_install_commands |
| E-19 | Instance type not available | 400 | `instance_type_unavailable` | "Instance type {type} is not available in the current region." | Select a different instance type |
| E-20 | Startup script too large | 400 | `script_too_large` | "Custom install commands exceed 16KB limit." | Reduce script size |

---

## 8. Observability & Monitoring

### 8.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `agent_worker_create_total` | Counter | `tool`, `compute_type`, `agent_type` | Total worker creation requests |
| `agent_worker_create_errors` | Counter | `error_code` | Worker creation failures |
| `agent_worker_provision_duration_seconds` | Histogram | `tool`, `compute_type` | Time from create to ready (buckets: 10, 30, 60, 90, 120, 180) |
| `agent_worker_provision_step_duration_seconds` | Histogram | `step` | Duration of each provisioning step |
| `agent_workers_active` | Gauge | `status`, `tool` | Currently active workers by status |
| `agent_worker_idle_shutdown_total` | Counter | `tool` | Workers auto-stopped due to idle timeout |
| `agent_worker_lifecycle_total` | Counter | `action` (stop/start/terminate) | Worker lifecycle operations |

### 8.2 Log Events

| Event | Level | Fields | When |
|-------|-------|--------|------|
| `worker.created` | INFO | `worker_id`, `user_id`, `tool`, `compute_type`, `instance_type` | After DDB write |
| `worker.provision.step` | INFO | `worker_id`, `step`, `status`, `duration_ms` | Each provisioning step completion |
| `worker.provision.error` | ERROR | `worker_id`, `step`, `error`, `traceback` | Provisioning step failure |
| `worker.ready` | INFO | `worker_id`, `total_provision_seconds`, `tool_version` | Worker reaches ready state |
| `worker.stopped` | INFO | `worker_id`, `uptime_seconds` | Worker stopped (manual or idle) |
| `worker.started` | INFO | `worker_id` | Stopped worker restarted |
| `worker.terminated` | INFO | `worker_id`, `lifetime_seconds` | Worker terminated |
| `worker.idle_shutdown` | WARN | `worker_id`, `idle_seconds`, `threshold` | Auto-shutdown due to idle timeout |
| `worker.limit_reached` | WARN | `user_id`, `current_count`, `max_limit` | User hit worker limit |

### 8.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High provision failure rate | `rate(agent_worker_create_errors[5m]) / rate(agent_worker_create_total[5m]) > 0.3` | P2 | Check EC2/K8s service health; inspect recent provision logs |
| Provisioning stuck | `agent_worker_provision_duration_seconds{quantile="0.99"} > 180` | P3 | Investigate slow instance launches; check AMI availability |
| Worker count anomaly | `agent_workers_active{status="ready"} > 50` (platform-wide) | P3 | Verify no runaway creation; check billing impact |
| Idle workers accumulating | `agent_workers_active{status="ready"} - rate(agent_worker_lifecycle_total{action="terminate"}[1h]) > 20` | P4 | Review idle timeout settings; send user notifications |

### 8.4 Dashboard Queries

```promql
# Provisioning success rate (last hour)
1 - (sum(rate(agent_worker_create_errors[1h])) / sum(rate(agent_worker_create_total[1h])))

# Average provision time by tool
histogram_quantile(0.5, rate(agent_worker_provision_duration_seconds_bucket[1h]))

# Active workers by status
agent_workers_active

# Worker creation rate
sum(rate(agent_worker_create_total[1h])) by (tool)
```

---

## 9. Rollout Plan

### 9.1 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `AGENT_WORKERS_ENABLED` | `false` | Master toggle — hides Workers nav item and returns 404 from all endpoints |
| `AGENT_WORKERS_K8S_ENABLED` | `false` | Enable K8s compute option (EC2 only when false) |
| `AGENT_WORKERS_CUSTOM_TOOL_ENABLED` | `false` | Allow custom tool installations (security-sensitive) |

### 9.2 Migration Steps

| Phase | Action | Duration | Rollback |
|-------|--------|----------|----------|
| 1. Schema | Run `local-ddb-init.py` to create `agent_workers` table with 3 GSIs | 1 min | Drop table (no data yet) |
| 2. Backend | Deploy `agent_worker_provisioner.py` + `agent_workers.py` router; flag OFF | Instant | Remove router registration from `main.py` |
| 3. Internal alpha | Enable `AGENT_WORKERS_ENABLED=true` for internal team accounts only | 3 days | Flip flag to false |
| 4. EC2 GA | Enable for all users; K8s still behind flag | 1 week | Disable flag; terminate any active workers via admin API |
| 5. K8s beta | Enable `AGENT_WORKERS_K8S_ENABLED=true` for beta users | 1 week | Flip K8s flag; K8s workers gracefully terminated |
| 6. Full GA | Enable all flags; remove flag checks in next release | Permanent | N/A |

### 9.3 Canary Deployment

- Deploy backend changes behind feature flag to 100% of instances
- Enable for 1% of users (internal + beta) for 48 hours
- Monitor provisioning success rate, provision latency, error rates
- If error rate > 5%: disable flag, investigate
- Ramp: 1% -> 10% -> 50% -> 100% over 2 weeks

---

## 10. Performance Considerations

### 10.1 Provisioning Latency Budget

| Step | Target (EC2) | Target (K8s) | Notes |
|------|-------------|-------------|-------|
| Input validation + limit check | < 10ms | < 10ms | DDB GetItem + conditional check |
| LLM key decryption (KMS) | < 50ms | < 50ms | KMS Decrypt API; mock is instant |
| Startup script construction | < 5ms | < 5ms | String concatenation; no I/O |
| Compute launch (API call) | 30-45s | 3-8s | EC2 RunInstances vs K8s CreatePod |
| Tool installation (SSH) | 30-60s | 10-20s | npm install over network; K8s uses pre-built image layers |
| Tool verification | 2-5s | 2-5s | Run `claude --version` or equivalent |
| **Total provision time** | **60-120s** | **15-35s** | K8s is 4x faster due to container reuse |

### 10.2 DynamoDB Capacity

| Operation | RCU/WCU | Frequency | Daily Estimate |
|-----------|---------|-----------|----------------|
| Create worker (PutItem) | 1 WCU | ~50/day (platform) | 50 WCU |
| Update provision step (UpdateItem) | 1 WCU | ~4 per create | 200 WCU |
| Get worker (GetItem) | 0.5 RCU (eventual) | ~500/day (polling) | 250 RCU |
| List workers (Query) | 1-5 RCU | ~200/day | 1000 RCU |
| Idle check scan (GSI Query) | 5-20 RCU | 288/day (every 5 min) | 5760 RCU |

On-demand DDB pricing handles this easily. For provisioned mode, 10 RCU + 5 WCU is sufficient for up to ~100 concurrent users.

### 10.3 Caching Strategy

| Data | Cache Location | TTL | Invalidation |
|------|---------------|-----|--------------|
| Tool list | Frontend (React Query) | 24h (staleTime) | Rarely changes; manual refetch |
| Compute options | Frontend (React Query) | 1h (staleTime) | Cost updates; manual refetch |
| Worker list | Frontend (React Query) | 30s (staleTime) | Invalidate on create/stop/start/terminate mutation |
| Worker detail (polling) | Frontend (React Query) | 5s (refetchInterval during provisioning) | Stop polling once status=ready |

### 10.4 Rate Limiting

| Endpoint | Limit | Window | Reason |
|----------|-------|--------|--------|
| POST `/ui/agent/workers` | 5 | 1 hour | Prevent compute resource abuse |
| POST `/{id}/stop` | 10 | 1 minute | Prevent rapid state cycling |
| POST `/{id}/start` | 10 | 1 minute | Prevent rapid state cycling |
| GET `/ui/agent/workers` | 60 | 1 minute | Standard read limit |
| GET `/{id}/provision-log` | 30 | 1 minute | Polling during provisioning |

### 10.5 Background Task Efficiency

The idle worker checker runs every 5 minutes and queries the `ByStatus` GSI for `worker_status="ready"` per user. At scale (1000+ users), this becomes a table scan unless we add a global secondary index with `GSI1PK = STATUS#{worker_status}`. For the initial rollout, per-user queries are acceptable (most users have < 5 workers).

---

## 11. Frontend Component Tree

```
WorkersPage
├── PageHeader
│   ├── h1 "Agent Workers"
│   └── Button "Create Worker" → opens WorkerCreateWizard
├── WorkerFilters
│   ├── Select (status filter: all, provisioning, ready, running, stopped, error, terminated)
│   └── Select (agent type filter: all, coder, qa, reviewer, devops, custom)
├── WorkerTable
│   ├── DataTable (columns: label, agent_type, tool, status, compute, created_at, actions)
│   └── WorkerRow (for each worker)
│       ├── Badge (status: color-coded)
│       ├── Tooltip (hover: public_ip, instance_type)
│       ├── DropdownMenu (actions)
│       │   ├── MenuItem "View Details" → navigates to detail
│       │   ├── MenuItem "Open Terminal" → opens /remote/ssh/{host_id}
│       │   ├── MenuItem "Stop" (if ready/running)
│       │   ├── MenuItem "Start" (if stopped)
│       │   └── MenuItem "Terminate" → ConfirmDialog
│       └── ProvisionProgress (if provisioning/installing)
│           └── Progress bar with step labels
├── WorkerDetailPanel (slide-over or separate page)
│   ├── WorkerHeader
│   │   ├── h2 "{label}"
│   │   ├── Badge (status)
│   │   └── LifecycleButtons (Stop / Start / Terminate)
│   ├── WorkerInfo
│   │   ├── Field "Agent Type" → agent_type
│   │   ├── Field "Tool" → tool (tool_version)
│   │   ├── Field "Compute" → compute_type / instance_type
│   │   ├── Field "LLM Key" → llm_provider / llm_key_id
│   │   ├── Field "Public IP" → public_ip
│   │   ├── Field "Repository" → repo_url (link)
│   │   └── Field "Idle Timeout" → idle_timeout_seconds formatted
│   ├── ProvisionLog
│   │   └── Timeline (provision_log entries)
│   │       └── TimelineEntry
│   │           ├── Icon (check / spinner / x based on status)
│   │           ├── Label (step name)
│   │           ├── Detail text
│   │           └── Timestamp
│   └── TerminalButton
│       └── Button "Open Terminal" → window.open(/remote/ssh/{host_id})
└── EmptyState (when no workers)
    ├── Icon (Bot)
    ├── h3 "No workers yet"
    ├── p "Create your first agent worker to get started."
    └── Button "Create Worker"

WorkerCreateWizard (Dialog)
├── DialogHeader "Create Agent Worker"
├── Stepper (5 steps, progress indicator)
├── Step 1: AgentTypeSelector
│   └── CardGrid (5 cards: Coder, QA, Reviewer, DevOps, Custom)
│       └── AgentTypeCard
│           ├── Icon
│           ├── Title
│           └── Description
├── Step 2: ToolSelector
│   └── CardGrid (loaded from GET /tools)
│       └── ToolCard
│           ├── Icon (tool logo)
│           ├── Title (display_name)
│           ├── Description
│           └── Badge "Required: {required_provider}"
├── Step 3: ComputeSelector
│   └── DataTable (loaded from GET /compute-options)
│       └── ComputeOptionRow
│           ├── Badge (ec2 / k8s)
│           ├── Text (instance_type)
│           ├── Text (vcpu + memory_gb)
│           ├── Text (cost_cents_per_min formatted)
│           └── Text (startup_seconds)
├── Step 4: LlmKeySelector
│   └── Select (dropdown of keys from AGENT-001, filtered by required_provider)
│       └── Option "{provider} - {label} (****{last4})"
├── Step 5: ConfigForm
│   ├── Input "Label" (required)
│   ├── Input "Repository URL" (optional)
│   ├── Input "Branch Convention" (default: agent/{worker_id}/{ticket_id})
│   ├── Slider "Idle Timeout" (10 min - 24 hr)
│   └── CostEstimate
│       └── p "Estimated cost: ${cost}/hour"
├── NavigationButtons
│   ├── Button "Back" (step > 1)
│   ├── Button "Next" (step < 5)
│   └── Button "Create Worker" (step 5, disabled until valid)
└── DialogFooter
```

### 11.1 TypeScript Interfaces

```typescript
// frontend/src/api/types.ts

export interface CreateWorkerIn {
  label: string;
  agent_type: "coder" | "qa" | "reviewer" | "devops" | "custom";
  tool: "claude_code" | "codex" | "custom";
  compute_type: "ec2" | "k8s";
  instance_type: string;
  llm_key_id: string;
  repo_url?: string;
  branch_convention?: string;
  idle_timeout_seconds?: number;
  template_id?: string;
  custom_install_commands?: string[];
  custom_env_var?: string;
  custom_verify_command?: string;
}

export interface ProvisionStep {
  step: string;
  status: "running" | "done" | "error";
  ts: number;
  detail: string;
}

export interface Worker {
  worker_id: string;
  user_id: string;
  label: string;
  agent_type: string;
  tool: string;
  tool_version: string;
  compute_type: string;
  compute_instance_id: string;
  instance_type: string;
  llm_key_id: string;
  llm_provider: string;
  host_id: string;
  public_ip: string;
  worker_status: "provisioning" | "installing" | "ready" | "running" | "stopped" | "error" | "terminated";
  provision_log: ProvisionStep[];
  repo_url: string;
  branch_convention: string;
  idle_timeout_seconds: number;
  last_activity_at: number;
  created_at: number;
  started_at: number;
  stopped_at: number;
  terminated_at: number;
  template_id: string;
  error_message: string;
}

export interface WorkerList {
  workers: Worker[];
  count: number;
}

export interface ToolInfo {
  tool: string;
  display_name: string;
  description: string;
  install_time_seconds: number;
  required_provider: string;
}

export interface ComputeOption {
  compute_type: "ec2" | "k8s";
  instance_type: string;
  vcpu: number;
  memory_gb: number;
  cost_cents_per_min: number;
  startup_seconds: number;
}
```

### 11.2 State Management

```typescript
// React Query keys and hooks

const workerKeys = {
  all: ["agent-workers"] as const,
  list: (filters?: { status?: string; agent_type?: string }) =>
    [...workerKeys.all, "list", filters] as const,
  detail: (id: string) => [...workerKeys.all, "detail", id] as const,
  provisionLog: (id: string) => [...workerKeys.all, "provision-log", id] as const,
  tools: () => [...workerKeys.all, "tools"] as const,
  computeOptions: () => [...workerKeys.all, "compute-options"] as const,
};

// useWorkers() — list with optional filters
// useWorker(id) — single worker detail, refetchInterval=5s when provisioning
// useCreateWorker() — mutation, invalidates list on success
// useStopWorker() — mutation, invalidates list + detail
// useStartWorker() — mutation, invalidates list + detail
// useTerminateWorker() — mutation with confirmation dialog, invalidates list
// useProvisionLog(id) — refetchInterval=3s when provisioning
// useTools() — staleTime=24h
// useComputeOptions() — staleTime=1h
```

---

## 12. Expanded E2E Test Details

Expanding the original 4 sections (18 tests) to 6 sections (28 tests) with edge cases, negative tests, and concurrent access tests.

**Section 627: Compute & Tool Options API (4 tests)**

1. `List available AI tools` -- GET `/ui/agent/workers/tools`. Verify at least 2 tools: `claude_code` with `display_name: "Claude Code"`, `codex` with `display_name: "OpenAI Codex"`. Each has `install_time_seconds > 0`.
2. `List compute options` -- GET `/ui/agent/workers/compute-options`. Verify at least 2 EC2 options and at least 1 K8s option. Each has `vcpu`, `memory_gb`, `cost_cents_per_min`.
3. `Compute options include startup time` -- Verify K8s options have `startup_seconds < 10` and EC2 options have `startup_seconds > 20`.
4. `Tools include required_provider` -- Verify `claude_code` has `required_provider: "anthropic"`, `codex` has `required_provider: "openai"`, `custom` has `required_provider: ""`.

**Section 628: Worker CRUD API (7 tests)**

5. `Alice creates a Claude Code worker on EC2` -- POST `/ui/agent/workers` with `agent_type: "coder"`, `tool: "claude_code"`, `compute_type: "ec2"`, `instance_type: "t3.medium"`, `llm_key_id` from setup. Verify 201 with `worker_id`, `worker_status` in `["provisioning", "installing", "ready"]`, `tool: "claude_code"`, `compute_type: "ec2"`.
6. `Worker provisioning completes to ready` -- Poll GET `/ui/agent/workers/{worker_id}` until `worker_status === "ready"` (max 10s). Verify `provision_log` has at least 3 entries, `public_ip` is non-empty, `host_id` is non-empty.
7. `Alice lists workers` -- GET `/ui/agent/workers`. Verify `count >= 1`, first worker has matching `worker_id`.
8. `Alice creates a K8s Codex worker` -- POST with `tool: "codex"`, `compute_type: "k8s"`, `instance_type: "standard-2cpu-4gb"`, `llm_key_id` for OpenAI key. Verify 201, `compute_type: "k8s"`.
9. `Alice cannot exceed worker limit` -- Create workers until hitting `MAX_WORKERS_PER_USER`. Attempt one more, verify 409 or 400 with message about limit.
10. `Invalid LLM key_id returns 400` -- POST with `llm_key_id: "nonexistent_key"`. Verify 400 error about LLM key not found.
11. `Provider mismatch returns 400` -- Create worker with `tool: "claude_code"` but `llm_key_id` pointing to an OpenAI key. Verify 400 about provider mismatch.

**Section 629: Worker Lifecycle API (6 tests)**

12. `Alice stops a running worker` -- POST `/ui/agent/workers/{worker_id}/stop`. Verify `worker_status: "stopped"`, `stopped_at > 0`.
13. `Alice starts a stopped worker` -- POST `/ui/agent/workers/{worker_id}/start`. Verify `worker_status` transitions to `ready`.
14. `Alice terminates a worker` -- DELETE `/ui/agent/workers/{worker_id}`. Verify `worker_status: "terminated"`, `terminated_at > 0`.
15. `Cannot stop an already terminated worker` -- POST `/stop` on terminated worker. Verify 400/409 with error about invalid state.
16. `Cannot start a provisioning worker` -- POST `/start` on a worker still in `provisioning` state. Verify 400 about invalid state.
17. `Provision log shows all steps` -- GET `/ui/agent/workers/{worker_id}/provision-log`. Verify list with entries for `compute_launch`, `tool_install`, `key_inject`, `verify`. Each entry has `step`, `status`, `ts`.

**Section 630: Worker Creation UI (5 tests)**

18. `Workers page renders empty state` -- Navigate to `/agents/workers`. Verify "No workers" empty state message visible.
19. `Create Worker wizard shows agent type selector` -- Click "Create Worker" button. Verify cards for "Coder", "QA", "Reviewer", "DevOps" are visible.
20. `Wizard progresses through all steps` -- Select "Coder" agent type, click Next. Select "Claude Code" tool, click Next. Select compute option, click Next. Verify LLM key dropdown is visible.
21. `Complete wizard creates worker` -- Fill all steps, submit. Verify new row appears in workers table with status badge.
22. `Worker row shows provisioning progress` -- Verify status badge transitions (provisioning -> installing -> ready) with polling.

**Section 631: Input Validation & Edge Cases (3 tests)**

23. `Empty label returns 422` -- POST with `label: ""`. Verify 422 validation error.
24. `Invalid agent_type returns 422` -- POST with `agent_type: "hacker"`. Verify 422.
25. `Custom tool without install commands returns 400` -- POST with `tool: "custom"`, `custom_install_commands: []`. Verify 400 about missing install commands.

**Section 632: Concurrent Access & Stress (3 tests)**

26. `Parallel worker creation respects limit` -- Send 6 concurrent POST requests to create workers (limit is 5). Verify exactly 5 succeed and 1 fails with limit error. Total workers count equals 5.
27. `Simultaneous stop and terminate` -- Send stop and terminate concurrently for the same worker. Verify one succeeds and the other fails (or terminate wins). Final state is `terminated`.
28. `Rapid start-stop cycling` -- Stop then immediately start a worker 3 times. Verify final state is consistent (`ready` or `stopped`), no error state from race conditions.

---

## 13. Security Considerations

### 13.1 API Key Injection

LLM API keys are decrypted from KMS only during provisioning and injected as environment variables in the instance's `.bashrc`. The decrypted key is never stored in DynamoDB, never logged, and is available only within the instance's shell environment.

### 13.2 Worker Isolation

Each worker runs on a separate EC2 instance or K8s pod with its own network namespace. Workers cannot access each other's environments or API keys.

### 13.3 Startup Script Validation

Custom install commands are limited to 16KB total. Shell metacharacter injection is mitigated by writing commands to a script file rather than passing via command-line arguments.

### 13.4 Worker Limit

Per-user maximum (default: 5) prevents resource abuse. Configurable via `S.agent_max_workers_per_user`.

### 13.5 Idle Auto-Shutdown

Workers automatically stop after `idle_timeout_seconds` of inactivity to prevent cost accumulation. The background checker runs every 5 minutes.

---

## 14. Dependencies

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

## 15. Acceptance Criteria

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

---

## Codebase References

| Reference | Path | Line(s) | Status |
|-----------|------|---------|--------|
| SSH terminal router | `app/routers/browser_ssh_terminal.py` | entire file | Verified — **not** `app/routers/terminal.py` (does not exist) |
| SSH terminal registration | `app/main.py` | 82-85, 404 | Verified |
| KMS decrypt | `app/core/crypto.py` | 22 | Verified |
| Settings singleton | `app/core/settings.py` | 254 (`dev_mode`), 1494 (`S = Settings()`) | Verified |
| DDB init script | `scripts/local-ddb-init.py` | 42 | Verified — new TableDef entry needed |
| Router registration | `app/main.py` | 297-465 | Verified |
| EC2 launcher service | `app/services/ec2_launcher.py` | — | **Does not exist** — requires INFRA-003 |
| K8s launcher service | `app/services/k8s_launcher.py` | — | **Does not exist** — requires INFRA-004 |
| SSH key manager service | `app/services/ssh_key_manager.py` | — | **Does not exist** — requires INFRA-002 |
| Host inventory service | `app/services/remote_hosts.py` | — | **Does not exist** — requires INFRA-001 |
| LLM key store | `app/services/llm_provider_keys.py` | — | **Does not exist** — requires AGENT-001 |
| INFRA ticket specs | `docs/tickets/INFRA-001-*.md` through `INFRA-005-*.md` | — | Verified — ticket files exist |
| `agent_workers` DDB table | — | — | **Does not exist** — new table required |
| `agent_worker_provisioner` service | — | — | **Does not exist** — new file required |

---

## Testing Strategy


### Unit Tests (pytest)


**Test file**: `tests/test_agent_worker_provisioner.py`


**Mock setup**: moto for DynamoDB tables, `unittest.mock.patch` for external services (S3, Cognito, Stripe mock). All DDB tables created in-memory via moto `@mock_dynamodb` decorator.


| Test Function | Verifies |
|---|---|
| `test_create_agent_worker_provisioner` | Creates record with correct fields and generated ID |
| `test_create_agent_worker_provisioner_validation` | Rejects invalid input (missing required fields, out-of-range values) |
| `test_get_agent_worker_provisioner_found` | Returns correct record by ID |
| `test_get_agent_worker_provisioner_not_found` | Returns None for non-existent ID |
| `test_list_agent_worker_provisioner` | Returns all records for the given scope/owner |
| `test_update_agent_worker_provisioner` | Updates mutable fields and sets updated_at |
| `test_delete_agent_worker_provisioner` | Removes record; subsequent get returns None |
| `test_agent_worker_provisioner_owner_check` | Rejects operations from non-owner users |
| `test_agent_worker_provisioner_admin_only` | Admin/root endpoints reject USER role with 403 |
| `test_agent_worker_provisioner_concurrent_write` | Conditional update prevents stale overwrites |

### Integration Tests


Cross-service tests with real DDB (moto), verifying end-to-end flows:


1. Full CRUD lifecycle: create -> read -> update -> delete with real DDB (moto)
2. Authorization enforcement: non-owner access returns 403/404
3. Admin review/approval workflow with role-gated endpoints
4. Concurrent write safety: conditional updates prevent stale overwrites
5. Edge case: empty list returns `[]` not error; missing optional fields use defaults

### E2E Tests (Playwright)


**Test file**: `frontend/e2e/agent-workers.spec.ts`


**Auth setup**:
- Cookie auth: `injectAuth(page, "alice")` for UI session tests
- CSRF header: `headers: { "x-csrf-token": sessions[identity].csrf_token }`
- Bearer auth: global `request` fixture for API-only tests (bypasses CSRF)
- Admin auth: `injectAuth(page, "root")` for admin endpoints

| # | Test | Key Assertion |
|---|------|--------------|
| 1 | Create resource via API | `expect(response.status()).toBe(201)` with correct fields |
| 2 | List resources returns array | `expect(response.status()).toBe(200)`; array length > 0 |
| 3 | Get single resource by ID | `expect(response.status()).toBe(200)`; fields match |
| 4 | Update resource | `expect(response.status()).toBe(200)`; GET confirms change |
| 5 | Delete resource | `expect(response.status()).toBe(200)`; subsequent GET 404 |
| 6 | Non-owner access blocked | `expect(response.status()).toBe(403)` or `toBe(404)` |
| 7 | Admin endpoint blocked for USER | `expect(response.status()).toBe(403)` |
| 8 | Unauthenticated request | `expect(response.status()).toBe(401)` |
| 9 | Invalid input rejected | `expect(response.status()).toBe(422)` |
| 10 | Duplicate/conflict handled | `expect(response.status()).toBe(409)` or idempotent 200 |
| 11 | UI page loads correctly | `page.getByRole("heading", { name: expectedTitle })` visible |
| 12 | UI create flow works | Click create -> fill form -> submit -> new item in list |
| 13 | UI status badges display | `page.getByText("Active")` or `page.getByText("Pending")` |
| 14 | Concurrent operations safe | Parallel requests both succeed or one gets 409 |
| 15 | Edge case: empty state | Empty list shows placeholder text, not error |

### Test Data Requirements


**Test users**: Alice = USER (primary actor), Bob = USER (secondary/viewer), Root = ROOT (admin reviewer), Charlie = ADMIN (scoped admin)


**DDB seed data**:


| Table | PK/SK Pattern | Notes |
|-------|--------------|-------|
| `AgentWorkers` | See DDB schema in technical design section | Created by `scripts/local-ddb-init.py` |

### CI/Pipeline


- **Feature flags**: None required for dev/test
- **Execution**: E2E tests run serially (1 worker, Chromium only) per `playwright.config.ts`; pytest can run in parallel
- **Retry safety**: All tests are idempotent; unique `TS = Date.now()` suffixed identifiers prevent cross-run collisions
- **Prerequisite**: `just restart` to create DDB tables and seed E2E sessions before running

## Dependencies & Merge Safety


### Depends On


| Ticket | What's Needed | Status | Can Overlap? |
|--------|--------------|--------|-------------|
| AGENT-001 | LLM provider key management | Pending | No |
| INFRA-003 | EC2 instance launcher | Pending | Yes (parallel dev) |
| INFRA-004 | K8s container launcher | Pending | Yes (parallel dev) |

### Depended On By


| Ticket | What It Needs From This |
|--------|------------------------|
| AGENT-003 | Worker provisioning for agent lifecycle |
| AGENT-004 | Worker data for fleet UI |
| AGENT-005 | Worker context for memory injection |
| AGENT-006 | Worker monitoring targets |

### Merge Strategy


**Sequential (after AGENT-001)**


- Must merge after: AGENT-001, INFRA-003, INFRA-004
- Branch from `main` after dependencies are merged
- Can begin development in parallel but must rebase before merge
- DDB table creation is additive (no migration needed for new tables)

### Merge Checklist


- [ ] DDB table(s) added to `scripts/local-ddb-init.py`: `AgentWorkers`
- [ ] Settings added to `app/core/settings.py` + `app/core/tables.py`: `agent_workers_table_name`
- [ ] `.env.local` updated with any new environment variables
- [ ] Router registered in `app/main.py` (from `app/routers/agent_workers.py`)
- [ ] All E2E tests passing (`just e2e` or targeted spec file)
- [ ] No breaking changes to existing endpoints or UI components
- [ ] `just restart` succeeds with new table definitions
