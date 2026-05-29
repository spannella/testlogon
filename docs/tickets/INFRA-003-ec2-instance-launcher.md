# INFRA-003: EC2 Instance Launcher

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 8-10 days  
**Dependencies**: INFRA-001 (Host Inventory), INFRA-002 (SSH Key Manager)

---

## 1. Overview & Motivation

### The Gap

The platform provides browser-based SSH and VNC access to remote hosts, but users must provision their own infrastructure outside the platform. There is no way to:

1. Launch an EC2 instance directly from the platform UI
2. Have the instance automatically appear in the host inventory (INFRA-001)
3. Inject SSH keys from the key manager (INFRA-002) during launch
4. Track instance lifecycle (running, stopped, terminated) within the platform
5. Auto-terminate idle instances to prevent cost overruns

The platform already has boto3 client infrastructure in `app/core/aws.py` for DynamoDB, S3, Cognito, KMS, SQS, SES, and SNS. However, **no EC2 client exists**. Adding EC2 integration requires a new boto3 client and a mock implementation for dev mode (to avoid real AWS costs during development and testing).

### Why This Matters

1. **Zero-to-connected workflow**: Users should go from "I need a Linux box" to "I'm typing commands in a shell" in under 60 seconds — without leaving the platform.
2. **Key injection**: Auto-injecting SSH keys from INFRA-002 eliminates the manual step of copying public keys to `authorized_keys`.
3. **Cost control**: Auto-terminate idle instances and enforce per-user instance limits to prevent bill shock.
4. **Foundation**: INFRA-005 (Cost Tracking), INFRA-007 (Templates), INFRA-008 (Monitoring), and INFRA-012 (Admin Dashboard) all depend on instance tracking.

### Architecture After This Change

```
EC2 Launch Flow

  POST /ui/remote/ec2/launch
  { instance_type, ami_id, ssh_key_id?, label }
       |
       v
  +-------------------+        +-------------------+
  | ec2_launcher.py   |------->| Mock EC2 Service  |  (dev mode)
  | (service layer)   |        | (in-memory)       |
  +-------------------+        +-------------------+
       |                            |
       | real mode                  | mock mode
       v                            v
  +-------------------+        +-------------------+
  | boto3 EC2 client  |        | _MockEc2Store     |
  | (real AWS)        |        | (dict-based)      |
  +-------------------+        +-------------------+
       |
       v
  +-------------------+
  | ec2_instances DDB  |  PK=user_sub, SK=INSTANCE#{instance_id}
  | (tracking table)   |  GSIs: ByStatus, ByCreatedAt
  +-------------------+
       |
       +---> Auto-register in remote_hosts (INFRA-001)
       |
       +---> Inject SSH public key via user-data (INFRA-002)
       |
       +---> Auto-security-group: SSH port open to platform
       |
       +---> Background idle checker (every 5 min):
              idle > 2 hours → auto-terminate
```

---

## 2. Current State Analysis

### 2.1 AWS Client Infrastructure (`app/core/aws.py`)
<!-- VERIFIED: app/core/aws.py exists; has sns_client() at :30, sqs_client() at :40; NO EC2 client exists -->

The `aws.py` module creates boto3 clients via helper functions. Example pattern:

```python
import boto3
from app.core.settings import S

_ddb_resource = None
def ddb():
    global _ddb_resource
    if _ddb_resource is None:
        kwargs = {}
        if S.ddb_endpoint_url:
            kwargs["endpoint_url"] = S.ddb_endpoint_url
        _ddb_resource = boto3.resource("dynamodb", region_name=S.aws_region, **kwargs)
    return _ddb_resource
```

An EC2 client would follow this same pattern, with an endpoint override for mock mode.

### 2.2 Dev Mode Detection (`app/core/settings.py`)

`S.dev_mode` is a boolean setting (`DEV_MODE` env var, default `True` in development). All mock services check this flag. The EC2 launcher must use a fully in-memory mock when `dev_mode=True` to avoid real AWS EC2 API calls.

### 2.3 Billing Infrastructure

The billing system in the `billing` DDB table uses a ledger pattern:
- `pk=USER#{user_sub}`, `sk=LEDGER#{timestamp}#{entry_id}`
- Fields: `amount_cents`, `currency`, `reason`, `resource_type`, `resource_id`

Per-minute billing is implemented in `app/routers/call_billing.py` for video calls:
- `HeartbeatIn` / `HeartbeatOut` models
- `call_heartbeat()` endpoint deducts per-minute charges
- `CallBillingStatusOut` tracks accumulated cost

This same heartbeat/ledger pattern will be reused for compute billing (INFRA-005).

### 2.4 Existing Instance Type References

No instance type configuration exists in the codebase. The launcher must define an allowlist of instance types with pricing metadata.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `ec2_instances`
<!-- NOTE: ec2_instances table does not exist yet in scripts/local-ddb-init.py — new table required -->

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.ec2_instances_table_name, "ec2_instances"),
    "user_sub",            # PK — instance owner
    "sk",                  # SK — INSTANCE#{instance_id}
    gsis=[
        {"index_name": "ByStatus", "partition_key": "user_sub", "sort_key": "status"},
        {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | S (PK) | Instance owner |
| `sk` | S (SK) | `INSTANCE#{instance_id}` |
| `instance_id` | S | Platform-generated UUID (maps to EC2 instance ID in real mode) |
| `ec2_instance_id` | S | AWS EC2 instance ID (e.g., `i-0abc123`) or mock ID |
| `label` | S | User-assigned name |
| `instance_type` | S | EC2 instance type (e.g., `t3.micro`) |
| `ami_id` | S | AMI identifier |
| `ami_name` | S | Human-readable AMI name (e.g., "Ubuntu 22.04 LTS") |
| `status` | S | `launching`, `running`, `stopping`, `stopped`, `terminating`, `terminated` |
| `public_ip` | S | Public IPv4 address (mock: `10.mock.x.y`) |
| `private_ip` | S | Private IPv4 address |
| `ssh_key_id` | S | Reference to INFRA-002 key used for launch |
| `host_id` | S | Reference to auto-created host in INFRA-001 |
| `security_group_id` | S | Associated security group |
| `created_at` | N | Unix timestamp of launch request |
| `started_at` | N | Unix timestamp when instance reached `running` |
| `stopped_at` | N | Unix timestamp of last stop |
| `terminated_at` | N | Unix timestamp of termination |
| `last_activity_at` | N | Unix timestamp of last SSH/VNC connection |
| `auto_terminate_after` | N | Seconds of idle time before auto-terminate (default: 7200) |
| `template_id` | S | INFRA-007 template used for launch (optional) |
| `startup_script` | S | Cloud-init / user-data script |
| `source` | S | `manual`, `template` |

### 3.2 Mock EC2 Service: `app/services/ec2_launcher.py`
<!-- NOTE: app/services/ec2_launcher.py does not exist yet — new implementation required -->

New file (~400 lines). The service provides a unified interface that delegates to either real EC2 API or an in-memory mock based on `S.dev_mode`.

```python
"""EC2 instance launcher — launch, stop, start, terminate instances.
Uses in-memory mock in dev mode; real boto3 EC2 client in production."""

from __future__ import annotations
import random
import uuid
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event
from app.services.remote_hosts import create_host, delete_host
from app.services.ssh_key_manager import get_key_metadata

# Instance type allowlist with cost metadata (cents per minute)
INSTANCE_TYPES = {
    "t3.micro":  {"vcpu": 2, "memory_gb": 1,  "cost_cents_per_min": 0.2},
    "t3.small":  {"vcpu": 2, "memory_gb": 2,  "cost_cents_per_min": 0.4},
    "t3.medium": {"vcpu": 2, "memory_gb": 4,  "cost_cents_per_min": 0.8},
    "t3.large":  {"vcpu": 2, "memory_gb": 8,  "cost_cents_per_min": 1.5},
}

# Curated AMI list
AMIS = {
    "ami-ubuntu-2204":  {"name": "Ubuntu 22.04 LTS", "os_type": "linux", "username": "ubuntu"},
    "ami-ubuntu-2404":  {"name": "Ubuntu 24.04 LTS", "os_type": "linux", "username": "ubuntu"},
    "ami-amzn2":        {"name": "Amazon Linux 2023", "os_type": "linux", "username": "ec2-user"},
    "ami-windows-2022": {"name": "Windows Server 2022", "os_type": "windows", "username": "Administrator"},
}

MAX_INSTANCES_PER_USER = 3
DEFAULT_AUTO_TERMINATE_SECONDS = 7200  # 2 hours


class _MockEc2Store:
    """In-memory EC2 instance store for dev mode."""
    def __init__(self):
        self._instances: Dict[str, Dict[str, Any]] = {}

    def launch(self, *, instance_id: str, instance_type: str, ami_id: str, key_name: str | None = None, user_data: str | None = None) -> Dict[str, Any]:
        mock_ec2_id = f"i-mock{uuid.uuid4().hex[:12]}"
        ip_a, ip_b = random.randint(1, 254), random.randint(1, 254)
        instance = {
            "ec2_instance_id": mock_ec2_id,
            "instance_type": instance_type,
            "ami_id": ami_id,
            "status": "running",
            "public_ip": f"10.mock.{ip_a}.{ip_b}",
            "private_ip": f"172.16.{ip_a}.{ip_b}",
        }
        self._instances[mock_ec2_id] = instance
        return instance

    def stop(self, ec2_instance_id: str) -> bool:
        inst = self._instances.get(ec2_instance_id)
        if inst:
            inst["status"] = "stopped"
            return True
        return False

    def start(self, ec2_instance_id: str) -> bool:
        inst = self._instances.get(ec2_instance_id)
        if inst and inst["status"] == "stopped":
            inst["status"] = "running"
            return True
        return False

    def terminate(self, ec2_instance_id: str) -> bool:
        inst = self._instances.get(ec2_instance_id)
        if inst:
            inst["status"] = "terminated"
            return True
        return False

    def describe(self, ec2_instance_id: str) -> Dict[str, Any] | None:
        return self._instances.get(ec2_instance_id)


_mock_store = _MockEc2Store()


def launch_instance(
    user_sub: str,
    *,
    label: str,
    instance_type: str,
    ami_id: str,
    ssh_key_id: str | None = None,
    auto_terminate_after: int = DEFAULT_AUTO_TERMINATE_SECONDS,
    startup_script: str = "",
    template_id: str | None = None,
) -> Dict[str, Any]:
    """Launch a new EC2 instance."""

def list_instances(user_sub: str, *, status: str | None = None) -> List[Dict[str, Any]]:
    """List user's instances with optional status filter."""

def get_instance(user_sub: str, instance_id: str) -> Dict[str, Any] | None:
    """Get a single instance by ID."""

def stop_instance(user_sub: str, instance_id: str) -> Dict[str, Any]:
    """Stop a running instance."""

def start_instance(user_sub: str, instance_id: str) -> Dict[str, Any]:
    """Start a stopped instance."""

def terminate_instance(user_sub: str, instance_id: str) -> Dict[str, Any]:
    """Terminate an instance (irreversible)."""

def check_idle_instances() -> int:
    """Background task: find and terminate idle instances. Returns count terminated."""
```

**Launch implementation detail**:

```python
def launch_instance(user_sub, *, label, instance_type, ami_id, ssh_key_id=None, ...):
    # 1. Validate instance_type in allowlist
    if instance_type not in INSTANCE_TYPES:
        raise ValueError(f"Instance type {instance_type} not allowed")

    # 2. Validate AMI
    if ami_id not in AMIS:
        raise ValueError(f"AMI {ami_id} not available")

    # 3. Check instance limit
    active = list_instances(user_sub, status="running") + list_instances(user_sub, status="stopped")
    if len(active) >= MAX_INSTANCES_PER_USER:
        raise ValueError(f"Maximum {MAX_INSTANCES_PER_USER} instances allowed")

    # 4. Prepare SSH key user-data
    user_data = startup_script
    if ssh_key_id:
        key_meta = get_key_metadata(user_sub, ssh_key_id)
        if key_meta:
            pub_key = key_meta["public_key_openssh"]
            ami_user = AMIS[ami_id]["username"]
            user_data = _inject_ssh_key_userdata(pub_key, ami_user, startup_script)

    # 5. Launch (mock or real)
    instance_id = uuid.uuid4().hex
    if S.dev_mode:
        result = _mock_store.launch(
            instance_id=instance_id, instance_type=instance_type,
            ami_id=ami_id, user_data=user_data,
        )
    else:
        result = _real_ec2_launch(...)

    # 6. Store in DDB
    now = now_ts()
    item = {
        "user_sub": user_sub, "sk": f"INSTANCE#{instance_id}",
        "instance_id": instance_id, "ec2_instance_id": result["ec2_instance_id"],
        "label": label, "instance_type": instance_type,
        "ami_id": ami_id, "ami_name": AMIS[ami_id]["name"],
        "status": "running", "public_ip": result["public_ip"],
        "private_ip": result["private_ip"],
        "ssh_key_id": ssh_key_id or "", "host_id": "",
        "created_at": now, "started_at": now,
        "last_activity_at": now,
        "auto_terminate_after": auto_terminate_after,
        ...
    }
    T.ec2_instances.put_item(Item=item)

    # 7. Auto-register in host inventory
    host = create_host(
        user_sub, label=f"{label} (EC2)", hostname=result["public_ip"],
        port=22, protocol="ssh", os_type=AMIS[ami_id]["os_type"],
        source="ec2_auto", group="EC2 Instances",
    )
    T.ec2_instances.update_item(
        Key={"user_sub": user_sub, "sk": f"INSTANCE#{instance_id}"},
        UpdateExpression="SET host_id = :hid",
        ExpressionAttributeValues={":hid": host["host_id"]},
    )

    # 8. Associate SSH key with auto-created host
    if ssh_key_id:
        from app.services.ssh_key_manager import associate_key_with_host
        associate_key_with_host(user_sub, ssh_key_id, host["host_id"])

    audit_event(user_sub, event="ec2.launch", outcome="success",
                details={"instance_id": instance_id, "instance_type": instance_type})
    return item
```

### 3.3 Idle Instance Checker

Background task registered in `app/main.py` via `app.add_event_handler("startup", ...)`:

```python
async def run_idle_instance_checker(*, poll_interval: int = 300):
    """Every 5 minutes, scan for instances where
    now() - last_activity_at > auto_terminate_after. Auto-terminate them."""
    while True:
        try:
            terminated = check_idle_instances()
            if terminated:
                logger.info("Auto-terminated %d idle instances", terminated)
        except Exception:
            logger.exception("Idle instance checker error")
        await asyncio.sleep(poll_interval)
```

### 3.4 API Router: `app/routers/ec2_launcher.py`
<!-- NOTE: app/routers/ec2_launcher.py does not exist yet — new implementation required -->

New file (~200 lines). Prefix: `/ui/remote/ec2`.

| Method | Path | Request | Response | Description |
|--------|------|---------|----------|-------------|
| `POST` | `/ui/remote/ec2/launch` | `LaunchInstanceIn` | `InstanceOut` (201) | Launch instance |
| `GET` | `/ui/remote/ec2/instances` | query params | `InstanceListOut` | List instances |
| `GET` | `/ui/remote/ec2/instances/{id}` | — | `InstanceOut` | Get instance |
| `POST` | `/ui/remote/ec2/{id}/stop` | — | `InstanceOut` | Stop instance |
| `POST` | `/ui/remote/ec2/{id}/start` | — | `InstanceOut` | Start stopped instance |
| `DELETE` | `/ui/remote/ec2/{id}/terminate` | — | `InstanceOut` | Terminate instance |
| `GET` | `/ui/remote/ec2/instance-types` | — | `InstanceTypeListOut` | List allowed types |
| `GET` | `/ui/remote/ec2/amis` | — | `AmiListOut` | List available AMIs |

#### Pydantic Models

```python
class LaunchInstanceIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    instance_type: str = Field(..., min_length=1)
    ami_id: str = Field(..., min_length=1)
    ssh_key_id: Optional[str] = None
    auto_terminate_after: int = Field(default=7200, ge=600, le=86400)
    startup_script: str = Field(default="", max_length=16_384)
    template_id: Optional[str] = None

class InstanceOut(BaseModel):
    instance_id: str
    ec2_instance_id: str
    label: str
    instance_type: str
    ami_id: str
    ami_name: str
    status: str
    public_ip: str
    private_ip: str
    ssh_key_id: str = ""
    host_id: str = ""
    created_at: int
    started_at: int = 0
    stopped_at: int = 0
    terminated_at: int = 0
    last_activity_at: int = 0
    auto_terminate_after: int = 7200

class InstanceListOut(BaseModel):
    instances: List[InstanceOut]
    count: int

class InstanceTypeInfo(BaseModel):
    instance_type: str
    vcpu: int
    memory_gb: float
    cost_cents_per_min: float

class InstanceTypeListOut(BaseModel):
    types: List[InstanceTypeInfo]

class AmiInfo(BaseModel):
    ami_id: str
    name: str
    os_type: str
    username: str

class AmiListOut(BaseModel):
    amis: List[AmiInfo]
```

### 3.5 Frontend Components

#### Ec2LauncherPage (`frontend/src/pages/remote/Ec2LauncherPage.tsx`)

New page (~450 lines):

- **Header**: "EC2 Instances" with "Launch Instance" button
- **Instance table**: DataTable with columns: Label, Type, AMI, Status badge (color-coded), Public IP, Created (relative), Auto-Terminate countdown, Actions
- **Status badges**: `running` (green), `stopped` (yellow), `launching` (blue spinner), `terminated` (gray), `stopping`/`terminating` (orange)
- **Actions**: Connect (→ SSH terminal with host pre-filled), Stop, Start, Terminate (with confirmation)
- **Empty state**: "No instances running. Launch your first EC2 instance."
- **Auto-refresh**: `useQuery` with `refetchInterval: 10_000` to poll instance status

#### LaunchInstanceDialog (`frontend/src/pages/remote/LaunchInstanceDialog.tsx`)

Dialog (~200 lines):

- **Step 1**: Instance type selector (card grid with vCPU/memory/cost badges)
- **Step 2**: AMI selector (card grid with OS icon and name)
- **Step 3**: Configuration — label, SSH key dropdown (from INFRA-002), auto-terminate duration, startup script textarea
- **Launch button**: Shows estimated cost per hour

#### Route & Navigation

```tsx
<Route path="/remote/ec2" element={<Ec2LauncherPage />} />
```

Sidebar: "EC2 Instances" with `Cloud` icon under Infrastructure group.

---

## 4. Implementation Plan

### Phase 1: Backend Mock EC2 Service (2 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `ec2_instances_table_name`, `ec2_max_per_user`, `ec2_auto_terminate_enabled` |
| `app/core/tables.py` | Add `ec2_instances` table handle |
| `scripts/local-ddb-init.py` | Add `ec2_instances` TableDef |
| `app/services/ec2_launcher.py` | New file: mock store + launch/stop/start/terminate + idle checker |
| `app/models.py` | Add EC2 Pydantic models |

### Phase 2: API + Background Task (2 days)

| File | Change |
|------|--------|
| `app/routers/ec2_launcher.py` | New file: 8 endpoints |
| `app/main.py` | Register router + idle checker background task |

### Phase 3: Frontend (3-4 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add EC2 types |
| `frontend/src/api/endpoints/ec2.ts` | New file: API wrappers |
| `frontend/src/pages/remote/Ec2LauncherPage.tsx` | New file: instance list |
| `frontend/src/pages/remote/LaunchInstanceDialog.tsx` | New file: launch wizard |
| `frontend/src/App.tsx` | Add `/remote/ec2` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "EC2 Instances" nav item |

### Phase 4: E2E Tests (1-2 days)

| File | Change |
|------|--------|
| `frontend/e2e/ec2-launcher.spec.ts` | New file: ~22 tests in 5 sections |

---

## 5. E2E Test Plan (`frontend/e2e/ec2-launcher.spec.ts`)

**Section 248: Instance Type & AMI API (3 tests)**

1. `List instance types returns allowlist` — GET `/instance-types`. Verify 4 types with `vcpu`, `memory_gb`, `cost_cents_per_min` populated.
2. `List AMIs returns curated list` — GET `/amis`. Verify at least 3 AMIs with `name`, `os_type`, `username`.
3. `Unknown instance type on launch returns 400` — POST `/launch` with `instance_type: "m5.24xlarge"`, verify 400.

**Section 249: Launch & Lifecycle API (6 tests)**

4. `Alice launches a t3.micro Ubuntu instance` — POST `/launch` with label, instance_type, ami_id. Verify 201 with `status: "running"`, non-empty `public_ip`, `ec2_instance_id`, `host_id`.
5. `Launched instance appears in host inventory` — After launch, GET `/ui/remote/hosts`. Verify a host with `source: "ec2_auto"` and matching IP exists.
6. `Alice stops a running instance` — POST `/{id}/stop`. Verify `status: "stopped"`, `stopped_at` > 0.
7. `Alice starts a stopped instance` — POST `/{id}/start`. Verify `status: "running"`.
8. `Alice terminates an instance` — DELETE `/{id}/terminate`. Verify `status: "terminated"`, `terminated_at` > 0.
9. `Terminate removes host from inventory` — After terminate, GET host_id → 404.

**Section 250: Instance Limits & Validation (4 tests)**

10. `Alice cannot exceed max instances` — Launch 3 instances (max default). Attempt 4th, verify 409 "Maximum instances reached".
11. `Launch with SSH key injects key` — Generate key (INFRA-002), launch with `ssh_key_id`. Verify `ssh_key_id` in response, host has `ssh_key_id` set.
12. `Cannot stop a terminated instance` — Terminate, then POST `/stop` → 409.
13. `Cannot start a running instance` — POST `/start` on running instance → 409.

**Section 251: Instance List & Filter (4 tests)**

14. `List instances returns all user instances` — Launch 2 instances. GET list, verify count=2.
15. `Filter by status` — Launch + terminate one. GET `?status=running`, verify only running instances.
16. `List sorted by created_at descending` — Launch 2 sequentially. Verify first returned is newest.
17. `Alice cannot see Bob's instances` — Alice launches, Bob lists → Bob's list does not include Alice's instance.

**Section 252: EC2 Launcher UI (5 tests)**

18. `Ec2LauncherPage renders instance table` — Navigate to `/remote/ec2`, verify table with headers: Label, Type, Status, IP, Created.
19. `Launch dialog shows instance types and AMIs` — Click "Launch Instance". Verify instance type cards and AMI cards are visible.
20. `Launch from dialog creates instance` — Fill launch form, submit. Verify new row appears in table with "running" badge.
21. `Stop button stops instance` — Click Stop on running instance. Verify status changes to "stopped".
22. `Terminate with confirmation dialog` — Click Terminate, verify confirmation dialog appears. Confirm. Verify status changes to "terminated".

---

## 6. Security Considerations

### 6.1 Instance Limits

Per-user maximum (default: 3) prevents resource abuse. Configurable via `S.ec2_max_per_user`.

### 6.2 Instance Type Allowlist

Only pre-approved instance types can be launched. The allowlist is defined in `INSTANCE_TYPES` and cannot be extended via the API. Admin-only endpoint (INFRA-012) could extend the allowlist in the future.

### 6.3 Auto-Terminate

Idle instances are terminated after `auto_terminate_after` seconds (default: 2 hours) to prevent cost accumulation. Users can set this between 10 minutes and 24 hours.

### 6.4 Network Security

Auto-created security groups restrict SSH (port 22) access to the platform's egress IP range only. No 0.0.0.0/0 ingress on SSH is allowed by default.

### 6.5 User Isolation

All instance records use `user_sub` as the DDB partition key. No cross-user access is possible via the API.

---

## 7. Observability & Monitoring

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ec2_instance_launched_total` | Counter | `instance_type`, `ami_id` | Instances launched |
| `ec2_instance_terminated_total` | Counter | `reason` (user/auto_idle/admin) | Terminations by reason |
| `ec2_instance_stopped_total` | Counter | — | Stop events |
| `ec2_instance_started_total` | Counter | — | Start events |
| `ec2_instance_launch_latency_seconds` | Histogram | `instance_type` | Time from launch request to running |
| `ec2_auto_terminate_total` | Counter | — | Idle auto-terminations |
| `ec2_active_instances` | Gauge | `user_sub` | Currently running instances per user |
| `ec2_instance_limit_reached_total` | Counter | — | Instance limit rejection events |
| `ec2_mock_mode` | Gauge | — | 1 if mock EC2, 0 if real |

### 7.2 Structured Log Events

```json
{"logger": "ec2_launcher", "level": "info", "event": "instance_launched", "user_sub": "alice-uuid", "instance_id": "i-mock-abc123", "instance_type": "t3.micro", "ami_id": "ami-ubuntu-22", "ssh_key_id": "k_def456"}

{"logger": "ec2_launcher", "level": "info", "event": "instance_terminated", "user_sub": "alice-uuid", "instance_id": "i-mock-abc123", "reason": "auto_idle", "runtime_minutes": 125}

{"logger": "ec2_launcher", "level": "warn", "event": "instance_limit_reached", "user_sub": "alice-uuid", "current_count": 3, "max_allowed": 3}

{"logger": "ec2_launcher", "level": "info", "event": "auto_terminate_scan", "scanned": 45, "terminated": 3, "duration_ms": 250}
```

### 7.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High launch rate | `rate(ec2_instance_launched_total[1h]) > 50` platform-wide | Warning | Possible abuse |
| Auto-terminate failures | Background task errors > 3 consecutively | Critical | Manual instance cleanup needed |
| Instance stuck in pending | Instance in `pending` state > 5 minutes | Warning | Check EC2 API / mock |
| Long-running instance | Instance running > 24 hours | Info | Notify user about costs |

---

## 8. Rollout Plan

### Phase 1: Mock Mode (Days 1-3)

- **Feature flag**: `EC2_LAUNCHER_ENABLED=false`
- Deploy with mock EC2 service only (no real AWS calls)
- All endpoints return 404 when flag is off
- Integration tests validate full lifecycle in mock mode

### Phase 2: Internal Beta (Days 4-6)

- **Feature flag**: `EC2_LAUNCHER_ENABLED=true` for internal users
- Deploy frontend pages
- Test launch + connect + auto-terminate flow
- Validate host inventory auto-registration
- Validate SSH key injection

### Phase 3: Real EC2 (Days 7-8)

- Configure real AWS credentials and VPC settings
- Enable `ec2_real_mode=true` for staging
- Validate real EC2 lifecycle matches mock behavior
- **Rollback**: Set `EC2_LAUNCHER_ENABLED=false`; terminate any running instances manually

### Phase 4: GA (Day 9+)

- Enable for all users with conservative limits (max 2 instances)
- Monitor spending, instance count, auto-terminate patterns
- Gradually increase limits based on usage data

---

## 9. Performance Considerations

### 9.1 Latency Targets

| Operation | Target p50 | Target p99 | Notes |
|-----------|-----------|-----------|-------|
| Launch instance (mock) | < 100ms | < 300ms | In-memory mock |
| Launch instance (real) | < 3s | < 10s | EC2 RunInstances API |
| Stop/start instance | < 50ms | < 200ms | EC2 API call |
| Terminate instance | < 50ms | < 200ms | EC2 API + DDB update |
| List instances | < 30ms | < 100ms | DDB query |
| Auto-terminate scan | < 2s | < 5s | Scan all running instances |

### 9.2 DynamoDB Costs

| Operation | RCU | WCU | Notes |
|-----------|-----|-----|-------|
| Launch (create record) | — | 2.5 | Instance + host inventory |
| List instances | 2.0 | — | Query per user |
| Terminate | — | 2.5 | Update instance + host |
| Auto-terminate scan | 10.0 | varies | Scan + batch updates |

### 9.3 Scalability

- **Per-user instance limit**: Default 3, configurable. Keeps DDB item count bounded.
- **Auto-terminate background task**: Runs every 60 seconds. Scans GSI for `status=running, last_activity_at < now - auto_terminate_after`. Efficient with GSI range query.
- **Mock EC2 state**: In-memory `_MockEc2Store` is per-process. With `--workers 1` this is fine for dev. Production uses real EC2 API (stateless).
- **EC2 API rate limits**: AWS allows ~100 RunInstances/sec per account. Platform-wide launches are well under this.

### 9.4 Rate Limiting

| Action | Limit | Window | Key |
|--------|-------|--------|-----|
| Launch instance | 5 | 1 hour | user_sub |
| Stop/start | 10 | 1 hour | user_sub |
| Terminate | 10 | 1 hour | user_sub |
| List instances | 60 | 1 minute | user_sub |

### 9.5 Caching

| Data | Cache | TTL | Invalidation |
|------|-------|-----|--------------|
| Instance list | React Query | 10s staleTime | On launch/stop/start/terminate |
| Instance types (allowlist) | In-memory dict | 300s | On settings change |
| AMI list | In-memory dict | 300s | On settings change |

---

## 10. Acceptance Criteria

1. Users can launch EC2 instances from a curated list of instance types and AMIs.
2. Mock EC2 service works in dev mode with simulated IPs and lifecycle.
3. Launched instances auto-register in host inventory with `source: "ec2_auto"`.
4. SSH keys from INFRA-002 can be injected at launch time.
5. Instance lifecycle (stop/start/terminate) is fully functional.
6. Per-user instance limit is enforced.
7. Idle instance auto-termination runs as a background task.
8. Instance list page shows real-time status with auto-refresh.
9. All lifecycle operations produce audit events.
10. Terminated instances are cleaned up from host inventory.

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| AWS client helpers | `app/core/aws.py` | 30, 40 | `sns_client()`, `sqs_client()` — pattern for EC2 client; NO EC2 client exists yet |
| `S.dev_mode` | `app/core/settings.py` | — | Boolean; controls mock vs real services |
| `audit_event()` | `app/services/alerts.py` | 695 | Audit logging for lifecycle events |
| Call billing heartbeat pattern | `app/routers/call_billing.py` | — | Per-minute billing model for reuse in INFRA-005 |
| `ec2_instances` DDB table | — | — | Does not exist yet in `scripts/local-ddb-init.py` |
| `app/services/ec2_launcher.py` | — | — | Does not exist yet |
| `app/routers/ec2_launcher.py` | — | — | Does not exist yet |
| `remote_hosts` (INFRA-001 dep) | — | — | Host auto-registration target; does not exist yet |
| `ssh_key_manager` (INFRA-002 dep) | — | — | Key injection source; does not exist yet |
