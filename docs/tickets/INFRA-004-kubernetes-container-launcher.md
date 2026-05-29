# INFRA-004: Kubernetes Container Launcher

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 8-10 days  
**Dependencies**: INFRA-001 (Host Inventory), INFRA-002 (SSH Key Manager)

---

## 1. Overview & Motivation

### The Gap

While INFRA-003 provides EC2 instance launching for full virtual machines, many users need lightweight, ephemeral workspaces — containers that spin up in seconds, cost less, and are disposable. The platform has no Kubernetes integration and no way to:

1. Launch containers in a Kubernetes cluster from the UI
2. Track pod lifecycle (pending, running, succeeded, failed)
3. View container logs
4. Enforce per-user resource quotas (CPU, memory)
5. Auto-terminate pods after a TTL to prevent orphaned resources
6. Isolate users into separate Kubernetes namespaces

Kubernetes is the industry standard for container orchestration. Adding a K8s launcher alongside the EC2 launcher gives users two tiers of compute: heavyweight VMs (EC2) for long-running workloads and lightweight containers (K8s) for quick experiments, dev environments, and CI tasks.

### Why This Matters

1. **Fast startup**: Containers start in 2-5 seconds vs. 30-60 seconds for EC2 instances.
2. **Lower cost**: A container with 500m CPU / 512Mi RAM costs a fraction of even `t3.micro`.
3. **Disposability**: Users can launch, use, and discard containers freely.
4. **Resource efficiency**: Kubernetes packs multiple containers on shared nodes.
5. **Foundation**: INFRA-005 (Cost Tracking), INFRA-008 (Monitoring), and INFRA-012 (Admin Dashboard) need pod tracking data.

### Architecture After This Change

```
K8s Launch Flow

  POST /ui/remote/k8s/launch
  { image, preset, label, ssh_key_id? }
       |
       v
  +--------------------+        +--------------------+
  | k8s_launcher.py    |------->| Mock K8s API       |  (dev mode)
  | (service layer)    |        | (in-memory)        |
  +--------------------+        +--------------------+
       |                             |
       | real mode                   | mock mode
       v                             v
  +--------------------+        +--------------------+
  | kubernetes client  |        | _MockK8sStore      |
  | (official Python)  |        | (dict-based)       |
  +--------------------+        +--------------------+
       |
       v
  +--------------------+
  | k8s_pods DDB        |  PK=user_sub, SK=POD#{pod_id}
  | (tracking table)    |  GSIs: ByNamespace, ByStatus, ByCreatedAt
  +--------------------+
       |
       +---> Auto-register in remote_hosts (INFRA-001)
       |     hostname = pod-service.namespace.svc.cluster.local
       |
       +---> Inject SSH public key via authorized_keys volume mount
       |
       +---> TTL auto-termination (default 4 hours)
```

---

## 2. Current State Analysis

### 2.1 No Kubernetes Client
<!-- VERIFIED: No kubernetes Python client in codebase; no K8s-related services or routers exist -->

The codebase has no Kubernetes integration. The official `kubernetes` Python client is not in the project's dependencies. For dev mode, a fully in-memory mock is needed — no real K8s cluster required.

### 2.2 Container Image Requirements

SSH-enabled containers are needed for browser terminal access. Pre-built images must include an SSH server:
- `ubuntu-ssh`: Ubuntu 22.04 with OpenSSH server, basic dev tools
- `alpine-ssh`: Alpine 3.18 with OpenSSH, minimal footprint
- `dev-workspace`: Ubuntu 22.04 with OpenSSH, Python 3.12, Node 20, git, vim, tmux

### 2.3 Resource Quotas

Kubernetes supports `ResourceQuota` and `LimitRange` objects per namespace. The launcher should enforce:
- CPU: 100m to 2000m per container
- Memory: 128Mi to 4Gi per container
- Max pods per user: 5 (default)

### 2.4 Host Inventory Integration (INFRA-001)

Pods auto-register as hosts with `source: "k8s_auto"`. The hostname is the K8s service DNS name (`pod-name.namespace.svc.cluster.local`) or a NodePort IP in mock mode.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `k8s_pods`
<!-- NOTE: k8s_pods table does not exist yet in scripts/local-ddb-init.py — new table required -->

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.k8s_pods_table_name, "k8s_pods"),
    "user_sub",            # PK — pod owner
    "sk",                  # SK — POD#{pod_id}
    gsis=[
        {"index_name": "ByNamespace", "partition_key": "namespace", "sort_key": "created_at"},
        {"index_name": "ByStatus", "partition_key": "user_sub", "sort_key": "status"},
        {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | S (PK) | Pod owner |
| `sk` | S (SK) | `POD#{pod_id}` |
| `pod_id` | S | Platform-generated UUID |
| `k8s_pod_name` | S | Kubernetes pod name (e.g., `ws-user123-abc`) |
| `namespace` | S | K8s namespace (e.g., `user-{user_sub_short}`) |
| `label` | S | User-assigned name |
| `image` | S | Container image (from allowlist) |
| `image_display_name` | S | Human-readable image name |
| `preset` | S | Resource preset name: `small`, `medium`, `large` |
| `cpu_millicores` | N | CPU limit in millicores (e.g., 500) |
| `memory_mb` | N | Memory limit in MB (e.g., 512) |
| `status` | S | `pending`, `running`, `succeeded`, `failed`, `terminated` |
| `pod_ip` | S | Pod cluster IP (mock: `10.pod.x.y`) |
| `service_hostname` | S | DNS hostname for SSH access |
| `ssh_port` | N | SSH port (22 inside container, NodePort externally) |
| `ssh_key_id` | S | Reference to INFRA-002 key |
| `host_id` | S | Reference to auto-created host in INFRA-001 |
| `created_at` | N | Unix timestamp |
| `started_at` | N | When pod reached `running` |
| `terminated_at` | N | When pod was deleted |
| `ttl_seconds` | N | Max lifetime (default: 14400 = 4 hours) |
| `expires_at` | N | `created_at + ttl_seconds` — auto-terminate deadline |
| `last_activity_at` | N | Last SSH connection timestamp |
| `template_id` | S | INFRA-007 template used (optional) |
| `env_vars` | M | Environment variables injected into container |
| `ports` | L[N] | Exposed ports |

### 3.2 Resource Presets

```python
RESOURCE_PRESETS = {
    "small":  {"cpu_millicores": 250,  "memory_mb": 256,  "cost_cents_per_min": 0.1},
    "medium": {"cpu_millicores": 500,  "memory_mb": 512,  "cost_cents_per_min": 0.3},
    "large":  {"cpu_millicores": 1000, "memory_mb": 1024, "cost_cents_per_min": 0.6},
    "xlarge": {"cpu_millicores": 2000, "memory_mb": 4096, "cost_cents_per_min": 1.2},
}

IMAGE_ALLOWLIST = {
    "ubuntu-ssh":     {"display_name": "Ubuntu SSH",     "os_type": "linux", "username": "ubuntu"},
    "alpine-ssh":     {"display_name": "Alpine SSH",     "os_type": "linux", "username": "alpine"},
    "dev-workspace":  {"display_name": "Dev Workspace",  "os_type": "linux", "username": "dev"},
}
```

### 3.3 Mock K8s Service: `app/services/k8s_launcher.py`
<!-- NOTE: app/services/k8s_launcher.py does not exist yet — new implementation required -->

New file (~400 lines). Follows the same mock pattern as INFRA-003:

```python
"""Kubernetes pod launcher — launch, monitor, terminate containers.
Uses in-memory mock in dev mode; real K8s client in production."""

from __future__ import annotations
import random
import uuid
from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event
from app.services.remote_hosts import create_host, delete_host

MAX_PODS_PER_USER = 5
DEFAULT_TTL_SECONDS = 14400  # 4 hours


class _MockK8sStore:
    """In-memory K8s pod store for dev mode."""
    def __init__(self):
        self._pods: Dict[str, Dict[str, Any]] = {}
        self._logs: Dict[str, List[str]] = {}

    def create_pod(self, *, pod_name: str, namespace: str, image: str,
                   cpu: int, memory_mb: int, env_vars: dict, ssh_pub_key: str | None) -> Dict[str, Any]:
        ip_a, ip_b = random.randint(1, 254), random.randint(1, 254)
        pod = {
            "pod_name": pod_name,
            "namespace": namespace,
            "status": "running",  # mock goes straight to running
            "pod_ip": f"10.pod.{ip_a}.{ip_b}",
            "service_hostname": f"{pod_name}.{namespace}.svc.cluster.local",
        }
        self._pods[pod_name] = pod
        self._logs[pod_name] = [
            f"Starting SSH server on port 22...",
            f"SSH server ready. Accepting connections.",
            f"Container {image} started successfully.",
        ]
        return pod

    def delete_pod(self, pod_name: str, namespace: str) -> bool:
        pod = self._pods.get(pod_name)
        if pod:
            pod["status"] = "terminated"
            return True
        return False

    def get_logs(self, pod_name: str, namespace: str, tail: int = 100) -> List[str]:
        return self._logs.get(pod_name, [])[-tail:]


_mock_store = _MockK8sStore()


def launch_pod(
    user_sub: str,
    *,
    label: str,
    image: str,
    preset: str = "small",
    ssh_key_id: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    env_vars: dict | None = None,
    template_id: str | None = None,
) -> Dict[str, Any]:
    """Launch a new container pod."""

def list_pods(user_sub: str, *, status: str | None = None) -> List[Dict[str, Any]]:
    """List user's pods with optional status filter."""

def get_pod(user_sub: str, pod_id: str) -> Dict[str, Any] | None:
    """Get a single pod by ID."""

def get_pod_logs(user_sub: str, pod_id: str, *, tail: int = 100) -> List[str]:
    """Get recent container logs."""

def terminate_pod(user_sub: str, pod_id: str) -> Dict[str, Any]:
    """Delete a pod (immediate termination)."""

def check_expired_pods() -> int:
    """Background task: find pods past their TTL and terminate them."""
```

### 3.4 API Router: `app/routers/k8s_launcher.py`
<!-- NOTE: app/routers/k8s_launcher.py does not exist yet — new implementation required -->

New file (~180 lines). Prefix: `/ui/remote/k8s`.

| Method | Path | Request | Response | Description |
|--------|------|---------|----------|-------------|
| `POST` | `/ui/remote/k8s/launch` | `LaunchPodIn` | `PodOut` (201) | Launch pod |
| `GET` | `/ui/remote/k8s/pods` | query params | `PodListOut` | List pods |
| `GET` | `/ui/remote/k8s/pods/{id}` | — | `PodOut` | Get pod detail |
| `GET` | `/ui/remote/k8s/pods/{id}/logs` | `?tail=100` | `PodLogsOut` | Get pod logs |
| `DELETE` | `/ui/remote/k8s/pods/{id}` | — | `PodOut` | Terminate pod |
| `GET` | `/ui/remote/k8s/images` | — | `ImageListOut` | List allowed images |
| `GET` | `/ui/remote/k8s/presets` | — | `PresetListOut` | List resource presets |

#### Pydantic Models

```python
class LaunchPodIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    image: str = Field(..., min_length=1)
    preset: Literal["small", "medium", "large", "xlarge"] = "small"
    ssh_key_id: Optional[str] = None
    ttl_seconds: int = Field(default=14400, ge=600, le=86400)
    env_vars: Dict[str, str] = Field(default_factory=dict)
    template_id: Optional[str] = None

class PodOut(BaseModel):
    pod_id: str
    k8s_pod_name: str
    namespace: str
    label: str
    image: str
    image_display_name: str
    preset: str
    cpu_millicores: int
    memory_mb: int
    status: str
    pod_ip: str
    service_hostname: str
    ssh_port: int = 22
    ssh_key_id: str = ""
    host_id: str = ""
    created_at: int
    started_at: int = 0
    terminated_at: int = 0
    ttl_seconds: int
    expires_at: int
    last_activity_at: int = 0

class PodListOut(BaseModel):
    pods: List[PodOut]
    count: int

class PodLogsOut(BaseModel):
    pod_id: str
    lines: List[str]

class ImageInfo(BaseModel):
    image: str
    display_name: str
    os_type: str
    username: str

class ImageListOut(BaseModel):
    images: List[ImageInfo]

class PresetInfo(BaseModel):
    preset: str
    cpu_millicores: int
    memory_mb: int
    cost_cents_per_min: float

class PresetListOut(BaseModel):
    presets: List[PresetInfo]
```

### 3.5 Namespace Isolation

Each user gets a dedicated K8s namespace: `user-{user_sub_short}` where `user_sub_short` is the first 12 characters of the user_sub (sanitized for K8s naming rules: lowercase alphanumeric + hyphens). In mock mode, namespaces are tracked in-memory. In production, the launcher creates the namespace if it does not exist.

### 3.6 SSH Key Injection

When `ssh_key_id` is provided, the launcher:
1. Reads the public key from INFRA-002 (`get_key_metadata`)
2. Creates a K8s ConfigMap containing the public key
3. Mounts it as `/home/{username}/.ssh/authorized_keys` in the container
4. In mock mode, this is a no-op — the mock SSH bridge accepts any key

### 3.7 TTL Auto-Termination

Background task registered in `app/main.py`:

```python
async def run_pod_ttl_checker(*, poll_interval: int = 300):
    """Every 5 minutes, scan for pods where now() > expires_at. Terminate them."""
    while True:
        try:
            terminated = check_expired_pods()
            if terminated:
                logger.info("Auto-terminated %d expired pods", terminated)
        except Exception:
            logger.exception("Pod TTL checker error")
        await asyncio.sleep(poll_interval)
```

### 3.8 Frontend Components

#### K8sLauncherPage (`frontend/src/pages/remote/K8sLauncherPage.tsx`)

New page (~400 lines):

- **Header**: "Containers" with "Launch Container" button
- **Pod table**: DataTable with columns: Label, Image, Preset, Status badge, Pod IP, TTL remaining (countdown), Created, Actions
- **Status badges**: `running` (green), `pending` (blue spinner), `failed` (red), `terminated` (gray)
- **Actions**: Connect (→ SSH terminal), View Logs, Terminate
- **Log viewer**: Slide-over panel with scrollable log output, auto-scroll, tail count selector
- **Auto-refresh**: `refetchInterval: 10_000`

#### LaunchPodDialog (`frontend/src/pages/remote/LaunchPodDialog.tsx`)

Dialog (~180 lines):

- **Image selector**: Card grid with image name, description, OS icon
- **Preset selector**: Radio group with CPU/memory/cost breakdown
- **Configuration**: Label, SSH key dropdown, TTL duration picker, env vars key-value editor
- **Launch button**: Shows TTL expiry time and estimated cost

#### Route & Navigation

```tsx
<Route path="/remote/k8s" element={<K8sLauncherPage />} />
```

Sidebar: "Containers" with `Container` icon under Infrastructure group.

---

## 4. Implementation Plan

### Phase 1: Backend Mock K8s Service (2 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `k8s_pods_table_name`, `k8s_max_pods_per_user`, `k8s_ttl_checker_enabled` |
| `app/core/tables.py` | Add `k8s_pods` table handle |
| `scripts/local-ddb-init.py` | Add `k8s_pods` TableDef with 3 GSIs |
| `app/services/k8s_launcher.py` | New file: mock store + launch/terminate/logs + TTL checker |
| `app/models.py` | Add K8s Pydantic models |

### Phase 2: API + Background Task (2 days)

| File | Change |
|------|--------|
| `app/routers/k8s_launcher.py` | New file: 7 endpoints |
| `app/main.py` | Register router + TTL checker background task |

### Phase 3: Frontend (3-4 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add K8s types |
| `frontend/src/api/endpoints/k8s.ts` | New file: API wrappers |
| `frontend/src/pages/remote/K8sLauncherPage.tsx` | New file: pod list + log viewer |
| `frontend/src/pages/remote/LaunchPodDialog.tsx` | New file: launch dialog |
| `frontend/src/App.tsx` | Add `/remote/k8s` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Containers" nav item |

### Phase 4: E2E Tests (1-2 days)

| File | Change |
|------|--------|
| `frontend/e2e/k8s-launcher.spec.ts` | New file: ~20 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/k8s-launcher.spec.ts`)

**Section 253: Image & Preset API (3 tests)**

1. `List images returns allowlist` — GET `/images`. Verify 3 images with `display_name`, `os_type`, `username`.
2. `List presets returns resource options` — GET `/presets`. Verify 4 presets with `cpu_millicores`, `memory_mb`, `cost_cents_per_min`.
3. `Unknown image on launch returns 400` — POST `/launch` with `image: "not-an-image"`, verify 400.

**Section 254: Pod Launch & Lifecycle API (6 tests)**

4. `Alice launches an ubuntu-ssh pod` — POST `/launch` with label, image, preset. Verify 201 with `status: "running"`, `pod_ip`, `service_hostname`, `expires_at > created_at`.
5. `Launched pod appears in host inventory` — After launch, GET `/ui/remote/hosts`. Verify host with `source: "k8s_auto"`.
6. `Alice terminates a pod` — DELETE `/{pod_id}`. Verify `status: "terminated"`, `terminated_at` > 0.
7. `Terminate removes host from inventory` — After terminate, verify host removed.
8. `Pod logs are available` — GET `/{pod_id}/logs?tail=10`. Verify `lines` array is non-empty.
9. `Launch with SSH key sets key association` — Launch pod with `ssh_key_id`. Verify `ssh_key_id` in response.

**Section 255: Pod Limits & TTL (5 tests)**

10. `Alice cannot exceed max pods` — Launch 5 pods (max default). Attempt 6th → 409.
11. `TTL defaults to 4 hours` — Launch without `ttl_seconds`. Verify `ttl_seconds: 14400` and `expires_at == created_at + 14400`.
12. `Custom TTL is respected` — Launch with `ttl_seconds: 3600`. Verify `expires_at == created_at + 3600`.
13. `TTL below minimum returns 422` — Launch with `ttl_seconds: 60` (min 600). Verify 422.
14. `Alice cannot access Bob's pods` — Alice launches, Bob tries GET/DELETE → 404.

**Section 256: Containers UI (6 tests)**

15. `K8sLauncherPage renders pod table` — Navigate to `/remote/k8s`, verify table headers visible.
16. `Launch dialog shows images and presets` — Click "Launch Container", verify image cards and preset options.
17. `Launch from dialog creates pod` — Fill form, submit. Verify new row with "running" badge.
18. `View logs shows container output` — Click "View Logs" on pod. Verify log panel opens with text.
19. `Terminate with confirmation` — Click Terminate, confirm. Verify status changes.
20. `TTL countdown displays remaining time` — Verify TTL column shows countdown (e.g., "3h 59m").

---

## 6. Security Considerations

### 6.1 Image Allowlist

Only pre-approved container images can be launched. Users cannot specify arbitrary Docker images. This prevents supply-chain attacks from malicious images.

### 6.2 Resource Limits

All containers have enforced CPU and memory limits via K8s `resources.limits`. No unbounded containers.

### 6.3 Namespace Isolation

Each user operates in their own K8s namespace. Users cannot access pods in other namespaces.

### 6.4 Network Policy

In production, K8s NetworkPolicy restricts container egress to the platform's SSH endpoint only. Containers cannot reach other users' pods or internal services.

---

## 7. DynamoDB Access Patterns

### 7.1 Access Pattern Matrix

| Access Pattern | Table/GSI | PK | SK / Condition | Projection | Frequency |
|---------------|-----------|-----|----------------|------------|-----------|
| Get pod by ID | Main table | `user_sub` | `SK = POD#{pod_id}` | All | High — every detail/action |
| List user pods | Main table | `user_sub` | `SK begins_with POD#` | All | High — pod table view |
| List pods by status | ByStatus GSI | `user_sub` | `status = running` | All | Medium — filter views |
| List pods by namespace | ByNamespace GSI | `namespace` | `created_at BETWEEN` | All | Low — admin namespace view |
| List pods by creation date | ByCreatedAt GSI | `user_sub` | `created_at BETWEEN` | All | Medium — sorted listing |
| TTL scan for expired pods | ByCreatedAt GSI | Scan | `expires_at < :now` | pod_id, user_sub, status | Every 30 sec (background) |
| Count active pods per user | ByStatus GSI | `user_sub` | `status = running` | COUNT | On each launch (quota check) |

### 7.2 Example DynamoDB Items

**Running pod record:**

```json
{
  "user_sub":         {"S": "abc-123-def"},
  "sk":               {"S": "POD#p_9f4a2b1c"},
  "pod_id":           {"S": "p_9f4a2b1c"},
  "k8s_pod_name":     {"S": "ws-abc123def-9f4a2b1c"},
  "namespace":        {"S": "user-abc123def"},
  "label":            {"S": "My Dev Environment"},
  "image":            {"S": "dev-workspace"},
  "image_display_name": {"S": "Dev Workspace"},
  "preset":           {"S": "medium"},
  "cpu_millicores":   {"N": "500"},
  "memory_mb":        {"N": "512"},
  "status":           {"S": "running"},
  "pod_ip":           {"S": "10.pod.42.17"},
  "service_hostname": {"S": "ws-abc123def-9f4a2b1c.user-abc123def.svc.cluster.local"},
  "ssh_port":         {"N": "22"},
  "ssh_key_id":       {"S": "key_7d3f1a"},
  "host_id":          {"S": "host_a2c8e4"},
  "created_at":       {"N": "1748520000"},
  "started_at":       {"N": "1748520003"},
  "terminated_at":    {"N": "0"},
  "ttl_seconds":      {"N": "14400"},
  "expires_at":       {"N": "1748534400"},
  "last_activity_at": {"N": "1748521500"},
  "env_vars":         {"M": {"NODE_ENV": {"S": "development"}, "DEBUG": {"S": "true"}}},
  "ports":            {"L": [{"N": "22"}, {"N": "8080"}]}
}
```

**Terminated pod record:**

```json
{
  "user_sub":         {"S": "abc-123-def"},
  "sk":               {"S": "POD#p_e7b3c5d2"},
  "pod_id":           {"S": "p_e7b3c5d2"},
  "status":           {"S": "terminated"},
  "terminated_at":    {"N": "1748525600"},
  "last_activity_at": {"N": "1748525590"}
}
```

---

## 8. API Request/Response Examples

### 8.1 Launch a Pod

```bash
curl -s -X POST http://localhost:8000/ui/remote/k8s/launch \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_abc; ui_csrf=tok123; ui_access_token=eyJ..." \
  -H "x-csrf-token: tok123" \
  -d '{
    "label": "My Dev Env",
    "image": "dev-workspace",
    "preset": "medium",
    "ssh_key_id": "key_7d3f1a",
    "ttl_seconds": 7200,
    "env_vars": {"NODE_ENV": "development"}
  }'
```

**Response (201):**

```json
{
  "pod_id": "p_9f4a2b1c",
  "k8s_pod_name": "ws-abc123def-9f4a2b1c",
  "namespace": "user-abc123def",
  "label": "My Dev Env",
  "image": "dev-workspace",
  "image_display_name": "Dev Workspace",
  "preset": "medium",
  "cpu_millicores": 500,
  "memory_mb": 512,
  "status": "running",
  "pod_ip": "10.pod.42.17",
  "service_hostname": "ws-abc123def-9f4a2b1c.user-abc123def.svc.cluster.local",
  "ssh_port": 22,
  "ssh_key_id": "key_7d3f1a",
  "host_id": "host_a2c8e4",
  "created_at": 1748520000,
  "started_at": 1748520003,
  "terminated_at": 0,
  "ttl_seconds": 7200,
  "expires_at": 1748527200,
  "last_activity_at": 0
}
```

### 8.2 Get Pod Logs

```bash
curl -s http://localhost:8000/ui/remote/k8s/pods/p_9f4a2b1c/logs?tail=50 \
  -H "Cookie: ui_session=sess_abc; ui_csrf=tok123; ui_access_token=eyJ..."
```

**Response (200):**

```json
{
  "pod_id": "p_9f4a2b1c",
  "lines": [
    "Starting SSH server on port 22...",
    "SSH server ready. Accepting connections.",
    "Container dev-workspace started successfully."
  ]
}
```

---

## 9. Error Handling Matrix

| HTTP | Error Code | Condition | Response Body | Client Recovery |
|------|-----------|-----------|---------------|-----------------|
| 400 | `INVALID_IMAGE` | Image not in allowlist | `{"detail": "Image 'x' not in allowed image list"}` | Show image picker |
| 400 | `INVALID_PRESET` | Preset not recognized | `{"detail": "Unknown preset 'y'"}` | Show preset picker |
| 404 | `POD_NOT_FOUND` | Pod ID doesn't exist or belongs to another user | `{"detail": "Pod not found"}` | Refresh pod list |
| 409 | `POD_LIMIT_REACHED` | User has max pods running | `{"detail": "Maximum 5 running pods. Terminate one first."}` | Show terminate option |
| 409 | `POD_ALREADY_TERMINATED` | Terminate called on terminated pod | `{"detail": "Pod already terminated"}` | Refresh status |
| 422 | `TTL_TOO_SHORT` | ttl_seconds < 600 | `{"detail": "TTL must be >= 600 seconds"}` | Show min value |
| 422 | `TTL_TOO_LONG` | ttl_seconds > 86400 | `{"detail": "TTL must be <= 86400 seconds (24h)"}` | Show max value |
| 422 | `INVALID_LABEL` | Label empty or > 100 chars | `{"detail": "Label must be 1-100 characters"}` | Fix label input |
| 422 | `INVALID_ENV_VAR` | Reserved env var key (e.g., `PATH`) | `{"detail": "Cannot override system environment variables"}` | Remove reserved key |
| 500 | `K8S_API_ERROR` | Real K8s API unreachable | `{"detail": "Container service temporarily unavailable"}` | Retry with backoff |
| 502 | `K8S_TIMEOUT` | K8s API response > 10s | `{"detail": "Container service timed out"}` | Retry |
| 503 | `MAINTENANCE` | Feature flag disabled | `{"detail": "Container launcher is currently disabled"}` | Wait for re-enable |

---

## 10. Observability & Monitoring

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `k8s_pod_launched_total` | Counter | `image`, `preset` | Pods launched |
| `k8s_pod_terminated_total` | Counter | `reason` (user/ttl_expired/admin/failed) | Terminations by reason |
| `k8s_pod_launch_latency_seconds` | Histogram | `image` | Time from launch to running |
| `k8s_ttl_terminated_total` | Counter | — | TTL-based auto-terminations |
| `k8s_active_pods` | Gauge | `user_sub` | Currently running pods per user |
| `k8s_pod_limit_reached_total` | Counter | — | Pod limit rejection events |
| `k8s_log_fetch_total` | Counter | — | Log fetch requests |
| `k8s_log_fetch_latency_seconds` | Histogram | — | Log retrieval latency |
| `k8s_mock_mode` | Gauge | — | 1 if mock K8s, 0 if real |
| `k8s_resource_utilization_cpu` | Gauge | `user_sub` | Total CPU allocated per user (millicores) |
| `k8s_resource_utilization_memory` | Gauge | `user_sub` | Total memory allocated per user (MiB) |

### 7.2 Structured Log Events

```json
{"logger": "k8s_launcher", "level": "info", "event": "pod_launched", "user_sub": "alice-uuid", "pod_id": "pod-abc123", "image": "ubuntu:22.04", "preset": "small", "ttl_seconds": 14400}

{"logger": "k8s_launcher", "level": "info", "event": "pod_terminated", "user_sub": "alice-uuid", "pod_id": "pod-abc123", "reason": "ttl_expired", "runtime_seconds": 14400}

{"logger": "k8s_launcher", "level": "warn", "event": "pod_limit_reached", "user_sub": "alice-uuid", "current_count": 5, "max_allowed": 5}

{"logger": "k8s_launcher", "level": "info", "event": "ttl_scan_complete", "scanned": 30, "terminated": 5, "duration_ms": 180}

{"logger": "k8s_launcher", "level": "error", "event": "pod_launch_failed", "user_sub": "alice-uuid", "image": "ubuntu:22.04", "error": "ImagePullBackOff"}
```

### 7.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High pod failure rate | `rate(k8s_pod_terminated_total{reason=failed}[1h]) > 10` | Warning | Check image availability |
| TTL scan failures | Background task errors > 3 consecutively | Critical | Manual pod cleanup needed |
| Pod stuck in pending | Pod in `pending` > 2 minutes | Warning | Check K8s scheduler / node capacity |
| Resource quota exhaustion | Total CPU/memory across all users > 80% of cluster capacity | Warning | Scale cluster or restrict launches |
| Log fetch slow | `p99(k8s_log_fetch_latency_seconds) > 5s` | Warning | Check K8s API performance |

---

## 11. Rollout Plan

### Phase 1: Mock Mode (Days 1-3)

- **Feature flag**: `K8S_LAUNCHER_ENABLED=false`
- Deploy with mock K8s service only
- All endpoints return 404 when flag is off
- Integration tests validate full pod lifecycle in mock mode
- Validate TTL expiration logic with short TTLs

### Phase 2: Internal Beta (Days 4-6)

- **Feature flag**: `K8S_LAUNCHER_ENABLED=true` for internal users
- Deploy frontend pages
- Test launch + logs + terminate flow
- Validate host inventory auto-registration
- Test namespace isolation between users

### Phase 3: Real K8s (Days 7-8)

- Configure kubeconfig for staging K8s cluster
- Enable `k8s_real_mode=true` for staging
- Validate real pod lifecycle matches mock behavior
- Test resource limits enforcement
- **Rollback**: Set `K8S_LAUNCHER_ENABLED=false`; terminate running pods via kubectl

### Phase 4: GA (Day 9+)

- Enable for all users with conservative limits (max 3 pods)
- Monitor resource utilization and TTL patterns
- Gradually increase limits

---

## 12. Performance Considerations

### 9.1 Latency Targets

| Operation | Target p50 | Target p99 | Notes |
|-----------|-----------|-----------|-------|
| Launch pod (mock) | < 50ms | < 150ms | In-memory mock |
| Launch pod (real) | < 2s | < 8s | K8s API + image pull |
| Terminate pod | < 30ms | < 100ms | K8s API + DDB update |
| Get pod logs | < 100ms | < 500ms | K8s API log stream |
| List pods | < 30ms | < 100ms | DDB query |
| TTL scan | < 1s | < 3s | Scan + batch terminates |

### 9.2 DynamoDB Costs

| Operation | RCU | WCU | Notes |
|-----------|-----|-----|-------|
| Launch (create record) | — | 2.5 | Pod + host inventory |
| List pods | 2.0 | — | Query per user |
| Terminate | — | 2.5 | Update pod + host |
| TTL scan | 5.0 | varies | Scan + batch updates |

### 9.3 Caching Strategy

| Data | Cache | TTL | Invalidation |
|------|-------|-----|--------------|
| Pod list | React Query | 5s staleTime | On launch/terminate |
| Pod logs | React Query | 3s staleTime | Manual refresh |
| Image allowlist | In-memory dict | 300s | On settings change |
| Resource presets | In-memory dict | 300s | On settings change |

### 9.4 Rate Limiting

| Action | Limit | Window | Key |
|--------|-------|--------|-----|
| Launch pod | 10 | 1 hour | user_sub |
| Terminate | 20 | 1 hour | user_sub |
| Get logs | 60 | 1 minute | user_sub |
| List pods | 60 | 1 minute | user_sub |

### 9.5 Scalability

- **Per-user pod limit**: Default 5 (configurable). Keeps DDB and K8s resource usage bounded.
- **TTL background task**: Runs every 30 seconds. Queries `expires_at < now` with GSI. Efficient range query.
- **Mock K8s state**: In-memory store, same pattern as mock EC2. Per-process.
- **K8s API rate**: K8s API server handles ~50 requests/sec per client. Rate-limit launch requests to stay well under this.
- **Log streaming**: Logs fetched on-demand from K8s API. No persistent storage of container logs (K8s handles retention).

---

## 13. Acceptance Criteria

1. Users can launch containers from a curated image list with selectable resource presets.
2. Mock K8s service works in dev mode without a real cluster.
3. Pods auto-register in host inventory with `source: "k8s_auto"`.
4. Container logs are accessible via the API and UI.
5. Per-user pod limit is enforced.
6. TTL auto-termination runs as a background task.
7. SSH key injection works via INFRA-002 key association.
8. All operations produce audit events.
9. User isolation via namespaces prevents cross-user access.

---

## Codebase References

| Reference | File | Line(s) | Notes |
|-----------|------|---------|-------|
| `S.dev_mode` | `app/core/settings.py` | — | Controls mock vs real K8s client |
| `audit_event()` | `app/services/alerts.py` | 695 | Audit logging for pod lifecycle events |
| `k8s_pods` DDB table | — | — | Does not exist yet in `scripts/local-ddb-init.py` |
| `app/services/k8s_launcher.py` | — | — | Does not exist yet |
| `app/routers/k8s_launcher.py` | — | — | Does not exist yet |
| `remote_hosts` (INFRA-001 dep) | — | — | Host auto-registration target; does not exist yet |
| `ssh_key_manager` (INFRA-002 dep) | — | — | Key injection source; does not exist yet |
| Kubernetes Python client | — | — | Not in project dependencies; must be added for production mode |
10. Frontend shows real-time pod status with auto-refresh and log viewer.
