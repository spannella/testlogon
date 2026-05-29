# INFRA-009: Security Groups & Network Rules

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 5-7 days  
**Dependencies**: INFRA-003 (EC2 Launcher), INFRA-004 (K8s Launcher)

---

## 1. Overview & Motivation

### The Gap

INFRA-003 (EC2 Launcher) mentions auto-creating security groups with SSH/VNC ports open, but there is no user-facing security group management. Users cannot:

1. View or manage firewall rules for their instances
2. Create custom security groups with specific port/protocol/source rules
3. Restrict access to "platform only" (so instances are only reachable via the platform's SSH/VNC bridge)
4. Open additional ports (e.g., 8080, 3000, 5432) for development purposes
5. Apply different security groups to different instances

The platform has CIDR validation utilities in `app/core/normalize.py` with `normalize_cidr()` and `ip_in_any_cidr()`, which can be reused for rule source validation. However, there is no security group model, storage, or management API.

### Why This Matters

1. **Defense in depth**: Without configurable firewall rules, all instances have the same network exposure. Users cannot restrict access to specific ports or source IPs.
2. **Development needs**: Developers need to open additional ports (web servers, databases, Jupyter notebooks) without exposing SSH to the public internet.
3. **Compliance**: Enterprise users need to demonstrate that compute resources have restrictive network policies.
4. **Platform-only mode**: The most common desired configuration is "only allow SSH from the platform's own egress IPs" — this should be a one-click option.
5. **Instance launch integration**: Security groups should be selectable at launch time (INFRA-003/004).

### Architecture After This Change

```
Security Group System

  security_groups DDB table
  PK=user_sub, SK=SG#{sg_id}
  +-- sg_id, name, description
  +-- rules: List[SecurityRule]
  |   +-- protocol: tcp/udp/icmp
  |   +-- port_from: int
  |   +-- port_to: int
  |   +-- source: cidr | sg_ref | platform_only
  |   +-- direction: inbound | outbound
  |   +-- description: str
  +-- created_at, updated_at
  +-- is_default: bool
       |
       +---> Instance launch: select SG
       |     POST /ui/remote/ec2/launch { security_group_id }
       |
       +---> Default SG auto-created per user:
       |     SSH (22) + VNC (5900-5999) from platform only
       |
       +---> SecurityGroupsPage (rule table, add/edit rules)
       |
       +---> Rule validation:
             - No 0.0.0.0/0 on SSH without explicit override
             - CIDR validation via app/core/normalize.py
             - Max 50 rules per security group
```

---

## 2. Current State Analysis

### 2.1 No Security Group Storage

The platform has no security group model. INFRA-003's `launch_instance()` references `security_group_id` as a field but does not create or manage security groups.

### 2.2 CIDR Utilities (`app/core/normalize.py`)

```python
def normalize_cidr(s: str) -> str:
    """Normalize a CIDR string (e.g., '10.0.0.0/8'). Raises ValueError if invalid."""

def ip_in_any_cidr(ip_str: str, cidrs: List[str]) -> bool:
    """Check if an IP is in any of the given CIDR ranges."""
```

These can validate security group rule sources.

### 2.3 SSH Destination Policy (`app/routers/browser_ssh_terminal.py`)

The SSH terminal has a built-in destination policy (whitelist/blacklist) for hosts. This operates at the platform level — which hosts the platform will proxy SSH connections to. Security groups are a different layer — they control which network traffic the instance itself accepts.

### 2.4 EC2 Security Groups (Real AWS)

In production, AWS EC2 uses real VPC security groups. The platform's security group model would translate to actual `authorize-security-group-ingress` / `revoke-security-group-ingress` API calls. In dev mode, security groups are tracked in DDB only (mock enforcement).

---

## 3. Technical Design

### 3.1 DynamoDB Table: `security_groups`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.security_groups_table_name, "security_groups"),
    "user_sub",            # PK — SG owner
    "sk",                  # SK — SG#{sg_id}
    gsis=[
        {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | S (PK) | SG owner |
| `sk` | S (SK) | `SG#{sg_id}` |
| `sg_id` | S | UUID |
| `name` | S | Security group name (e.g., "Web Server Rules") |
| `description` | S | Description |
| `rules` | L[M] | List of security rules (see below) |
| `is_default` | BOOL | Whether this is the user's default SG |
| `created_at` | N | Unix timestamp |
| `updated_at` | N | Unix timestamp |
| `associated_instances` | L[S] | Instance/pod IDs using this SG |

**Security rule schema** (within `rules` list):

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | S | UUID for the rule |
| `protocol` | S | `tcp`, `udp`, `icmp`, `all` |
| `port_from` | N | Start of port range (0 for ICMP/all) |
| `port_to` | N | End of port range (0 for ICMP/all) |
| `source` | S | CIDR notation (e.g., `10.0.0.0/8`), `platform_only`, or `sg:{sg_id}` |
| `direction` | S | `inbound` or `outbound` |
| `description` | S | Human-readable rule description |

### 3.2 Default Security Group

When a user first interacts with the security group system (or launches their first instance), a default SG is auto-created:

```python
DEFAULT_SG_RULES = [
    {
        "rule_id": "default-ssh",
        "protocol": "tcp",
        "port_from": 22,
        "port_to": 22,
        "source": "platform_only",
        "direction": "inbound",
        "description": "SSH from platform only",
    },
    {
        "rule_id": "default-vnc",
        "protocol": "tcp",
        "port_from": 5900,
        "port_to": 5999,
        "source": "platform_only",
        "direction": "inbound",
        "description": "VNC from platform only",
    },
    {
        "rule_id": "default-outbound",
        "protocol": "all",
        "port_from": 0,
        "port_to": 65535,
        "source": "0.0.0.0/0",
        "direction": "outbound",
        "description": "Allow all outbound traffic",
    },
]
```

The `platform_only` source resolves to the platform's egress IP/CIDR ranges (configured via `S.platform_egress_cidrs`).

### 3.3 Rule Validation

```python
def validate_rule(rule: dict) -> list[str]:
    """Validate a security rule. Returns list of error messages (empty = valid)."""
    errors = []

    # Protocol validation
    if rule["protocol"] not in ("tcp", "udp", "icmp", "all"):
        errors.append(f"Invalid protocol: {rule['protocol']}")

    # Port range validation
    if rule["protocol"] in ("tcp", "udp"):
        if not (0 <= rule["port_from"] <= 65535):
            errors.append("port_from must be 0-65535")
        if not (0 <= rule["port_to"] <= 65535):
            errors.append("port_to must be 0-65535")
        if rule["port_from"] > rule["port_to"]:
            errors.append("port_from must be <= port_to")

    # Source validation
    source = rule["source"]
    if source == "platform_only":
        pass  # Valid special value
    elif source.startswith("sg:"):
        pass  # Security group reference — validated separately
    else:
        try:
            normalize_cidr(source)
        except ValueError:
            errors.append(f"Invalid CIDR: {source}")

    # Dangerous rule warnings
    if (source == "0.0.0.0/0" and rule["direction"] == "inbound"
            and rule["protocol"] == "tcp" and rule["port_from"] <= 22 <= rule["port_to"]):
        errors.append("SSH (port 22) open to 0.0.0.0/0 is not recommended. "
                       "Use 'platform_only' or a specific CIDR.")

    return errors
```

### 3.4 Service Layer: `app/services/security_groups.py`

New file (~250 lines):

```python
"""Security group management — CRUD for firewall rules applied to compute resources."""

from __future__ import annotations
import uuid
from typing import Any, Dict, List, Optional

from app.core.normalize import normalize_cidr
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event


def ensure_default_sg(user_sub: str) -> Dict[str, Any]:
    """Create default security group if not exists. Idempotent."""

def create_security_group(
    user_sub: str,
    *,
    name: str,
    description: str = "",
    rules: list[dict] | None = None,
) -> Dict[str, Any]:
    """Create a custom security group."""

def get_security_group(user_sub: str, sg_id: str) -> Dict[str, Any] | None:
    """Get a security group by ID."""

def list_security_groups(user_sub: str) -> List[Dict[str, Any]]:
    """List all security groups for a user (including default)."""

def update_security_group(user_sub: str, sg_id: str, **updates) -> Dict[str, Any]:
    """Update SG name/description."""

def delete_security_group(user_sub: str, sg_id: str) -> bool:
    """Delete a custom SG. Default SG cannot be deleted. Fails if SG has associated instances."""

def add_rule(user_sub: str, sg_id: str, rule: dict) -> Dict[str, Any]:
    """Add a rule to a security group. Validates the rule. Max 50 rules per SG."""

def remove_rule(user_sub: str, sg_id: str, rule_id: str) -> bool:
    """Remove a rule from a security group."""

def update_rule(user_sub: str, sg_id: str, rule_id: str, **updates) -> Dict[str, Any]:
    """Update fields on an existing rule."""

def resolve_platform_cidrs() -> list[str]:
    """Return the platform's egress CIDR ranges for 'platform_only' source resolution."""

def get_effective_rules(user_sub: str, sg_id: str) -> list[dict]:
    """Resolve all rules, expanding 'platform_only' to actual CIDRs and sg: references."""
```

### 3.5 API Router: `app/routers/security_groups.py`

New file (~200 lines). Prefix: `/ui/remote/security-groups`.

| Method | Path | Request | Response | Description |
|--------|------|---------|----------|-------------|
| `POST` | `/ui/remote/security-groups` | `CreateSgIn` | `SecurityGroupOut` (201) | Create SG |
| `GET` | `/ui/remote/security-groups` | — | `SgListOut` | List SGs |
| `GET` | `/ui/remote/security-groups/{sg_id}` | — | `SecurityGroupOut` | Get SG detail |
| `PATCH` | `/ui/remote/security-groups/{sg_id}` | `UpdateSgIn` | `SecurityGroupOut` | Update SG |
| `DELETE` | `/ui/remote/security-groups/{sg_id}` | — | `{"ok": true}` | Delete SG |
| `POST` | `/ui/remote/security-groups/{sg_id}/rules` | `AddRuleIn` | `SecurityGroupOut` | Add rule |
| `DELETE` | `/ui/remote/security-groups/{sg_id}/rules/{rule_id}` | — | `SecurityGroupOut` | Remove rule |
| `PATCH` | `/ui/remote/security-groups/{sg_id}/rules/{rule_id}` | `UpdateRuleIn` | `SecurityGroupOut` | Update rule |

#### Pydantic Models

```python
class SecurityRuleIn(BaseModel):
    protocol: Literal["tcp", "udp", "icmp", "all"]
    port_from: int = Field(default=0, ge=0, le=65535)
    port_to: int = Field(default=0, ge=0, le=65535)
    source: str = Field(..., min_length=1, max_length=100)
    direction: Literal["inbound", "outbound"] = "inbound"
    description: str = Field(default="", max_length=200)

class SecurityRuleOut(BaseModel):
    rule_id: str
    protocol: str
    port_from: int
    port_to: int
    source: str
    direction: str
    description: str

class CreateSgIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    rules: List[SecurityRuleIn] = Field(default_factory=list)

class UpdateSgIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)

class SecurityGroupOut(BaseModel):
    sg_id: str
    name: str
    description: str
    rules: List[SecurityRuleOut]
    is_default: bool
    created_at: int
    updated_at: int
    associated_instances: List[str]

class SgListOut(BaseModel):
    security_groups: List[SecurityGroupOut]
    count: int

class AddRuleIn(SecurityRuleIn):
    pass

class UpdateRuleIn(BaseModel):
    protocol: Optional[Literal["tcp", "udp", "icmp", "all"]] = None
    port_from: Optional[int] = Field(default=None, ge=0, le=65535)
    port_to: Optional[int] = Field(default=None, ge=0, le=65535)
    source: Optional[str] = Field(default=None, min_length=1, max_length=100)
    direction: Optional[Literal["inbound", "outbound"]] = None
    description: Optional[str] = Field(default=None, max_length=200)
```

### 3.6 Launch Integration

Modify `LaunchInstanceIn` (INFRA-003) and `LaunchPodIn` (INFRA-004) to accept `security_group_id`:

```python
class LaunchInstanceIn(BaseModel):
    # ... existing fields ...
    security_group_id: Optional[str] = None  # Defaults to user's default SG
```

In the launch flow:
1. If `security_group_id` is provided, validate it exists and belongs to the user
2. If not provided, use the user's default SG (auto-create if needed)
3. Record the SG association on the instance/pod item
4. In production: translate rules to AWS VPC security group rules

### 3.7 Frontend Components

#### SecurityGroupsPage (`frontend/src/pages/remote/SecurityGroupsPage.tsx`)

New page (~400 lines):

- **Header**: "Security Groups" with "Create Security Group" button
- **SG list**: Accordion or card list showing each SG with name, description, rule count, associated instance count
- **Default SG**: Always shown first with "Default" badge, cannot be deleted
- **Rule table** (per SG): Columns: Direction (in/out icon), Protocol, Port Range, Source, Description, Actions (Edit/Delete)
- **Add Rule dialog**: Protocol selector, port range inputs, source input (with "Platform Only" shortcut button, CIDR input), direction toggle
- **Source input helpers**:
  - "Platform Only" button → auto-fills `platform_only`
  - "Anywhere" button → auto-fills `0.0.0.0/0` with warning badge
  - Custom CIDR input with validation feedback
- **Warning banner**: Shown when any rule has `0.0.0.0/0` source on SSH/VNC ports

#### Route & Navigation

```tsx
<Route path="/remote/security-groups" element={<SecurityGroupsPage />} />
```

Sidebar: "Security Groups" with `Shield` icon under Infrastructure group.

---

## 4. Implementation Plan

### Phase 1: Backend SG Service (2 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `security_groups_table_name`, `platform_egress_cidrs` |
| `app/core/tables.py` | Add `security_groups` table handle |
| `scripts/local-ddb-init.py` | Add `security_groups` TableDef |
| `app/services/security_groups.py` | New file: SG CRUD + rule management + validation |
| `app/models.py` | Add SG Pydantic models |

### Phase 2: API + Launch Integration (1-2 days)

| File | Change |
|------|--------|
| `app/routers/security_groups.py` | New file: 8 endpoints |
| `app/main.py` | Register router |
| `app/services/ec2_launcher.py` | Accept `security_group_id`, auto-create default SG |
| `app/services/k8s_launcher.py` | Accept `security_group_id` |

### Phase 3: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add SG types |
| `frontend/src/api/endpoints/security-groups.ts` | New file: API wrappers |
| `frontend/src/pages/remote/SecurityGroupsPage.tsx` | New file: SG management page |
| `frontend/src/App.tsx` | Add `/remote/security-groups` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Security Groups" nav item |
| `frontend/src/pages/remote/LaunchInstanceDialog.tsx` | Add SG selector |

### Phase 4: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/security-groups.spec.ts` | New file: ~15 tests in 3 sections |

---

## 5. E2E Test Plan (`frontend/e2e/security-groups.spec.ts`)

**Section 270: Security Group CRUD API (5 tests)**

1. `Default SG is auto-created on first list` — GET `/security-groups`. Verify 1 SG with `is_default: true` and 3 default rules (SSH, VNC, outbound).
2. `Create custom SG` — POST with name, 2 rules. Verify 201 with `is_default: false`, 2 rules.
3. `Update SG name` — PATCH with new name. Verify updated.
4. `Delete custom SG` — DELETE. Verify 200. GET list, verify only default SG remains.
5. `Cannot delete default SG` — DELETE default SG → 409 "Cannot delete default security group".

**Section 271: Rule Management API (5 tests)**

6. `Add inbound TCP rule` — POST rule with `protocol: "tcp"`, `port_from: 8080`, `port_to: 8080`, `source: "10.0.0.0/8"`. Verify rule added with `rule_id`.
7. `Add platform_only rule` — POST rule with `source: "platform_only"`. Verify accepted.
8. `Remove rule` — DELETE rule by `rule_id`. Verify rule removed from SG.
9. `Reject invalid CIDR` — POST rule with `source: "not-a-cidr"` → 400 validation error.
10. `Warn on 0.0.0.0/0 SSH` — POST inbound TCP 22 with `source: "0.0.0.0/0"` → 400 with message about SSH open to all. (Can be overridden with explicit flag in future.)

**Section 272: Security Groups UI (5 tests)**

11. `SecurityGroupsPage shows default SG` — Navigate to `/remote/security-groups`. Verify "Default" badge visible.
12. `Create SG via dialog` — Click "Create", fill name, submit. Verify new SG card.
13. `Add rule via dialog` — Click "Add Rule" on SG. Fill protocol/port/source, submit. Verify rule in table.
14. `Platform Only shortcut button works` — Click "Platform Only" in source field. Verify `platform_only` text appears.
15. `Delete rule removes from table` — Click delete on rule, confirm. Verify rule removed.

---

## 6. Security Considerations

### 6.1 SSH/VNC Port Protection

The default SG restricts SSH (22) and VNC (5900-5999) to `platform_only`. Users must explicitly create rules to open these ports to other sources. Opening SSH to `0.0.0.0/0` is blocked by default and returns a validation error.

### 6.2 Platform-Only Source

`platform_only` resolves to the platform's egress CIDR ranges. In dev mode, this defaults to `["127.0.0.1/32", "10.0.0.0/8"]`. In production, it is configured via `S.platform_egress_cidrs`.

### 6.3 Rule Limit

Max 50 rules per SG prevents overly complex configurations that could cause performance issues in production AWS security group translation.

### 6.4 User Isolation

SGs use `user_sub` as PK. Users cannot view or modify other users' security groups.

---

## 7. Acceptance Criteria

1. Default security group is auto-created with SSH/VNC from platform only + all outbound.
2. Users can create custom SGs with up to 50 rules.
3. Rules validate protocol, port range, and source (CIDR or `platform_only`).
4. SSH to `0.0.0.0/0` is blocked by default.
5. SGs can be selected during instance/pod launch.
6. Default SG cannot be deleted.
7. CIDR sources are validated using existing `normalize_cidr()`.
8. Frontend shows rule tables with add/edit/delete capabilities.
9. "Platform Only" shortcut simplifies common security configuration.
10. All SG mutations produce audit events.
