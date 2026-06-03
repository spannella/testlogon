# INFRA-009: Security Groups & Network Rules

**Status**: Implemented  
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

The platform has CIDR validation utilities in `app/core/normalize.py` with `normalize_cidr()` (see `app/core/normalize.py:43`) and `ip_in_any_cidr()` (see `app/core/normalize.py:53`), which can be reused for rule source validation. However, there is no security group model, storage, or management API.

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

These can validate security group rule sources (see `app/core/normalize.py:43-53`).

### 2.3 SSH Destination Policy (`app/routers/browser_ssh_terminal.py`, see line 60 for `ParamikoSshBridge`)

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

---

## 8. Architecture & Data Flow

```
  User creates Security Group
       │
       ▼
  POST /ui/remote/security-groups { name, rules[] }
       │
       ├── validate_rule() for each rule
       │     ├── Protocol in (tcp/udp/icmp/all)?
       │     ├── Port range valid (0-65535, from <= to)?
       │     ├── Source: CIDR → normalize_cidr()
       │     │           platform_only → resolve later
       │     │           sg:{id} → validate SG exists
       │     └── Dangerous rule check: SSH on 0.0.0.0/0 → BLOCKED
       │
       ├── DDB PutItem: PK=user_sub, SK=SG#{sg_id}
       │     └── Stores rules as List of Maps
       │
       └── audit_event("compute.sg_created", ...)

  Instance Launch with SG
       │
       ▼
  POST /ui/remote/ec2/launch { security_group_id }
       │
       ├── Validate SG exists + belongs to user
       │     └── If no SG provided → ensure_default_sg(user_sub)
       │           └── Auto-creates default SG (SSH + VNC from platform_only)
       │
       ├── Record SG association on instance item
       │     └── DDB UpdateItem: SET security_group_id = :sg_id
       │
       └── Production: translate rules → AWS authorize-security-group-ingress
             └── Dev: mock enforcement (DDB tracking only)
```

---

## 9. Detailed DynamoDB Access Patterns

| # | Access Pattern | Table / GSI | PK | SK | Operation | Notes |
|---|---------------|-------------|----|----|-----------|-------|
| 1 | Get SG by ID | Main table | `user_sub` | `SG#{sg_id}` | GetItem | Returns full SG with rules |
| 2 | List user SGs | Main table | `user_sub` | begins_with `SG#` | Query | All SGs for a user |
| 3 | List by creation date | GSI `ByCreatedAt` | `user_sub` | `created_at` (N) | Query | Newest-first ordering |
| 4 | Create SG | Main table | `user_sub` | `SG#{sg_id}` | PutItem with ConditionExpression `attribute_not_exists(sk)` | Prevents duplicates |
| 5 | Update SG rules | Main table | `user_sub` | `SG#{sg_id}` | UpdateItem SET rules = :rules, updated_at = :ts | Replaces entire rules list |
| 6 | Delete SG | Main table | `user_sub` | `SG#{sg_id}` | DeleteItem with ConditionExpression `is_default = :false` | Prevents default SG deletion |
| 7 | Find default SG | Main table | `user_sub` | begins_with `SG#` | Query + FilterExpression `is_default = :true` | Used during auto-creation check |
| 8 | Add SG association to instance | `ec2_instances` | `user_sub` | `INSTANCE#{id}` | UpdateItem SET security_group_id | Links instance to SG |

---

## 10. API Request/Response Examples

**POST /ui/remote/security-groups** (Create SG)

```bash
curl -X POST http://localhost:8000/ui/remote/security-groups \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -d '{
    "name": "Web Server Rules",
    "description": "Allow HTTP/HTTPS and SSH from platform",
    "rules": [
      { "protocol": "tcp", "port_from": 80, "port_to": 80, "source": "0.0.0.0/0", "direction": "inbound", "description": "HTTP" },
      { "protocol": "tcp", "port_from": 443, "port_to": 443, "source": "0.0.0.0/0", "direction": "inbound", "description": "HTTPS" },
      { "protocol": "tcp", "port_from": 22, "port_to": 22, "source": "platform_only", "direction": "inbound", "description": "SSH from platform" }
    ]
  }'
```

Response (201):
```json
{
  "sg_id": "sg-a1b2c3d4",
  "name": "Web Server Rules",
  "description": "Allow HTTP/HTTPS and SSH from platform",
  "rules": [
    { "rule_id": "r-001", "protocol": "tcp", "port_from": 80, "port_to": 80, "source": "0.0.0.0/0", "direction": "inbound", "description": "HTTP" },
    { "rule_id": "r-002", "protocol": "tcp", "port_from": 443, "port_to": 443, "source": "0.0.0.0/0", "direction": "inbound", "description": "HTTPS" },
    { "rule_id": "r-003", "protocol": "tcp", "port_from": 22, "port_to": 22, "source": "platform_only", "direction": "inbound", "description": "SSH from platform" }
  ],
  "is_default": false,
  "created_at": 1748520000,
  "updated_at": 1748520000,
  "associated_instances": []
}
```

**GET /ui/remote/security-groups**

Response (200):
```json
{
  "security_groups": [
    {
      "sg_id": "sg-default-alice",
      "name": "Default Security Group",
      "rules": [
        { "rule_id": "default-ssh", "protocol": "tcp", "port_from": 22, "port_to": 22, "source": "platform_only", "direction": "inbound" },
        { "rule_id": "default-vnc", "protocol": "tcp", "port_from": 5900, "port_to": 5999, "source": "platform_only", "direction": "inbound" },
        { "rule_id": "default-outbound", "protocol": "all", "port_from": 0, "port_to": 65535, "source": "0.0.0.0/0", "direction": "outbound" }
      ],
      "is_default": true,
      "associated_instances": ["i-abc123"]
    }
  ],
  "count": 1
}
```

**POST /ui/remote/security-groups/{sg_id}/rules** (Add rule)

```json
// Request
{ "protocol": "tcp", "port_from": 8080, "port_to": 8080, "source": "10.0.0.0/8", "direction": "inbound", "description": "Dev server" }

// Response (200) — returns full updated SG
```

**Attempting to add SSH open to all:**

```json
// Request
{ "protocol": "tcp", "port_from": 22, "port_to": 22, "source": "0.0.0.0/0", "direction": "inbound" }

// Response (400)
{ "detail": "SSH (port 22) open to 0.0.0.0/0 is not recommended. Use 'platform_only' or a specific CIDR." }
```

---

## 11. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| SG not found | 404 | `sg_not_found` | "Security group not found" | Verify SG ID |
| Delete default SG | 409 | `cannot_delete_default` | "Cannot delete default security group" | Create a custom SG instead |
| Delete SG with associated instances | 409 | `sg_in_use` | "Cannot delete SG with associated instances" | Disassociate instances first |
| Invalid CIDR source | 400 | `invalid_cidr` | "Invalid CIDR: not-a-cidr" | Use valid CIDR notation |
| SSH open to 0.0.0.0/0 | 400 | `dangerous_rule` | "SSH open to all is blocked" | Use `platform_only` or specific CIDR |
| port_from > port_to | 422 | `validation_error` | "port_from must be <= port_to" | Fix port range |
| Max 50 rules exceeded | 409 | `max_rules_exceeded` | "Security group cannot have more than 50 rules" | Remove unused rules |
| Invalid protocol | 422 | `validation_error` | "Protocol must be tcp, udp, icmp, or all" | Fix protocol |
| Other user's SG | 403 | `forbidden` | "Access denied" | Use your own SGs |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Log in |

---

## 12. Frontend Component Tree

```
SecurityGroupsPage
├── PageHeader
│   ├── Title ("Security Groups")
│   └── CreateSgButton → opens CreateSgDialog
├── SgList (accordion or card layout)
│   └── SgCard[]
│       ├── SgHeader
│       │   ├── SgName
│       │   ├── DefaultBadge (if is_default)
│       │   ├── RuleCount ("5 rules")
│       │   ├── InstanceCount ("2 instances")
│       │   └── ActionsDropdown (edit name / delete — disabled for default)
│       └── RuleTable (expanded view)
│           ├── TableHeader: Direction | Protocol | Port Range | Source | Description | Actions
│           └── RuleRow[]
│               ├── DirectionIcon (↓ inbound / ↑ outbound)
│               ├── ProtocolBadge ("TCP" / "UDP" / "ICMP" / "ALL")
│               ├── PortRange ("22" or "5900-5999")
│               ├── SourceDisplay
│               │   ├── "Platform Only" (blue badge)
│               │   ├── CIDR (monospace text)
│               │   └── "Anywhere" (red warning badge for 0.0.0.0/0)
│               ├── Description
│               └── RuleActions (Edit / Delete buttons)
├── AddRuleDialog
│   ├── ProtocolSelect (TCP / UDP / ICMP / All)
│   ├── PortFromInput + PortToInput (disabled for ICMP/All)
│   ├── SourceInput
│   │   ├── PlatformOnlyButton → auto-fills "platform_only"
│   │   ├── AnywhereButton → auto-fills "0.0.0.0/0" with WarningBanner
│   │   └── CidrInput (text input with validation feedback)
│   ├── DirectionToggle (Inbound / Outbound)
│   ├── DescriptionInput
│   └── SubmitButton
└── WarningBanner (shown when any rule has 0.0.0.0/0 on SSH/VNC)
```

**Props interfaces:**

```typescript
interface SgCardProps {
  sg: SecurityGroupOut;
  onAddRule: (sgId: string) => void;
  onDeleteRule: (sgId: string, ruleId: string) => void;
  onDelete: (sgId: string) => void;
}

interface AddRuleDialogProps {
  open: boolean;
  onClose: () => void;
  sgId: string;
  onRuleAdded: (sg: SecurityGroupOut) => void;
}

interface SourceInputProps {
  value: string;
  onChange: (value: string) => void;
  error?: string;
}
```

---

## 13. Observability

### 13.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `security_group_created_total` | Counter | `is_default` (true/false) | SGs created |
| `security_group_rule_added_total` | Counter | `protocol`, `direction` | Rules added |
| `security_group_dangerous_rule_blocked_total` | Counter | `port`, `source` | Dangerous rule attempts blocked |
| `security_group_default_auto_created_total` | Counter | | Default SGs auto-created |
| `security_group_launch_association_total` | Counter | | SGs associated with launched instances |

### 13.2 Structured Logging

| Log Event | Level | Fields | Trigger |
|-----------|-------|--------|---------|
| `sg.created` | INFO | `sg_id`, `user_sub`, `rule_count` | SG creation |
| `sg.rule_added` | INFO | `sg_id`, `rule_id`, `protocol`, `port_range`, `source` | Rule added |
| `sg.rule_removed` | INFO | `sg_id`, `rule_id` | Rule removed |
| `sg.dangerous_rule_blocked` | WARN | `user_sub`, `protocol`, `port`, `source` | 0.0.0.0/0 on SSH blocked |
| `sg.deleted` | INFO | `sg_id`, `user_sub` | SG deleted |
| `sg.default_created` | INFO | `sg_id`, `user_sub` | Default SG auto-created |

### 13.3 Alerting

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| Spike in dangerous rule attempts | > 10 blocked dangerous rules in 1 hour | Warning | Review user activity for abuse |
| Default SG auto-creation failures | Any exception in `ensure_default_sg` | Critical | Check DDB connectivity |

---

## 14. Performance Considerations

### 14.1 Latency Targets

| Operation | Target P95 | Notes |
|-----------|-----------|-------|
| List SGs | < 100ms | Single DDB Query on PK=user_sub |
| Get SG detail | < 50ms | Single GetItem |
| Create SG | < 100ms | PutItem with condition |
| Add/remove rule | < 100ms | UpdateItem with rule list replacement |
| Validate rule | < 5ms | In-memory validation, no DDB call |

### 14.2 Rule Validation Performance

- CIDR validation uses Python's `ipaddress` module (in-memory, microseconds).
- Rule limit of 50 per SG keeps the `rules` list small (< 10KB serialized).
- Full SG item size: < 20KB (well under DDB 400KB limit).

### 14.3 Platform CIDR Resolution

- `platform_only` resolves to `S.platform_egress_cidrs` at read time (not stored expanded).
- Resolution is O(1) — simple config lookup, no external call.

---

## 15. Rollout Plan

### 15.1 Feature Flags

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `security_groups_enabled` | `SECURITY_GROUPS_ENABLED` | `true` | Master switch |
| `sg_dangerous_rule_block` | `SG_BLOCK_DANGEROUS_RULES` | `true` | Block SSH to 0.0.0.0/0 |
| `sg_max_rules_per_group` | `SG_MAX_RULES` | `50` | Max rules per SG |

### 15.2 Phased Rollout

**Phase 1 (Day 1-2)**: Backend service + DDB table + default SG auto-creation + rule validation.

**Phase 2 (Day 3-4)**: API router (8 endpoints) + launch integration.

**Phase 3 (Day 5-6)**: Frontend SecurityGroupsPage with rule management.

**Phase 4 (Day 7)**: E2E tests, production rollout.

### 15.3 Rollback

1. Set `SECURITY_GROUPS_ENABLED=false` — API returns 400.
2. Instance launches fall back to no SG association.
3. Existing SG records remain in DDB but are inert.

---

## 16. Expanded E2E Tests

### Section 270: Security Group CRUD API (5 tests) -- existing

1-5. (As defined above in Section 5)

### Section 271: Rule Management API (5 tests) -- existing

6-10. (As defined above in Section 5)

### Section 272: Security Groups UI (5 tests) -- existing

11-15. (As defined above in Section 5)

### Section 273: Rule Validation Edge Cases (7 tests)

16. `ICMP rule ignores port range` -- Add ICMP inbound rule with port_from=0, port_to=0. Verify accepted.
17. `Protocol "all" ignores port range` -- Add "all" protocol rule. Verify accepted.
18. `Port range 0-65535 accepted for TCP` -- Full port range rule. Verify accepted.
19. `Source "sg:{sg_id}" accepted for SG reference` -- Add rule referencing another SG. Verify accepted.
20. `Rule with empty description accepted` -- Add rule with `description: ""`. Verify accepted.
21. `50th rule succeeds, 51st rejected` -- Add 50 rules (verify ok), add 51st (verify 409).
22. `platform_only resolves to non-empty CIDR list` -- GET effective rules. Verify platform_only source is expanded.

### Section 274: SG Launch Integration & Multi-User Isolation (6 tests)

23. `Launch with custom SG associates instance` -- Launch with `security_group_id`. GET SG, verify `associated_instances` includes instance ID.
24. `Launch without SG auto-creates default` -- Launch without SG. GET SGs, verify default exists.
25. `Alice cannot view Bob's SGs` -- Bob creates SG. Alice lists SGs. Bob's SG not visible.
26. `Alice cannot add rule to Bob's SG` -- POST rule to Bob's SG. Verify 403.
27. `Delete SG with associated instance fails` -- Launch instance with SG, DELETE SG. Verify 409.
28. `Delete SG succeeds after disassociating instances` -- Terminate instance, DELETE SG. Verify 200.

---

## Codebase References

> **Verification performed**: 2026-05-29

### Verified (EXISTS in codebase)

| Reference | File | Line(s) | Status |
|-----------|------|---------|--------|
| `normalize_cidr()` | `app/core/normalize.py` | 43 | VERIFIED |
| `ip_in_any_cidr()` | `app/core/normalize.py` | 53 | VERIFIED |
| DDB table init script | `scripts/local-ddb-init.py` | exists | VERIFIED (1360 lines) |

### Not Yet Implemented (requires new code)

<!-- NOTE: INFRA-003 (EC2 Launcher) and INFRA-004 (K8s Launcher) are dependencies but do not exist yet. Security group infrastructure is entirely new. -->

| Reference | Expected Location | Status |
|-----------|-------------------|--------|
| `security_groups` DDB table | `scripts/local-ddb-init.py` | NOT FOUND -- new table required |
| `app/routers/security_groups.py` | `app/routers/` | NOT FOUND -- new router required |
| `app/services/security_groups.py` | `app/services/` | NOT FOUND -- new service required |
| Security groups router registration | `app/main.py` | NOT FOUND -- needs `app.include_router()` |
| `SecurityGroupOut` / `SecurityRuleOut` models | `app/models.py` | NOT FOUND -- new models required |
| Security group settings | `app/core/settings.py` | NOT FOUND -- new settings required |
| EC2 launch integration (INFRA-003) | `app/services/ec2_launcher.py` | NOT FOUND -- new implementation required |
| `frontend/src/pages/remote/SecurityGroupsPage.tsx` | `frontend/src/pages/remote/` | NOT FOUND -- new page required |

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_security_groups.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_create_security_group`
  - `test_add_inbound_rule`
  - `test_add_outbound_rule`
  - `test_remove_rule`
  - `test_attach_group_to_instance`
  - `test_validate_cidr_format`
  - `test_default_deny_all`

### Integration Tests

  - EC2 launch applies configured security group rules
  - K8s launch translates security group to NetworkPolicy
  - Rule update propagates to attached instances

### E2E Tests (Playwright)

**File**: `frontend/e2e/security-groups.spec.ts`
**Test count**: 12

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `security_groups` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `SECURITY_GROUPS_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| INFRA-003 | EC2 Instance Launcher | Applies security groups to EC2 instances |
| INFRA-004 | K8s Container Launcher | Applies network policies to containers |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Sequential**

Merge after INFRA-003, INFRA-004. This ticket depends on tables/services introduced by those tickets.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 12 E2E tests pass with `npx playwright test security-groups.spec.ts`
