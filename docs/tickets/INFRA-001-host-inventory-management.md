# INFRA-001: Host Inventory Management

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: High  
**Estimated effort**: 5-7 days  
**Dependencies**: None (foundational for INFRA-002 through INFRA-012)

---

## 1. Overview & Motivation

### The Gap

The platform has two mature remote access systems:

1. **VNC Remote Desktop** (`app/services/vnc_sessions.py`, `app/routers/vnc_sessions.py`): A noVNC browser-based system with JWT session tokens, capability negotiation, timeout policies, and audit logging. Targets are **hardcoded** in `_default_targets()` (line 200) as `TargetConfig` objects with `target_id`, `ws_url`, `allowed_users`, and `capabilities`. There is no DDB table for hosts — the entire target inventory lives in Python code.

2. **SSH Terminal** (`app/routers/browser_ssh_terminal.py`, 1,126 lines): A WebSocket-based Paramiko SSH bridge with per-user session limits, destination policy (host/port whitelist/blacklist), rate limiting, and role-based access. Credentials are supplied per-session via WebSocket (not stored). The user must manually enter hostname, port, and credentials for every connection.

Neither system offers a persistent, user-managed inventory of hosts. Users cannot:

1. Save a list of hosts they connect to regularly
2. Organize hosts into groups or folders
3. See connection history or last-connected timestamps
4. Import hosts from a CSV file or other bulk source
5. Quick-connect to a saved host without re-entering connection details

### Why This Matters

1. **Repeated manual entry**: Power users who manage 10+ hosts must re-type hostname/port/username on every session. This is error-prone and slow.
2. **No organizational structure**: Without groups/folders, users with many hosts have no way to categorize them (e.g., "Production", "Staging", "Personal").
3. **No connection history**: Users cannot see which hosts they connected to recently or how frequently.
4. **Foundation for other features**: INFRA-002 (SSH Key Manager), INFRA-003 (EC2 Launcher), INFRA-004 (K8s Launcher), INFRA-006 (Connection Profiles), and INFRA-011 (Multi-Hop SSH) all depend on a persistent host inventory to associate keys, auto-register launched instances, store connection profiles, and configure bastion chains.
5. **Parity with professional tools**: PuTTY, MobaXterm, Termius, and every SSH client application provides a saved host list. This is table-stakes for a remote access platform.

### Architecture After This Change

```
Host Inventory Flow

  User creates host entry
  POST /ui/remote/hosts
       |
       v
  +------------------+
  | remote_hosts DDB  |  PK=user_sub, SK=HOST#{host_id}
  | (per-user)        |  GSIs: ByLabel, ByProtocol, ByLastConnected
  +------------------+
       |
       +---> HostInventoryPage (DataTable with search/filter/sort)
       |         |
       |         +---> Add/Edit dialog (hostname, port, protocol, tags, group)
       |         |
       |         +---> Quick-connect button → opens RemoteDesktopPage or SSH terminal
       |         |                            with pre-filled params
       |         +---> Import CSV button → bulk upload hosts
       |
       +---> VNC session creation: _resolve_target() extended to check DDB inventory
       |
       +---> SSH terminal: connect payload pre-filled from host record
```

---

## 2. Current State Analysis

### 2.1 VNC Target Configuration (`app/services/vnc_sessions.py`, line 200)

The `_default_targets()` function returns a hardcoded dictionary:

```python
def _default_targets() -> dict[str, TargetConfig]:
    return {
        "demo": TargetConfig(
            target_id="demo",
            ws_url="ws://localhost:6080/websockify",
            allowed_users=("*",),
            capabilities={"clipboard": True, "file_transfer": True, "drag_drop_upload": True},
            ...
        ),
        "ops-admin": TargetConfig(
            target_id="ops-admin",
            ws_url="ws://ops-vnc.internal:6080/websockify",
            allowed_users=("root.admin@testdev.local",),
            ...
        ),
    }
```

The `_resolve_target()` function (line 237) looks up targets by `target_id` in this dictionary. There is no fallback to a database. User-defined VNC targets are not supported.

### 2.2 SSH Destination Policy (`app/routers/browser_ssh_terminal.py`)

The SSH terminal validates destinations against a whitelist/blacklist policy in the WebSocket `connect` handler. The user supplies `host`, `port`, `username`, and credentials in the `connect` message payload. There is no pre-population or saved connection concept.

### 2.3 VNC Session Store (`app/services/vnc_sessions.py`, line 41)

`VncSessionStore` is an in-memory dictionary (`self._sessions`). It tracks active VNC sessions but does not persist to DDB. It has no concept of a "host" — only `target_id` references the hardcoded targets.

### 2.4 RemoteDesktopPage (`frontend/src/pages/remote/RemoteDesktopPage.tsx`, ~800 lines)

The frontend remote desktop page presents a target selector dropdown populated from a `GET /api/vnc/targets` endpoint (or hardcoded list). There is no "saved hosts" section, no host management UI, and no CSV import.

### 2.5 Frontend Routing (`frontend/src/App.tsx`)

The existing route `/remote` maps to `RemoteDesktopPage`. There is no `/remote/hosts` route for a host inventory page.

### 2.6 DynamoDB Table Patterns (`scripts/local-ddb-init.py`)

All tables follow the `TableDef` pattern with `PK`, optional `SK`, GSIs, and `attr_types` for numeric sort keys. The host inventory table will follow this established pattern.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `remote_hosts`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.remote_hosts_table_name, "remote_hosts"),
    "user_sub",        # PK — host owner
    "sk",              # SK — HOST#{host_id}
    gsis=[
        {"index_name": "ByLabel", "partition_key": "user_sub", "sort_key": "label_lower"},
        {"index_name": "ByProtocol", "partition_key": "user_sub", "sort_key": "protocol"},
        {"index_name": "ByLastConnected", "partition_key": "user_sub", "sort_key": "last_connected_at"},
    ],
    attr_types={"last_connected_at": "N"},
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | S (PK) | Host owner's user ID |
| `sk` | S (SK) | `HOST#{host_id}` |
| `host_id` | S | UUID for the host |
| `label` | S | Human-readable name (e.g., "Prod DB Server") |
| `label_lower` | S | Lowercase label for case-insensitive GSI sort |
| `description` | S | Optional description/notes |
| `hostname` | S | IP address or DNS hostname |
| `port` | N | Port number (default: 22 for SSH, 5900 for VNC) |
| `protocol` | S | `ssh`, `vnc`, or `rdp` |
| `tags` | L[S] | User-defined tags for filtering |
| `group` | S | Group/folder name (e.g., "Production", "Staging") |
| `os_type` | S | `linux`, `windows`, `macos`, `unknown` |
| `created_at` | N | Unix timestamp of creation |
| `updated_at` | N | Unix timestamp of last update |
| `last_connected_at` | N | Unix timestamp of last successful connection (0 if never) |
| `connection_count` | N | Total connection count |
| `status` | S | `online`, `offline`, `unknown` (default: `unknown`) |
| `is_pinned` | BOOL | Whether host is pinned to top of list |
| `source` | S | `manual`, `csv_import`, `ec2_auto`, `k8s_auto` |

**Access patterns**:

| Pattern | GSI | Key condition |
|---------|-----|--------------|
| List hosts alphabetically | ByLabel | `PK=user_sub`, sorted by `label_lower` |
| List hosts by protocol | ByProtocol | `PK=user_sub`, `SK=ssh` or `SK=vnc` |
| Recent connections first | ByLastConnected | `PK=user_sub`, `ScanIndexForward=False` |
| Get single host | Table | `PK=user_sub`, `SK=HOST#{host_id}` |

### 3.2 Settings & Table Handle

**`app/core/settings.py`** — add:

```python
remote_hosts_table_name: str = "remote_hosts"
```

**`app/core/tables.py`** — add:

```python
remote_hosts = _table(S.remote_hosts_table_name)
```

### 3.3 Service Layer: `app/services/remote_hosts.py`

New file (~250 lines). Core functions:

```python
"""Host inventory management — CRUD + import + connection tracking."""

from __future__ import annotations
import csv
import io
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event


def create_host(
    user_sub: str,
    *,
    label: str,
    hostname: str,
    port: int = 22,
    protocol: str = "ssh",
    description: str = "",
    tags: list[str] | None = None,
    group: str = "",
    os_type: str = "unknown",
    source: str = "manual",
) -> Dict[str, Any]:
    """Create a new host entry in the user's inventory."""

def get_host(user_sub: str, host_id: str) -> Dict[str, Any] | None:
    """Retrieve a single host by ID."""

def update_host(user_sub: str, host_id: str, **updates) -> Dict[str, Any]:
    """Update mutable fields on a host entry."""

def delete_host(user_sub: str, host_id: str) -> bool:
    """Soft-delete a host entry (sets status='deleted')."""

def list_hosts(
    user_sub: str,
    *,
    protocol: str | None = None,
    group: str | None = None,
    sort_by: str = "label",  # label | last_connected | created_at
    limit: int = 100,
    cursor: str | None = None,
) -> Dict[str, Any]:
    """List hosts with filtering and pagination."""

def record_connection(user_sub: str, host_id: str) -> None:
    """Update last_connected_at and increment connection_count."""

def import_hosts_csv(user_sub: str, csv_content: str) -> Dict[str, Any]:
    """Parse CSV and bulk-create host entries."""

def list_groups(user_sub: str) -> List[str]:
    """Return distinct group names from user's hosts."""
```

### 3.4 CSV Import Format

```csv
label,hostname,port,protocol,group,os_type,description,tags
Prod Web 1,10.0.1.10,22,ssh,Production,linux,Primary web server,"web,prod"
Staging DB,staging-db.internal,5432,ssh,Staging,linux,PostgreSQL,"db,staging"
Dev VNC,192.168.1.100,5900,vnc,Development,linux,Dev desktop,"dev,vnc"
```

**Validation rules**:
- Max 200 hosts per import
- `hostname` required, validated as IP or valid DNS name
- `port` defaults to 22 (SSH) or 5900 (VNC) based on protocol
- `protocol` must be `ssh`, `vnc`, or `rdp`
- Duplicate labels within the same import are rejected
- Tags parsed as comma-separated within quotes

### 3.5 API Router: `app/routers/remote_hosts.py`

New file (~200 lines). Prefix: `/ui/remote/hosts`. All endpoints use `Depends(require_ui_session)`.

```python
router = APIRouter(prefix="/ui/remote/hosts", tags=["remote-hosts"])
```

#### Endpoints

| Method | Path | Request Body | Response | Description |
|--------|------|-------------|----------|-------------|
| `POST` | `/ui/remote/hosts` | `CreateHostIn` | `HostOut` (201) | Create a host entry |
| `GET` | `/ui/remote/hosts` | — (query params) | `HostListOut` | List hosts with filters |
| `GET` | `/ui/remote/hosts/{host_id}` | — | `HostOut` | Get single host |
| `PATCH` | `/ui/remote/hosts/{host_id}` | `UpdateHostIn` | `HostOut` | Update host fields |
| `DELETE` | `/ui/remote/hosts/{host_id}` | — | `{"ok": true}` | Delete host |
| `POST` | `/ui/remote/hosts/import` | `ImportHostsCsvIn` | `ImportResultOut` | Bulk import from CSV |
| `GET` | `/ui/remote/hosts/groups` | — | `GroupListOut` | List distinct groups |

#### Pydantic Models (in `app/models.py`)

```python
class CreateHostIn(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    hostname: str = Field(..., min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    protocol: Literal["ssh", "vnc", "rdp"] = "ssh"
    description: str = Field(default="", max_length=500)
    tags: List[str] = Field(default_factory=list, max_length=20)
    group: str = Field(default="", max_length=50)
    os_type: Literal["linux", "windows", "macos", "unknown"] = "unknown"

class UpdateHostIn(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=100)
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: Optional[Literal["ssh", "vnc", "rdp"]] = None
    description: Optional[str] = Field(default=None, max_length=500)
    tags: Optional[List[str]] = Field(default=None, max_length=20)
    group: Optional[str] = Field(default=None, max_length=50)
    os_type: Optional[Literal["linux", "windows", "macos", "unknown"]] = None
    is_pinned: Optional[bool] = None

class HostOut(BaseModel):
    host_id: str
    label: str
    hostname: str
    port: int
    protocol: str
    description: str = ""
    tags: List[str] = []
    group: str = ""
    os_type: str = "unknown"
    created_at: int
    updated_at: int
    last_connected_at: int = 0
    connection_count: int = 0
    status: str = "unknown"
    is_pinned: bool = False
    source: str = "manual"

class HostListOut(BaseModel):
    hosts: List[HostOut]
    count: int
    cursor: Optional[str] = None

class ImportHostsCsvIn(BaseModel):
    csv_content: str = Field(..., max_length=100_000)

class ImportResultOut(BaseModel):
    imported: int
    skipped: int
    errors: List[str]

class GroupListOut(BaseModel):
    groups: List[str]
```

### 3.6 Router Registration (`app/main.py`)

```python
from app.routers import remote_hosts
app.include_router(remote_hosts.router)
```

### 3.7 Quick-Connect Integration

#### VNC Quick-Connect

When a user clicks "Connect" on a VNC host, the frontend navigates to `/remote?target_id=user:{host_id}` with query params. The VNC system's `_resolve_target()` function in `app/services/vnc_sessions.py` (line 237) must be extended:

```python
def _resolve_target(target_id: str, *, user_sub: str | None = None) -> TargetConfig:
    inventory = _default_targets()
    if target_id in inventory:
        return inventory[target_id]
    # NEW: Check user's host inventory for user-defined VNC targets
    if target_id.startswith("user:") and user_sub:
        host_id = target_id.removeprefix("user:")
        host = get_host(user_sub, host_id)
        if host and host["protocol"] == "vnc":
            return TargetConfig(
                target_id=target_id,
                ws_url=f"ws://{host['hostname']}:{host['port']}/websockify",
                allowed_users=(user_sub,),
                capabilities={"clipboard": True, "file_transfer": False, "drag_drop_upload": False},
            )
    raise VncSessionError(http_status=404, code="TARGET_NOT_FOUND", message="Unknown target")
```

#### SSH Quick-Connect

When a user clicks "Connect" on an SSH host, the frontend navigates to the SSH terminal page with query params `?host={hostname}&port={port}&username={default_username}`. The SSH terminal WebSocket handler does not need backend changes — the frontend pre-fills the connection form from the host record.

### 3.8 Connection Tracking

When a VNC session is created or an SSH WebSocket connection succeeds, call `record_connection(user_sub, host_id)` to update `last_connected_at` and `connection_count`:

```python
def record_connection(user_sub: str, host_id: str) -> None:
    T.remote_hosts.update_item(
        Key={"user_sub": user_sub, "sk": f"HOST#{host_id}"},
        UpdateExpression="SET last_connected_at = :ts, connection_count = if_not_exists(connection_count, :zero) + :one, updated_at = :ts",
        ExpressionAttributeValues={":ts": now_ts(), ":zero": 0, ":one": 1},
    )
```

### 3.9 Frontend Components

#### HostInventoryPage (`frontend/src/pages/remote/HostInventoryPage.tsx`)

New page component (~400 lines):

- **Header**: "Host Inventory" title with "Add Host" and "Import CSV" buttons
- **Filter bar**: Protocol dropdown (All/SSH/VNC/RDP), group dropdown, search input
- **DataTable** columns: Pin icon, Label, Hostname:Port, Protocol badge, Group, OS icon, Last Connected (relative time), Connection Count, Actions (Connect, Edit, Delete)
- **Sort**: Click column headers (label, last_connected, connection_count)
- **Pagination**: cursor-based, 50 per page
- **Empty state**: "No hosts saved. Add your first host or import from CSV."

#### AddHostDialog (`frontend/src/pages/remote/AddHostDialog.tsx`)

Dialog component (~150 lines):

- Form fields: Label, Hostname, Port, Protocol (select), Group (combobox with existing groups), OS Type (select), Description (textarea), Tags (tag input)
- Port auto-updates when protocol changes (SSH→22, VNC→5900, RDP→3389)
- Hostname validation: IP address or valid DNS name
- Submit: `POST /ui/remote/hosts`

#### ImportCsvDialog (`frontend/src/pages/remote/ImportCsvDialog.tsx`)

Dialog component (~100 lines):

- Textarea for CSV paste or file upload
- Preview table showing parsed rows with validation status
- Import button with progress indicator
- Result summary: "Imported 15 hosts, skipped 2 duplicates, 1 error"

#### Frontend API (`frontend/src/api/endpoints/remote-hosts.ts`)

```typescript
export const createHost = (data: CreateHostIn) =>
  client.post<HostOut>("/ui/remote/hosts", data);

export const listHosts = (params?: HostListParams) =>
  client.get<HostListOut>("/ui/remote/hosts", { params });

export const getHost = (hostId: string) =>
  client.get<HostOut>(`/ui/remote/hosts/${hostId}`);

export const updateHost = (hostId: string, data: UpdateHostIn) =>
  client.patch<HostOut>(`/ui/remote/hosts/${hostId}`, data);

export const deleteHost = (hostId: string) =>
  client.delete(`/ui/remote/hosts/${hostId}`);

export const importHostsCsv = (csvContent: string) =>
  client.post<ImportResultOut>("/ui/remote/hosts/import", { csv_content: csvContent });

export const listGroups = () =>
  client.get<GroupListOut>("/ui/remote/hosts/groups");
```

#### Frontend Types (`frontend/src/api/types.ts`)

```typescript
export interface HostOut {
  host_id: string;
  label: string;
  hostname: string;
  port: number;
  protocol: "ssh" | "vnc" | "rdp";
  description: string;
  tags: string[];
  group: string;
  os_type: "linux" | "windows" | "macos" | "unknown";
  created_at: number;
  updated_at: number;
  last_connected_at: number;
  connection_count: number;
  status: "online" | "offline" | "unknown";
  is_pinned: boolean;
  source: "manual" | "csv_import" | "ec2_auto" | "k8s_auto";
}

export interface HostListOut {
  hosts: HostOut[];
  count: number;
  cursor?: string;
}
```

#### Route Registration (`frontend/src/App.tsx`)

```tsx
<Route path="/remote/hosts" element={<HostInventoryPage />} />
```

#### Sidebar Navigation (`frontend/src/components/layout/Sidebar.tsx`)

Add "Hosts" entry under the Infrastructure group with `Server` icon from lucide-react.

---

## 4. Implementation Plan

### Phase 1: Backend Foundation (2 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `remote_hosts_table_name: str = "remote_hosts"` |
| `app/core/tables.py` | Add `remote_hosts` table handle |
| `scripts/local-ddb-init.py` | Add `remote_hosts` `TableDef` with 3 GSIs |
| `app/services/remote_hosts.py` | New file: CRUD + CSV import + connection tracking |
| `app/models.py` | Add `CreateHostIn`, `UpdateHostIn`, `HostOut`, `HostListOut`, `ImportHostsCsvIn`, `ImportResultOut`, `GroupListOut` |
| `app/routers/remote_hosts.py` | New file: 7 endpoints |
| `app/main.py` | Register `remote_hosts.router` |

### Phase 2: Quick-Connect Integration (1 day)

| File | Change |
|------|--------|
| `app/services/vnc_sessions.py` | Extend `_resolve_target()` to check user host inventory for `user:` prefixed targets |
| `app/routers/vnc_sessions.py` | Pass `user_sub` to `_resolve_target()` when available |
| `app/routers/browser_ssh_terminal.py` | Call `record_connection()` on successful SSH connect |

### Phase 3: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add host inventory types |
| `frontend/src/api/endpoints/remote-hosts.ts` | New file: API wrappers |
| `frontend/src/pages/remote/HostInventoryPage.tsx` | New file: main page |
| `frontend/src/pages/remote/AddHostDialog.tsx` | New file: add/edit dialog |
| `frontend/src/pages/remote/ImportCsvDialog.tsx` | New file: CSV import dialog |
| `frontend/src/App.tsx` | Add `/remote/hosts` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Hosts" nav item |
| `frontend/src/components/layout/AppShell.tsx` | Add "Hosts" to MobileSidebar |

### Phase 4: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/host-inventory.spec.ts` | New file: ~20 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/host-inventory.spec.ts`)

**Section 240: Host CRUD API (6 tests)**

1. `Alice creates an SSH host` — POST with label/hostname/port, verify 201 response with all fields populated including `host_id`, `created_at`, `status: "unknown"`, `source: "manual"`.
2. `Alice creates a VNC host` — POST with `protocol: "vnc"`, `port: 5900`, verify response.
3. `Alice updates host label and group` — PATCH with new label and group, verify updated fields and `updated_at` changed.
4. `Alice deletes a host` — DELETE, verify 200. GET returns 404.
5. `Alice cannot access Bob's host` — Alice creates host, Bob tries GET/PATCH/DELETE on it → 404 (user isolation via PK).
6. `Create host with invalid hostname returns 422` — POST with empty hostname, verify 422 validation error.

**Section 241: Host List & Filter API (5 tests)**

7. `List hosts returns all hosts sorted by label` — Create 3 hosts with labels "Zulu", "Alpha", "Mango". GET without sort param returns alphabetical order.
8. `Filter by protocol` — Create SSH + VNC hosts. GET with `?protocol=ssh` returns only SSH hosts.
9. `Filter by group` — Create hosts in "Production" and "Staging" groups. GET with `?group=Production` returns only production hosts.
10. `Pagination works with cursor` — Create 5 hosts, request with `?limit=2`. Verify `cursor` in response. Request second page with cursor, verify next 2 hosts.
11. `List groups returns distinct group names` — Create hosts in 3 groups. GET `/groups` returns all 3 group names.

**Section 242: CSV Import API (4 tests)**

12. `Import 3 hosts from CSV` — POST CSV with 3 valid rows. Verify `imported: 3`, `skipped: 0`, `errors: []`. List hosts returns 3 new entries.
13. `Import with invalid rows reports errors` — CSV with 1 valid row and 1 row with missing hostname. Verify `imported: 1`, `errors` contains description of the bad row.
14. `Import rejects CSV exceeding 200 hosts` — POST CSV with 201 rows. Verify 400 error.
15. `Import sets source to csv_import` — Import 1 host, GET it, verify `source: "csv_import"`.

**Section 243: Host Inventory UI (5 tests)**

16. `HostInventoryPage renders host table` — Navigate to `/remote/hosts`, verify DataTable headers visible: Label, Hostname, Protocol, Group, Last Connected.
17. `Add Host dialog creates and shows new host` — Click "Add Host", fill form, submit. Verify new row appears in table.
18. `Edit host via dialog` — Click edit on existing host, change label, save. Verify updated label in table.
19. `Delete host via action menu` — Click delete on host, confirm dialog. Verify host removed from table.
20. `Quick-connect navigates to SSH terminal` — Create SSH host, click Connect. Verify navigation includes host params in URL.

**Test Setup**:

```typescript
const TS = Date.now();
let alicePage: Page;
let bobPage: Page;

test.beforeAll(async ({ browser }) => {
  const { getOrCreateSession } = await import("../../e2e_session_setup");
  sessions["alice"] = await getOrCreateSession("alice");
  sessions["bob"] = await getOrCreateSession("bob");
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");
  bobPage = await browser.newPage();
  await injectAuth(bobPage, "bob");
});
```

---

## 6. Security Considerations

### 6.1 User Isolation

Host records use `user_sub` as the DDB partition key. All service functions require `user_sub` as the first argument and include it in every DDB operation. A user cannot read, update, or delete another user's hosts.

### 6.2 Input Validation

- **Hostname**: Validated against a regex allowing IPv4, IPv6, and DNS names. No scheme prefix allowed (no `ssh://`).
- **Port**: Integer 1-65535. Pydantic enforces `ge=1, le=65535`.
- **Label**: 1-100 characters, stripped of leading/trailing whitespace.
- **Tags**: Max 20 tags per host, each tag max 30 characters.
- **CSV**: Max 100KB payload (`max_length=100_000`), max 200 rows per import.

### 6.3 Hostname Sensitivity

Host records may contain internal IP addresses or DNS names that reveal infrastructure topology. Responses are only returned to the owning user (PK=user_sub). Admin endpoints do not expose other users' host inventories (INFRA-012 is a separate concern with its own access controls).

### 6.4 Audit Trail

`create_host`, `update_host`, `delete_host`, and `import_hosts_csv` all call `audit_event()` from `app/services/alerts.py` with event type `remote_host.*`.

---

## 7. Observability & Monitoring

### 7.1 Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `host_inventory_created_total` | Counter | `protocol`, `source` | Hosts created (manual, csv_import, ec2_auto, k8s_auto) |
| `host_inventory_deleted_total` | Counter | `protocol` | Hosts deleted |
| `host_inventory_csv_import_total` | Counter | `result` (success/partial/failed) | CSV import attempts |
| `host_inventory_csv_rows_total` | Counter | `status` (imported/skipped/error) | Per-row import results |
| `host_inventory_connection_total` | Counter | `protocol` | Quick-connect events |
| `host_inventory_list_latency_seconds` | Histogram | `sort_by`, `has_filter` | List hosts query latency |
| `host_inventory_count` | Gauge | `protocol` | Current host count per user (sampled) |

### 7.2 Structured Log Events

```json
{"logger": "remote_hosts", "level": "info", "event": "host_created", "user_sub": "alice-uuid", "host_id": "h_abc123", "protocol": "ssh", "hostname": "10.0.1.10", "source": "manual"}

{"logger": "remote_hosts", "level": "info", "event": "csv_import_complete", "user_sub": "alice-uuid", "imported": 15, "skipped": 2, "errors": 1, "total_rows": 18}

{"logger": "remote_hosts", "level": "info", "event": "connection_recorded", "user_sub": "alice-uuid", "host_id": "h_abc123", "protocol": "ssh", "connection_count": 42}

{"logger": "remote_hosts", "level": "warn", "event": "csv_import_too_large", "user_sub": "alice-uuid", "row_count": 250, "max_allowed": 200}
```

### 7.3 Alert Rules

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| CSV import failure rate | `rate(host_inventory_csv_import_total{result=failed}[1h]) > 10` | Warning | Investigate CSV format issues |
| Excessive host creation | User creates > 100 hosts in 1 hour | Warning | Possible automation abuse |
| DDB throttling | ThrottledRequestCount > 0 on `remote_hosts` | Critical | Increase auto-scaling |
| List query slow | `p99(host_inventory_list_latency_seconds) > 1s` | Warning | Check GSI health |

---

## 8. Rollout Plan

### Phase 1: Backend (Days 1-2)

- **Feature flag**: `REMOTE_HOSTS_ENABLED=false`
- Deploy DDB table, service, router behind flag
- All endpoints return 404 when flag is off
- Run integration tests against staging

### Phase 2: Internal Beta (Days 3-4)

- **Feature flag**: `REMOTE_HOSTS_ENABLED=true` for internal users
- Deploy frontend pages
- QA exercises full CRUD + CSV import + quick-connect
- Validate VNC `_resolve_target()` extension

### Phase 3: GA (Day 5+)

- **Feature flag**: `REMOTE_HOSTS_ENABLED=true` for all users
- Monitor creation patterns and DDB capacity
- **Rollback**: Set `REMOTE_HOSTS_ENABLED=false`; data preserved

---

## 9. Performance Considerations

### 9.1 Latency Targets

| Operation | Target p50 | Target p99 | Notes |
|-----------|-----------|-----------|-------|
| Create host | < 30ms | < 80ms | Single put_item |
| Get host | < 10ms | < 40ms | Single get_item |
| Update host | < 20ms | < 60ms | Single update_item |
| List hosts (page) | < 40ms | < 120ms | GSI query, Limit=50 |
| CSV import (100 rows) | < 2s | < 5s | Batch writes (25 per batch) |
| Record connection | < 15ms | < 50ms | Single update_item |

### 9.2 DynamoDB Costs

| Operation | RCU | WCU | Notes |
|-----------|-----|-----|-------|
| Get host | 0.5 | — | Single item eventual read |
| List hosts (50) | 5.0 | — | GSI query |
| Create host | — | 1.0 | Single put |
| CSV import (100) | — | 100 | 4 batch_write calls of 25 |
| Record connection | — | 1.0 | Single update |

### 9.3 Scalability

- **Per-user host count**: Default max 500 hosts per user (configurable). Most users expected < 50 hosts.
- **CSV import batch writes**: `batch_write_item` sends 25 items per batch. 200-row import = 8 batches, ~2s.
- **GSI hot partitions**: Each user is a separate partition. No cross-user hot key concerns.
- **Connection tracking writes**: `record_connection` is fire-and-forget (no retry). If write fails, connection still succeeds.

---

## 10. Migration & Rollback

### 7.1 DDB Changes

- New table `remote_hosts` with 3 GSIs — created by `scripts/local-ddb-init.py` on next stack restart.
- In production: create table via `aws dynamodb create-table` before deploying backend code.

### 7.2 Rollback

- Remove `remote_hosts.router` from `app/main.py` to disable endpoints.
- Frontend route removal prevents UI access.
- DDB table can remain — orphaned data is harmless.
- VNC `_resolve_target()` extension is backward-compatible: `user:` prefix targets only resolve if the host exists; hardcoded targets are unaffected.

---

## 8. Acceptance Criteria

1. A user can create, read, update, and delete hosts in their inventory.
2. Host records are isolated per user — no cross-user access.
3. Hosts can be filtered by protocol and group, sorted by label or last-connected.
4. CSV import creates hosts from a valid CSV payload, reporting errors for invalid rows.
5. Groups list returns distinct group names from the user's hosts.
6. Quick-connect on an SSH host navigates to the SSH terminal with pre-filled params.
7. Quick-connect on a VNC host creates a VNC session targeting the user's saved host.
8. Connection tracking updates `last_connected_at` and `connection_count` on each connect.
9. Frontend DataTable displays hosts with search, filter, sort, and pagination.
10. All mutations produce audit events.
