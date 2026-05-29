# INFRA-006: Connection Profiles & Quick Connect

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 4-6 days  
**Dependencies**: INFRA-001 (Host Inventory), INFRA-002 (SSH Key Manager)

---

## 1. Overview & Motivation

### The Gap

INFRA-001 provides a host inventory with basic fields (hostname, port, protocol), and INFRA-002 provides SSH key storage with host associations. However, a "host" is not the same as a "connection profile." Users still need to:

1. Specify SSH username for each connection (not stored on the host)
2. Choose terminal settings (columns, rows, font size, color scheme)
3. Configure VNC-specific parameters (display label, custom WebSocket URL override)
4. Remember which settings they used for their last successful connection
5. See and re-use recent connections quickly
6. Pin frequently-used connections for one-click access

The SSH terminal WebSocket handler in `app/routers/browser_ssh_terminal.py` accepts connection parameters in the `connect` message but does not store or recall them. The VNC system in `app/services/vnc_sessions.py` uses hardcoded `TargetConfig` objects with no user customization. Every connection starts from scratch.

### Why This Matters

1. **One-click connect**: Users should select a saved connection and immediately be in a shell or VNC session, without filling out any form fields.
2. **Terminal preferences**: Power users have strong preferences for terminal dimensions, font size, and color scheme. These should persist per-connection.
3. **Recent connections**: A "recently connected" list surfaces the hosts users care about most, reducing navigation time.
4. **Pinned connections**: Pinning a connection makes it always visible at the top of the list — essential for users with 20+ hosts.

### Architecture After This Change

```
Connection Profile Flow

  remote_hosts table (INFRA-001)
  +-- Extended with connection profile fields:
  |   default_username, terminal_settings, vnc_settings,
  |   vnc_password_encrypted, is_pinned, last_connection_params
  |
  +---> ConnectionProfileDialog (edit profile on host)
  |
  +---> RecentConnectionsList (last 10 connections)
  |     Stored in remote_hosts table: sk=RECENT#{user_sub}
  |
  +---> Quick Connect:
  |     1. User clicks "Connect" on host/recent entry
  |     2. All params pre-filled from profile
  |     3. SSH: auto-connect mode (skip form, go to shell)
  |     4. VNC: auto-create session with profile params
```

---

## 2. Current State Analysis

### 2.1 SSH Terminal Connection Form

The SSH terminal frontend presents a connection form before establishing the WebSocket. The user must fill in:
- Hostname (required)
- Port (default 22)
- Username (required)
- Auth type (password / private key)
- Password or private key content
- Terminal columns/rows

None of these are pre-populated from any stored state (unless INFRA-001's query-param-based quick connect is used, which only fills hostname and port).

### 2.2 VNC Session Creation (`app/routers/vnc_sessions.py`)

The VNC session is created via `POST /api/vnc/sessions` with a `target_id`. The `CreateVncSessionReq` model (line 36) accepts only `target_id`. There is no field for display label, custom WebSocket URL, or user preferences. The `VncTimeoutPolicy` is hardcoded per-target, not user-configurable.

### 2.3 Host Inventory Schema (INFRA-001)

The `remote_hosts` table has basic fields but no connection-profile-specific fields like `default_username`, `terminal_settings`, or `vnc_password_encrypted`.

### 2.4 KMS Encryption for VNC Passwords

VNC connections sometimes require a password. The platform already has `kms_encrypt()` / `kms_decrypt()` in `app/core/crypto.py` which can be used to store VNC passwords encrypted at rest, following the same pattern as SSH key encryption in INFRA-002.

---

## 3. Technical Design

### 3.1 Extend `remote_hosts` Table (INFRA-001)

Add connection profile fields to existing host items. No new table needed.

**New fields on host items**:

| Field | Type | Description |
|-------|------|-------------|
| `default_username` | S | Default SSH username (e.g., `ubuntu`, `root`) |
| `auth_method` | S | `password`, `key`, `key_ref` (reference to INFRA-002 key) |
| `ssh_key_id` | S | Reference to stored SSH key (INFRA-002) |
| `vnc_password_encrypted` | S | KMS-encrypted VNC password |
| `vnc_display_label` | S | Custom display label for VNC sessions |
| `vnc_ws_url_override` | S | Custom WebSocket URL override |
| `terminal_cols` | N | Terminal columns (default: 80) |
| `terminal_rows` | N | Terminal rows (default: 24) |
| `terminal_font_size` | N | Font size in pixels (default: 14) |
| `terminal_color_scheme` | S | Color scheme name (e.g., `dark`, `light`, `monokai`, `solarized`) |
| `auto_connect` | BOOL | Skip connection form, go straight to shell/VNC |
| `last_connection_params` | M | Last successful connection parameters (for recall) |

**Recent connections item** (same table, different SK pattern):

| Field | SK Pattern | Description |
|-------|-----------|-------------|
| `user_sub` | PK | User ID |
| `sk` | `RECENT#{user_sub}` | Singleton item per user |
| `recent_connections` | L[M] | Last 10 connections: `[{host_id, label, hostname, port, protocol, connected_at}]` |

### 3.2 Service Layer: `app/services/connection_profiles.py`

New file (~200 lines):

```python
"""Connection profile management — extends host records with connection-specific settings."""

from __future__ import annotations
from typing import Any, Dict, List, Optional

from app.core.crypto import kms_encrypt, kms_decrypt
from app.core.tables import T
from app.core.time import now_ts


def update_connection_profile(
    user_sub: str,
    host_id: str,
    *,
    default_username: str | None = None,
    auth_method: str | None = None,
    ssh_key_id: str | None = None,
    vnc_password: str | None = None,       # plaintext — encrypted before storage
    vnc_display_label: str | None = None,
    vnc_ws_url_override: str | None = None,
    terminal_cols: int | None = None,
    terminal_rows: int | None = None,
    terminal_font_size: int | None = None,
    terminal_color_scheme: str | None = None,
    auto_connect: bool | None = None,
) -> Dict[str, Any]:
    """Update connection profile fields on a host record."""

def get_connection_profile(user_sub: str, host_id: str) -> Dict[str, Any] | None:
    """Get full connection profile including terminal settings."""

def record_recent_connection(
    user_sub: str,
    *,
    host_id: str,
    label: str,
    hostname: str,
    port: int,
    protocol: str,
) -> None:
    """Add a connection to the recent list (max 10, LIFO)."""

def get_recent_connections(user_sub: str) -> List[Dict[str, Any]]:
    """Get last 10 connections."""

def clear_recent_connections(user_sub: str) -> None:
    """Clear recent connections list."""

def get_quick_connect_params(user_sub: str, host_id: str) -> Dict[str, Any]:
    """Build complete connection parameters from host + profile + key.
    For SSH: returns host, port, username, auth_type, key_id (or password flag).
    For VNC: returns target_id, ws_url, display_label.
    Terminal settings included for both."""
```

### 3.3 VNC Password Encryption

```python
def update_connection_profile(user_sub, host_id, *, vnc_password=None, **kwargs):
    updates = {}
    if vnc_password is not None:
        if vnc_password == "":
            updates["vnc_password_encrypted"] = ""  # clear password
        else:
            updates["vnc_password_encrypted"] = kms_encrypt(vnc_password)
    # ... other fields ...
```

The VNC password is encrypted with KMS before storage. When building quick-connect params for VNC, the password is decrypted server-side and passed to the VNC session creation flow. It is never returned to the frontend in plaintext.

### 3.4 API Endpoints

Extend `app/routers/remote_hosts.py` (from INFRA-001) with profile-specific endpoints:

| Method | Path | Request | Response | Description |
|--------|------|---------|----------|-------------|
| `PATCH` | `/ui/remote/hosts/{id}/profile` | `UpdateProfileIn` | `ProfileOut` | Update connection profile |
| `GET` | `/ui/remote/hosts/{id}/profile` | — | `ProfileOut` | Get connection profile |
| `GET` | `/ui/remote/hosts/{id}/quick-connect` | — | `QuickConnectParamsOut` | Get pre-filled params |
| `GET` | `/ui/remote/connections/recent` | — | `RecentConnectionsOut` | List recent connections |
| `DELETE` | `/ui/remote/connections/recent` | — | `{"ok": true}` | Clear recent list |

#### Pydantic Models

```python
class UpdateProfileIn(BaseModel):
    default_username: Optional[str] = Field(default=None, max_length=64)
    auth_method: Optional[Literal["password", "key", "key_ref"]] = None
    ssh_key_id: Optional[str] = None
    vnc_password: Optional[str] = Field(default=None, max_length=128)
    vnc_display_label: Optional[str] = Field(default=None, max_length=100)
    vnc_ws_url_override: Optional[str] = Field(default=None, max_length=512)
    terminal_cols: Optional[int] = Field(default=None, ge=40, le=300)
    terminal_rows: Optional[int] = Field(default=None, ge=10, le=100)
    terminal_font_size: Optional[int] = Field(default=None, ge=8, le=32)
    terminal_color_scheme: Optional[Literal["dark", "light", "monokai", "solarized", "dracula"]] = None
    auto_connect: Optional[bool] = None

class ProfileOut(BaseModel):
    host_id: str
    default_username: str = ""
    auth_method: str = "password"
    ssh_key_id: str = ""
    has_vnc_password: bool = False  # Never expose actual password
    vnc_display_label: str = ""
    vnc_ws_url_override: str = ""
    terminal_cols: int = 80
    terminal_rows: int = 24
    terminal_font_size: int = 14
    terminal_color_scheme: str = "dark"
    auto_connect: bool = False

class QuickConnectParamsOut(BaseModel):
    host_id: str
    hostname: str
    port: int
    protocol: str
    username: str
    auth_method: str
    ssh_key_id: str = ""
    terminal_cols: int = 80
    terminal_rows: int = 24
    terminal_font_size: int = 14
    terminal_color_scheme: str = "dark"
    auto_connect: bool = False
    # VNC-specific
    vnc_target_id: str = ""
    vnc_display_label: str = ""

class RecentConnection(BaseModel):
    host_id: str
    label: str
    hostname: str
    port: int
    protocol: str
    connected_at: int

class RecentConnectionsOut(BaseModel):
    connections: List[RecentConnection]
```

### 3.5 SSH Auto-Connect Mode

When `auto_connect=True` and all required params are available (hostname, port, username, and either a stored key or saved password), the SSH terminal frontend:

1. Skips the connection form entirely
2. Immediately opens the WebSocket with pre-filled params
3. Sends the `connect` message with `authType: "stored_key"` and `keyId` (or password)
4. Shows the terminal output directly

The frontend detects auto-connect via query params: `/remote/ssh?host_id={id}&auto=true`. It fetches the quick-connect params from `GET /ui/remote/hosts/{id}/quick-connect` and proceeds without user input.

### 3.6 Frontend Components

#### ConnectionProfileDialog (`frontend/src/pages/remote/ConnectionProfileDialog.tsx`)

Dialog component (~200 lines):

- **SSH Settings section**: Username input, auth method selector (Password/Stored Key), key dropdown (from INFRA-002 keys), password toggle
- **VNC Settings section** (shown when protocol=vnc): VNC password input (masked), display label, WebSocket URL override
- **Terminal Settings section**: Columns/rows number inputs, font size slider, color scheme dropdown (with preview swatches)
- **Auto-connect toggle**: "Connect automatically when selecting this host"
- Save button updates the host's connection profile

#### RecentConnectionsList (`frontend/src/pages/remote/RecentConnectionsList.tsx`)

Widget component (~100 lines):

- Rendered at the top of HostInventoryPage (INFRA-001)
- Horizontal scrollable card list showing last 10 connections
- Each card: host label, hostname:port, protocol badge, "2 hours ago" relative time
- Click → quick-connect to that host
- "Clear" button to remove all recent entries

#### Frontend Integration Points

```typescript
// In HostInventoryPage: add RecentConnectionsList above the DataTable
// In host row actions: add "Edit Profile" menu item → opens ConnectionProfileDialog
// In Connect button: use quick-connect endpoint to get params, respect auto_connect flag
```

---

## 4. Implementation Plan

### Phase 1: Backend Profile Service (2 days)

| File | Change |
|------|--------|
| `app/services/connection_profiles.py` | New file: profile CRUD, recent connections, quick-connect params |
| `app/routers/remote_hosts.py` | Add 5 profile/recent endpoints |
| `app/models.py` | Add profile Pydantic models |

### Phase 2: SSH Auto-Connect (1 day)

| File | Change |
|------|--------|
| `app/routers/browser_ssh_terminal.py` | Accept pre-populated params from quick-connect endpoint; pass stored key auth to bridge |

### Phase 3: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add profile types |
| `frontend/src/api/endpoints/remote-hosts.ts` | Add profile + recent API calls |
| `frontend/src/pages/remote/ConnectionProfileDialog.tsx` | New file |
| `frontend/src/pages/remote/RecentConnectionsList.tsx` | New file |
| `frontend/src/pages/remote/HostInventoryPage.tsx` | Integrate RecentConnectionsList + profile dialog |
| `frontend/src/pages/remote/RemoteDesktopPage.tsx` | Support auto-connect via query params |

### Phase 4: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/connection-profiles.spec.ts` | New file: ~15 tests in 3 sections |

---

## 5. E2E Test Plan (`frontend/e2e/connection-profiles.spec.ts`)

**Section 261: Connection Profile API (6 tests)**

1. `Set SSH profile with username and key` — Create host, PATCH profile with `default_username: "ubuntu"`, `auth_method: "key_ref"`, `ssh_key_id`. GET profile, verify all fields.
2. `Set VNC profile with encrypted password` — Create VNC host, PATCH profile with `vnc_password: "secret123"`. GET profile, verify `has_vnc_password: true` (password not exposed).
3. `Set terminal settings` — PATCH with `terminal_cols: 120`, `terminal_rows: 40`, `terminal_font_size: 16`, `terminal_color_scheme: "monokai"`. GET, verify all values.
4. `Enable auto-connect` — PATCH with `auto_connect: true`. GET, verify `auto_connect: true`.
5. `Get quick-connect params includes all profile fields` — Set profile with username + key + terminal settings. GET `/quick-connect`. Verify `username`, `ssh_key_id`, `terminal_cols`, `auto_connect` all populated.
6. `Profile fields are user-isolated` — Alice sets profile on her host. Bob cannot GET Alice's profile → 404.

**Section 262: Recent Connections API (4 tests)**

7. `Record recent connection adds to list` — Connect to a host (via PATCH to simulate). GET recent, verify 1 entry with host_id, label, connected_at.
8. `Recent connections max 10 (LIFO)` — Record 12 connections. GET recent, verify 10 entries. Oldest 2 dropped.
9. `Clear recent connections` — Record 3 connections. DELETE recent. GET recent, verify empty list.
10. `Recent connections are per-user` — Alice records connection. Bob's recent list is empty.

**Section 263: Connection Profiles UI (5 tests)**

11. `Edit Profile dialog opens from host list` — Navigate to `/remote/hosts`. Click "Edit Profile" on a host. Verify dialog with SSH Settings, Terminal Settings sections.
12. `Save profile updates host` — Fill username + select color scheme, save. Reopen dialog, verify values persisted.
13. `Recent connections widget shows recent hosts` — Record 2 connections. Navigate to `/remote/hosts`. Verify recent cards visible above table.
14. `Click recent connection navigates to SSH terminal` — Click a recent SSH connection card. Verify navigation to SSH terminal page with params.
15. `Quick-connect button respects auto-connect` — Set `auto_connect: true` on host. Click Connect. Verify no connection form shown (immediate WebSocket attempt).

**Test Setup**:

```typescript
test.beforeAll(async ({ browser }) => {
  sessions["alice"] = await getOrCreateSession("alice");
  sessions["bob"] = await getOrCreateSession("bob");
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");

  // Create test hosts for profile tests
  sshHost = await apiPost(alicePage, "alice", "/ui/remote/hosts", {
    label: `profile-ssh-${TS}`, hostname: "10.0.0.1", port: 22, protocol: "ssh",
  });
  vncHost = await apiPost(alicePage, "alice", "/ui/remote/hosts", {
    label: `profile-vnc-${TS}`, hostname: "10.0.0.2", port: 5900, protocol: "vnc",
  });
});
```

---

## 6. Security Considerations

### 6.1 VNC Password Encryption

VNC passwords are encrypted with KMS before storage. The `ProfileOut` model returns `has_vnc_password: bool` instead of the actual password. The password is only decrypted server-side when building quick-connect params for a VNC session.

### 6.2 Password Storage Decision

SSH passwords are **not stored** — only key references (`key_ref` auth method). Users who prefer password auth must enter it each time. This is a deliberate security decision: passwords are more sensitive than key references and would require additional protection (rotation, breach detection).

### 6.3 Auto-Connect Security

Auto-connect requires that the host has a stored SSH key associated (not just a password). This ensures that auto-connect does not store or transmit passwords automatically.

---

## 7. Acceptance Criteria

1. Users can set a default username, auth method, and terminal preferences per host.
2. VNC passwords are KMS-encrypted and never exposed via the API.
3. Quick-connect endpoint returns all pre-filled params for one-click connection.
4. SSH auto-connect mode skips the connection form when all params are available.
5. Recent connections list shows the last 10 connections in reverse chronological order.
6. Recent connections are per-user and can be cleared.
7. Connection profiles are stored on the host record (no new table).
8. Terminal settings (cols, rows, font, color scheme) persist per-connection.
9. Profile data is user-isolated via DDB partition key.
10. Frontend integrates profile editing and recent connections into the host inventory page.
