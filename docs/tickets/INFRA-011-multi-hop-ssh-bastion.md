# INFRA-011: Multi-Hop SSH (Bastion/Jump Host)

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 5-7 days  
**Dependencies**: INFRA-001 (Host Inventory), INFRA-002 (SSH Key Manager)

---

## 1. Overview & Motivation

### The Gap

The SSH terminal (`app/routers/browser_ssh_terminal.py`, 1,126 lines) establishes a direct connection from the platform backend to the target host via Paramiko. This works for hosts that are directly reachable from the platform's network. However, many production environments are designed with network segmentation:

1. **Private subnets**: Databases, application servers, and internal services sit in private subnets with no public IP addresses.
2. **Bastion/jump hosts**: A single hardened bastion host sits in a public subnet and acts as the gateway to private hosts.
3. **Multi-layer networks**: Some architectures have multiple network tiers (DMZ → application → data), each requiring a hop through a gateway.

Currently, the platform cannot reach hosts in private subnets because:
- The `ParamikoSshBridge` connects directly to `host:port`
- There is no SSH channel forwarding or ProxyJump equivalent
- Users must manually set up SSH tunnels outside the platform

### Why This Matters

1. **Enterprise adoption**: Production infrastructure almost always uses bastion hosts. Without multi-hop support, the platform cannot be used for production access.
2. **Security**: Bastion hosts reduce attack surface by limiting the number of machines exposed to the internet.
3. **Convenience**: Users should not need to manually set up SSH tunnels. The platform should handle the full connection chain.
4. **Host inventory integration**: Bastion relationships should be stored in the host inventory so connections are one-click.

### Architecture After This Change

```
Multi-Hop SSH Flow

  Platform Backend
       |
       | Hop 1: Connect to bastion
       v
  +-------------------+
  | Bastion Host      |  (public IP, SSH port 22)
  | ParamikoTransport |  Authenticated via stored key (INFRA-002)
  +-------------------+
       |
       | Hop 2: Open channel to target via bastion
       |         (Paramiko direct-tcpip channel forwarding)
       v
  +-------------------+
  | Target Host       |  (private IP, SSH port 22)
  | ParamikoSshBridge |  Authenticated via stored key (INFRA-002)
  +-------------------+
       |
       | Hop 3 (optional): Open channel to final target via target
       v
  +-------------------+
  | Final Host        |  (deeper private subnet)
  +-------------------+

  Host Inventory Model:
  +-- bastion_host (is_bastion: true, public IP)
  +-- target_host (bastion_host_id: <bastion's host_id>, private IP)
  +-- deep_host (bastion_host_id: <target's host_id>, deeper private IP)
```

---

## 2. Current State Analysis

### 2.1 Direct Connection Model (`app/routers/browser_ssh_terminal.py`)

The `ParamikoSshBridge.__init__()` creates a direct socket connection:

```python
# Simplified from browser_ssh_terminal.py
self._transport = paramiko.Transport((host, port))
self._transport.connect(username=username, password=password, pkey=pkey)
self._channel = self._transport.open_session()
self._channel.get_pty(term="xterm-256color", width=cols, height=rows)
self._channel.invoke_shell()
```

There is no intermediate hop. The `Transport` is created directly with the target `(host, port)`.

### 2.2 Paramiko Channel Forwarding

Paramiko supports SSH channel forwarding via `Transport.open_channel("direct-tcpip", ...)`, which is the equivalent of OpenSSH's `ProxyJump`/`ProxyCommand`. The flow:

```python
# 1. Connect to bastion
bastion_transport = paramiko.Transport((bastion_host, bastion_port))
bastion_transport.connect(username=bastion_user, pkey=bastion_key)

# 2. Open forwarded channel to target through bastion
channel = bastion_transport.open_channel(
    "direct-tcpip",
    dest_addr=(target_host, target_port),
    src_addr=("127.0.0.1", 0),
)

# 3. Create transport to target over the forwarded channel
target_transport = paramiko.Transport(channel)
target_transport.connect(username=target_user, pkey=target_key)

# 4. Open session on target
session = target_transport.open_session()
session.get_pty(...)
session.invoke_shell()
```

This is a well-established Paramiko pattern. The key change is passing a channel (from step 2) instead of a `(host, port)` tuple to `Transport()`.

### 2.3 Host Inventory (INFRA-001)

The `remote_hosts` table stores host records. Multi-hop support requires two new fields:
- `is_bastion: bool` — marks a host as a bastion/jump host
- `bastion_host_id: str` — references the bastion host to use when connecting to this host

### 2.4 SSH Key Manager (INFRA-002)

Each hop may require different credentials. The bastion host typically has its own SSH key, and the target host has a different key. The key manager stores keys per host via `associated_hosts[]`, which supports this multi-key requirement.

---

## 3. Technical Design

### 3.1 Host Inventory Extension

Add fields to `remote_hosts` table (INFRA-001):

| Field | Type | Description |
|-------|------|-------------|
| `is_bastion` | BOOL | Whether this host is a bastion/jump host |
| `bastion_host_id` | S | Host ID of the bastion to use for connecting (if not directly reachable) |

Update `HostOut` and `UpdateHostIn` Pydantic models:

```python
class HostOut(BaseModel):
    # ... existing fields ...
    is_bastion: bool = False
    bastion_host_id: str = ""

class UpdateHostIn(BaseModel):
    # ... existing fields ...
    is_bastion: Optional[bool] = None
    bastion_host_id: Optional[str] = None
```

### 3.2 Connection Chain Resolution

New function in `app/services/connection_profiles.py` (or `app/services/remote_hosts.py`):

```python
def resolve_connection_chain(user_sub: str, host_id: str, *, max_hops: int = 3) -> List[Dict[str, Any]]:
    """Resolve the full connection chain from the platform to the target host.
    Returns a list of hops, each with host details and credentials.
    The last hop is the target. Preceding hops are bastions.
    
    Example:
      host_id = "target-host"
      target-host.bastion_host_id = "bastion-1"
      bastion-1.bastion_host_id = "" (directly reachable)
      
      Returns: [
          {"host": bastion-1, "key_id": "...", "username": "..."},
          {"host": target-host, "key_id": "...", "username": "..."},
      ]
    """
    chain = []
    current_id = host_id
    visited = set()

    while current_id:
        if current_id in visited:
            raise ValueError("Circular bastion chain detected")
        if len(chain) >= max_hops:
            raise ValueError(f"Connection chain exceeds maximum {max_hops} hops")

        visited.add(current_id)
        host = get_host(user_sub, current_id)
        if not host:
            raise ValueError(f"Host {current_id} not found")

        # Get connection profile for this hop
        profile = get_connection_profile(user_sub, current_id)

        chain.append({
            "host_id": current_id,
            "hostname": host["hostname"],
            "port": host["port"],
            "username": profile.get("default_username", ""),
            "ssh_key_id": profile.get("ssh_key_id") or host.get("ssh_key_id", ""),
            "auth_method": profile.get("auth_method", "key_ref"),
            "is_bastion": host.get("is_bastion", False),
        })

        bastion_id = host.get("bastion_host_id", "")
        if bastion_id:
            current_id = bastion_id
        else:
            break  # This host is directly reachable

    chain.reverse()  # First hop = outermost bastion, last hop = target
    return chain
```

### 3.3 Multi-Hop SSH Bridge

New class in `app/routers/browser_ssh_terminal.py`:

```python
class MultiHopSshBridge:
    """SSH bridge that connects through one or more bastion/jump hosts."""

    def __init__(
        self,
        *,
        chain: List[Dict[str, Any]],
        cols: int,
        rows: int,
        user_sub: str,
    ):
        self._chain = chain
        self._cols = cols
        self._rows = rows
        self._user_sub = user_sub
        self._transports: List[paramiko.Transport] = []
        self._channels: List[paramiko.Channel] = []
        self._session: paramiko.Channel | None = None

    def connect(self) -> None:
        """Establish the full connection chain."""
        prev_channel = None

        for i, hop in enumerate(self._chain):
            hostname = hop["hostname"]
            port = hop["port"]
            username = hop["username"]

            # Get authentication credential
            pkey = None
            password = None
            if hop.get("ssh_key_id"):
                from app.services.ssh_key_manager import get_decrypted_private_key
                key_pem = get_decrypted_private_key(self._user_sub, hop["ssh_key_id"])
                pkey = _parse_private_key(key_pem)

            if prev_channel is None:
                # First hop: direct TCP connection
                transport = paramiko.Transport((hostname, port))
            else:
                # Subsequent hops: connect through forwarded channel
                channel = prev_channel.get_transport().open_channel(
                    "direct-tcpip",
                    dest_addr=(hostname, port),
                    src_addr=("127.0.0.1", 0),
                )
                self._channels.append(channel)
                transport = paramiko.Transport(channel)

            transport.connect(username=username, password=password, pkey=pkey)
            self._transports.append(transport)

            if i == len(self._chain) - 1:
                # Last hop: open interactive session
                self._session = transport.open_session()
                self._session.get_pty(
                    term="xterm-256color",
                    width=self._cols,
                    height=self._rows,
                )
                self._session.invoke_shell()
            else:
                # Intermediate hop: keep transport alive for channel forwarding
                prev_channel = transport.open_channel(
                    "direct-tcpip",
                    dest_addr=(self._chain[i + 1]["hostname"], self._chain[i + 1]["port"]),
                    src_addr=("127.0.0.1", 0),
                )

    def send(self, data: str) -> None:
        """Send input to the terminal session."""
        if self._session:
            self._session.sendall(data.encode("utf-8"))

    def recv(self, size: int = 4096) -> str:
        """Receive output from the terminal session."""
        if self._session and self._session.recv_ready():
            return self._session.recv(size).decode("utf-8", errors="replace")
        return ""

    def resize(self, cols: int, rows: int) -> None:
        """Resize the terminal."""
        if self._session:
            self._session.resize_pty(width=cols, height=rows)

    def close(self) -> None:
        """Close all transports and channels in reverse order."""
        if self._session:
            self._session.close()
        for channel in reversed(self._channels):
            try:
                channel.close()
            except Exception:
                pass
        for transport in reversed(self._transports):
            try:
                transport.close()
            except Exception:
                pass
```

### 3.4 WebSocket Handler Changes

Modify the WebSocket `connect` message handler to support multi-hop:

```python
# New connect message format:
# { "type": "connect", "payload": {
#     "host_id": "target-host-id",     # NEW: resolve chain from host inventory
#     // OR traditional direct connect:
#     "host": "10.0.1.5", "port": 22, "username": "ubuntu", ...
# }}

if "host_id" in payload:
    # Multi-hop via host inventory
    chain = resolve_connection_chain(user_sub, payload["host_id"])
    if len(chain) > 1:
        bridge = MultiHopSshBridge(
            chain=chain, cols=cols, rows=rows, user_sub=user_sub,
        )
        bridge.connect()
    else:
        # Single hop — use existing direct bridge
        hop = chain[0]
        bridge = ParamikoSshBridge(
            host=hop["hostname"], port=hop["port"], username=hop["username"],
            auth_type="stored_key", private_key=..., cols=cols, rows=rows,
        )
else:
    # Traditional direct connect (backward compatible)
    bridge = ParamikoSshBridge(
        host=payload["host"], port=payload.get("port", 22), ...
    )
```

### 3.5 Mock Multi-Hop

In dev mode, multi-hop is "simulated" — the mock doesn't actually create TCP channels. Instead, the service validates the chain resolution and connects directly to the target (since all hosts in dev mode are either mocked or local). The important thing is that the chain resolution logic, UI flow, and configuration are fully testable.

### 3.6 Frontend Changes

#### Host Edit Dialog Updates

In `AddHostDialog` / `ConnectionProfileDialog` (INFRA-001 / INFRA-006):

- **Bastion toggle**: Checkbox "This is a bastion/jump host" → sets `is_bastion: true`
- **Bastion selector**: Dropdown "Connect via bastion" → shows list of hosts with `is_bastion: true` → sets `bastion_host_id`
- **Connection chain preview**: When a bastion is selected, show the connection chain visually: `Platform → Bastion (10.0.0.1) → Target (172.16.0.5)`

#### HostInventoryPage Updates

- Bastion hosts show a "Bastion" badge
- Hosts with `bastion_host_id` show "via {bastion_label}" text
- Connection chain is validated before quick-connect (all hops have credentials)

#### SSH Terminal Updates

- Connection status shows hop progress: "Connecting to bastion... Connected. Connecting to target... Connected."
- Each hop's status is displayed as it connects

---

## 4. Implementation Plan

### Phase 1: Host Inventory Extension (1 day)

| File | Change |
|------|--------|
| `app/services/remote_hosts.py` | Add `is_bastion`, `bastion_host_id` fields |
| `app/models.py` | Update `HostOut`, `UpdateHostIn` with bastion fields |

### Phase 2: Chain Resolution (1 day)

| File | Change |
|------|--------|
| `app/services/connection_profiles.py` | Add `resolve_connection_chain()` function |

### Phase 3: Multi-Hop Bridge (2-3 days)

| File | Change |
|------|--------|
| `app/routers/browser_ssh_terminal.py` | Add `MultiHopSshBridge` class, modify WebSocket handler to support `host_id` connect |

### Phase 4: Frontend (1-2 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add `is_bastion`, `bastion_host_id` to `HostOut` |
| `frontend/src/pages/remote/AddHostDialog.tsx` | Add bastion toggle + bastion selector dropdown |
| `frontend/src/pages/remote/HostInventoryPage.tsx` | Show bastion badges and "via" text |

### Phase 5: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/multi-hop-ssh.spec.ts` | New file: ~12 tests in 3 sections |

---

## 5. E2E Test Plan (`frontend/e2e/multi-hop-ssh.spec.ts`)

**Section 277: Bastion Host Configuration API (5 tests)**

1. `Mark host as bastion` — PATCH host with `is_bastion: true`. GET host, verify `is_bastion: true`.
2. `Set bastion_host_id on target host` — Create bastion host + target host. PATCH target with `bastion_host_id: <bastion's host_id>`. Verify set.
3. `Resolve connection chain for direct host` — Host with no bastion. GET `/ui/remote/hosts/{id}/connection-chain`. Verify chain has 1 hop.
4. `Resolve connection chain for bastion target` — Target with bastion. GET chain. Verify 2 hops: bastion first, target second.
5. `Circular bastion chain returns 400` — Host A bastion → Host B, Host B bastion → Host A. GET chain → 400 "Circular bastion chain detected".

**Section 278: Multi-Hop Chain Validation API (4 tests)**

6. `Chain exceeding max hops returns 400` — Create 4-hop chain (default max 3). GET chain → 400.
7. `Chain with missing bastion returns 404` — Set `bastion_host_id` to non-existent host. GET chain → 404.
8. `Bastion list returns only bastion hosts` — Create 3 hosts (1 bastion, 2 regular). GET `/ui/remote/hosts?is_bastion=true`. Verify 1 result.
9. `Clear bastion_host_id` — PATCH host with `bastion_host_id: ""`. GET chain. Verify 1 hop (direct).

**Section 279: Bastion Host UI (3 tests)**

10. `Host edit dialog shows bastion toggle` — Open edit dialog. Verify "This is a bastion/jump host" checkbox visible.
11. `Bastion selector dropdown shows bastion hosts` — Mark host as bastion. Open edit dialog for another host. Verify bastion appears in "Connect via bastion" dropdown.
12. `Host list shows bastion badge` — Mark host as bastion. Navigate to `/remote/hosts`. Verify "Bastion" badge on host row.

**Test Setup**:

```typescript
let bastionHost: any;
let targetHost: any;

test.beforeAll(async ({ browser }) => {
  sessions["alice"] = await getOrCreateSession("alice");
  alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");

  // Create bastion and target hosts
  bastionHost = await apiPost(alicePage, "alice", "/ui/remote/hosts", {
    label: `bastion-${TS}`, hostname: "10.0.0.1", port: 22, protocol: "ssh",
  });
  await apiPatch(alicePage, "alice", `/ui/remote/hosts/${bastionHost.host_id}`, {
    is_bastion: true,
  });

  targetHost = await apiPost(alicePage, "alice", "/ui/remote/hosts", {
    label: `target-${TS}`, hostname: "172.16.0.5", port: 22, protocol: "ssh",
  });
});
```

---

## 6. Security Considerations

### 6.1 Credential Isolation per Hop

Each hop in the chain uses its own SSH key from INFRA-002. The bastion key does not grant access to the target, and vice versa.

### 6.2 Channel Forwarding Security

Paramiko's `direct-tcpip` channel forwarding is point-to-point. The bastion opens a channel to exactly the target host:port specified. No arbitrary forwarding is allowed.

### 6.3 Maximum Hop Limit

`max_hops=3` prevents excessively long chains that could be used for network pivoting or resource exhaustion.

### 6.4 Circular Chain Detection

The `resolve_connection_chain()` function maintains a `visited` set and raises `ValueError` if a cycle is detected.

### 6.5 Audit Trail

Each hop in a multi-hop connection is audit-logged: `ssh.connect_hop` with hop number, bastion host, and target host. This creates a complete record of the network path traversed.

---

## 7. Acceptance Criteria

1. Hosts can be marked as bastions via `is_bastion: true`.
2. Hosts can reference a bastion via `bastion_host_id`.
3. Connection chains are resolved correctly (1-3 hops).
4. Circular chains are detected and rejected.
5. Multi-hop SSH connections work via Paramiko channel forwarding.
6. Each hop uses its own SSH key from INFRA-002.
7. Frontend shows bastion badges and "via" labels in host inventory.
8. Host edit dialog includes bastion toggle and bastion selector.
9. Connection status shows per-hop progress.
10. All multi-hop connections produce per-hop audit events.

---

## 8. Architecture & Data Flow

```
  User clicks "Connect" on a host with bastion_host_id
       │
       ▼
  Frontend: WebSocket connect { host_id: "target-host-id" }
       │
       ▼
  WebSocket handler (browser_ssh_terminal.py)
       │
       ├── resolve_connection_chain(user_sub, host_id)
       │     │
       │     ├── get_host(user_sub, "target-host") → { bastion_host_id: "bastion-1" }
       │     ├── get_host(user_sub, "bastion-1") → { bastion_host_id: "" } (direct)
       │     │
       │     ├── Cycle detection: visited = {"target-host", "bastion-1"} ✓
       │     ├── Hop count: 2 <= max_hops(3) ✓
       │     │
       │     └── Returns chain: [
       │           { hostname: "10.0.0.1", port: 22, key_id: "bastion-key" },  # hop 1
       │           { hostname: "172.16.0.5", port: 22, key_id: "target-key" },  # hop 2
       │         ]
       │
       ├── len(chain) > 1 → MultiHopSshBridge
       │     │
       │     ├── Hop 1: paramiko.Transport(("10.0.0.1", 22))
       │     │     └── connect(username, pkey=bastion_key)
       │     │
       │     ├── open_channel("direct-tcpip", dest=("172.16.0.5", 22))
       │     │     └── TCP forwarding through bastion transport
       │     │
       │     ├── Hop 2: paramiko.Transport(channel)
       │     │     └── connect(username, pkey=target_key)
       │     │
       │     └── open_session() + get_pty() + invoke_shell()
       │           └── Interactive terminal session on target host
       │
       └── audit_event per hop:
             ├── "ssh.connect_hop" { hop: 1, host: "bastion-1" }
             └── "ssh.connect_hop" { hop: 2, host: "target-host" }
```

---

## 9. Detailed DynamoDB Access Patterns

| # | Access Pattern | Table / GSI | PK | SK | Operation | Notes |
|---|---------------|-------------|----|----|-----------|-------|
| 1 | Get host with bastion fields | `remote_hosts` | `user_sub` | `HOST#{host_id}` | GetItem | Returns is_bastion, bastion_host_id |
| 2 | Update host bastion fields | `remote_hosts` | `user_sub` | `HOST#{host_id}` | UpdateItem SET is_bastion, bastion_host_id | User-initiated |
| 3 | List bastion hosts only | `remote_hosts` | `user_sub` | begins_with `HOST#` | Query + FilterExpression `is_bastion = :true` | For dropdown selector |
| 4 | Resolve chain (recursive) | `remote_hosts` | `user_sub` | `HOST#{host_id}` | GetItem (1 per hop) | Up to 3 GetItems for max_hops=3 |
| 5 | Get connection profile per hop | `connection_profiles` | `user_sub` | `PROFILE#{host_id}` | GetItem | SSH key + auth method per hop |
| 6 | Get SSH key per hop | `ssh_keys` | `user_sub` | `KEY#{key_id}` | GetItem | Decrypted private key for auth |
| 7 | Audit log per hop | `audit_log` | `user_sub` | `{timestamp}#{event_id}` | PutItem | One per hop in chain |

---

## 10. API Request/Response Examples

**PATCH /ui/remote/hosts/{id}** (Mark as bastion)

```bash
curl -X PATCH http://localhost:8000/ui/remote/hosts/h-bastion-1 \
  -H "Content-Type: application/json" \
  -H "Cookie: ui_session=sess_xxx; ui_csrf=csrf_xxx; ui_access_token=jwt_xxx" \
  -H "x-csrf-token: csrf_xxx" \
  -d '{ "is_bastion": true }'
```

Response (200):
```json
{
  "host_id": "h-bastion-1",
  "label": "Production Bastion",
  "hostname": "10.0.0.1",
  "port": 22,
  "is_bastion": true,
  "bastion_host_id": ""
}
```

**PATCH /ui/remote/hosts/{id}** (Set bastion for target)

```json
// Request
{ "bastion_host_id": "h-bastion-1" }

// Response (200)
{
  "host_id": "h-target-1",
  "label": "App Server",
  "hostname": "172.16.0.5",
  "port": 22,
  "is_bastion": false,
  "bastion_host_id": "h-bastion-1"
}
```

**GET /ui/remote/hosts/{id}/connection-chain**

```bash
curl http://localhost:8000/ui/remote/hosts/h-target-1/connection-chain \
  -H "Cookie: ui_session=sess_xxx; ui_access_token=jwt_xxx"
```

Response (200):
```json
{
  "chain": [
    {
      "host_id": "h-bastion-1",
      "hostname": "10.0.0.1",
      "port": 22,
      "username": "ubuntu",
      "ssh_key_id": "key-bastion",
      "auth_method": "key_ref",
      "is_bastion": true,
      "hop_number": 1
    },
    {
      "host_id": "h-target-1",
      "hostname": "172.16.0.5",
      "port": 22,
      "username": "ubuntu",
      "ssh_key_id": "key-target",
      "auth_method": "key_ref",
      "is_bastion": false,
      "hop_number": 2
    }
  ],
  "total_hops": 2
}
```

**Circular chain error:**

Response (400):
```json
{ "detail": "Circular bastion chain detected" }
```

**Chain exceeding max hops:**

Response (400):
```json
{ "detail": "Connection chain exceeds maximum 3 hops" }
```

---

## 11. Error Handling Matrix

| Scenario | HTTP Status | Error Code | User-Facing Message | Recovery Action |
|----------|-------------|------------|---------------------|-----------------|
| Host not found | 404 | `host_not_found` | "Host not found" | Verify host ID |
| Bastion host not found | 404 | `bastion_not_found` | "Bastion host not found" | Check bastion_host_id |
| Circular bastion chain | 400 | `circular_chain` | "Circular bastion chain detected" | Remove the circular reference |
| Chain exceeds max hops | 400 | `max_hops_exceeded` | "Connection chain exceeds 3 hops" | Reduce chain depth |
| Missing SSH key for hop | 400 | `missing_credentials` | "No SSH key configured for hop" | Add SSH key via INFRA-002 |
| Bastion unreachable | 502 | `connection_failed` | "Could not connect to bastion host" | Check bastion connectivity |
| Target unreachable via bastion | 502 | `channel_failed` | "Could not reach target through bastion" | Verify target is reachable from bastion |
| Self-referencing bastion | 400 | `circular_chain` | "Host cannot be its own bastion" | Set a different bastion |
| Other user's host | 403 | `forbidden` | "Access denied" | Use your own hosts |
| Unauthenticated | 401 | `unauthorized` | "Authentication required" | Log in |

---

## 12. Frontend Component Tree

```
HostInventoryPage (modified)
├── HostTable
│   └── HostRow[]
│       ├── HostLabel
│       ├── Hostname
│       ├── BastionBadge (shown if is_bastion=true, blue "Bastion" badge)
│       ├── ViaLabel ("via Production Bastion" if bastion_host_id set)
│       ├── ConnectButton
│       │   └── onClick → resolve chain, validate all hops have keys, connect
│       └── EditButton → opens AddHostDialog
│
AddHostDialog (modified)
├── ExistingFields (label, hostname, port, protocol, etc.)
├── BastionSection
│   ├── IsBastionCheckbox ("This is a bastion/jump host")
│   └── BastionSelectorDropdown ("Connect via bastion")
│       ├── OptionList (hosts where is_bastion=true)
│       └── ClearOption ("Direct connection — no bastion")
├── ConnectionChainPreview (shown when bastion selected)
│   └── ChainVisualization
│       ├── PlatformNode ("Platform")
│       ├── Arrow ("→")
│       ├── BastionNode ("Bastion (10.0.0.1)")
│       ├── Arrow ("→")
│       └── TargetNode ("Target (172.16.0.5)")
└── SaveButton

SSH Terminal (modified connection status)
├── ConnectionProgress
│   ├── HopStatus("Connecting to bastion...", spinner)
│   ├── HopStatus("Connected to bastion ✓")
│   ├── HopStatus("Connecting to target...", spinner)
│   └── HopStatus("Connected to target ✓")
└── TerminalView (existing)
```

**Props interfaces:**

```typescript
interface BastionBadgeProps {
  isBastion: boolean;
}

interface ViaLabelProps {
  bastionLabel: string;
}

interface BastionSelectorProps {
  value: string;           // bastion_host_id or ""
  onChange: (hostId: string) => void;
  bastionHosts: HostOut[];
  excludeHostId: string;   // can't select self
}

interface ConnectionChainPreviewProps {
  chain: ConnectionChainHop[];
}

interface HopStatusProps {
  hopNumber: number;
  hostLabel: string;
  status: "connecting" | "connected" | "failed";
}
```

---

## 13. Observability

### 13.1 Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `ssh_multihop_connections_total` | Counter | `hops` (1/2/3), `result` (success/failed) | Multi-hop connection attempts |
| `ssh_hop_latency_seconds` | Histogram | `hop_number` | Time to establish each hop |
| `ssh_chain_resolution_total` | Counter | `result` (ok/circular/max_hops/missing) | Chain resolution attempts |
| `ssh_bastion_hosts_total` | Gauge | | Total bastion hosts configured |
| `ssh_channel_forwarding_total` | Counter | | Paramiko direct-tcpip channels opened |

### 13.2 Structured Logging

| Log Event | Level | Fields | Trigger |
|-----------|-------|--------|---------|
| `ssh.chain_resolved` | INFO | `user_sub`, `target_host_id`, `hops`, `chain` | Chain successfully resolved |
| `ssh.chain_circular` | WARN | `user_sub`, `visited_hosts` | Circular chain detected |
| `ssh.hop_connected` | INFO | `user_sub`, `hop_number`, `hostname`, `duration_ms` | Individual hop connected |
| `ssh.hop_failed` | ERROR | `user_sub`, `hop_number`, `hostname`, `error` | Individual hop failed |
| `ssh.multihop_session_started` | INFO | `user_sub`, `total_hops`, `target_host_id` | Full session established |

### 13.3 Alerting

| Alert | Condition | Severity | Action |
|-------|-----------|----------|--------|
| High multi-hop failure rate | > 20% of multi-hop connections fail in 1 hour | Warning | Check bastion health |
| Circular chain detected | Any circular chain resolution | Info | Notify user to fix config |

---

## 14. Performance Considerations

### 14.1 Latency Targets

| Operation | Target P95 | Notes |
|-----------|-----------|-------|
| Chain resolution | < 100ms | 1-3 DDB GetItems (parallel where possible) |
| Bastion list query | < 100ms | DDB Query + FilterExpression |
| Single hop connection (dev mock) | < 50ms | No real TCP connection |
| Single hop connection (production) | < 5s | TCP + SSH handshake |
| Full 3-hop connection (production) | < 15s | Sequential hops |

### 14.2 Connection Lifecycle

- Each hop maintains an open Paramiko Transport for the duration of the session.
- Channel forwarding adds ~5ms latency per hop for data throughput (negligible for interactive SSH).
- `MultiHopSshBridge.close()` tears down in reverse order to prevent orphaned channels.

### 14.3 Resource Cleanup

- On WebSocket disconnect, all transports and channels are closed in reverse order.
- A 30-second grace period prevents premature cleanup on brief network blips.
- If cleanup fails, transports have built-in TCP keepalive that will close after timeout.

---

## 15. Rollout Plan

### 15.1 Feature Flags

| Flag | Environment Variable | Default | Description |
|------|---------------------|---------|-------------|
| `multihop_ssh_enabled` | `MULTIHOP_SSH_ENABLED` | `true` | Master switch for multi-hop |
| `max_ssh_hops` | `MAX_SSH_HOPS` | `3` | Maximum hops in a chain |

### 15.2 Phased Rollout

**Phase 1 (Day 1)**: Host inventory extension (is_bastion, bastion_host_id fields).

**Phase 2 (Day 2)**: Chain resolution service with cycle detection and hop limits.

**Phase 3 (Day 3-4)**: MultiHopSshBridge class + WebSocket handler integration.

**Phase 4 (Day 5)**: Frontend bastion toggle, selector, chain preview.

**Phase 5 (Day 6-7)**: E2E tests, production rollout.

### 15.3 Rollback

1. Set `MULTIHOP_SSH_ENABLED=false` — WebSocket handler ignores `host_id` and falls back to direct connect.
2. Bastion fields remain on host records but are unused.
3. Frontend hides bastion selector when flag is off.

---

## 16. Expanded E2E Tests

### Section 277: Bastion Host Configuration API (5 tests) -- existing

1-5. (As defined above in Section 5)

### Section 278: Multi-Hop Chain Validation API (4 tests) -- existing

6-9. (As defined above in Section 5)

### Section 279: Bastion Host UI (3 tests) -- existing

10-12. (As defined above in Section 5)

### Section 280: Chain Resolution Edge Cases (7 tests)

13. `3-hop chain resolves correctly` -- Create A → B → C chain (3 hops). GET chain for C. Verify 3 hops in correct order.
14. `Self-referencing bastion returns 400` -- Set host's bastion_host_id to itself. GET chain → 400.
15. `Chain with non-existent intermediate bastion returns 404` -- Host A bastion → "non-existent-id". GET chain → 404.
16. `Clear bastion_host_id makes host direct-connect` -- PATCH bastion_host_id="". GET chain. Verify 1 hop.
17. `Bastion list endpoint returns only bastions` -- Create 3 hosts (1 bastion, 2 regular). GET hosts with `?is_bastion=true`. Verify 1 result.
18. `Chain resolution includes connection profile data` -- Set connection profile on each hop. GET chain. Verify `ssh_key_id` and `username` populated on each hop.
19. `Multiple hosts can reference same bastion` -- Host B and Host C both use bastion A. GET chain for B → 2 hops. GET chain for C → 2 hops. Both have same first hop.

### Section 281: Multi-User Isolation & Security (5 tests)

20. `Alice cannot resolve chain for Bob's host` -- Bob creates host. Alice GET chain for Bob's host → 403 or 404.
21. `Alice cannot modify Bob's host bastion field` -- PATCH Bob's host → 403.
22. `Bastion selector only shows user's own bastion hosts` -- Alice marks host as bastion. Bob's bastion list does not include Alice's host.
23. `Connection audit records include all hops` -- Connect via 2-hop chain. Query audit log. Verify 2 `ssh.connect_hop` events.
24. `Each hop in chain uses different SSH key` -- Configure different keys for bastion and target. Verify chain resolution returns correct key_id per hop.
