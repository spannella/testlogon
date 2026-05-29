# INFRA-010: SSH Session Recording & Playback

**Status**: Proposed  
**Author**: Engineering  
**Date**: 2026-05-29  
**Priority**: Medium  
**Estimated effort**: 6-8 days  
**Dependencies**: INFRA-001 (Host Inventory)

---

## 1. Overview & Motivation

### The Gap

The SSH terminal (`app/routers/browser_ssh_terminal.py`, 1,126 lines) provides a fully functional browser-based SSH bridge via WebSocket. However, no record of terminal sessions is kept. Once the WebSocket closes:

1. All terminal output is lost — there is no recording or transcript
2. There is no way to review what commands were executed in past sessions
3. Compliance teams cannot audit SSH activity
4. Users cannot replay sessions for training, debugging, or documentation
5. Admins have no visibility into what users are doing on managed infrastructure

The platform already has S3 storage via moto (`app/core/dev_s3.py`) for file uploads and media, and a file manager service (`app/services/filemanager.py`). Session recordings can be stored as files in S3 using the asciicast format (compatible with the asciinema player), which is a simple JSON-based format for terminal recordings.

### Why This Matters

1. **Compliance**: Many industries (finance, healthcare, government) require audit trails for all privileged access to compute resources.
2. **Debugging**: "What did I run that broke the server?" — session recordings answer this.
3. **Knowledge sharing**: Recordings can be shared with teammates to demonstrate procedures.
4. **Security monitoring**: Admins can review suspicious activity (INFRA-012).
5. **Training**: New team members can watch experienced engineers' sessions.

### Architecture After This Change

```
SSH Session Recording Flow

  WebSocket connect (browser_ssh_terminal.py)
       |
       | If host.record_sessions == true:
       v
  +-------------------+
  | SessionRecorder   |  In-memory buffer of asciicast events
  | (per connection)  |  [timestamp, "o", "output data"]
  +-------------------+
       |
       | On WebSocket close:
       v
  +-------------------+
  | Upload to S3      |  Key: ssh-recordings/{user_sub}/{recording_id}.cast
  | (.cast file)      |
  +-------------------+
       |
       v
  +-------------------+
  | ssh_recordings     |  PK=user_sub, SK=RECORDING#{recording_id}
  | DDB metadata      |  GSIs: ByHost, ByCreatedAt
  +-------------------+
       |
       +---> RecordingsPage (list, search, filter, playback)
       |     Embedded asciinema-player for .cast file playback
       |
       +---> Admin access (INFRA-012):
             Admin can view any user's recordings with audit trail
```

---

## 2. Current State Analysis

### 2.1 SSH Terminal WebSocket Flow (`app/routers/browser_ssh_terminal.py`)

The WebSocket handler processes three client message types:
- `connect`: Establishes SSH connection via Paramiko
- `input`: Sends keystrokes to the SSH channel
- `resize`: Resizes the terminal

Server sends:
- `output`: Terminal output data from the SSH channel
- `status`: Connection status updates
- `error`: Error messages

The `ParamikoSshBridge` class (line ~65) has a `_read_loop()` thread that reads from the SSH channel and buffers output. The WebSocket handler forwards this output to the browser.

**Recording hook point**: The `output` messages in the WebSocket handler are the data source for recordings. Each `output` payload contains terminal data that should be captured with a timestamp.

### 2.2 S3 Storage (`app/core/dev_s3.py`, `app/services/filemanager.py`)

- S3 mock runs via moto in-process (started at FastAPI startup)
- File uploads use `boto3.client("s3").put_object()` or `upload_fileobj()`
- Presigned URLs for downloads: `s3.generate_presigned_url("get_object", ...)`
- Bucket name from settings: `S.s3_bucket`

### 2.3 Asciicast Format (v2)

The asciicast v2 format is a newline-delimited JSON file:

```jsonl
{"version": 2, "width": 80, "height": 24, "timestamp": 1700000000}
[0.0, "o", "$ "]
[0.5, "o", "ls -la\r\n"]
[0.8, "o", "total 42\r\n-rw-r--r-- 1 user user 1234 Nov 14 app.py\r\n"]
[1.2, "i", "exit\r"]
```

- First line: header with version, terminal dimensions, Unix timestamp
- Subsequent lines: `[elapsed_seconds, event_type, data]`
- `"o"` = output (server → client), `"i"` = input (client → server)
- Files use `.cast` extension

### 2.4 Host Inventory (INFRA-001)

The `remote_hosts` table can store a `record_sessions: bool` field per host, controlling whether sessions to that host are recorded.

---

## 3. Technical Design

### 3.1 DynamoDB Table: `ssh_recordings`

```python
# scripts/local-ddb-init.py
TableDef(
    _resolve_table_name(S.ssh_recordings_table_name, "ssh_recordings"),
    "user_sub",            # PK — session owner
    "sk",                  # SK — RECORDING#{recording_id}
    gsis=[
        {"index_name": "ByHost", "partition_key": "user_sub", "sort_key": "host_key"},
        {"index_name": "ByCreatedAt", "partition_key": "user_sub", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Item schema**:

| Field | Type | Description |
|-------|------|-------------|
| `user_sub` | S (PK) | Session owner |
| `sk` | S (SK) | `RECORDING#{recording_id}` |
| `recording_id` | S | UUID |
| `session_id` | S | WebSocket session ID (correlation) |
| `host_id` | S | Host from INFRA-001 (if known) |
| `hostname` | S | Target hostname |
| `port` | N | Target port |
| `username` | S | SSH username |
| `host_key` | S | `{hostname}:{port}` for GSI sort |
| `start_time` | N | Unix timestamp of session start |
| `end_time` | N | Unix timestamp of session end |
| `duration_seconds` | N | Session duration |
| `file_size_bytes` | N | Size of .cast file |
| `s3_key` | S | S3 object key for the .cast file |
| `created_at` | N | Unix timestamp |
| `terminal_cols` | N | Terminal columns at session start |
| `terminal_rows` | N | Terminal rows at session start |
| `event_count` | N | Number of output events recorded |
| `retention_days` | N | Auto-delete after N days (default: 90) |
| `expires_at` | N | Unix timestamp for auto-deletion |

### 3.2 Session Recorder: `app/services/ssh_recorder.py`

New file (~200 lines):

```python
"""SSH session recording — captures terminal output in asciicast v2 format."""

from __future__ import annotations
import io
import json
import time
import uuid
from typing import Any, Dict, List, Optional

import boto3
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


class SessionRecorder:
    """Captures SSH terminal events in asciicast v2 format.
    Instantiated per WebSocket connection. Collects events in memory,
    then uploads to S3 on close."""

    def __init__(
        self,
        *,
        user_sub: str,
        hostname: str,
        port: int,
        username: str,
        cols: int,
        rows: int,
        host_id: str = "",
    ):
        self._user_sub = user_sub
        self._hostname = hostname
        self._port = port
        self._username = username
        self._cols = cols
        self._rows = rows
        self._host_id = host_id
        self._recording_id = uuid.uuid4().hex
        self._session_id = uuid.uuid4().hex
        self._start_time = time.time()
        self._events: List[str] = []
        self._event_count = 0

        # Write header
        header = {
            "version": 2,
            "width": cols,
            "height": rows,
            "timestamp": int(self._start_time),
            "env": {"TERM": "xterm-256color"},
            "title": f"SSH session to {hostname}:{port} as {username}",
        }
        self._events.append(json.dumps(header, separators=(",", ":")))

    def record_output(self, data: str) -> None:
        """Record an output event (server → client terminal data)."""
        elapsed = time.time() - self._start_time
        event = json.dumps([round(elapsed, 6), "o", data], separators=(",", ":"))
        self._events.append(event)
        self._event_count += 1

    def record_input(self, data: str) -> None:
        """Record an input event (client → server keystrokes)."""
        elapsed = time.time() - self._start_time
        event = json.dumps([round(elapsed, 6), "i", data], separators=(",", ":"))
        self._events.append(event)

    def finalize(self) -> Dict[str, Any]:
        """Upload recording to S3 and write metadata to DDB.
        Called when the WebSocket session closes."""
        end_time = time.time()
        duration = end_time - self._start_time

        # Build .cast file content
        cast_content = "\n".join(self._events) + "\n"
        cast_bytes = cast_content.encode("utf-8")

        # Upload to S3
        s3_key = f"ssh-recordings/{self._user_sub}/{self._recording_id}.cast"
        s3 = boto3.client("s3", endpoint_url=S.s3_endpoint_url if S.dev_mode else None,
                          region_name=S.aws_region)
        s3.put_object(
            Bucket=S.s3_bucket,
            Key=s3_key,
            Body=cast_bytes,
            ContentType="application/x-asciicast",
        )

        # Write metadata to DDB
        now = now_ts()
        item = {
            "user_sub": self._user_sub,
            "sk": f"RECORDING#{self._recording_id}",
            "recording_id": self._recording_id,
            "session_id": self._session_id,
            "host_id": self._host_id,
            "hostname": self._hostname,
            "port": self._port,
            "username": self._username,
            "host_key": f"{self._hostname}:{self._port}",
            "start_time": int(self._start_time),
            "end_time": int(end_time),
            "duration_seconds": int(duration),
            "file_size_bytes": len(cast_bytes),
            "s3_key": s3_key,
            "created_at": now,
            "terminal_cols": self._cols,
            "terminal_rows": self._rows,
            "event_count": self._event_count,
            "retention_days": 90,
            "expires_at": now + (90 * 86400),
        }
        T.ssh_recordings.put_item(Item=item)
        return item
```

### 3.3 SSH Terminal Integration

Modify `app/routers/browser_ssh_terminal.py` to hook the recorder into the WebSocket flow:

```python
# In the WebSocket handler, after successful SSH connect:
recorder = None
if _should_record(user_sub, hostname, port, host_id):
    from app.services.ssh_recorder import SessionRecorder
    recorder = SessionRecorder(
        user_sub=user_sub, hostname=hostname, port=port,
        username=username, cols=cols, rows=rows, host_id=host_id,
    )

# In the output forwarding loop:
if msg_type == "output":
    if recorder:
        recorder.record_output(payload["data"])
    await websocket.send_json({"type": "output", "payload": payload})

# In the input handling:
if msg_type == "input":
    if recorder:
        recorder.record_input(payload["data"])
    bridge.send(payload["data"])

# On WebSocket close:
try:
    if recorder:
        recording = recorder.finalize()
        logger.info("Recording saved: %s (%d events, %d bytes)",
                    recording["recording_id"], recording["event_count"],
                    recording["file_size_bytes"])
except Exception:
    logger.exception("Failed to finalize recording")
```

### 3.4 Recording Decision

```python
def _should_record(user_sub: str, hostname: str, port: int, host_id: str) -> bool:
    """Determine if this SSH session should be recorded."""
    if not S.ssh_recording_enabled:
        return False
    if host_id:
        # Check host's record_sessions flag (INFRA-001)
        host = get_host(user_sub, host_id)
        if host and host.get("record_sessions"):
            return True
    # Default: check global setting
    return S.ssh_recording_default_enabled
```

### 3.5 API Router: `app/routers/ssh_recordings.py`

New file (~150 lines). Prefix: `/ui/remote/recordings`.

| Method | Path | Request | Response | Description |
|--------|------|---------|----------|-------------|
| `GET` | `/ui/remote/recordings` | query params | `RecordingListOut` | List recordings |
| `GET` | `/ui/remote/recordings/{id}` | — | `RecordingOut` | Get recording metadata |
| `GET` | `/ui/remote/recordings/{id}/stream` | — | `RecordingStreamOut` | Get presigned URL for .cast file |
| `DELETE` | `/ui/remote/recordings/{id}` | — | `{"ok": true}` | Delete recording |

#### Pydantic Models

```python
class RecordingOut(BaseModel):
    recording_id: str
    session_id: str
    host_id: str = ""
    hostname: str
    port: int
    username: str
    start_time: int
    end_time: int
    duration_seconds: int
    file_size_bytes: int
    terminal_cols: int
    terminal_rows: int
    event_count: int
    created_at: int
    retention_days: int

class RecordingListOut(BaseModel):
    recordings: List[RecordingOut]
    count: int
    cursor: Optional[str] = None

class RecordingStreamOut(BaseModel):
    recording_id: str
    stream_url: str     # S3 presigned URL (expires in 1 hour)
    content_type: str   # "application/x-asciicast"
    file_size_bytes: int
```

### 3.6 Playback Endpoint

```python
@router.get("/{recording_id}/stream")
async def get_recording_stream(recording_id: str, ctx=Depends(require_ui_session)):
    user_sub = ctx["user_sub"]
    rec = get_recording(user_sub, recording_id)
    if not rec:
        raise HTTPException(404, "Recording not found")

    s3 = boto3.client("s3", endpoint_url=S.s3_endpoint_url if S.dev_mode else None,
                      region_name=S.aws_region)
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": S.s3_bucket, "Key": rec["s3_key"]},
        ExpiresIn=3600,
    )
    return RecordingStreamOut(
        recording_id=recording_id,
        stream_url=url,
        content_type="application/x-asciicast",
        file_size_bytes=rec["file_size_bytes"],
    )
```

### 3.7 Admin Access

Admins can view any user's recordings via a separate endpoint (covered in INFRA-012):

```python
# In INFRA-012's admin router:
@router.get("/admin/recordings/{user_sub}")
async def admin_list_recordings(user_sub: str, ctx=Depends(require_admin_session)):
    audit_event(ctx["user_sub"], event="admin.view_recordings",
                outcome="success", details={"target_user": user_sub})
    return list_recordings(user_sub)
```

### 3.8 Retention Policy

A background task runs daily to delete expired recordings:

```python
async def run_recording_cleanup(*, poll_interval: int = 86400):
    """Daily: delete recordings where expires_at <= now."""
    while True:
        try:
            count = cleanup_expired_recordings()
            if count:
                logger.info("Cleaned up %d expired recordings", count)
        except Exception:
            logger.exception("Recording cleanup error")
        await asyncio.sleep(poll_interval)
```

### 3.9 Frontend Components

#### RecordingsPage (`frontend/src/pages/remote/RecordingsPage.tsx`)

New page (~350 lines):

- **Header**: "Session Recordings" title
- **Filter bar**: Host dropdown, date range picker, search by hostname
- **Recording list**: DataTable with columns: Host, Username, Started (relative), Duration, Size, Actions (Play, Delete)
- **Playback view**: Embedded asciinema-player component
  - Uses `@asciinema/player` npm package or iframe embed
  - Fetches .cast file via presigned URL from `/stream` endpoint
  - Controls: play/pause, speed (0.5x/1x/2x/4x), seek bar, fullscreen
  - Terminal dimensions match recorded `cols` x `rows`

#### AsciinemaPlayer (`frontend/src/components/shared/AsciinemaPlayer.tsx`)

Reusable player component (~80 lines):

```typescript
interface AsciinemaPlayerProps {
  src: string;       // Presigned URL to .cast file
  cols?: number;
  rows?: number;
  autoPlay?: boolean;
  speed?: number;
}
```

Uses the `asciinema-player` library or an iframe pointing to `asciinema.org/a/...` for static hosting. In dev mode, the presigned URL points to the moto S3 mock.

#### Route & Navigation

```tsx
<Route path="/remote/recordings" element={<RecordingsPage />} />
```

Sidebar: "Recordings" with `Video` icon under Infrastructure group.

---

## 4. Implementation Plan

### Phase 1: Backend Recorder (2-3 days)

| File | Change |
|------|--------|
| `app/core/settings.py` | Add `ssh_recordings_table_name`, `ssh_recording_enabled`, `ssh_recording_default_enabled` |
| `app/core/tables.py` | Add `ssh_recordings` table handle |
| `scripts/local-ddb-init.py` | Add `ssh_recordings` TableDef with 2 GSIs |
| `app/services/ssh_recorder.py` | New file: SessionRecorder class + finalize (S3 upload + DDB write) |
| `app/routers/browser_ssh_terminal.py` | Hook recorder into WebSocket output/input/close flow |

### Phase 2: API + Cleanup (1 day)

| File | Change |
|------|--------|
| `app/routers/ssh_recordings.py` | New file: 4 endpoints (list, get, stream, delete) |
| `app/models.py` | Add recording Pydantic models |
| `app/main.py` | Register router + recording cleanup background task |

### Phase 3: Host Recording Flag (0.5 days)

| File | Change |
|------|--------|
| `app/services/remote_hosts.py` | Add `record_sessions: bool` field to host schema |
| `app/models.py` | Add `record_sessions` to `HostOut` and `UpdateHostIn` |

### Phase 4: Frontend (2-3 days)

| File | Change |
|------|--------|
| `frontend/src/api/types.ts` | Add recording types |
| `frontend/src/api/endpoints/recordings.ts` | New file: API wrappers |
| `frontend/src/pages/remote/RecordingsPage.tsx` | New file: recording list + playback |
| `frontend/src/components/shared/AsciinemaPlayer.tsx` | New file: player component |
| `frontend/src/App.tsx` | Add `/remote/recordings` route |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Recordings" nav item |
| `package.json` | Add `asciinema-player` dependency |

### Phase 5: E2E Tests (1 day)

| File | Change |
|------|--------|
| `frontend/e2e/ssh-recordings.spec.ts` | New file: ~18 tests in 4 sections |

---

## 5. E2E Test Plan (`frontend/e2e/ssh-recordings.spec.ts`)

**Section 273: Recording Creation API (4 tests)**

1. `SSH session with record_sessions host creates recording` — Create host with `record_sessions: true`. Simulate SSH session (connect + send output + close via mock). GET `/recordings`. Verify 1 recording with hostname, duration > 0, `event_count > 0`.
2. `SSH session without record_sessions does not create recording` — Create host with `record_sessions: false`. Simulate session. GET `/recordings`. Verify no new recording.
3. `Recording metadata matches session params` — Verify `hostname`, `port`, `username`, `terminal_cols`, `terminal_rows`, `host_id` match the connection.
4. `Recording file size is non-zero` — Verify `file_size_bytes > 0`.

**Section 274: Recording Stream API (4 tests)**

5. `Stream endpoint returns presigned URL` — GET `/recordings/{id}/stream`. Verify `stream_url` is non-empty, `content_type: "application/x-asciicast"`.
6. `Presigned URL is accessible` — Fetch the `stream_url`. Verify 200 response with asciicast content (first line contains `"version": 2`).
7. `Stream for non-existent recording returns 404` — GET `/recordings/nonexistent/stream` → 404.
8. `Alice cannot stream Bob's recording` — Alice's recording, Bob tries GET `/stream` → 404.

**Section 275: Recording List & Delete API (5 tests)**

9. `List recordings returns all user recordings` — Create 3 recordings. GET list. Verify count=3.
10. `List sorted by created_at descending` — Verify most recent recording first.
11. `Filter by hostname` — Create recordings for different hosts. GET `?hostname=host1`. Verify only matching recordings.
12. `Delete recording removes from list and S3` — DELETE recording. GET list, verify removed. GET `/stream` → 404.
13. `Alice cannot delete Bob's recording` — Bob tries DELETE Alice's recording → 404.

**Section 276: Recordings UI (5 tests)**

14. `RecordingsPage renders recording list` — Navigate to `/remote/recordings`. Verify table headers: Host, Username, Started, Duration, Size.
15. `Play button opens player` — Click Play on a recording. Verify asciinema player component appears.
16. `Player loads .cast file` — Verify player shows terminal output (check for player container element).
17. `Delete recording removes from table` — Click Delete, confirm. Verify recording removed.
18. `Filter by host works` — Select host in filter dropdown. Verify only recordings for that host shown.

**Test Setup**:

Because the SSH WebSocket handler creates recordings during real SSH sessions, and we cannot establish real SSH connections in E2E tests, the test setup will:
1. Directly write mock recording metadata to DDB
2. Upload a sample .cast file to S3
3. Test the listing, streaming, and deletion APIs

```typescript
const SAMPLE_CAST = `{"version":2,"width":80,"height":24,"timestamp":1700000000}
[0.0,"o","$ "]
[0.5,"o","ls\\r\\n"]
[0.8,"o","file1.txt  file2.txt\\r\\n"]
[1.0,"o","$ "]`;

test.beforeAll(async ({ browser }) => {
  // Upload sample .cast file to S3 mock
  // Write recording metadata to DDB
});
```

---

## 6. Security Considerations

### 6.1 Recording Content Sensitivity

Recordings may capture sensitive data (passwords typed in terminals, secret keys, database credentials). The `.cast` files are stored encrypted at rest in S3 (S3 server-side encryption). Presigned URLs expire after 1 hour.

### 6.2 User Isolation

Recording records use `user_sub` as the DDB partition key. Users can only list, stream, and delete their own recordings. Admin access (INFRA-012) requires audit logging.

### 6.3 S3 Key Isolation

S3 keys include `user_sub` in the path: `ssh-recordings/{user_sub}/{recording_id}.cast`. This provides a secondary isolation layer even if DDB access controls fail.

### 6.4 Retention Policy

Default 90-day retention with automatic cleanup. This limits the exposure window for sensitive recording data.

---

## 7. Acceptance Criteria

1. SSH sessions to hosts with `record_sessions: true` produce .cast recordings.
2. Recordings are stored in S3 in asciicast v2 format.
3. Recording metadata is stored in DDB with all session details.
4. Stream endpoint provides time-limited presigned URLs for playback.
5. Recordings are user-isolated with admin override (INFRA-012).
6. Automatic retention cleanup deletes recordings after 90 days.
7. Frontend shows recording list with filter, search, and embedded playback.
8. Recording does not impact SSH session performance (events buffered in memory).
9. All recording access is audit-logged.
10. Host-level `record_sessions` flag controls recording per host.
