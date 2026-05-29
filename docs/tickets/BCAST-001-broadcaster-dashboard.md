# BCAST-001: Broadcaster Dashboard Page (Create/Manage Sessions)

## 1. Overview & Motivation

### Problem Statement

Broadcasters need a dedicated UI to manage their live-streaming infrastructure without
resorting to direct API calls or the dev-tools panel. The backend broadcast API is fully
implemented (`app/routers/broadcast.py`) and supports the complete lifecycle: creating
encoding profiles, creating sessions tied to those profiles, starting/stopping sessions
via an orchestration layer, monitoring status transitions, viewing RTMP ingest URLs, and
minting playback URLs. However, there is currently **zero frontend code** referencing
broadcast endpoints -- the only UI is the admin-gated dev-tools page at
`/broadcast-devtools` which is limited to ingest health checks.

<!-- NOTE: This claim is NOW OUTDATED. Extensive frontend broadcast code exists:
  - `frontend/src/pages/broadcast/BroadcastPage.tsx` (main broadcast page, 20+ components)
  - `frontend/src/api/endpoints/broadcast.ts` and 7 other broadcast endpoint files
  - Route at `App.tsx:56,166`: `/broadcast` gated by `isBroadcastNavigationEnabled()`
  - Components: BroadcastChat, LivePlayer, TipGoalBar, ProductShelf, QA panels, etc.
-->

### User Stories

1. **As a broadcaster**, I want to create an encoding profile (name, region, rendition
   preset, optional watermark/DRM) so my sessions share consistent settings.
2. **As a broadcaster**, I want to create a new session linked to a profile and receive an
   RTMP ingest URL + stream key reference so I can configure OBS/Wirecast.
3. **As a broadcaster**, I want to see all my sessions with their real-time status
   (draft, provisioning, ready, live, stopping, stopped, error) so I know what is running.
4. **As a broadcaster (admin/root)**, I want to start/stop/delete sessions from the UI,
   with confirmation dialogs, so I can control my streams safely.
5. **As a broadcaster**, I want to mint a playback URL for an active session so I can
   share it with viewers or embed it in another page.
6. **As an admin**, I want to view the audit log of broadcast actions to trace who
   started/stopped which session and when.

### Key Data the UI Must Display

| Field | Source | Notes |
|-------|--------|-------|
| Session ID | `BroadcastSessionOut.id` | UUID |
| Status | `BroadcastSessionOut.status` | One of: `draft`, `provisioning`, `ready`, `live`, `stopping`, `stopped`, `error` |
| Ingest URL | `BroadcastSessionOut.ingest_url` | RTMP URL, copyable |
| Stream Key Ref | `BroadcastSessionOut.stream_key_ref` | Secret manager ARN, show masked |
| Playback URL | `BroadcastPlaybackUrlOut.playback_url` | Minted on demand |
| CloudFront URL | `BroadcastSessionOut.cloudfront_playback_url` | If provisioned |
| Started At / Stopped At | `BroadcastSessionOut.started_at/stopped_at` | ISO timestamps |
| Profile Name | `BroadcastProfileOut.name` | From linked profile |
| Region | `BroadcastProfileOut.region` | e.g. `us-east-1` |
| Rendition Preset | `BroadcastProfileOut.rendition_preset` | e.g. `720p_3mbps` |

---

## 2. Current State Analysis

### Backend API Endpoints (all registered at `/broadcast/*`)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/broadcast/profiles` | `require_ui_session` | Create encoding profile |
| POST | `/broadcast/sessions` | `require_ui_session` | Create session (status=draft) |
| GET | `/broadcast/sessions/{id}` | `require_ui_session` | Get session + output details |
| POST | `/broadcast/sessions/{id}/start` | admin/root | Start session (draft -> provisioning -> ready -> live) |
| POST | `/broadcast/sessions/{id}/stop` | admin/root | Stop session (live -> stopping -> stopped) |
| DELETE | `/broadcast/sessions/{id}` | admin/root | Delete session |
| POST | `/broadcast/sessions/{id}/playback-url` | `require_ui_session` | Mint signed playback URL |
| GET | `/broadcast/admin/audit` | admin/root | Query audit log |
| GET | `/broadcast/playback/verify` | `require_ui_session` | Verify CloudFront token |

**Note**: There is no explicit `GET /broadcast/sessions` (list all) endpoint. The store
layer has `list_sessions_by_status` and `list_sessions_by_creator` functions, but these are
not exposed via the router. The implementation plan includes adding a list endpoint (or the
frontend can poll individual sessions by ID stored in local state until a list endpoint is
added).

<!-- NOTE: This claim is NOW OUTDATED. `GET /broadcast/sessions` exists at `app/routers/broadcast.py:286` (response_model=BroadcastSessionListOut). The endpoint is implemented and calls the store functions. Additionally, `GET /broadcast/sessions/scheduled` exists at line 300. -->

### State Machine (`app/services/broadcast_state_machine.py`)

```
draft -> provisioning -> ready -> live -> stopping -> stopped
  |          |             |        |         |
  v          v             v        v         v
error      error         error    error     error
                                              |
                                              v
                                         provisioning (retry)
```

Allowed transitions:
- `draft` -> `provisioning`, `error`
- `provisioning` -> `ready`, `error`
- `ready` -> `live`, `stopping`, `error`
- `live` -> `stopping`, `error`
- `stopping` -> `stopped`, `error`
- `stopped` -> (terminal)
- `error` -> `provisioning` (retry), `stopped` (abandon)

### Frontend Patterns for Similar Pages

**ProjectsPage** (`frontend/src/pages/projects/ProjectsPage.tsx`):
- Uses `PageHeader` with `actions` slot for "New project" button
- `useQuery` with key `["projects", "list"]` for data fetching
- `useMutation` with `onSuccess` -> `queryClient.invalidateQueries` + `toast.success`
- `Dialog` component for create form
- Grid layout of `Card` components for list items
- `EmptyState` component when no items exist
- Loading/error states with `Loader2` spinner

**TicketsPage** (`frontend/src/pages/tickets/TicketsPage.tsx`):
- Polling via `setInterval` every 15 seconds for real-time status
- Status badges with `Badge` component
- Admin summary cards in a grid
- Master-detail layout (list on left, detail on right)
- Status filter dropdowns
- Mutations for state transitions (assign, mark done, reopen)

**CalendarPage** (`frontend/src/pages/calendar/CalendarPage.tsx`):
- Tabs-based layout for multiple sub-views
- `Tabs`, `TabsList`, `TabsTrigger`, `TabsContent` from shadcn/ui

### Relevant shadcn/ui Components Available

`alert-dialog.tsx`, `badge.tsx`, `button.tsx`, `card.tsx`, `dialog.tsx`,
`dropdown-menu.tsx`, `input.tsx`, `label.tsx`, `select.tsx`, `separator.tsx`,
`skeleton.tsx`, `switch.tsx`, `table.tsx`, `tabs.tsx`, `textarea.tsx`, `tooltip.tsx`

### API Client Pattern

All endpoint wrappers use the `api` function from `frontend/src/api/client.ts`:
```typescript
import { api } from "@/api/client";

// GET with typed response
export const listSessions = () => api.get<SessionListResponse>("/broadcast/sessions");

// POST with body
export const createProfile = (body: CreateProfileReq) =>
  api.post<BroadcastProfileOut>("/broadcast/profiles", body);
```

The client automatically attaches Bearer token, CSRF token, handles 401 refresh, and
provides typed error handling via `ApiError`.

---

## 3. Technical Design

### 3.1 Page Layout (Wireframe)

```
+------------------------------------------------------------------+
| PageHeader: "Broadcaster"  [+ New Session] [+ New Profile]       |
| "Manage broadcast profiles, sessions, and live streams"          |
+------------------------------------------------------------------+
| Tabs: [Sessions] [Profiles] [Audit Log]                          |
+------------------------------------------------------------------+
| TAB: Sessions                                                     |
| +-------------------------------------------------------------+  |
| | Filter: [Status v] [Refresh]                     [Auto: 10s]|  |
| +-------------------------------------------------------------+  |
| | Session Cards Grid (2 cols on desktop)                       |  |
| | +---------------------------+ +---------------------------+  |  |
| | | Card: Session abc123      | | Card: Session def456      |  |  |
| | | Status: [LIVE] badge      | | Status: [DRAFT] badge     |  |  |
| | | Profile: "Main Encoder"   | | Profile: "Backup"         |  |  |
| | | Region: us-east-1         | | Region: eu-west-1         |  |  |
| | | Started: 2026-05-24 14:00 | | Created: 2026-05-24 12:00 |  |  |
| | | [View Details] [Stop]     | | [View Details] [Start]    |  |  |
| | +---------------------------+ +---------------------------+  |  |
| +-------------------------------------------------------------+  |
+------------------------------------------------------------------+
| TAB: Profiles                                                     |
| +-------------------------------------------------------------+  |
| | Profile Cards Grid                                           |  |
| | +---------------------------+ +---------------------------+  |  |
| | | Name: "Main Encoder"     | | Name: "Backup"            |  |  |
| | | Region: us-east-1         | | Region: eu-west-1         |  |  |
| | | Preset: 1080p_6mbps       | | Preset: 720p_3mbps        |  |  |
| | | Watermark: yes            | | DRM: BuyDRM               |  |  |
| | +---------------------------+ +---------------------------+  |  |
| +-------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### 3.2 Session Detail Dialog

When "View Details" is clicked, a full-width `Dialog` opens:

```
+------------------------------------------------------------------+
| Dialog: Session abc123                                [X]         |
+------------------------------------------------------------------+
| Status: [LIVE]    Profile: Main Encoder    Region: us-east-1     |
| Created: 2026-05-24 12:00    Started: 2026-05-24 14:00          |
+------------------------------------------------------------------+
| Ingest Configuration                                              |
| RTMP URL: rtmp://ingest.example.com/live/abc123      [Copy]      |
| Stream Key: arn:aws:secretsmanager:...               [Copy]      |
| Key Rotation: every 86400s (last: 2026-05-24 10:00)             |
+------------------------------------------------------------------+
| Playback                                                          |
| CloudFront URL: https://d1234.cloudfront.net/abc.m3u8 [Copy]    |
| [Mint New Playback URL]  -> expires_at shown after minting       |
+------------------------------------------------------------------+
| AWS Resources                                                     |
| Input ARN: arn:aws:medialive:...                                 |
| Channel ARN: arn:aws:medialive:...                               |
| MediaPackage: https://...mediapackage.../v1/...                  |
| S3 Archive: s3://bucket/broadcast/abc123/                        |
+------------------------------------------------------------------+
| Actions                                                           |
| [Start Session] [Stop Session] [Delete Session]                  |
+------------------------------------------------------------------+
```

### 3.3 Component Hierarchy

```
BroadcasterPage (route: /broadcaster)
├── PageHeader (title="Broadcaster", actions=[New Session, New Profile])
├── Tabs
│   ├── TabContent: Sessions
│   │   ├── SessionFilterBar
│   │   │   ├── Select (status filter)
│   │   │   ├── Button (refresh)
│   │   │   └── Badge (auto-poll indicator)
│   │   ├── SessionCardGrid
│   │   │   └── SessionCard[] (Card + Badge + action buttons)
│   │   └── EmptyState (when no sessions)
│   ├── TabContent: Profiles
│   │   ├── ProfileCardGrid
│   │   │   └── ProfileCard[] (Card with profile info)
│   │   └── EmptyState (when no profiles)
│   └── TabContent: Audit Log (admin only)
│       └── AuditTable (Table component with audit entries)
├── CreateSessionDialog (Dialog with form)
├── CreateProfileDialog (Dialog with form)
└── SessionDetailDialog (Dialog with full session info + actions)
```

### 3.4 React Query Hooks

```typescript
// Query keys
const QUERY_KEYS = {
  sessions: (status?: string) => ["broadcast", "sessions", { status }] as const,
  session: (id: string) => ["broadcast", "sessions", id] as const,
  profiles: () => ["broadcast", "profiles"] as const,
  audit: (params?: AuditParams) => ["broadcast", "audit", params] as const,
  playbackUrl: (sessionId: string) => ["broadcast", "playback-url", sessionId] as const,
};

// Sessions list (poll every 10s)
const sessionsQuery = useQuery({
  queryKey: QUERY_KEYS.sessions(statusFilter),
  queryFn: () => listSessions({ status: statusFilter }),
  refetchInterval: 10_000,  // auto-poll for status updates
  refetchIntervalInBackground: false,
});

// Single session detail
const sessionDetailQuery = useQuery({
  queryKey: QUERY_KEYS.session(selectedSessionId),
  queryFn: () => getSession(selectedSessionId),
  enabled: !!selectedSessionId,
  refetchInterval: selectedSessionId ? 5_000 : false,  // faster poll when viewing detail
});

// Profiles list (less dynamic, longer stale time)
const profilesQuery = useQuery({
  queryKey: QUERY_KEYS.profiles(),
  queryFn: () => listProfiles(),
  staleTime: 60_000,
});

// Mutations
const startMutation = useMutation({
  mutationFn: (id: string) => startSession(id, { reason: "operator-request" }),
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ["broadcast", "sessions"] });
    toast.success("Session starting...");
  },
  onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to start"),
});
```

### 3.5 State Management

Local component state (no Zustand store needed):
- `statusFilter: string` -- filter sessions by status
- `selectedSessionId: string | null` -- which session detail dialog is open
- `createSessionOpen: boolean` -- create session dialog visibility
- `createProfileOpen: boolean` -- create profile dialog visibility
- `confirmAction: { type: "start"|"stop"|"delete", sessionId: string } | null` -- confirmation dialog

### 3.6 Real-Time Status Updates via Polling

The broadcast system does not use SSE/WebSocket for status changes. Instead:

1. **Session list**: `refetchInterval: 10_000` (10 seconds) -- catches status transitions
   like `provisioning -> ready` or `live -> stopping -> stopped`.
2. **Session detail dialog**: `refetchInterval: 5_000` (5 seconds) -- faster polling when
   the operator is actively watching a session start/stop.
3. **Conditional polling**: Only poll when the tab is visible
   (`refetchIntervalInBackground: false`).
4. **Visual indicators**: Show a pulsing dot next to "live" status, a spinner next to
   transitional states (`provisioning`, `stopping`).

### 3.7 Status Badge Color Mapping

```typescript
const STATUS_COLORS: Record<BroadcastSessionStatus, string> = {
  draft: "bg-gray-100 text-gray-700",
  provisioning: "bg-yellow-100 text-yellow-800",
  ready: "bg-blue-100 text-blue-800",
  live: "bg-green-100 text-green-800",
  stopping: "bg-orange-100 text-orange-800",
  stopped: "bg-gray-100 text-gray-600",
  error: "bg-red-100 text-red-800",
};
```

---

## 4. Implementation Plan

### 4.1 New Files to Create
<!-- NOTE: Many of these files ALREADY EXIST under different paths:
  - `frontend/src/api/endpoints/broadcast.ts` EXISTS (+ 7 other broadcast endpoint files)
  - `frontend/src/pages/broadcast/BroadcastPage.tsx` EXISTS (NOT `pages/broadcaster/`)
  - The route is at `/broadcast` not `/broadcaster` (App.tsx:166)
  - Over 20 broadcast UI components already exist in `frontend/src/pages/broadcast/`
  Ticket uses `pages/broadcaster/` but actual codebase uses `pages/broadcast/`.
-->

| File | Purpose | Status |
|------|---------|--------|
| `frontend/src/api/endpoints/broadcast.ts` | API endpoint wrappers | **ALREADY EXISTS** |
| `frontend/src/pages/broadcaster/BroadcasterPage.tsx` | Main page component | **EXISTS** as `pages/broadcast/BroadcastPage.tsx` |
| `frontend/src/pages/broadcaster/SessionCard.tsx` | Session card in grid | Check if exists in BroadcastPage |
| `frontend/src/pages/broadcaster/SessionDetailDialog.tsx` | Full session detail | Check if exists in BroadcastPage |
| `frontend/src/pages/broadcaster/CreateSessionDialog.tsx` | Create session form | Check if exists in BroadcastPage |
| `frontend/src/pages/broadcaster/CreateProfileDialog.tsx` | Create profile form | Check if exists in BroadcastPage |
| `frontend/src/pages/broadcaster/ProfileCard.tsx` | Profile card in grid | Check if exists in BroadcastPage |
| `frontend/src/pages/broadcaster/AuditLog.tsx` | Audit log table (admin) | Check if exists in BroadcastPage |
| `frontend/src/pages/broadcaster/constants.ts` | Status colors, labels | Check if exists in BroadcastPage |
| `frontend/e2e/broadcaster.spec.ts` | E2E test suite | Verify |

### 4.2 API Endpoint Wrappers (`frontend/src/api/endpoints/broadcast.ts`)

```typescript
import { api } from "@/api/client";

// ─── Types ─────────────────���────────────────────────────────────

export type BroadcastSessionStatus =
  | "draft" | "provisioning" | "ready" | "live" | "stopping" | "stopped" | "error";

export interface BroadcastProfile {
  id: string;
  name: string;
  region: string;
  rendition_preset: string;
  watermark_asset: string | null;
  drm_policy_id: string | null;
  drm_credentials_ref: string | null;
  drm_credentials_last_rotated_at: string | null;
  drm_credentials_rotation_interval_seconds: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface BroadcastSession {
  id: string;
  profile_id: string;
  status: BroadcastSessionStatus;
  ingest_url: string | null;
  stream_key_ref: string | null;
  stream_key_last_rotated_at: string | null;
  stream_key_rotation_interval_seconds: number;
  started_at: string | null;
  stopped_at: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
  mediapackage_endpoint: string | null;
  cloudfront_playback_url: string | null;
  s3_archive_prefix: string | null;
  aws_input_arn: string | null;
  aws_channel_arn: string | null;
  provider_state_snapshot: Record<string, unknown>;
}

export interface BroadcastPlaybackUrl {
  session_id: string;
  playback_url: string;
  expires_at: number;
}

export interface BroadcastAuditEntry {
  audit_id: string;
  action: string;
  actor: string;
  correlation_id: string;
  resource_type: string;
  resource_id: string;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface CreateProfileReq {
  name: string;
  region: string;
  rendition_preset: string;
  watermark_asset?: string | null;
  drm_policy_id?: string | null;
  drm_credentials_ref?: string | null;
  drm_credentials_rotation_interval_seconds?: number;
}

export interface CreateSessionReq {
  profile_id: string;
  ingest_url?: string | null;
  stream_key_ref?: string | null;
  stream_key_rotation_interval_seconds?: number;
}

export interface SessionActionReq {
  reason?: string;
}

// ─── API functions ──────────────────────────────────────────────

export const createProfile = (body: CreateProfileReq) =>
  api.post<BroadcastProfile>("/broadcast/profiles", body);

export const createSession = (body: CreateSessionReq) =>
  api.post<BroadcastSession>("/broadcast/sessions", body);

export const getSession = (id: string) =>
  api.get<BroadcastSession>(`/broadcast/sessions/${id}`);

export const startSession = (id: string, body?: SessionActionReq) =>
  api.post<BroadcastSession>(`/broadcast/sessions/${id}/start`, body ?? { reason: "operator-request" });

export const stopSession = (id: string, body?: SessionActionReq) =>
  api.post<BroadcastSession>(`/broadcast/sessions/${id}/stop`, body ?? { reason: "operator-request" });

export const deleteSession = (id: string) =>
  api.del<{ ok: boolean }>(`/broadcast/sessions/${id}`);

export const mintPlaybackUrl = (id: string) =>
  api.post<BroadcastPlaybackUrl>(`/broadcast/sessions/${id}/playback-url`);

export const getAuditLog = (params?: { actor?: string; limit?: number }) =>
  api.get<{ items: BroadcastAuditEntry[] }>("/broadcast/admin/audit", params as Record<string, string>);
```

### 4.3 Backend: Add List Sessions Endpoint

The broadcast router currently lacks a `GET /broadcast/sessions` list endpoint. The store
has `list_sessions_by_status` and `list_sessions_by_creator` ready. Add to
`app/routers/broadcast.py`:

```python
from app.services.broadcast_store import list_sessions_by_creator, list_sessions_by_status

class BroadcastSessionListOut(BaseModel):
    items: List[BroadcastSessionOut] = Field(default_factory=list)
    has_more: bool = False

@router.get("/sessions", response_model=BroadcastSessionListOut)
def list_sessions_route(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: dict = Depends(_ctx),
):
    if status:
        result = list_sessions_by_status(status, limit=limit)
    else:
        result = list_sessions_by_creator(ctx["user_sub"], limit=limit)
    items = [_to_session_out(s) for s in result["items"]]
    return BroadcastSessionListOut(items=items, has_more=bool(result.get("cursor")))
```

Similarly, add a `GET /broadcast/profiles` list endpoint using the profiles table scan.

### 4.4 Vite Proxy Configuration

The Vite dev server proxy does NOT currently proxy `/broadcast` to the backend. Add to
`frontend/vite.config.ts`:
<!-- NOTE: This is NOW OUTDATED. The `/broadcast` proxy ALREADY EXISTS in vite.config.ts at line 73. -->

```typescript
proxy: {
  // ... existing entries ...
  "/broadcast": "http://localhost:8000",
}
```

This is required because the broadcast endpoints do not use the `/ui` or `/api` prefixes
that are already proxied.

### 4.5 Route Registration (`frontend/src/App.tsx`)
<!-- NOTE: This route ALREADY EXISTS at App.tsx:56,166 as:
  `const BroadcastPage = lazy(() => import("@/pages/broadcast/BroadcastPage"));`
  `<Route path="broadcast" element={<BroadcastPage />} />`
  Route is `/broadcast` not `/broadcaster`, gated by `isBroadcastNavigationEnabled()`.
-->

```typescript
// Add lazy import
const BroadcasterPage = lazy(() => import("@/pages/broadcaster/BroadcasterPage"));

// Add route inside ProtectedRoute/AppShell
<Route path="broadcaster" element={<BroadcasterPage />} />
```

### 4.6 Sidebar Entry (`frontend/src/components/layout/Sidebar.tsx`)

Add to the "Productivity" group (or create a new "Media" group):

```typescript
import { Radio } from "lucide-react";  // broadcast tower icon

// In NAV_GROUPS, Productivity items array:
{ label: "Broadcaster", path: "/broadcaster", icon: <Radio className="h-5 w-5" /> },
```

Also add to `MobileNav.tsx` MORE_LINKS:
```typescript
{ label: "Broadcaster", path: "/broadcaster", icon: Radio },
```

And to `AppShell.tsx` MobileSidebar NAV_ITEMS.

### 4.7 Implementation Order

1. **Phase 1 -- Backend list endpoint** (1 hour)
   - Add `GET /broadcast/sessions` and `GET /broadcast/profiles` to the router
   - Add unit tests in `tests/test_broadcast_store.py`

2. **Phase 2 -- Frontend API + types** (30 min)
   - Create `frontend/src/api/endpoints/broadcast.ts`
   - Add Vite proxy entry

3. **Phase 3 -- Page skeleton + routing** (1 hour)
   - Create `BroadcasterPage.tsx` with Tabs layout
   - Register route in `App.tsx`
   - Add sidebar/mobile nav entries

4. **Phase 4 -- Sessions tab** (2 hours)
   - `SessionCard.tsx` with status badges, timestamps, action buttons
   - `SessionDetailDialog.tsx` with full info + RTMP URL copy + playback mint
   - `CreateSessionDialog.tsx` with profile selector + ingest URL input
   - Polling integration (10s list, 5s detail)

5. **Phase 5 -- Profiles tab** (1 hour)
   - `ProfileCard.tsx` with region, preset, DRM info
   - `CreateProfileDialog.tsx` with all fields

6. **Phase 6 -- Audit tab** (1 hour)
   - `AuditLog.tsx` with `Table` component, actor filter, date range
   - Admin-only gating

7. **Phase 7 -- Polish** (1 hour)
   - Confirmation dialogs for destructive actions (stop, delete)
   - Copy-to-clipboard for RTMP URL and stream key
   - Skeleton loading states
   - Error retry buttons
   - Responsive grid (1 col mobile, 2 col desktop)

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_broadcast_dashboard.py`

**Mock setup**: moto mock for DynamoDB (`BroadcastProfiles`, `BroadcastSessions`, `BroadcastOutputs` tables). Mock broadcast provider returns instant transitions.

| Test Function | Description |
|---|---|
| `test_list_sessions_returns_creator_sessions` | List sessions filtered by creator; returns only owned sessions |
| `test_create_session_with_profile_link` | Create session linked to profile; status = draft |
| `test_get_session_returns_full_details` | Get session by ID; includes ingest_url, stream_key_ref, status |
| `test_list_profiles_returns_all` | List all profiles for creator; includes region, preset, DRM fields |
| `test_create_profile_validation` | Missing name/region/preset returns 422 |
| `test_delete_session_requires_admin` | Non-admin delete returns 403 |
| `test_audit_log_records_actions` | Create+start+stop; audit log has all 3 entries |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Create profile -> create session -> start -> verify status transitions through DDB
2. List sessions with status filter returns only matching sessions
3. Audit log query returns entries with correct actor and action fields
4. Playback URL minting returns valid signed URL with future expires_at

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/broadcaster.spec.ts`

**Auth pattern**: `injectAuth(page, "root")` for admin/root operations; CSRF header for POST/DELETE

| # | Test Name | Assertion |
|---|---|---|
| 1 | Create profile with all fields | POST returns 200 with profile ID; profile appears in GET list |
| 2 | Create session linked to profile | POST returns session with status='draft' and ingest_url |
| 3 | Get session by ID returns details | Response includes id, status, ingest_url, stream_key_ref |
| 4 | List sessions returns created session | GET `/broadcast/sessions` includes test session |
| 5 | Start session transitions status | POST `.../start`; status transitions to 'live' |
| 6 | Stop session transitions to stopped | POST `.../stop`; status = 'stopped'; stopped_at set |
| 7 | Delete session removes it | DELETE returns 200; subsequent GET returns 404 |
| 8 | Mint playback URL returns signed URL | Response has playback_url and future expires_at |
| 9 | Audit log records all actions | GET `/broadcast/admin/audit` returns create/start/stop entries |
| 10 | Page loads with Sessions tab | Navigate to `/broadcast`; 'Sessions' tab heading visible |
| 11 | Session card shows status badge | Card displays status badge with correct color |
| 12 | Profile tab shows profile cards | Switch to Profiles tab; profile name and region visible |
| 13 | Invalid transition returns 409 | Attempt start on stopped session -> 409 |
| 14 | Non-admin start returns 403 | Alice (USER) attempts start -> 403 |

**Negative tests**: 409 invalid state transition, 403 non-admin start/stop/delete, 404 non-existent session, 422 missing required fields

**Edge cases**: Concurrent start requests (idempotency), polling during transition states, empty session list

### Test Data Requirements

Seed broadcast profile + session via API in `beforeAll`. Use unique `Date.now()` suffixed names to avoid cross-run conflicts.

**Test users**: Root (ROOT, start/stop/delete), Alice (USER, create profile/session), Charlie (ADMIN, audit access)

### CI/Pipeline

Serial execution (shared broadcast state). `BROADCAST_PROVIDER=local` for instant transitions. Retry-safe (idempotent create with unique names).

---

## Dependencies & Merge Safety

### Depends On

No upstream dependencies. This ticket is self-contained.

### Depended On By

| Ticket | What It Needs |
|---|---|
| BCAST-002 | Broadcast session and playback URL endpoints for viewer player |
| BCAST-007 | Sidebar navigation routes to `/broadcast` |
| BCAST-009 | Session scheduling uses session CRUD endpoints |

### Merge Strategy

Independent. Frontend page at `/broadcast` (already exists), backend endpoints already registered. No new DDB tables needed.

### Merge Checklist

- [ ] Broadcast endpoint files exist in `frontend/src/api/endpoints/broadcast*.ts`
- [ ] Route `/broadcast` registered in `App.tsx` with lazy import
- [ ] Sidebar entry present in `Sidebar.tsx` and `MobileNav.tsx`
- [ ] Vite proxy for `/broadcast` configured in `vite.config.ts`
- [ ] E2E test `broadcaster.spec.ts` passes in CI
- [ ] No breaking changes to existing broadcast API

---

## Codebase References

| File | Line(s) | Status | Notes |
|------|---------|--------|-------|
| `app/routers/broadcast.py` | 265-505+ | EXISTS | All broadcast endpoints including `GET /sessions` at line 286 |
| `app/models_broadcast.py` | — | EXISTS | Pydantic models for broadcast |
| `app/services/broadcast_store.py` | 394, 414 | EXISTS | `list_sessions_by_status`, `list_sessions_by_creator` |
| `app/services/broadcast_state_machine.py` | — | EXISTS | Status transition validation |
| `app/services/broadcast_orchestrator.py` | — | EXISTS | Start/stop with provider integration |
| `app/services/broadcast_playback.py` | — | EXISTS | Playback URL minting |
| `app/services/broadcast_audit.py` | — | EXISTS | Audit log query/record |
| `app/services/broadcast_cloudfront.py` | — | EXISTS | CloudFront token validation |
| `app/routers/broadcast_devtools.py` | — | EXISTS | Dev-only debug endpoint |
| `frontend/src/api/endpoints/broadcast.ts` | — | **ALREADY EXISTS** | Plus 7 more broadcast endpoint files |
| `frontend/src/pages/broadcast/BroadcastPage.tsx` | — | **ALREADY EXISTS** | Main broadcast page (NOT `pages/broadcaster/`) |
| `frontend/src/pages/broadcast/` | — | **ALREADY EXISTS** | 20+ component files (Chat, LivePlayer, Tips, QA, etc.) |
| `frontend/src/App.tsx` | 56, 166 | **ALREADY EXISTS** | Route at `/broadcast` gated by feature flag |
| `frontend/vite.config.ts` | 73 | **ALREADY EXISTS** | `/broadcast` proxy to backend |
| `app/main.py` | 396-398 | EXISTS | `broadcast_router`, `broadcast_clips_router`, `broadcast_devtools_router` registered |
| `scripts/local-ddb-init.py` | 513-578 | EXISTS | BroadcastProfiles, BroadcastSessions, BroadcastOutputs, etc. tables |
| `app/core/settings.py` | 452-453 | EXISTS | `broadcast_profiles_table_name`, `broadcast_sessions_table_name` |
| `app/core/tables.py` | 39-43 | EXISTS | Broadcast table handles |

### Key Discrepancies
- Ticket says "zero frontend code" but broadcast frontend is fully built (20+ components, 8 endpoint files)
- Ticket says "no list endpoint" but `GET /broadcast/sessions` exists at `broadcast.py:286`
- Ticket uses path `pages/broadcaster/` but codebase uses `pages/broadcast/`
- Ticket proposes route `/broadcaster` but codebase uses `/broadcast`
- Vite proxy for `/broadcast` already exists
