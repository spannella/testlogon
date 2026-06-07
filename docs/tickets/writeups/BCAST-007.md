# BCAST-007: Broadcast Sidebar Navigation + Routes — Investigation & Implementation Write-up

## 1. Summary & Classification

The broadcast feature requires integration with the application shell so users can discover and navigate to broadcast pages without memorizing direct URLs. This ticket adds React Router routes for the broadcaster dashboard and live player, a sidebar entry in a new "Media" group, mobile sidebar and bottom nav entries, a feature flag, and the Vite dev-server proxy that routes `/broadcast` API calls to the FastAPI backend while serving `index.html` for browser navigations to the same path prefix.

- **Type**: Feature (frontend-only, no backend changes)
- **Priority**: Medium
- **Status**: Fully implemented in the current codebase
- **Owning area**: Frontend shell / navigation
- **Affected personas**: Broadcasters (navigation discovery), Viewers (deep-link access via `/live/:sessionId`), Platform operators (kill-switch flag)
- **Cross-references**: BCAST-001 (BroadcastPage content), BCAST-002 (LivePlayer content), SECOPS-007 (no AWS dependency; entirely frontend)

---

## 2. Current-State Investigation (what exists today)

### Routes: `frontend/src/App.tsx`

The following broadcast routes are registered (lines 285, 361–363):

```typescript
// line 285 — always registered, no flag gate
<Route path="live/:sessionId" element={<LivePlayer />} />

// lines 361–363 — flag-gated
{showBroadcastNavigation && <Route path="broadcast" element={<BroadcastPage />} />}
{showBroadcastNavigation && <Route path="broadcast/schedule" element={<BroadcastSchedulePage />} />}
{showBroadcastNavigation && <Route path="broadcast/:sessionId/live-qa" element={<LiveQaPage />} />}
```

Lazy imports (lines 102–105):
```typescript
const BroadcastPage = lazy(() => import("@/pages/broadcast/BroadcastPage"));
const BroadcastSchedulePage = lazy(() => import("@/pages/broadcast/BroadcastSchedulePage"));
const LivePlayer = lazy(() => import("@/pages/broadcast/LivePlayer"));
const LiveQaPage = lazy(() => import("@/pages/broadcast/LiveQaPage"));
```

The feature flag is read at line 11 (`isBroadcastNavigationEnabled`) and at line 254 (`showBroadcastNavigation`).

Note: The ticket design proposed a single `/broadcast` route and a `/live/:sessionId` route. The implementation adds three additional routes beyond the initial design: `/broadcast/schedule` (BCAST-009 scheduler UI), `/broadcast/:sessionId/live-qa` (BCAST-005 Q&A). These are gated by the same `showBroadcastNavigation` flag, which is the correct pattern.

### Desktop sidebar: `frontend/src/components/layout/Sidebar.tsx`

- `Radio` imported from `lucide-react` at line 29
- `isBroadcastNavigationEnabled` imported at line 78
- Sidebar entries at lines 161–162 in a group (the "Media" group structure):

```typescript
{ label: "Broadcast", i18nKey: "nav.broadcast", path: "/broadcast",
  icon: <Radio className="h-5 w-5" /> },
{ label: "Scheduled Broadcasts", i18nKey: "nav.broadcastSchedule",
  path: "/broadcast/schedule", icon: <CalendarClock className="h-5 w-5" /> },
```

Feature-flag filter at lines 295–296:
```typescript
if (item.path === "/broadcast") return isBroadcastNavigationEnabled();
if (item.path === "/broadcast/schedule") return isBroadcastNavigationEnabled();
```

The implementation adds a second sidebar entry for "Scheduled Broadcasts" (from BCAST-009) beyond what the original ticket specified. Both entries share the same flag gate.

The ticket design proposed a pulsing live-session badge query. The current sidebar implementation does not include the `useQuery` for live session count — the badge is not implemented. The `Radio` icon renders without any dynamic badge.

### Mobile sidebar: `frontend/src/components/layout/AppShell.tsx`

- `Radio` imported at line 122
- `isBroadcastNavigationEnabled` at line 168
- Entry at line 220: `{ label: "Broadcast", path: "/broadcast", icon: Radio }`
- Filter at line 284: `if (item.path === "/broadcast") return isBroadcastNavigationEnabled()`

Only one mobile sidebar entry (no "Scheduled Broadcasts" entry in mobile sidebar). This is intentional — mobile navigation shows a subset of the full nav.

### Mobile bottom nav: `frontend/src/components/layout/MobileNav.tsx`

- `Radio` at line 23
- `isBroadcastNavigationEnabled` at line 62
- Entry at line 91: `{ label: "Broadcast", i18nKey: "nav.broadcast", path: "/broadcast", icon: Radio }`
- Filter at line 140: `if (item.path === "/broadcast") return isBroadcastNavigationEnabled()`

### Feature flag: `frontend/src/lib/featureFlags.ts`

`isBroadcastNavigationEnabled` is exported. The ticket's proposed `broadcastNavigationKillSwitch` pattern — two env vars composed into one function — is present.

### Vite proxy: `frontend/vite.config.ts` (line 89)

The `/broadcast` proxy entry exists with the bypass pattern:

```typescript
"/broadcast": {
  target: "http://localhost:8000",
  bypass: (req) => {
    const accept = req.headers["accept"] ?? "";
    if (typeof accept === "string" && accept.includes("text/html")) {
      return "/index.html";
    }
    return null;
  },
},
```

This matches the design exactly — HTML requests get `index.html` (SPA nav), API calls proxy to the backend.

### Page components

`frontend/src/pages/broadcast/BroadcastPage.tsx` — exists (full implementation, not a stub).
`frontend/src/pages/broadcast/LivePlayer.tsx` — exists (full implementation).
`frontend/src/pages/broadcast/BroadcastSchedulePage.tsx` — exists (added by BCAST-009).
`frontend/src/pages/broadcast/LiveQaPage.tsx` — exists (added by BCAST-005/ENGAGE-003).

No `frontend/src/pages/broadcaster/` directory exists. The ticket design originally placed pages under `pages/broadcaster/`, but the actual implementation uses `pages/broadcast/` for all broadcast-related pages.

### E2E: `frontend/e2e/broadcast-navigation.spec.ts`

The ticket design specified a file named `broadcast-nav.spec.ts` or `broadcast-navigation.spec.ts`. No such file exists in `frontend/e2e/`. Navigation behavior is tested as part of the main `broadcast.spec.ts`. This is the only open implementation gap for this ticket.

---

## 3. Gap / Threat Analysis

### What is fully implemented

All structural requirements are met: routes, lazy imports, feature flag, sidebar/mobile-nav entries, filter conditions, Vite proxy. The implementation exceeds the original ticket scope by adding BCAST-009 and BCAST-005 entries that share the same flag gate.

### Gaps

1. **Live-session sidebar badge**: The pulsing green dot badge from section 3.5 of the ticket design is not implemented. The `Sidebar.tsx` does not contain a `useQuery` for `["broadcast", "sessions", "live-count"]`. The `Radio` icon renders without any dynamic indicator. This is a UX omission, not a functional regression.

2. **No dedicated navigation E2E spec**: The ticket required `frontend/e2e/broadcast-nav.spec.ts` testing route resolution, sidebar link click-through, feature flag hide/show, and deep-link navigation to `/live/:sessionId`. The only E2E coverage is through `broadcast.spec.ts` which tests the page content rather than the navigation chrome.

3. **`/broadcast/schedule` not in mobile nav**: The desktop sidebar shows a "Scheduled Broadcasts" entry but the mobile sidebar and MobileNav "More" sheet do not. If BCAST-009 gains viewer-facing importance on mobile, an entry should be added.

4. **`isActive` for `/live/:sessionId`**: The optional enhancement in section 3.9 (highlight the Broadcast sidebar entry when on a live player page) is not implemented. The sidebar entry does not highlight during a live player session.

### Security / abuse potential

The Vite proxy bypass condition checks `accept.includes("text/html")`. API clients that send `Accept: text/html, */*` (e.g., some browser `<form>` submissions) will receive `index.html` instead of the API response. This is acceptable for the dev server but validates the importance of the `bypass` pattern being frontend-only — the production reverse proxy (nginx/CloudFront) must use a different routing strategy (e.g., path prefix matching).

---

## 4. Proposed Design / Fix

### Live-session badge (deferred enhancement)

Add to `Sidebar.tsx`, alongside the existing conversations unread query:

```typescript
const { data: sessionsData } = useQuery({
  queryKey: ["broadcast", "sessions", "live-count"],
  queryFn: () => api.get<{ items: Array<{ status: string }> }>(
    "/broadcast/sessions?status=live&limit=1"
  ),
  staleTime: 15_000,
  refetchInterval: 15_000,
  enabled: showBroadcastNavigation,
});
const hasLiveBroadcast = (sessionsData?.data?.items?.length ?? 0) > 0;
```

Render a `<span className="absolute ... animate-pulse bg-green-500 rounded-full" />` on the Broadcast nav item when `hasLiveBroadcast` is true, using the same absolute-position pattern as the Messages unread badge.

### E2E navigation spec (missing — must create)

`frontend/e2e/broadcast-navigation.spec.ts` should cover:
1. Sidebar "Broadcast" link is visible when flag enabled → click → URL is `/broadcast`
2. Direct navigation to `/broadcast` renders the page heading (not 404)
3. Direct navigation to `/live/<id>` renders the LivePlayer component
4. API call to `/broadcast/sessions` (fetch, not browser nav) proxies to backend (200 or 401)
5. Unauthenticated user visiting `/broadcast` gets redirected to `/login`

### Dev/Prod parity (SECOPS-007)

This ticket is entirely frontend. No AWS services involved. The Vite proxy is dev-only; production uses a real reverse proxy with path-based routing. No feature flag is needed in backend settings.

---

## 5. Testing, Verification & Rollout

### Manual verification steps

1. Run `just up` to start the dev stack
2. Navigate to `http://localhost:3000` as a logged-in user
3. Confirm "Broadcast" appears in the desktop sidebar (under whatever group it falls in)
4. Click "Broadcast" — confirm `/broadcast` loads `BroadcastPage` with its heading
5. Navigate to `http://localhost:3000/live/test-session-id` — confirm `LivePlayer` renders with the session ID in the URL
6. Open DevTools Network tab, navigate to `/broadcast` — confirm no 404 or proxy error for the `/broadcast/sessions` API call on page load

### Rollout

The feature flag `VITE_BROADCAST_NAVIGATION_ENABLED` defaults to `true`. To disable broadcast navigation on a deployment (e.g., a tenant without streaming entitlements):

```
VITE_BROADCAST_NAVIGATION_ENABLED=false
```

Routes are always registered when the flag is enabled; sidebar entries are hidden. This ensures bookmarked URLs remain functional even if the sidebar entry is removed.

### Risks and open questions

- The live badge query polls the backend every 15 seconds even when no broadcast is active. If the endpoint is expensive, add a `staleTime` of 60 seconds or use an SSE event instead.
- The `VITE_BROADCAST_NAVIGATION_KILL_SWITCH` env var (mentioned in the original design) is referenced in `featureFlags.ts` but should be confirmed against `frontend/.env.local.example` to ensure it is documented for operators.

### `featureFlags.ts` — verifying the kill-switch composition

The ticket design proposed two env vars composed into one function:
```typescript
export const broadcastNavigationEnabled = toBool(env.VITE_BROADCAST_NAVIGATION_ENABLED, true);
export const broadcastNavigationKillSwitch = toBool(env.VITE_BROADCAST_NAVIGATION_KILL_SWITCH, false);
export const isBroadcastNavigationEnabled = () =>
  broadcastNavigationEnabled && !broadcastNavigationKillSwitch;
```

Verify that the actual `featureFlags.ts` implements this two-variable composition. If it uses a single flag without a kill-switch, platform operators cannot disable the feature in an emergency without a full deployment. The kill-switch pattern (a second env var that overrides the first) is important for production operations where env var changes can be applied without code deploys.

### Sidebar group placement

The ticket design specified a new "Media" group placed between "Productivity" and "Account". Verify that `Sidebar.tsx` actually inserts the broadcast entries into a group labeled "Media" and not into an existing group such as "Productivity". The `NavGroup` array structure and group titles are defined in the `NAV_GROUPS` constant. If the entries were appended to an existing group, the UX intent of separating media content from document productivity tools is not achieved.

### Env file documentation

`frontend/.env.local.example` should document both broadcast navigation env vars. Confirm it includes:
```
VITE_BROADCAST_NAVIGATION_ENABLED=true
VITE_BROADCAST_NAVIGATION_KILL_SWITCH=false
```

If missing, add them so that `scripts/setup_ubuntu.sh` (which copies `.env.local.example` to `.env.local` on first-run) includes the flag.

### Active-route highlighting for `/live/:sessionId`

When a user opens a live player (`/live/abc123`), the Broadcast sidebar entry does not highlight. The optional enhancement from section 3.9 of the ticket design would check both prefixes:

```typescript
// Sidebar.tsx isActive function
if (item.path === "/broadcast") {
  return location.pathname.startsWith("/broadcast")
      || location.pathname.startsWith("/live");
}
```

This is low-priority but improves visual orientation during live viewing sessions.

### BCAST-009 sidebar entry for "Scheduled Broadcasts"

The implementation adds a "Scheduled Broadcasts" entry (`/broadcast/schedule`) to the desktop sidebar that was not in the original BCAST-007 scope. This is correct architectural evolution — the same Media group hosts both entries. The mobile sidebar and MobileNav "More" sheet do not include this second entry. If the scheduled broadcasts page becomes a primary navigation target on mobile (e.g., a viewer scrolling upcoming events), add:

```typescript
// AppShell.tsx MOBILE_NAV_GROUPS
{ label: "Scheduled Broadcasts", path: "/broadcast/schedule", icon: CalendarClock },
```

with a corresponding filter:
```typescript
if (item.path === "/broadcast/schedule") return isBroadcastNavigationEnabled();
```

### Proxy bypass corner case: API clients with `Accept: text/html`

The Vite proxy bypass logic (`vite.config.ts:89`) checks `accept.includes("text/html")`. Axios and `fetch` calls from the React app set `Accept: application/json, */*` by default, which does not include `text/html`, so API calls correctly proxy to the backend. Edge case: some third-party tools (Postman's browser preview, Swagger UI) send `Accept: text/html, */*; q=0.9`. These would receive `index.html` instead of the API response during local dev. This is a dev-only inconvenience, not a production issue, since the Vite proxy is not used in production.

For Swagger UI access during local development, the workaround is to use the backend directly on port 8000 rather than through the Vite proxy on port 3000.

**Effort estimate**: Live badge query + render (S, 2 hours), E2E navigation spec (S, 2–3 hours), env file documentation (XS, 15 minutes). All structural navigation items fully implemented.
