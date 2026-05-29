# UX-001: Dark Mode Backend Persistence

**Ticket**: UX-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-27
**Priority**: P3 (Nice to Have)
**Estimated effort**: 2-3 days

---

## 1. Executive Summary

The platform's dark mode preference is stored exclusively in the browser's localStorage via Zustand persist middleware. When a user switches to a new device or clears browser data, their theme preference resets to "system". This is a minor but noticeable friction point for users who work across multiple devices (phone, tablet, desktop).

Cross-device preference consistency is an established expectation in modern SaaS applications. Users who invest time personalizing their workspace -- selecting a dark theme, collapsing the sidebar, adjusting notification preferences -- expect those choices to follow them seamlessly. Currently, there is no backend persistence layer for any UI preference, which means every personalization decision is ephemeral and device-local. This creates a jarring experience when a user logs in on a new device and encounters the default "system" theme instead of their carefully chosen dark mode.

This feature adds a `PATCH /ui/settings/preferences` endpoint that persists UI preferences (starting with `theme`) to the user's DynamoDB profile record. On session initialization, the frontend loads the server-side preference and seeds the Zustand store, ensuring cross-device consistency. The localStorage store continues to serve as the fast read path and offline fallback. The architecture is intentionally extensible: the `ui_preferences` map attribute on the profile record can absorb future preference fields (notification density, locale, default landing page, etc.) without schema changes.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

**US-1: Cross-device theme consistency**
As a user who works on both desktop and mobile, I want my dark mode preference to follow me across devices so that I don't need to manually re-configure the theme every time I switch.

Acceptance Criteria:
- After setting dark mode on desktop, opening the app on mobile shows dark mode immediately after login.
- After setting light mode on mobile, refreshing desktop shows light mode.
- If no server-side preference exists (new user), the default is "system" (matching current behavior).
- The server round-trip does not introduce visible theme flicker on page load.

**US-2: Persistence across browser data resets**
As a user, I want my theme preference to survive browser cache clears and cookie deletions so that I don't lose my personalization.

Acceptance Criteria:
- After clearing localStorage, reloading the app restores the server-side theme within one render cycle.
- After clearing all site data (cookies + localStorage), re-logging in restores the theme.
- If the server is unreachable during preference fetch, the app falls back to "system" gracefully.

**US-3: Instant theme toggle (no latency)**
As a user, I want theme changes to apply instantly in the UI without waiting for a server response, so that the toggle feels responsive.

Acceptance Criteria:
- Toggling the theme in the Header dropdown applies the CSS class change within the same animation frame.
- The server sync is fire-and-forget (no loading spinner, no toast on success).
- If the server sync fails, the local theme is still applied; the server is retried on next toggle.
- Rapid toggling (system -> light -> dark -> light within 1 second) does not produce duplicate API calls.

**US-4: Sidebar collapse persistence**
As a user, I want my sidebar collapsed/expanded state to sync across devices alongside my theme.

Acceptance Criteria:
- Collapsing the sidebar on desktop and logging in on a second browser shows the sidebar collapsed.
- The `sidebar_collapsed` field is part of the same `ui_preferences` map attribute.

**US-5: Extensible preferences framework**
As an engineer, I want the preferences system to support arbitrary key-value pairs so that future UI preferences (locale, notification density, default page) can be added without schema migration.

Acceptance Criteria:
- The `ui_preferences` field is a DynamoDB map attribute, not a fixed set of columns.
- `PATCH /ui/settings/preferences` accepts partial updates (merge semantics, not replace).
- Unknown fields are ignored (forward compatibility).

### 2.2 Pain Points

1. **Cross-device inconsistency**: Users who set dark mode on one device see light mode on another.
2. **Data loss on cache clear**: Clearing browser storage resets the theme to "system".
3. **No backend record of UI preferences**: The profile record has no `preferences` field, making it impossible to sync any UI setting.
4. **No precedent for preference sync**: There is no existing pattern for frontend-to-backend preference persistence, so the first implementation needs to establish conventions.

---

## 3. Current State Analysis

### 3.1 Frontend Theme Store

`frontend/src/stores/uiStore.ts` defines a Zustand store with `persist` middleware (line 60). The store exports `useUiStore` with state fields: `theme` (type `Theme = "system" | "light" | "dark"`, line 6), `sidebarCollapsed` (boolean), and actions: `setTheme` (line 73), `toggleSidebar`, `setSidebarCollapsed`. The `persist` middleware writes to localStorage key `"ui-store"` and `partialize` (line 160) limits persistence to `theme` and `sidebarCollapsed`.

The `setTheme` action (line 73) is a simple synchronous setter: `set({ theme })`. There is no backend call, no debounce, and no side effect. Changes are immediately reflected in the Zustand store and persisted to localStorage by the middleware.

**Current store implementation:**

```typescript
export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      theme: "system",
      sidebarCollapsed: false,
      setTheme: (theme) => set({ theme }),
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
    }),
    {
      name: "ui-store",
      partialize: (state) => ({ theme: state.theme, sidebarCollapsed: state.sidebarCollapsed }),
    },
  ),
);
```

**Citations**:
- `frontend/src/stores/uiStore.ts:6` -- `type Theme = "system" | "light" | "dark"`
- `frontend/src/stores/uiStore.ts:60` -- `persist(` middleware wrapper
- `frontend/src/stores/uiStore.ts:73` -- `setTheme: (theme) => {`
- `frontend/src/stores/uiStore.ts:160-162` -- `partialize` saves `theme` and `sidebarCollapsed`

### 3.2 Theme Toggle in Header

`frontend/src/components/layout/Header.tsx` reads `theme` and `setTheme` from `useUiStore` (lines 129-130). The `THEME_OPTIONS` array (line 282) provides system/light/dark choices rendered as `DropdownMenuItem` elements. Clicking a theme option calls `setTheme(value)` directly with no server interaction.

```typescript
const theme = useUiStore((s) => s.theme);
const setTheme = useUiStore((s) => s.setTheme);
// ...
const THEME_OPTIONS: { value: Theme; label: string; icon: React.ReactNode }[] = [
  { value: "system", label: "System", icon: <Monitor className="h-4 w-4" /> },
  { value: "light",  label: "Light",  icon: <Sun    className="h-4 w-4" /> },
  { value: "dark",   label: "Dark",   icon: <Moon   className="h-4 w-4" /> },
];
```

**Citations**:
- `frontend/src/components/layout/Header.tsx:129-130` -- `const theme = useUiStore((s) => s.theme)` / `const setTheme = useUiStore((s) => s.setTheme)`
- `frontend/src/components/layout/Header.tsx:282` -- `THEME_OPTIONS` array

### 3.3 Theme Application in HTML Root

The `<html>` element's `class` attribute is toggled between `dark` and empty by a `useEffect` in `App.tsx` (or `main.tsx`). This controls Tailwind's dark mode variant (`dark:bg-background`, etc.). The effect runs on every `theme` change and applies the preference using `matchMedia("(prefers-color-scheme: dark)")` for the "system" option.

### 3.4 Profile API

The profile system uses `PATCH /ui/profile` (profile.py:167) to update user profile fields stored in the `profiles` DynamoDB table (table handle `T.profile`, tables.py:153, settings.py:413). The profile record currently has fields like `first_name`, `last_name`, `display_name`, `bio`, `avatar_url`, etc. There is no `preferences` or `ui_settings` field. The `ProfilePatchReq` model (models.py) defines the allowed profile fields for PATCH -- UI preferences are not among them.

The `apply_profile_update` function (referenced from profile.py) uses DynamoDB `UpdateItem` with SET expressions to merge fields. This same pattern will be used for the preferences endpoint.

**Citations**:
- `app/routers/profile.py:167-168` -- `ui_patch_profile` endpoint
- `app/core/settings.py:413` -- `profile_table_name: str = "profiles"`
- `app/core/tables.py:153` -- `profile=ddb.Table(S.profile_table_name)`

### 3.5 Session Init Flow

On login, the frontend redirects to `/` (Dashboard). The `App.tsx` mounts `ProtectedRoute > AppShell` which renders the `Header`, `Sidebar`, and `Outlet`. No server-side preferences are loaded during this flow -- the Zustand persist middleware hydrates from localStorage synchronously before the first render.

### 3.6 Gaps

1. No backend endpoint to save/retrieve UI preferences.
2. No `preferences` or `ui_preferences` field in the profile DynamoDB record.
3. No frontend logic to load server-side preference on session init.
4. No debounced sync from Zustand store to backend.
5. No error handling for preference sync failure.
6. No precedent for a "fire-and-forget" PATCH pattern in the frontend codebase.

---

## 4. Implementation Plan

### 4.1 Backend: Pydantic Models (`app/models.py`)

Add a new request model for preference updates. The model uses `Optional` fields so that partial updates are supported (only provided fields are synced).

```python
class PreferencesPatchReq(BaseModel):
    """Partial update for user UI preferences.

    All fields are optional — only provided fields are merged into the
    existing preferences map. This allows the frontend to sync a single
    field (e.g., theme) without affecting other preferences.
    """
    theme: Optional[Literal["system", "light", "dark"]] = None
    sidebar_collapsed: Optional[bool] = None
    # Future extensibility: add fields here as needed
    # locale: Optional[str] = None
    # notification_density: Optional[Literal["compact", "comfortable", "spacious"]] = None
    # default_landing_page: Optional[str] = None
```

### 4.2 Backend: Service Layer (`app/services/user_preferences.py`)

**New file `app/services/user_preferences.py`:**

Store preferences as a top-level map attribute `ui_preferences` on the existing profile record in the `profiles` table. Use DynamoDB `UpdateItem` with `SET` expression to merge fields without overwriting unrelated profile data.

```python
"""User UI preferences persistence (UX-001).

Stores preferences as a DynamoDB map attribute `ui_preferences` on the
existing profile record. DynamoDB's schemaless design means no migration
is needed — the attribute is created on first write.

DynamoDB key schema for profiles table:
  PK: user_sub (string)
  No SK (simple primary key)
"""

from __future__ import annotations
import logging
from typing import Any, Dict

from app.core.tables import T

logger = logging.getLogger(__name__)


def update_user_preferences(user_sub: str, prefs: Dict[str, Any]) -> None:
    """Merge-update UI preferences for a user.

    Creates the ui_preferences map if it doesn't exist, then sets each
    provided key within the map. Uses two-step update to ensure the map
    exists before setting nested keys.

    Args:
        user_sub: The user's unique identifier (partition key).
        prefs: Dictionary of preference key-value pairs to merge.
               Only non-None values should be passed.
    """
    if not prefs:
        return

    # Step 1: Ensure the map attribute exists
    T.profile.update_item(
        Key={"user_sub": user_sub},
        UpdateExpression="SET ui_preferences = if_not_exists(ui_preferences, :empty)",
        ExpressionAttributeValues={":empty": {}},
    )

    # Step 2: Set each preference key within the map
    for key, value in prefs.items():
        # Sanitize key name to prevent expression injection
        safe_key = key.replace(".", "_").replace("#", "_")[:50]
        T.profile.update_item(
            Key={"user_sub": user_sub},
            UpdateExpression=f"SET ui_preferences.#k = :val",
            ExpressionAttributeNames={"#k": safe_key},
            ExpressionAttributeValues={":val": value},
        )


def get_user_preferences(user_sub: str) -> Dict[str, Any]:
    """Retrieve UI preferences for a user.

    Returns an empty dict if no preferences have been set.
    """
    resp = T.profile.get_item(Key={"user_sub": user_sub})
    item = resp.get("Item", {})
    return item.get("ui_preferences", {})


def delete_user_preference(user_sub: str, key: str) -> None:
    """Remove a single preference key.

    Used when a user wants to reset a preference to its default.
    """
    safe_key = key.replace(".", "_").replace("#", "_")[:50]
    try:
        T.profile.update_item(
            Key={"user_sub": user_sub},
            UpdateExpression="REMOVE ui_preferences.#k",
            ExpressionAttributeNames={"#k": safe_key},
        )
    except Exception:
        logger.warning("delete_preference_failed", extra={"user_sub": user_sub, "key": key})
```

### 4.3 Backend: Preferences Endpoints (`app/routers/profile.py`)

Add two new endpoints to the existing profile router. These share the `/ui/settings` prefix to distinguish them from profile data endpoints (`/ui/profile`).

```python
from app.services.user_preferences import get_user_preferences, update_user_preferences


@router.patch("/settings/preferences")
async def ui_update_preferences(
    body: PreferencesPatchReq,
    ctx=Depends(require_ui_session),
):
    """Merge-update UI preferences for the current user.

    Accepts partial updates — only provided fields are merged.
    Returns {"ok": True} on success.
    """
    user_sub = ctx["user_sub"]
    updates = body.model_dump(exclude_none=True)
    if not updates:
        return {"ok": True}  # No-op for empty body

    update_user_preferences(user_sub, updates)
    return {"ok": True}


@router.get("/settings/preferences")
async def ui_get_preferences(ctx=Depends(require_ui_session)):
    """Return the user's UI preferences.

    Returns {"preferences": {...}} where the preferences object contains
    only the keys that have been explicitly set. Missing keys mean the
    frontend should use its default value.
    """
    user_sub = ctx["user_sub"]
    prefs = get_user_preferences(user_sub)
    return {"preferences": prefs}
```

### 4.4 Frontend: API Endpoint (`frontend/src/api/endpoints/preferences.ts`)

**New file `frontend/src/api/endpoints/preferences.ts`:**

```typescript
import api from "../client";

export interface UiPreferences {
  theme?: "system" | "light" | "dark";
  sidebar_collapsed?: boolean;
}

/**
 * Fetch server-side UI preferences for the current user.
 * Returns an empty object if no preferences have been set.
 */
export const getPreferences = (): Promise<UiPreferences> =>
  api.get<{ preferences: UiPreferences }>("/ui/settings/preferences")
    .then((r) => r.data.preferences);

/**
 * Merge-update UI preferences on the server.
 * Fire-and-forget — the frontend does not wait for this to complete
 * before applying the preference locally.
 */
export const patchPreferences = (prefs: Partial<UiPreferences>): Promise<void> =>
  api.patch("/ui/settings/preferences", prefs).then(() => undefined);
```

### 4.5 Frontend: Sync Logic in `uiStore.ts`

Modify `useUiStore` to add two new capabilities:

1. **On session init**: A `loadServerPreferences()` action calls `getPreferences()` and seeds the store if server-side values exist. Server values take precedence over stale localStorage.
2. **On theme/sidebar change**: Call `patchPreferences()` as a fire-and-forget debounced call (500ms debounce to avoid rapid toggles hammering the API).
3. **Offline fallback**: If `getPreferences()` fails (network error), keep the localStorage value.

```typescript
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { getPreferences, patchPreferences } from "@/api/endpoints/preferences";
import type { UiPreferences } from "@/api/endpoints/preferences";

export type Theme = "system" | "light" | "dark";

// Debounce timer for server sync
let syncTimer: ReturnType<typeof setTimeout> | null = null;

function debouncedSyncToServer(prefs: Partial<UiPreferences>) {
  if (syncTimer) clearTimeout(syncTimer);
  syncTimer = setTimeout(() => {
    patchPreferences(prefs).catch(() => {
      // Fire-and-forget: swallow errors.
      // The preference is already applied locally.
    });
  }, 500);
}

interface UiState {
  theme: Theme;
  sidebarCollapsed: boolean;
  prefsLoaded: boolean;

  setTheme: (theme: Theme) => void;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  loadServerPreferences: () => Promise<void>;
}

export const useUiStore = create<UiState>()(
  persist(
    (set, get) => ({
      theme: "system",
      sidebarCollapsed: false,
      prefsLoaded: false,

      setTheme: (theme) => {
        set({ theme });
        debouncedSyncToServer({ theme });
      },

      toggleSidebar: () => {
        const next = !get().sidebarCollapsed;
        set({ sidebarCollapsed: next });
        debouncedSyncToServer({ sidebar_collapsed: next });
      },

      setSidebarCollapsed: (collapsed) => {
        set({ sidebarCollapsed: collapsed });
        debouncedSyncToServer({ sidebar_collapsed: collapsed });
      },

      loadServerPreferences: async () => {
        try {
          const prefs = await getPreferences();
          const updates: Partial<UiState> = { prefsLoaded: true };
          if (prefs.theme) updates.theme = prefs.theme;
          if (prefs.sidebar_collapsed !== undefined) {
            updates.sidebarCollapsed = prefs.sidebar_collapsed;
          }
          set(updates);
        } catch {
          // Network error or not authenticated — keep localStorage values
          set({ prefsLoaded: true });
        }
      },
    }),
    {
      name: "ui-store",
      partialize: (state) => ({
        theme: state.theme,
        sidebarCollapsed: state.sidebarCollapsed,
      }),
    },
  ),
);
```

### 4.6 Frontend: Load Preferences on Mount (`App.tsx`)

In `App.tsx`, call `loadServerPreferences()` on authenticated mount. This should happen inside the `ProtectedRoute` wrapper (or the `AppShell` component) so it only fires for authenticated sessions.

```typescript
// In AppShell.tsx or App.tsx, inside the authenticated layout:
import { useUiStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import { useEffect } from "react";

function AppShell() {
  const userId = useAuthStore((s) => s.userId);
  const loadServerPreferences = useUiStore((s) => s.loadServerPreferences);
  const prefsLoaded = useUiStore((s) => s.prefsLoaded);

  useEffect(() => {
    if (userId && !prefsLoaded) {
      loadServerPreferences();
    }
  }, [userId, prefsLoaded, loadServerPreferences]);

  // ... rest of AppShell
}
```

### 4.7 DynamoDB Changes

No new table required. The `ui_preferences` map attribute is added to existing profile records in the `profiles` table. DynamoDB's schema-less design means no migration is needed -- the attribute is created on first write.

**Profile record before (existing):**
```json
{
  "user_sub": "abc123",
  "first_name": "Alice",
  "last_name": "Smith",
  "display_name": "alice",
  "bio": "..."
}
```

**Profile record after (with preferences):**
```json
{
  "user_sub": "abc123",
  "first_name": "Alice",
  "last_name": "Smith",
  "display_name": "alice",
  "bio": "...",
  "ui_preferences": {
    "theme": "dark",
    "sidebar_collapsed": true
  }
}
```

### 4.8 Preventing Theme Flicker

A critical UX consideration: when the page loads, the Zustand store hydrates from localStorage (synchronous, fast), then `loadServerPreferences()` fires asynchronously. If the server value differs from localStorage, the theme switches mid-render, causing a visible "flash of wrong theme" (FOWT).

**Mitigation strategy:**

1. The Zustand persist middleware hydrates localStorage synchronously before the first React render. This ensures the *last known* theme is applied immediately.
2. `loadServerPreferences()` only overwrites local state if the server-side value is different AND the server response arrives before the user interacts.
3. The `prefsLoaded` flag prevents double-loading.
4. In the common case (same device, localStorage matches server), there is zero flicker.
5. In the edge case (new device, no localStorage), the "system" default is shown for ~50-200ms until the server response arrives. This is acceptable.

---

## 5. Data Model

### 5.1 Profile Table Schema (Existing)

| Attribute | Type | Description |
|-----------|------|-------------|
| `user_sub` | S (PK) | User's unique identifier |
| `first_name` | S | First name |
| `last_name` | S | Last name |
| `display_name` | S | Display name |
| `bio` | S | User biography |
| `avatar_url` | S | Avatar image URL |
| `ui_preferences` | M (new) | Map of UI preference key-value pairs |

### 5.2 `ui_preferences` Map Structure

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `theme` | S | `"system"` | Theme preference: `"system"`, `"light"`, `"dark"` |
| `sidebar_collapsed` | BOOL | `false` | Whether sidebar is collapsed |

---

## 6. API Design

### 6.1 `PATCH /ui/settings/preferences`

**Method**: PATCH
**Path**: `/ui/settings/preferences`
**Auth**: `require_ui_session` (cookie-based with CSRF)
**Description**: Merge-update UI preferences. Only provided fields are updated.

**Request Body:**
```json
{
  "theme": "dark",
  "sidebar_collapsed": true
}
```

All fields are optional. Empty body is a no-op (returns 200).

**Response (200):**
```json
{
  "ok": true
}
```

**Error Responses:**
| Status | Condition | Body |
|--------|-----------|------|
| 401 | Not authenticated | `{"detail": "Not authenticated"}` |
| 422 | Invalid theme value | `{"detail": [{"loc": ["body", "theme"], "msg": "...", "type": "literal_error"}]}` |

**Rate Limit**: 30 requests/minute (debounced on client, so unlikely to hit)

### 6.2 `GET /ui/settings/preferences`

**Method**: GET
**Path**: `/ui/settings/preferences`
**Auth**: `require_ui_session` (cookie-based)
**Description**: Retrieve the user's UI preferences.

**Response (200):**
```json
{
  "preferences": {
    "theme": "dark",
    "sidebar_collapsed": true
  }
}
```

For a new user with no preferences:
```json
{
  "preferences": {}
}
```

**Error Responses:**
| Status | Condition | Body |
|--------|-----------|------|
| 401 | Not authenticated | `{"detail": "Not authenticated"}` |

---

## 7. Frontend Implementation

### 7.1 Component Hierarchy

```
App.tsx
  └── ProtectedRoute
       └── AppShell
            ├── Header.tsx  ← reads theme, calls setTheme
            │   └── DropdownMenu (THEME_OPTIONS)
            ├── Sidebar.tsx ← reads sidebarCollapsed
            └── Outlet (page content)
```

### 7.2 State Flow

```
Page Load:
  1. Zustand hydrates from localStorage (sync, instant)
  2. React renders with localStorage theme
  3. AppShell.useEffect calls loadServerPreferences()
  4. Server response arrives → store updated (if different)
  5. React re-renders with server theme (rare, only on mismatch)

Theme Toggle:
  1. User clicks "Dark" in Header dropdown
  2. setTheme("dark") called → Zustand store updated (sync)
  3. React re-renders with dark theme (instant)
  4. debouncedSyncToServer({ theme: "dark" }) scheduled (500ms)
  5. After 500ms, PATCH /ui/settings/preferences fires (async)
  6. Server responds 200 (ignored by client)
```

### 7.3 React Query Integration

The preferences fetch does NOT use React Query because:
1. It only fires once on session init (not refetched on window focus).
2. The data is immediately consumed by the Zustand store (not rendered directly).
3. Stale-while-revalidate is not useful here -- we always want the freshest server value.

If future requirements need reactive preference loading (e.g., cross-tab sync), the fetch can be wrapped in a `useQuery` with `staleTime: Infinity`.

### 7.4 Responsive Behavior

No responsive breakpoint changes. The theme and sidebar preferences apply identically across all viewports. The sidebar collapse state is already hidden on mobile (sidebar is a sheet/drawer on `<md` breakpoints).

---

## 8. Testing Plan

### 8.1 Unit Tests (pytest)

**File**: `tests/test_user_preferences.py`

| # | Test Name | Description | Assertion |
|---|-----------|-------------|-----------|
| 1 | `test_patch_preferences_theme_dark` | PATCH with `{"theme": "dark"}` | 200; profile record has `ui_preferences.theme = "dark"` |
| 2 | `test_patch_preferences_theme_invalid` | PATCH with `{"theme": "blue"}` | 422 validation error (Literal type violation) |
| 3 | `test_patch_preferences_empty_body` | PATCH with `{}` | 200; `{"ok": true}` (no-op) |
| 4 | `test_get_preferences_returns_stored` | GET after PATCH `{"theme": "dark"}` | 200; `preferences.theme == "dark"` |
| 5 | `test_get_preferences_new_user` | GET without prior PATCH | 200; `preferences == {}` |
| 6 | `test_patch_preserves_other_fields` | PATCH `theme` then PATCH `sidebar_collapsed` | Both fields present in GET response |
| 7 | `test_patch_does_not_affect_profile_fields` | PATCH preferences | `first_name`, `display_name` unchanged |
| 8 | `test_patch_requires_auth` | PATCH without session cookie | 401 |
| 9 | `test_get_requires_auth` | GET without session cookie | 401 |
| 10 | `test_patch_sidebar_collapsed_boolean` | PATCH with `sidebar_collapsed: true` | 200; stored as boolean in DDB |

```python
# Example test implementation
def test_patch_preferences_theme_dark(auth_client, alice_session):
    """Setting theme to 'dark' persists to DynamoDB."""
    resp = auth_client.patch(
        "/ui/settings/preferences",
        json={"theme": "dark"},
        headers={"x-csrf-token": alice_session["csrf_token"]},
        cookies=alice_session["cookies"],
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    # Verify via GET
    get_resp = auth_client.get(
        "/ui/settings/preferences",
        cookies=alice_session["cookies"],
    )
    assert get_resp.json()["preferences"]["theme"] == "dark"


def test_patch_preserves_other_fields(auth_client, alice_session):
    """Setting theme does not overwrite sidebar_collapsed."""
    auth_client.patch(
        "/ui/settings/preferences",
        json={"sidebar_collapsed": True},
        headers={"x-csrf-token": alice_session["csrf_token"]},
        cookies=alice_session["cookies"],
    )
    auth_client.patch(
        "/ui/settings/preferences",
        json={"theme": "light"},
        headers={"x-csrf-token": alice_session["csrf_token"]},
        cookies=alice_session["cookies"],
    )
    get_resp = auth_client.get(
        "/ui/settings/preferences",
        cookies=alice_session["cookies"],
    )
    prefs = get_resp.json()["preferences"]
    assert prefs["theme"] == "light"
    assert prefs["sidebar_collapsed"] is True
```

### 8.2 E2E Tests

**File**: `frontend/e2e/dark-mode-sync.spec.ts`

| # | Section | Test Name | Description | Assertion |
|---|---------|-----------|-------------|-----------|
| 1 | API | PATCH stores theme | POST `{"theme": "dark"}`, GET returns `"dark"` | `preferences.theme === "dark"` |
| 2 | API | GET returns empty for fresh user | GET without prior PATCH | `preferences` is `{}` |
| 3 | API | PATCH with invalid theme returns 422 | POST `{"theme": "rainbow"}` | 422 status |
| 4 | API | PATCH preserves existing fields | PATCH theme, then sidebar_collapsed, then GET | Both fields present |
| 5 | UI | Theme persists across page reload | Set dark via Header dropdown, reload, verify `<html>` class | `document.documentElement.classList.contains("dark")` |
| 6 | UI | Sidebar collapsed state syncs | PATCH `sidebar_collapsed: true`, reload, sidebar is collapsed | Sidebar width is icon-only |
| 7 | UI | Theme toggle is instant | Click "Dark", measure time to `<html>` class change | Class change within same animation frame |

```typescript
// Example E2E test
import { test, expect } from "@playwright/test";
import { injectAuth, sessions } from "./helpers";

const ALICE_ID = "alice";

test.describe("UX-001: Dark mode sync — API", () => {
  test("PATCH /ui/settings/preferences stores theme", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const patchResp = await page.request.patch("/ui/settings/preferences", {
      headers: { "x-csrf-token": sessions[ALICE_ID].csrf_token },
      data: { theme: "dark" },
    });
    expect(patchResp.status()).toBe(200);

    const getResp = await page.request.get("/ui/settings/preferences");
    const body = await getResp.json();
    expect(body.preferences.theme).toBe("dark");
  });

  test("GET /ui/settings/preferences returns empty for fresh user", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    // Clean up any existing preferences
    await page.request.patch("/ui/settings/preferences", {
      headers: { "x-csrf-token": sessions[ALICE_ID].csrf_token },
      data: {},
    });

    const resp = await page.request.get("/ui/settings/preferences");
    const body = await resp.json();
    expect(body.preferences).toBeDefined();
  });
});
```

---

## 9. Security Considerations

### 9.1 Authentication

Both endpoints use `require_ui_session`, which validates the `ui_session` + `ui_access_token` cookies and enforces CSRF for non-GET requests. This is the same auth mechanism used by the profile PATCH endpoint, so no new attack surface is introduced.

### 9.2 Input Validation

- `theme` is a `Literal["system", "light", "dark"]` -- Pydantic rejects any value outside this set with 422.
- `sidebar_collapsed` is `Optional[bool]` -- Pydantic coerces truthy/falsy values or rejects non-boolean types.
- The `model_dump(exclude_none=True)` call ensures only explicitly provided fields are written to DDB.
- The `ExpressionAttributeNames` pattern in the service layer prevents DynamoDB expression injection.

### 9.3 Data Privacy

UI preferences are non-sensitive data (theme choice, sidebar state). They do not contain PII and are not included in GDPR export/deletion workflows unless the `ui_preferences` attribute happens to be on the profile record (which is already included in GDPR exports as part of the full profile).

### 9.4 Rate Limiting

The PATCH endpoint is debounced client-side (500ms). Server-side rate limiting of 30 requests/minute is sufficient. There is no risk of abuse since preferences only change on explicit user action.

---

## 10. Performance Considerations

### 10.1 DynamoDB Costs

- **Read**: 1 RCU per GET (single GetItem, ~500 bytes including profile + preferences)
- **Write**: 2 WCU per PATCH (one conditional SET for map init + one SET for nested key)
- **Frequency**: ~1 GET per session init, ~0.1 PATCH per session (users rarely toggle theme)
- **Monthly cost**: Negligible (< $0.01/month even at 10K DAU)

### 10.2 Latency

- GET: ~15ms (single DynamoDB GetItem)
- PATCH: ~25ms (two sequential DynamoDB UpdateItems)
- The PATCH could be optimized to a single UpdateItem using a more complex update expression, but the two-step approach is simpler and the 10ms difference is irrelevant for a fire-and-forget call.

### 10.3 Caching

No caching layer is needed. The frontend loads preferences once per session and writes are rare. The localStorage Zustand persist middleware serves as the effective cache.

---

## 11. Migration / Rollout Plan

### 11.1 Feature Flag

No feature flag needed. The endpoints are additive and the frontend change is backward-compatible:
- If the backend is deployed first, the endpoints exist but are unused until the frontend is deployed.
- If the frontend is deployed first, `getPreferences()` returns 404 (caught by the `catch` block in `loadServerPreferences()`), and the debounced PATCH fails silently.

### 11.2 Backward Compatibility

- Existing users with no `ui_preferences` attribute get an empty object from GET.
- The Zustand store defaults (`theme: "system"`, `sidebarCollapsed: false`) remain unchanged.
- No localStorage format change -- the `partialize` function still writes the same shape.

### 11.3 Data Migration

None required. DynamoDB is schemaless. The `ui_preferences` map attribute is created on the first PATCH call for each user.

---

## 12. Acceptance Criteria

1. `PATCH /ui/settings/preferences` with `{ "theme": "dark" }` persists theme to the user's profile record in the `ui_preferences` map attribute.
2. `GET /ui/settings/preferences` returns the stored theme value wrapped in `{ "preferences": { "theme": "dark" } }`.
3. On page load with an authenticated session, the frontend loads server-side preferences and applies them to the Zustand store.
4. Theme toggles apply instantly in the UI without waiting for the server response (fire-and-forget PATCH).
5. If the server is unreachable, the localStorage fallback continues to work without errors or UI disruption.
6. The `sidebar_collapsed` preference also syncs for cross-device consistency.
7. Rapid theme toggling (multiple changes within 500ms) produces at most one PATCH call.
8. `PATCH /ui/settings/preferences` with invalid theme value (e.g., `"rainbow"`) returns 422.
9. Setting one preference field does not overwrite other previously set fields (merge semantics).
10. The `ui_preferences` map attribute is forward-compatible: future preference keys can be added without schema changes.

---

## 13. Dependencies

### 13.1 Internal Dependencies

- Profile table (`profiles`) must exist -- it does (already used by `app/routers/profile.py`).
- `require_ui_session` auth dependency -- already implemented in `app/auth/deps.py`.
- Zustand `persist` middleware -- already in use by `uiStore.ts`.

### 13.2 External Dependencies

None. No new npm packages or Python libraries required.

### 13.3 Related Tickets

- **UX-002 (Keyboard Shortcuts)**: The command palette's "Toggle Dark Mode" action will use the same `setTheme` action, which now includes server sync.
- **PLATFORM-009 (CSV Export)**: No dependency, but follows the same pattern of adding a new router endpoint.

---

## 14. Open Questions / Risks

1. **Conflict resolution**: If a user changes theme on two devices simultaneously, the last PATCH wins. This is acceptable for non-critical UI preferences but should be documented.
2. **Server-side vs. client-side source of truth**: The current design gives the server precedence on page load. If a user changes theme while offline and then goes online, the offline change will be synced (debounced PATCH fires when network reconnects). However, if they also changed theme on another device while offline, the "last write wins" rule applies.
3. **Future preference explosion**: If many preferences are added, the two-step DynamoDB update (ensure map + set nested key) becomes O(n) UpdateItem calls. This should be refactored to a single UpdateItem with a complex SET expression if the number of preferences exceeds ~10.
4. **GDPR compliance**: The `ui_preferences` attribute is part of the profile record and will be included in GDPR data exports automatically. If a user requests account deletion, the profile record (including preferences) is already deleted by the existing GDPR deletion flow.

---

## 15. Files to Create

| File | Purpose |
|------|---------|
| `app/services/user_preferences.py` | DynamoDB read/write for `ui_preferences` map on profile record |
| `frontend/src/api/endpoints/preferences.ts` | API client for preferences endpoints |
| `frontend/e2e/dark-mode-sync.spec.ts` | E2E tests |
| `tests/test_user_preferences.py` | Pytest unit tests |

## 16. Files to Modify

| File | Change |
|------|--------|
| `app/routers/profile.py` | Add `PATCH /settings/preferences` and `GET /settings/preferences` endpoints |
| `app/models.py` | Add `PreferencesPatchReq` model |
| `frontend/src/stores/uiStore.ts` | Add `loadServerPreferences()` action, `prefsLoaded` flag, debounced sync on `setTheme`/`toggleSidebar`/`setSidebarCollapsed` |
| `frontend/src/App.tsx` (or `AppShell.tsx`) | Call `loadServerPreferences()` on authenticated mount |

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| Zustand persist to localStorage | `frontend/src/stores/uiStore.ts` | 60 (`persist(`) | VERIFIED |
| Theme type definition | `frontend/src/stores/uiStore.ts` | 6 | VERIFIED: `type Theme = "system" \| "light" \| "dark"` |
| setTheme action (sync, no backend call) | `frontend/src/stores/uiStore.ts` | 73 | VERIFIED: `setTheme: (theme) => {` |
| partialize saves theme + sidebarCollapsed | `frontend/src/stores/uiStore.ts` | 160-162 | VERIFIED |
| Header theme toggle reads from uiStore | `frontend/src/components/layout/Header.tsx` | 129-130 | VERIFIED |
| THEME_OPTIONS array | `frontend/src/components/layout/Header.tsx` | 282 | VERIFIED |
| Profile PATCH endpoint | `app/routers/profile.py` | 167-168 | VERIFIED |
| Profile table config | `app/core/settings.py` | 413 | VERIFIED: `profile_table_name: str = ...` |
| Profile table handle | `app/core/tables.py` | 153 | VERIFIED: `profile=ddb.Table(S.profile_table_name)` |
| No preferences field in profile | `app/routers/profile.py` | all | VERIFIED (grep for "preferences" returns 0 results) |
| No ui_preferences in DDB schema | `scripts/local-ddb-init.py` | all | VERIFIED (no preferences-related table or attribute) |
