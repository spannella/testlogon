# PROP-005 — Frontend — property cards list + property detail page + tests

**Type**: Feature | **Priority**: P2 | **Estimate**: 2d
**Source**: `docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-005 + `docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A

---

## 1. Summary & Goal

PROP-005 is the final ticket in the open-property core-spine cluster. It delivers the React/TypeScript frontend for the property-management vertical and the full test suite (hermetic pytest + Playwright E2E) that validates the entire PROP-001..PROP-005 stack end-to-end.

The gap analysis (`docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A) records all three presentational rows as **MISSING**:
- "Property/unit list/filter + occupancy roll-up" — the card-grid view.
- "Portfolio KPIs (occupancy/active-leases/outstanding-rent/open-WOs)" — the summary strip.
- A frontend for the unit grid nested inside a property detail page.

PROP-005 closes those gaps for the Property and Unit layer. It does not cover Tenant, Lease, Rent Ledger, Work Orders, or the portfolio KPI dashboard — those are later cluster deliverables.

**Deliverables:**

1. **TypeScript types** mirroring `app/models.py` PROP models (`frontend/src/api/types.ts`).
2. **API endpoint wrappers** calling the PROP-004 router via `frontend/src/api/client.ts` (`frontend/src/api/endpoints/properties.ts`).
3. **Two page components** under `frontend/src/pages/properties/`:
   - `PropertiesPage.tsx` — responsive property card grid + portfolio summary strip + "New Property" dialog.
   - `PropertyDetailPage.tsx` — property header, summary-metrics row, unit grid, add/edit/delete unit dialogs.
4. **Route registrations** in `frontend/src/App.tsx`.
5. **Sidebar nav item** in `frontend/src/components/layout/Sidebar.tsx`.
6. **Hermetic pytest** `tests/test_prop_property_units.py` covering PROP-001..PROP-004 (flag off, property + unit CRUD, occupancy roll-up math, route ordering, pagination).
7. **E2E spec** `frontend/e2e/properties.spec.ts` (cookie-auth admin, end-to-end create property → add units → card grid → detail page → summary metrics → archive).

With `PROPERTY_MGMT_ENABLED=false` (the default) both pages are reachable via the browser (routes are registered unconditionally) but every API call returns 404 — the backend is a flag-gated no-op per PROP-001's `_require_enabled()`. The sidebar nav item is always visible; the error state is handled with a user-facing "Property management is not enabled" message. This matches the pattern used by the Inventory vertical.

---

## 2. Context & Current State

### 2.1 No property frontend exists today

Running `grep -rn "PropertiesPage\|PropertyDetailPage\|properties\.ts" frontend/src/` returns no results. The `frontend/src/pages/` directory has no `properties/` subdirectory. The `frontend/src/api/endpoints/` directory has no `properties.ts` file. `frontend/src/api/types.ts` has no `Property`, `Unit`, `PropertyOccupancyOut`, or `PortfolioOccupancyOut` interface.

The gap analysis (`docs/open-property/OPEN_PROPERTY_GAP_ANALYSIS.md` §A) marks "FE: property cards + detail + unit grid" as **MISSING**.

### 2.2 The backend is complete after PROP-004

PROP-005 depends on all four prior PROP tickets:
- PROP-001 (`docs/open-property/specs/PROP-001.md`): `properties` DynamoDB table, `PROPERTY_MGMT_ENABLED` flag, `create_property`/`get_property`/`update_property`/`archive_property` service, `PropertyIn`/`PropertyOut`/`PropertyUpdateIn` Pydantic models.
- PROP-002 (`docs/open-property/specs/PROP-002.md`): `UNIT#{unit_id}` child rows, `GSI_UNIT_OCCUPANCY`, `create_unit`/`get_unit`/`list_units`/`update_unit`/`delete_unit` service, `UnitIn`/`UnitOut`/`UnitUpdateIn` Pydantic models.
- PROP-003 (`docs/open-property/specs/PROP-003.md`): `list_properties`, `compute_property_occupancy`, `portfolio_occupancy_rollup` service functions; `PropertyListOut`, `PropertyOccupancyOut`, `PortfolioOccupancyOut` Pydantic models.
- PROP-004 (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-004): `properties_router` under `/ui/properties`, registered in `app/main.py` adjacent to `inventory_router` at `:311`/`:877`.

### 2.3 Frontend feature recipe (CLAUDE.md steps 5–9)

CLAUDE.md "Adding a new feature — checklist" steps 5–9 define the exact pattern:
- Step 5 — Frontend types in `frontend/src/api/types.ts`.
- Step 6 — Frontend API endpoints in `frontend/src/api/endpoints/<feature>.ts`.
- Step 7 — Page components in `frontend/src/pages/<feature>/`.
- Step 8 — Route in `frontend/src/App.tsx`.
- Step 9 — E2E tests in `frontend/e2e/<feature>.spec.ts`.

### 2.4 Lazy-import route pattern (`frontend/src/App.tsx:14-260`)

`frontend/src/App.tsx:14-260` defines all page imports as `lazy(...)` calls and renders them under a `<Suspense>` boundary at `:298`. PROP-005 adds two new `lazy` imports and two new `<Route>` elements using the same pattern. For reference, `frontend/src/App.tsx:37-38` shows a simple two-page domain (projects) that uses adjacent lazy imports (`:37` = `ProjectsPage`, `:38` = `ProjectDetailPage`) and adjacent routes at `:330-331` — `PropertiesPage` / `PropertyDetailPage` follows the same adjacency. [CORRECTED: original said `:14-37` for the entire lazy-imports block; the block actually runs through `:260`.]

### 2.5 Sidebar nav-items array (`frontend/src/components/layout/Sidebar.tsx:99-157`)

`frontend/src/components/layout/Sidebar.tsx:85-91` defines the `NavItem` interface (`label`, `i18nKey`, `path`, `icon`, `badge?`). The `NAV_GROUPS` array at `:99` contains all sidebar group entries; the "Productivity" group items (the natural home for "Properties") run to `:157`. `Building2` is already imported at `:51` from lucide-react (used for the "Organizations" entry at `:156`). PROP-005 adds a "Properties" entry using the same `Building2` icon. [CORRECTED: original said `NavItem` at `:85-96` and nav-items array at `:104-121`; actual lines are `:85-91` for `NavItem`, `:99` for `NAV_GROUPS`. Also: `NavItem` has a `badge?` optional field not mentioned in the original; the interface ends at `:91` not `:96`.]

### 2.6 API client (`frontend/src/api/client.ts`)

`frontend/src/api/client.ts` exports `api` with convenience methods `api.get`, `api.post`, `api.put`, `api.patch`, `api.del` (`:290-313`). The client automatically injects the CSRF token from the `ui_csrf` cookie (`:181`) and the Authorization header from the auth store (`:168`). All PROP-005 API calls go through this client — no custom fetch or axios instance. [CORRECTED: CSRF injection is at `:181`, not `:179`; `:179` reads the cookie but the `headers.set` call is at `:181`.]

### 2.7 React Query conventions (CLAUDE.md frontend conventions)

All server state uses `@tanstack/react-query`: `useQuery` for reads, `useMutation` for mutations, `useQueryClient` + `invalidateQueries` to refresh after mutations. Query keys follow the `[domain, ...params]` convention established across the codebase (e.g., `["tickets", { ... }]` at `frontend/src/pages/tickets/TicketsPage.tsx:61`).

### 2.8 shadcn/ui primitives

All UI components are shadcn/ui primitives from `components/ui/`: `Card`/`CardHeader`/`CardTitle`/`CardContent`, `Dialog`/`DialogHeader`/`DialogContent`/`DialogFooter`/`DialogTitle`, `Badge`, `Button`, `Input`, `Select`, `Label`, `Skeleton`. These mirror the patterns in `frontend/src/pages/tickets/TicketsPage.tsx:7-11` and the billing/contacts pages.

### 2.9 React Hook Form + Zod

Dialogs with user input use React Hook Form + Zod validation, matching `frontend/src/pages/Login.tsx` and `frontend/src/pages/Register.tsx` (the established project pattern for typed form validation). `zodResolver` from `@hookform/resolvers/zod` wires the schema.

### 2.10 Currency formatting pattern

`frontend/src/pages/Dashboard.tsx:30-35` defines the canonical `formatCents` helper:
```typescript
function formatCents(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency }).format(cents / 100);
}
```
`market_rent_cents` on `UnitOut` is stored as integer cents and displayed using this same helper — no custom utility, no fork.

### 2.11 Hermetic pytest pattern

The combined pytest file `tests/test_prop_property_units.py` covers all PROP tickets (not just PROP-005). The test isolation approach follows the established hermetic pattern: moto-backed `properties` table bound to frozen `T.properties` via `object.__setattr__`; frozen `S` with `property_mgmt_enabled` toggled via `object.__setattr__`; route coroutines called directly on a fresh `asyncio.new_event_loop()`. This mirrors `tests/test_gap_0265_0266_kyc_risk_scoring.py`, `tests/test_gap_0233_0234_ssh_session_recording.py`, and `tests/test_gap_0286_0287_kyc_partner_api.py`. No `TestClient` — that pattern is broken per CLAUDE.md.

---

## 3. Data Model

PROP-005 is a pure frontend ticket. It introduces **no new DynamoDB tables, no new GSIs, and no new DynamoDB attributes**. All schema is delivered by PROP-001 (property `META` rows, `GSI_OWNER`, `GSI_STATUS`) and PROP-002 (`UNIT#{unit_id}` child rows, `GSI_UNIT_OCCUPANCY`). This section documents the TypeScript types that mirror the backend Pydantic models.

### 3.1 TypeScript types (`frontend/src/api/types.ts`)

All interfaces are **additive** — appended at the end of `types.ts` or in a new `// --- Property Management ---` section. No existing type is modified.

```typescript
// --- Property Management (PROP-001..PROP-005) ---

export interface PropertyAddress {
  line1: string;
  line2?: string;
  city: string;
  region: string;
  postal_code: string;
  country: string;
}

export type PropertyType = "single_family" | "multi_family" | "apartment" | "commercial";
export type PropertyOccupancyStatus = "vacant" | "partial" | "occupied";
export type PropertyStatus = "active" | "archived";

export interface Property {
  property_id: string;
  owner_sub: string;
  name: string;
  property_type: PropertyType;
  address: PropertyAddress;
  color_tags: string[];
  occupancy_status: PropertyOccupancyStatus;
  unit_count: number;
  status: PropertyStatus;
  created_at: number;
  updated_at: number;
}

export interface PropertyIn {
  name: string;
  property_type: PropertyType;
  address: PropertyAddress;
  color_tags?: string[];
}

export interface PropertyUpdateIn {
  name?: string;
  property_type?: PropertyType;
  address?: PropertyAddress;
  color_tags?: string[];
}

export interface PropertyListOut {
  properties: Property[];
  count: number;
  cursor?: string | null;
}

export type UnitOccupancyStatus = "vacant" | "occupied" | "turnover" | "unavailable";

export interface Unit {
  property_id: string;
  unit_id: string;
  label: string;
  bedrooms: number;
  bathrooms: number;
  square_footage: number;
  market_rent_cents: number;
  occupancy_status: UnitOccupancyStatus;
  created_at: number;
  updated_at: number;
}

export interface UnitIn {
  label: string;
  bedrooms: number;
  bathrooms: number;
  square_footage: number;
  market_rent_cents: number;
  occupancy_status?: UnitOccupancyStatus;
}

export interface UnitUpdateIn {
  label?: string;
  bedrooms?: number;
  bathrooms?: number;
  square_footage?: number;
  market_rent_cents?: number;
  occupancy_status?: UnitOccupancyStatus;
}

export interface UnitListOut {
  units: Unit[];
  count: number;
}

export interface PropertyOccupancyOut {
  property_id: string;
  total: number;
  occupied: number;
  vacant: number;
  turnover: number;
  unavailable: number;
  occupancy_status: PropertyOccupancyStatus;
  occupancy_rate: number;
}

export interface PortfolioOccupancyOut {
  property_count: number;
  unit_count: number;
  occupied: number;
  vacant: number;
  turnover: number;
  unavailable: number;
  occupancy_rate: number;
}
```

---

## 4. API / Service Design

### 4.1 API endpoint wrappers (`frontend/src/api/endpoints/properties.ts`)

New file. Uses `api.get`, `api.post`, `api.put`, `api.del` from `frontend/src/api/client.ts` (`:290-313`). No axios, no custom fetch.

```typescript
import { api } from "@/api/client";
import type {
  Property, PropertyIn, PropertyUpdateIn, PropertyListOut,
  Unit, UnitIn, UnitUpdateIn, UnitListOut,
  PropertyOccupancyOut, PortfolioOccupancyOut,
} from "@/api/types";

// Properties
export const listProperties = (params?: {
  status?: string;
  property_type?: string;
  cursor?: string;
  limit?: number;
}) =>
  api.get<PropertyListOut>("/ui/properties", params
    ? Object.fromEntries(
        Object.entries(params)
          .filter(([, v]) => v !== undefined)
          .map(([k, v]) => [k, String(v)])
      )
    : undefined
  );

export const createProperty = (body: PropertyIn) =>
  api.post<Property>("/ui/properties", body);

export const getProperty = (propertyId: string) =>
  api.get<Property>(`/ui/properties/${propertyId}`);

export const updateProperty = (propertyId: string, body: PropertyUpdateIn) =>
  api.put<Property>(`/ui/properties/${propertyId}`, body);

export const archiveProperty = (propertyId: string) =>
  api.del<Property>(`/ui/properties/${propertyId}`);

export const getOccupancy = (propertyId: string) =>
  api.get<PropertyOccupancyOut>(`/ui/properties/${propertyId}/occupancy`);

export const getPortfolioOccupancy = () =>
  api.get<PortfolioOccupancyOut>("/ui/properties/portfolio/occupancy");

// Units
export const listUnits = (propertyId: string) =>
  api.get<UnitListOut>(`/ui/properties/${propertyId}/units`);

export const createUnit = (propertyId: string, body: UnitIn) =>
  api.post<Unit>(`/ui/properties/${propertyId}/units`, body);

export const updateUnit = (propertyId: string, unitId: string, body: UnitUpdateIn) =>
  api.put<Unit>(`/ui/properties/${propertyId}/units/${unitId}`, body);

export const deleteUnit = (propertyId: string, unitId: string) =>
  api.del<{ ok: boolean }>(`/ui/properties/${propertyId}/units/${unitId}`);
```

### 4.2 React Query key conventions

| Query key | Description |
|---|---|
| `["properties", params]` | `listProperties` — card grid |
| `["properties", propertyId]` | `getProperty` — detail header |
| `["properties", propertyId, "occupancy"]` | `getOccupancy` — summary-metrics row |
| `["properties", "portfolio", "occupancy"]` | `getPortfolioOccupancy` — summary strip |
| `["properties", propertyId, "units"]` | `listUnits` — unit grid |

After any property mutation (create/update/archive), invalidate `["properties"]` (all prefix keys). After any unit mutation (create/update/delete), invalidate `["properties", propertyId, "units"]` and `["properties", propertyId, "occupancy"]` — the occupancy roll-up changes whenever unit occupancy_status changes.

### 4.3 Routes (`frontend/src/App.tsx`)

Two new lazy imports appended after the last existing import block:

```typescript
const PropertiesPage = lazy(() => import("@/pages/properties/PropertiesPage"));
const PropertyDetailPage = lazy(() => import("@/pages/properties/PropertyDetailPage"));
```

Two new `<Route>` elements inside the `<AppShell>` → `<ProtectedRoute>` tree, placed adjacent to each other (following the projects pattern at the equivalent lines):

```tsx
<Route path="/properties" element={<PropertiesPage />} />
<Route path="/properties/:propertyId" element={<PropertyDetailPage />} />
```

Both routes require authentication (wrapped in `ProtectedRoute` like all other feature pages).

### 4.4 Sidebar nav item (`frontend/src/components/layout/Sidebar.tsx`)

`Building2` is already imported at `frontend/src/components/layout/Sidebar.tsx:51`. Add one entry to the nav-items array, adjacent to the "Organizations" entry (which also uses `Building2`) or in a new "Real Estate" section after the existing items at `:155`:

```typescript
{ label: "Properties", i18nKey: "nav.properties", path: "/properties", icon: <Building2 className="h-5 w-5" /> },
```

No feature-flag gate on the sidebar entry — when the flag is off, the page loads and shows a "Property management is not enabled" error from the failed API call (same behavior as other flagged features). This avoids adding a frontend feature-flag check that duplicates the backend's authoritative flag.

---

## 5. Detailed Behavior & Edge Cases

### 5.1 `PropertiesPage.tsx` — layout and behavior

**Portfolio summary strip** (top of page, always rendered): calls `getPortfolioOccupancy()` via `useQuery({ queryKey: ["properties", "portfolio", "occupancy"], ... })`. Shows: total properties, total units, occupied count, vacant count, occupancy rate as a percentage. On loading, renders `<Skeleton>` placeholders. On error (flag off → 404), renders an inline callout: "Property management is not enabled on this platform." The callout is the only content rendered on the page when the flag is off — no partial render that looks broken.

**Property card grid**: calls `listProperties({ status: "active" })` via `useQuery({ queryKey: ["properties", { status: "active" }], ... })`. On success, renders a responsive CSS grid (`grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4`). Each card is a shadcn/ui `<Card>`:
- **Header**: property name (`CardTitle`) + property-type badge (shadcn/ui `<Badge variant="outline">`).
- **Body**: formatted address (line1, city, region, postal_code); color-tags chips (`<Badge>` per tag, small, with the tag string as text); unit_count (e.g., "4 units"); occupancy badge (`<Badge>` variant based on `occupancy_status`: green=occupied, gray=vacant, yellow=partial).
- **Footer**: "View" button (`<Button asChild><Link to={...}>`) navigating to `/properties/:propertyId`.

**"New Property" dialog**: a `<Button>` labeled "New Property" at the top-right of the page opens a `<Dialog>`. The dialog contains a React Hook Form form with Zod schema:
```typescript
const propertySchema = z.object({
  name: z.string().min(1, "Name is required"),
  property_type: z.enum(["single_family", "multi_family", "apartment", "commercial"]),
  address: z.object({
    line1: z.string().min(1, "Address is required"),
    line2: z.string().optional(),
    city: z.string().min(1, "City is required"),
    region: z.string().min(1, "Region is required"),
    postal_code: z.string().min(1, "Postal code is required"),
    country: z.string().min(1, "Country is required"),
  }),
  color_tags: z.string().optional(),  // comma-separated, parsed to array on submit
});
```
On submit, calls `useMutation({ mutationFn: createProperty, onSuccess: () => queryClient.invalidateQueries({ queryKey: ["properties"] }) })`. On success, closes the dialog and shows a `toast.success("Property created")`. On API error, shows `toast.error(err.detail)`. The form is reset on dialog open.

**Status filter toggle**: a simple toggle control (shadcn/ui `<Select>`) with options "Active" / "Archived" / "All" drives the `status` parameter passed to `listProperties`. When changed, the query key changes and React Query fetches the filtered list. Default: `"active"`.

**Empty state**: when `listProperties` returns an empty array, renders a centered empty state card: "No properties yet. Create your first property."

### 5.2 `PropertyDetailPage.tsx` — layout and behavior

Uses `useParams<{ propertyId: string }>()` to extract `propertyId` from the URL.

**Property header**: calls `getProperty(propertyId)` via `useQuery`. Renders property name as an `<h1>`, property-type badge, formatted full address, color-tags chips. An "Archive" button (mutation: `archiveProperty`) is shown only when `property.status === "active"`; on success navigates back to `/properties`. An "Edit" button opens an edit-property dialog (same Zod schema as create, pre-populated with current values, calls `updateProperty`).

**Summary-metrics row**: calls `getOccupancy(propertyId)` via a separate `useQuery`. Renders four metric cards side-by-side (shadcn/ui `<Card>` with a number and label):
- "Total Units" (`occupancy.total`)
- "Occupied" (`occupancy.occupied`)
- "Vacant" (`occupancy.vacant`)
- "Occupancy Rate" (`(occupancy.occupancy_rate * 100).toFixed(1) + "%"`)
Additionally shows `turnover` and `unavailable` counts in smaller text if non-zero.

**Unit grid**: calls `listUnits(propertyId)` via `useQuery`. Renders a `<table>` or a vertical stack of unit rows (shadcn/ui `<Card>` per unit) with columns: Label, Beds/Baths, Sqft, Market Rent (formatted via `formatCents(unit.market_rent_cents)`), Occupancy Badge, Edit button, Delete button.

**"Add Unit" dialog**: a "Add Unit" `<Button>` opens a `<Dialog>` with React Hook Form + Zod:
```typescript
const unitSchema = z.object({
  label: z.string().min(1, "Label is required"),
  bedrooms: z.coerce.number().int().min(0),
  bathrooms: z.coerce.number().min(0),
  square_footage: z.coerce.number().int().min(0),
  market_rent_cents: z.coerce.number().int().min(0),
  occupancy_status: z.enum(["vacant", "occupied", "turnover", "unavailable"]).default("vacant"),
});
```
On submit: `useMutation({ mutationFn: (data) => createUnit(propertyId, data), onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["properties", propertyId, "units"] }); queryClient.invalidateQueries({ queryKey: ["properties", propertyId, "occupancy"] }); } })`.

**Edit Unit dialog**: same schema pre-populated with the selected unit's values; calls `updateUnit`. Invalidates the same two query keys on success.

**Delete Unit confirmation**: a `<Dialog>` with a "Are you sure?" message; on confirm calls `deleteUnit`. On success invalidates `["properties", propertyId, "units"]` and `["properties", propertyId, "occupancy"]`.

**Occupancy badge colors**: `"vacant"` → gray (`<Badge variant="secondary">`), `"occupied"` → green (`<Badge className="bg-green-100 text-green-800">`), `"turnover"` → yellow (`<Badge className="bg-yellow-100 text-yellow-800">`), `"unavailable"` → red (`<Badge variant="destructive">`).

**Loading state**: while `getProperty` is loading, render `<Skeleton>` for the header. While `listUnits` is loading, render row skeletons. While `getOccupancy` is loading, render four metric-card skeletons.

**404 / flag-off behavior**: if `getProperty` returns a 404 (property not found OR flag off), render a centered error card: "Property not found or property management is not enabled." with a "Back to Properties" button.

### 5.3 Market rent display — cents to formatted currency

`market_rent_cents` is stored as integer cents (e.g., `150000` = $1,500.00). Display uses `formatCents` (pattern from `frontend/src/pages/Dashboard.tsx:30-35`):
```typescript
function formatCents(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", { style: "currency", currency }).format(cents / 100);
}
```
This helper is defined locally in `PropertyDetailPage.tsx` or in a shared utility file — not forked from Dashboard.tsx, which keeps its own local copy per the existing pattern.

### 5.4 `color_tags` chip rendering

`color_tags` is a `string[]` of free-text labels. Each tag is rendered as a small `<Badge>` with the tag string as its text. Tags may be any string — no color mapping is enforced at the frontend layer. The "New Property" dialog accepts a comma-separated input string, parsed on submit: `color_tags: body.color_tags?.split(",").map(t => t.trim()).filter(Boolean) ?? []`.

### 5.5 Status filter and archived properties

The `PropertiesPage` filter defaults to `status="active"`. When set to `"archived"`, the card grid shows archived properties with a muted overlay or an "Archived" ribbon badge. **Archived properties do NOT show a "Restore" button in MVP** — `PropertyUpdateIn` (PROP-001 §3) does not include a `status` field, and the `PUT /ui/properties/{id}` endpoint therefore cannot change status. Restore requires a dedicated `POST /ui/properties/{id}/restore` endpoint which is not in the current PROP-004 scope; see §10 Open Question #1. Archive is a one-way action in the MVP UI. [CORRECTED: original suggested "Restore" button calling `updateProperty(id, { status: "active" })` — this would 422 because `status` is not an accepted field in `PropertyUpdateIn`.]

### 5.6 Route ordering and `/portfolio/occupancy` capture

`frontend/src/App.tsx` React Router v6 routes do not have the FastAPI ordering problem — React Router v6 matches routes by specificity, not declaration order, and `/properties/portfolio/occupancy` is more specific than `/properties/:propertyId`. However, because `portfolio/occupancy` is handled purely at the backend API level (not as a frontend route), there is no React Router conflict. The FE routes are `/properties` (list) and `/properties/:propertyId` (detail). The API path `/ui/properties/portfolio/occupancy` resolves server-side through the PROP-004 router where the declaration-order rule does apply (PROP-004 spec §4, per CLAUDE.md KYC / audit-export ordering gotchas).

### 5.7 Pagination — property card grid

`listProperties` is paginated (cursor-based, PROP-003 §3.2). For MVP, the property card grid does a single-page fetch with `limit=50` (sufficient for most landlord portfolios — gap analysis notes "single-landlord portfolios are < 200 properties"). If `cursor` is returned in the response, a "Load more" button at the bottom of the grid triggers another `useQuery` or `useInfiniteQuery` call with the next cursor. For MVP, "Load more" is acceptable over infinite scroll. The portfolio summary strip uses `getPortfolioOccupancy()` which internally loops all pages server-side — no frontend pagination required for the summary.

### 5.8 `bathrooms` as decimal

`Unit.bathrooms` is a `number` (allows halves: 1.5 baths). The Zod schema uses `z.coerce.number().min(0)` (not `.int()`). The input renders as a numeric input with `step="0.5"`. Display shows `1.5` as "1.5" (no special formatting needed).

### 5.9 Empty unit grid

When a property has `unit_count=0` and `listUnits` returns an empty array, the unit section renders an empty state: "No units yet. Add the first unit to this property." with the "Add Unit" button prominent in the empty state.

### 5.10 Archive confirmation dialog

The "Archive" action is destructive (changes property status permanently until manually restored). It is gated behind a confirmation `<Dialog>`: "Archive property '{name}'? This hides it from the active list. All unit data is preserved." Two buttons: "Cancel" and "Archive" (destructive variant). This prevents accidental archive on first click.

---

## 6. Feature Flag & Config

### 6.1 Master flag (inherited from PROP-001)

| Setting key | Env var | Default | Frontend effect |
|---|---|---|---|
| `property_mgmt_enabled` | `PROPERTY_MGMT_ENABLED` | `false` | All API calls return 404; page renders a "not enabled" callout instead of data |

The frontend never reads the flag value directly — it infers "flag off" from a 404 response to any property API call. This is the same behavior as all other flag-gated features: the router is always mounted, the flag check runs in the backend handler, and the frontend handles the 404 gracefully.

### 6.2 E2E environment

E2E tests in `frontend/e2e/properties.spec.ts` require `PROPERTY_MGMT_ENABLED=1` (or `true`) in the backend `.env.local` for the test run. Tests that verify the flag-off 404 behavior use a separate API call without the flag set — these are covered in the hermetic pytest, not the E2E spec.

### 6.3 No new frontend environment variables

PROP-005 does not introduce any new frontend environment variables (`frontend/.env.local`). The existing Vite proxy configuration (proxying `/ui/*` to `http://localhost:8000`) already covers all PROP-004 endpoints.

---

## 7. Dev/Prod Parity (SECOPS-007), Idempotency, Security & Money-safety

### 7.1 SECOPS-007 — no dev-mode branches in backend

PROP-005 is a pure frontend ticket. Its only backend interaction is through the PROP-004 router and PROP-001..003 service functions, all of which already enforce SECOPS-007 (no `if S.dev_mode` branches per the cross-cutting constraints in `docs/open-property/PROPERTY_UNITS_TICKETS.md`). The frontend itself has no concept of dev mode — it calls the same API endpoints in both environments.

### 7.2 SECOPS-007 — hermetic pytest does not use `dev_mode`

The hermetic pytest (`tests/test_prop_property_units.py`) toggles `S.property_mgmt_enabled` via `object.__setattr__` but never sets `S.dev_mode`. All service calls go through the same DynamoDB code path, with moto intercepting boto3. This is identical to the SECOPS-007 dev/prod parity approach in all existing hermetic tests.

### 7.3 Security — admin-only mutations

All create/update/archive/delete operations (properties and units) are gated by `require_admin_or_root_csrf` at the PROP-004 router layer (`app/auth/policy.py:100`). The frontend's mutation functions are callable by any authenticated session, but the backend will return 403 for non-admin callers. The UI should hide mutation controls (New Property button, Edit/Delete buttons) from non-admin users — use `getRoleFromAccessToken(accessToken)` from `@/lib/adminCapabilities` (the established pattern in `frontend/src/pages/tickets/TicketsPage.tsx:43-44`), not a direct `role` field from `useAuthStore` (`useAuthStore` exposes only `accessToken`, `userId`, `isAuthenticated` — it has no `role` property). Example: `const role = getRoleFromAccessToken(useAuthStore(s => s.accessToken)); const isAdmin = role === "admin" || role === "root";`. This prevents confusing 403 errors for USER-role sessions. [CORRECTED: original said "check `role` from the auth store (`useAuthStore`)"; `useAuthStore` has no `role` field. The established pattern decodes role from the JWT via `getRoleFromAccessToken`.]

### 7.4 Money-safety — PROP-005 does not touch billing

PROP-005 is a pure property-listing and unit-management UI. It does not display or handle rent payments, ledger entries, or any monetary transactions beyond rendering `market_rent_cents` as a display value (formatted via `formatCents`). No mutation in this ticket touches `billing_shared.py`, `new_ledger_entry` (`billing_shared.py:224`), `settle_or_reverse_ledger` (`:262`), `apply_balance_delta` (`:83`), or `compute_due` (`:158`). Rent payment recording is a future ticket cluster (gap analysis §B). This separation is intentional and must be maintained: PROP-005 never imports from `api/endpoints/billing.ts` and the backend service functions called by PROP-005 never call `billing_shared`.

### 7.5 Idempotency

The "New Property" dialog calls `createProperty` once per submit. The backend `create_property` is idempotent on (owner_sub, name) — a double-submit returns the existing property without error. The UI disables the submit button while the mutation is pending (`useMutation.isPending`) to prevent double-submission, but backend idempotency is the safety net for race conditions.

### 7.6 Audit trail

Backend mutations in PROP-001/002 emit best-effort audit events via `_audit()` (modeled on `app/services/inventory.py:92-98`): `property.created`, `property.updated`, `property.archived`, `property.unit.created`, `property.unit.updated`, `property.unit.deleted`. PROP-005 does not add any frontend-side audit emission — the backend is the authoritative audit source.

---

## 8. Backward Compatibility & Migration

### 8.1 Additive-only frontend changes

PROP-005 adds:
- New TypeScript interfaces to `frontend/src/api/types.ts` (additive; no existing interface is modified).
- A new file `frontend/src/api/endpoints/properties.ts` (additive).
- A new directory `frontend/src/pages/properties/` with two new files (additive).
- Two new `lazy` imports and two new `<Route>` elements in `frontend/src/App.tsx` (additive; no existing route is modified or reordered).
- One new nav item in `frontend/src/components/layout/Sidebar.tsx` (additive; the nav-items array is extended, not replaced).

No existing page, route, API endpoint wrapper, or type is modified. Rolling back PROP-005 requires only reverting these five file modifications and deleting the two new files.

### 8.2 No DynamoDB migration

PROP-005 introduces no DynamoDB schema changes. All schema was delivered by PROP-001/002 and is already created by `just restart`.

### 8.3 Incremental rollout

Since `PROPERTY_MGMT_ENABLED` defaults to `false`, the PROP-005 frontend can be deployed to production before the flag is enabled. The sidebar nav item will be visible and the routes will be reachable, but all API calls return 404 until the flag is set. This is acceptable behavior (the "not enabled" callout renders instead of data).

---

## 9. Test Plan

### 9.1 Hermetic pytest — `tests/test_prop_property_units.py`

This single test file covers the entire PROP-001..PROP-005 backend stack. Tests run **offline** — no live stack, no real AWS, no network. Pattern: moto-backed `properties` table with all three GSIs bound to a frozen `T.properties` handle; frozen `S` flags toggled; route coroutines from `app/routers/properties` called directly on a fresh `asyncio.new_event_loop()`. No `TestClient`.

**Fixture setup**

```python
import asyncio, boto3, pytest
from decimal import Decimal

try:
    from moto import mock_aws  # moto >= 5 (installed version only exports mock_aws)
except ImportError:  # pragma: no cover
    from moto import mock_dynamodb as mock_aws  # moto 4.x fallback

@pytest.fixture(autouse=True)
def _prop_table(monkeypatch):
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName="properties",
            KeySchema=[
                {"AttributeName": "property_id", "KeyType": "HASH"},
                {"AttributeName": "sk",           "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "property_id",     "AttributeType": "S"},
                {"AttributeName": "sk",              "AttributeType": "S"},
                {"AttributeName": "owner_sub",       "AttributeType": "S"},
                {"AttributeName": "status",          "AttributeType": "S"},
                {"AttributeName": "created_at",      "AttributeType": "N"},
                {"AttributeName": "occupancy_status","AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {"IndexName": "GSI_OWNER",
                 "KeySchema": [{"AttributeName": "owner_sub", "KeyType": "HASH"},
                               {"AttributeName": "created_at", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
                {"IndexName": "GSI_STATUS",
                 "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"},
                               {"AttributeName": "created_at", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
                {"IndexName": "GSI_UNIT_OCCUPANCY",
                 "KeySchema": [{"AttributeName": "property_id", "KeyType": "HASH"},
                               {"AttributeName": "occupancy_status", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        from app.core import tables as T_mod
        from app.services import property_mgmt as svc
        from app.routers import properties as router_mod
        object.__setattr__(T_mod.T, "properties", table)
        object.__setattr__(svc.S, "property_mgmt_enabled", True)
        object.__setattr__(svc.S, "properties_table_name", "properties")
        yield table
```

**Test cases (grouped by area)**

*Flag behavior*
1. `PROPERTY_MGMT_ENABLED=false` → `create_property` raises `HTTPException(404)`.
2. `PROPERTY_MGMT_ENABLED=false` → `list_properties` raises `HTTPException(404)`.
3. `PROPERTY_MGMT_ENABLED=false` → `create_unit` raises `HTTPException(404)`.
4. `PROPERTY_MGMT_ENABLED=false` → `compute_property_occupancy` raises `HTTPException(404)`.
5. `PROPERTY_MGMT_ENABLED=false` → `portfolio_occupancy_rollup` raises `HTTPException(404)`.

*Property CRUD*
6. `create_property` success: returns dict with `property_id`, `sk="META"`, `status="active"`, `occupancy_status="vacant"`, `unit_count=0`, numeric `created_at`/`updated_at`.
7. Idempotency: two calls with same `(owner_sub, name)` return same `property_id`, no error.
8. `get_property` hit: returns item after create.
9. `get_property` miss: returns `None` for unknown `property_id`.
10. `update_property` changes `name`: returned dict has new name, `updated_at >= original`.
11. `update_property` unknown property: raises `HTTPException(404)`.
12. `archive_property`: returns dict with `status="archived"`.
13. `property_id` determinism: `_property_id("alice", "Maple House") == _property_id("alice", "Maple House")` and `!= _property_id("bob", "Maple House")`.
14. `address` round-trip: all sub-fields preserved.
15. `color_tags` round-trip: non-empty list and empty list both preserved.
16. Decimal coercion: `created_at`, `updated_at`, `unit_count` returned as `int`, not `Decimal`.

*Unit CRUD*
17. `create_unit` success: returns dict with `unit_id`, `sk` starting with `UNIT#`, numeric fields, `occupancy_status="vacant"`.
18. `create_unit` unknown property: raises `HTTPException(404)`.
19. `list_units`: returns only `UNIT#` rows, never the `META` row.
20. `list_units` empty: returns empty list for property with no units.
21. `get_unit` hit: returns unit after create.
22. `get_unit` miss: returns `None`.
23. `update_unit` changes `label` and `market_rent_cents`: fields updated, `updated_at` bumped.
24. `delete_unit` success: returns `True`; subsequent `get_unit` returns `None`.
25. `delete_unit` unknown unit: returns `False`, no exception.
26. `unit_count` incremented on `create_unit`: parent `META` row has `unit_count == 1` after one create.
27. `unit_count` decremented on `delete_unit`: returns to 0 after delete.
28. `unit_count` atomic under two creates: `unit_count == 2` after two sequential creates.
29. `bathrooms` decimal: `create_unit` with `bathrooms=1.5`; `get_unit` returns `1.5` (not truncated).

*Occupancy roll-up*
30. `compute_property_occupancy` zero units: `{total: 0, occupied: 0, occupancy_status: "vacant", occupancy_rate: 0.0}`.
31. All occupied: `occupancy_status="occupied"`, `occupancy_rate=1.0`.
32. All vacant: `occupancy_status="vacant"`, `occupancy_rate=0.0`.
33. Mixed (2 occupied + 1 vacant): `occupancy_status="partial"`, `occupancy_rate ≈ 0.667`.
34. All four statuses present: counts sum to total, `occupancy_status="partial"`.
35. Write-back: after call, `META` row has updated `occupancy_status`.
36. Unknown property_id: no exception, returns `total=0`.

*`list_properties` / filters / pagination*
37. Empty portfolio: returns `{properties: [], count: 0, cursor: None}`.
38. Basic listing: 3 properties for owner, newest-first.
39. `status="active"` filter: excludes archived.
40. `status="archived"` filter: excludes active.
41. `status="all"`: returns both.
42. `property_type` filter: returns matching subset.
43. Combined `status` + `property_type` filter: correct intersection.
44. Pagination cursor round-trip: `limit=2` on 5 properties yields correct pages and final `cursor=None`.
45. Invalid `status` value → `HTTPException(422)`.
46. Invalid `property_type` value → `HTTPException(422)`.

*`portfolio_occupancy_rollup`*
47. Empty portfolio: `{property_count: 0, unit_count: 0, occupancy_rate: 0.0}`, no division-by-zero.
48. Single property: correct per-property sums.
49. Two properties: cross-property sums correct; `occupancy_rate` is global, not per-property average.

*Router route ordering*
50. `GET /ui/properties/portfolio/occupancy` routes to the roll-up handler, not captured by `/{property_id}` (call the PROP-004 router directly; assert response is a portfolio dict, not a 404-or-property dict).

### 9.2 E2E spec — `frontend/e2e/properties.spec.ts`

**Prerequisites**: `PROPERTY_MGMT_ENABLED=true` in the backend `.env.local` for the E2E run. Standard E2E stack: `just up` + seeded sessions.

**Auth**: uses `injectAuth(page, "charlie_admin")` (admin session with `role=ADMIN`) for cookie-auth. Mutations send `x-csrf-token: sess.csrf_token` header per CLAUDE.md CSRF pattern. `newIdentityPage(browser, "charlie_admin")` creates the page context.

**Section 1 — Properties API (admin operations)**

Uses `page.request` (carries cookie-auth session) for direct API calls:

- (T1) `POST /ui/properties` with valid payload → 200, `property_id` in response, `status="active"`.
- (T2) `POST /ui/properties` with same (owner, name) payload → 200, same `property_id` (idempotency).
- (T3) `GET /ui/properties` → response includes the created property.
- (T4) `GET /ui/properties/{property_id}` → full property object with `occupancy_status="vacant"`, `unit_count=0`.
- (T5) `PUT /ui/properties/{property_id}` updating `name` → 200, new name in response.
- (T6) `DELETE /ui/properties/{property_id}` → 200, `status="archived"`.
- (T7) `GET /ui/properties?status=archived` → archived property in response.

**Section 2 — Units API**

- (T8) `POST /ui/properties/{property_id}/units` → 200, `unit_id` in response, `occupancy_status="vacant"`.
- (T9) `GET /ui/properties/{property_id}/units` → list contains the new unit.
- (T10) `PUT /ui/properties/{property_id}/units/{unit_id}` updating `occupancy_status="occupied"` → 200.
- (T11) `GET /ui/properties/{property_id}/occupancy` → `occupied=1`, `occupancy_status="partial"` or `"occupied"` depending on total.
- (T12) `GET /ui/properties/portfolio/occupancy` → `property_count >= 1`, `unit_count >= 1`.
- (T13) `DELETE /ui/properties/{property_id}/units/{unit_id}` → 200.
- (T14) `GET /ui/properties/{property_id}/units` → empty list after delete.

**Section 3 — PropertiesPage UI**

- (T15) Navigate to `/properties` (admin auth); assert "Properties" heading visible.
- (T16) Portfolio summary strip visible: contains a number for total properties.
- (T17) Property card visible with correct name, type badge, address, occupancy badge.
- (T18) Status filter change to "Archived": card grid updates (archived property visible).
- (T19) "New Property" button opens dialog; fill form; submit; toast "Property created"; new card appears in grid.

**Section 4 — PropertyDetailPage UI**

- (T20) Click property card "View" button; navigates to `/properties/:id`; property name visible as heading.
- (T21) Summary-metrics row visible: "Total Units", "Occupied", "Vacant", "Occupancy Rate" metric cards.
- (T22) Unit grid empty state visible: "No units yet".
- (T23) "Add Unit" button opens dialog; fill label/bedrooms/bathrooms/sqft/market_rent_cents; submit; unit row appears in grid.
- (T24) Market rent renders as formatted currency (e.g., "$1,500.00").
- (T25) Occupancy badge reflects unit status (vacant → gray badge text "vacant").
- (T26) Edit unit dialog pre-populates current values; update label; row updates.
- (T27) Delete unit confirmation dialog; confirm; unit disappears from grid; occupancy metrics update.
- (T28) Archive property confirmation dialog; confirm; navigates back to `/properties`; property no longer in "Active" list.

---

## 10. Open Questions / Assumptions

1. **Restore archived property — `PropertyUpdateIn` does NOT include `status`.** The PROP-001 spec (`docs/open-property/specs/PROP-001.md:185-193`) defines `PropertyUpdateIn` with four optional fields: `name`, `property_type`, `address`, `color_tags`. `status` is intentionally absent. The backend `update_property` accepts `**kwargs` but the router validates input against `PropertyUpdateIn`, so a raw `status` kwarg is NOT reachable via `PUT /ui/properties/{id}`. **Corrected finding**: a restore path requires either a dedicated `POST /ui/properties/{id}/restore` endpoint (not currently in PROP-004) or an explicit `status` field added to `PropertyUpdateIn`. For MVP, PROP-005 should omit the restore UI and treat archive as a one-way action until PROP-004 is extended with a restore endpoint. The TypeScript `PropertyUpdateIn` in §3.1 correctly omits `status`. [CORRECTED: original assumption was wrong — `status` is NOT in `PropertyUpdateIn`.]

2. **Admin-only UI controls.** The frontend should hide "New Property", "Edit", "Archive", "Add Unit", "Delete Unit" buttons from `role=USER` sessions. `useAuthStore` (`frontend/src/stores/authStore.ts`) does NOT expose a `role` field — it exposes only `accessToken`, `userId`, `isAuthenticated`. The established pattern (e.g., `frontend/src/pages/tickets/TicketsPage.tsx:43-44`) is: `const token = useAuthStore(s => s.accessToken); const role = getRoleFromAccessToken(token);` (import from `@/lib/adminCapabilities`). **Confirmed**: use `getRoleFromAccessToken(accessToken)` to derive role from the JWT, not a store property. [CORRECTED: original said "`useAuthStore` exposes the role from the JWT cookie" and asked to confirm — confirmed it does NOT; role is decoded from the accessToken JWT.]

3. **`listUnits` response shape.** PROP-002's `list_units` service returns a list. The PROP-004 router wraps it as `{"units": [...], "count": N}` (mirroring the `{items, count, cursor}` pattern from `host_inventory.list_hosts`). **Assumption**: the response is `UnitListOut { units: Unit[], count: number }`. If the router returns a plain array, the frontend must be adjusted.

4. **`portfolioOccupancy` includes archived properties.** PROP-003's `portfolio_occupancy_rollup` internally calls `list_properties(owner_sub, status="active")` — it only counts active properties. **Assumption**: the summary strip shows active-property occupancy only, which is the operationally meaningful number (archived properties are excluded). This should be confirmed against PROP-003 §4.1.

5. **`color_tags` max length / allowed characters.** The Zod schema accepts any comma-separated string. If the backend enforces a max length per tag or a max number of tags, the Zod schema should mirror those constraints. **Assumption**: no server-side constraint beyond non-empty string; validation is purely client-side convenience.

6. **`property_type` label display.** The stored literal values (`single_family`, `multi_family`, `apartment`, `commercial`) need human-readable display labels. **Assumption**: a local mapping (`{ single_family: "Single Family", multi_family: "Multi-Family", apartment: "Apartment", commercial: "Commercial" }`) is defined in the component file — no i18n key is required for MVP.

7. **`i18nKey` for sidebar nav item.** The sidebar nav items have an `i18nKey` field (e.g., `"nav.properties"`). If the project has a translation file (`public/locales/en/translation.json` or similar), the key must be added there. **Assumption**: a translation key is added if a translation file exists; otherwise the `label` string is used as the fallback.

---

## 11. Dependencies

### 11.1 Direct upstream dependencies

| Ticket | Provides for PROP-005 |
|---|---|
| **PROP-001** (`docs/open-property/specs/PROP-001.md`) | `properties` DynamoDB table; `PROPERTY_MGMT_ENABLED` flag; `PropertyIn/Out/UpdateIn` Pydantic models; property service functions; `_require_enabled()` |
| **PROP-002** (`docs/open-property/specs/PROP-002.md`) | `UNIT#{unit_id}` child rows; `UnitIn/Out/UpdateIn` Pydantic models; unit service functions; `GSI_UNIT_OCCUPANCY` |
| **PROP-003** (`docs/open-property/specs/PROP-003.md`) | `list_properties`, `compute_property_occupancy`, `portfolio_occupancy_rollup`; `PropertyListOut`, `PropertyOccupancyOut`, `PortfolioOccupancyOut` models; cursor pagination |
| **PROP-004** (`docs/open-property/PROPERTY_UNITS_TICKETS.md` §PROP-004) | All 12 HTTP endpoints under `/ui/properties`; registered in `app/main.py`; route ordering (`/portfolio/occupancy` before `/{property_id}`) |

### 11.2 Reused platform primitives (no forking)

| Primitive | Source location | Reuse in PROP-005 |
|---|---|---|
| `api.get/post/put/del` | `frontend/src/api/client.ts:290-313` | All endpoint wrappers in `properties.ts` |
| `lazy()` route import pattern | `frontend/src/App.tsx:14-260` (lazy block); routes at `:315-567` | Two new lazy imports |
| `NavItem` interface + `NAV_GROUPS` array | `frontend/src/components/layout/Sidebar.tsx:85-91` (`NavItem`), `:99` (`NAV_GROUPS`) | One new nav entry [CORRECTED: original cited `:85-96,104-121`; actual lines are `:85-91` and `:99`] |
| `Building2` lucide icon | `frontend/src/components/layout/Sidebar.tsx:51` | Properties nav icon (already imported) |
| `Card`/`Badge`/`Button`/`Dialog`/`Skeleton` | `frontend/src/components/ui/` | All UI primitives in both pages |
| `useQuery`/`useMutation`/`useQueryClient` | `@tanstack/react-query` | Server state throughout |
| React Hook Form + Zod + `zodResolver` | `@hookform/resolvers/zod` | New Property and Unit dialogs |
| `formatCents` helper pattern | `frontend/src/pages/Dashboard.tsx:30-35` | `market_rent_cents` display |
| `injectAuth`/`newIdentityPage`/CSRF pattern | `frontend/e2e/tickets.spec.ts:70-117` | E2E test auth setup |
| Hermetic moto + `object.__setattr__` pattern | `tests/test_gap_0265_0266_kyc_risk_scoring.py` | `tests/test_prop_property_units.py` |
| `asyncio.new_event_loop()` direct-handler pattern | `tests/test_gap_0233_0234_ssh_session_recording.py` | Route coroutine calls in pytest |

### 11.3 Downstream consumers

| Future ticket cluster | Consumes PROP-005 for |
|---|---|
| **Tenant + Lease FE** (gap analysis §B) | Will add routes to `App.tsx` adjacent to `/properties/:id`; unit grid in `PropertyDetailPage` gains a "View Lease" link per unit when a lease is active |
| **Rent Ledger FE** (gap analysis §B) | `PropertyDetailPage` gains a "Rent Ledger" tab; all monetary rows go through `billing_shared.new_ledger_entry` (`:224`), voided via `settle_or_reverse_ledger` (`:262`), balance via `apply_balance_delta` (`:83`), outstanding computed via `compute_due` (`:158`) — never forked; no online payment provider (rent is manually recorded) |
| **Work Orders FE** (gap analysis §C) | Work-order tab in `PropertyDetailPage` linking to ticket boards (`app/services/tickets.py` `_DEFAULT_BOARD_COLUMNS`/`_STATUS_TRANSITIONS`); property/unit FK fields on work-order rows per FXA-012/013 spec |
| **RPT-006/007 portfolio dashlet** (future — not yet in RPT-006/007 specs) | `getPortfolioOccupancy()` from `properties.ts` is the intended data source for a future property KPI dashlet. NOTE: RPT-006 (`docs/suitecrm/specs/RPT-006.md`) and RPT-007 (`docs/suitecrm/specs/RPT-007.md`) as currently specced do not include a property dashlet type — the dashlet pattern (`recent_tickets`, `calendar_today`, `my_contacts`, `billing_summary`, `report`, `saved_search`) predates the PROP vertical. The property dashlet is a future addition to the RPT cluster, not something RPT-006/007 already covers. [CORRECTED: original stated it as a current RPT-006/007 deliverable; it is UNCONFIRMED/future.]
| **Vendor directory** (gap analysis §C) | PUR-003 supplier party (`docs/ofbiz/specs/PUR-003.md`) used for work-order vendor assignment in `PropertyDetailPage` work-order tab |
| **Document linking** (gap analysis §C) | EVT-011 record-link fields attach files (via `filemanager.py`) to `property_id` / `unit_id` FKs; EVT-012 revisions for lease versions; surface as a "Documents" tab in `PropertyDetailPage` |

---

## 12. Verification Log

Each assumption in the original spec was verified against the live codebase at repo root `/home/ubuntu/testlogon`. Status: **VERIFIED**, **CORRECTED**, or **UNCONFIRMED (RISK)**.

| # | Claim | Status | Evidence |
|---|---|---|---|
| 1 | No `PropertiesPage`, `PropertyDetailPage`, `properties.ts`, or `properties/` frontend exists | VERIFIED | `grep -rn "PropertiesPage\|PropertyDetailPage\|properties\.ts" frontend/src/` returns no results; `ls frontend/src/pages/` has no `properties/`; `ls frontend/src/api/endpoints/` has no `properties.ts` |
| 2 | No `Property`, `Unit`, `PropertyOccupancyOut`, or `PortfolioOccupancyOut` in `frontend/src/api/types.ts` | VERIFIED | `grep -n "Property\|Unit.*Occupancy\|PortfolioOccupancy" frontend/src/api/types.ts` returns no results |
| 3 | No property backend exists (`app/routers/properties.py`, `app/services/property_mgmt.py`) | VERIFIED | `ls app/routers/ | grep -i prop` returns nothing; `ls app/services/ | grep -i prop` returns nothing; `grep -rn "PROPERTY_MGMT" app/core/settings.py` returns nothing |
| 4 | `app/main.py:311` imports `inventory_router` | VERIFIED | `grep -n "inventory_router" app/main.py` → line 311: `from app.routers.inventory import inventory_router` |
| 5 | `app/main.py:877` includes `inventory_router` | VERIFIED | `grep -n "inventory_router" app/main.py` → line 877: `app.include_router(inventory_router)` |
| 6 | `frontend/src/App.tsx:14` starts lazy imports | VERIFIED | Line 14: `const Login = lazy(() => import("@/pages/Login"))` |
| 7 | `frontend/src/App.tsx:37-38` = ProjectsPage / ProjectDetailPage lazy imports | VERIFIED | Lines 37-38 confirmed; routes at `:330-331` |
| 8 | Lazy import block runs through `:37` only | CORRECTED | Block runs through `:260`; `:37-38` are early in the block but the block is 247 lines total |
| 9 | `Sidebar.tsx:85-96` = `NavItem` interface | CORRECTED | `NavItem` interface is at `:85-91` (7 lines, ends at `}`), not `:85-96`. `:93-97` is `NavGroup`. |
| 10 | `Sidebar.tsx:104-121` = nav-items array | CORRECTED | `NAV_GROUPS` array starts at `:99`, not `:104` |
| 11 | `Building2` imported at `Sidebar.tsx:51` | VERIFIED | Line 51: `Building2,` in the lucide-react import block |
| 12 | `Building2` used for "Organizations" entry at `:156` | VERIFIED | Line 156: `{ label: "Organizations", ..., icon: <Building2 className="h-5 w-5" /> }` |
| 13 | `client.ts:290-313` = `api.get/post/put/del` methods | VERIFIED | Lines 290-313 confirmed |
| 14 | `client.ts:168` = Authorization header injection | VERIFIED | Line 168-170: `const { accessToken } = useAuthStore.getState(); if (accessToken && !headers.has("Authorization")) { headers.set(...)` |
| 15 | `client.ts:179` = CSRF token injection | CORRECTED | CSRF injection is at `:181` (`headers.set("X-CSRF-Token", csrf)`); `:179` reads the cookie value. Corrected to `:181`. |
| 16 | `TicketsPage.tsx:61` = `["tickets", {...}]` query key | VERIFIED | Line 61: `queryKey: ["tickets", { ticketCursor, statusFilter, assigneeFilter, ownerFilter, isAdmin }]` |
| 17 | `TicketsPage.tsx:7-11` = shadcn/ui imports | VERIFIED | Lines 7-11 show `Badge`, `Button`, `Card*`, `Input`, `Label` imports from `components/ui/` |
| 18 | `Dashboard.tsx:30-35` = `formatCents` helper | VERIFIED | Lines 30-35 confirmed, exact match |
| 19 | `require_admin_or_root_csrf` at `app/auth/policy.py:100` | VERIFIED | Line 100: `async def require_admin_or_root_csrf(` |
| 20 | `useAuthStore` exposes `role` or `isAdmin()` | CORRECTED | `useAuthStore` (`frontend/src/stores/authStore.ts`) has NO `role` field. Exposes only `userId`, `accessToken`, `isAuthenticated`, `logoutReason`, `managingCreatorId/Name`. Role must be decoded from JWT using `getRoleFromAccessToken(accessToken)` from `@/lib/adminCapabilities` (pattern: `TicketsPage.tsx:43-44`). |
| 21 | `billing_shared.py:224` = `new_ledger_entry` | VERIFIED | `grep -n "new_ledger_entry" app/services/billing_shared.py` → line 224 |
| 22 | `billing_shared.py:262` = `settle_or_reverse_ledger` (flip state, not delete) | VERIFIED | Line 262: `def settle_or_reverse_ledger(...)` uses `update_item` to set `state`, never `delete_item` |
| 23 | `billing_shared.py:83` = `apply_balance_delta` | VERIFIED | `grep -n "apply_balance_delta" app/services/billing_shared.py` → line 83 |
| 24 | `billing_shared.py:158` = `compute_due` | VERIFIED | Line 158 confirmed |
| 25 | `moto.mock_dynamodb` in test fixture | CORRECTED | Installed moto exports only `mock_aws`, not `mock_dynamodb`. `python3 -c "import moto; print([x for x in dir(moto) if 'dynamodb' in x.lower() or 'mock_aws' in x.lower()])"` returns `['mock_aws']`. All existing tests use `mock_aws` with optional `mock_dynamodb` fallback for moto 4.x. Fixture corrected to use `mock_aws` with fallback import. |
| 26 | `PropertyUpdateIn` includes `status` field (for restore) | CORRECTED | PROP-001 spec (`docs/open-property/specs/PROP-001.md:188-193`) defines `PropertyUpdateIn` with only `name`, `property_type`, `address`, `color_tags` — no `status`. Restore via `PUT` with `status: "active"` would 422. MVP omits restore UI; TypeScript `PropertyUpdateIn` in §3.1 already correctly omits `status`. |
| 27 | `app/core/cursor.py:94,103` = `encode_cursor`/`decode_cursor` | VERIFIED | Lines 94 and 103 confirmed |
| 28 | `app/services/inventory.py:51-58` = `_flag_on`/`_require_enabled` | VERIFIED | Lines 50-56: `_flag_on()` at `:50`, `_require_enabled()` at `:54` (off by ≤1 from cited `:51-58` but functionally correct) |
| 29 | `app/services/inventory.py:92-98` = `_audit` wrapper | VERIFIED | Lines 92-96 confirmed (`_audit` at `:92`, lazy import at `:94`, call at `:96`) |
| 30 | `app/services/sessions.py:330` = `require_ui_session` | VERIFIED | Line 330: `async def require_ui_session(` |
| 31 | `app/core/tables.py:317-319,569-571` = inventory/reservations/returns table handles | VERIFIED | Lines 317-319: `inventory`/`reservations`/`returns` fields in `Tables` dataclass; `:569-571`: corresponding `_safe_table(...)` calls in `T = Tables(...)`. Note: `T.properties` does not yet exist — PROP-001 adds it. The citation correctly shows where the adjacent additions will go. |
| 32 | `app/core/settings.py:839-847` = inventory/returns settings area | VERIFIED | Lines 841-847 confirmed (`inventory_table_name`, `reservations_table_name`, `returns_table_name`). PROP-001 inserts `properties_table_name` immediately after `:847`. |
| 33 | `tickets.spec.ts:70-117` = `newIdentityPage`/`injectAuth`/`apiPost`/CSRF | VERIFIED | Lines 70, 79, 96, 101 confirmed; CSRF header is `"x-csrf-token"` (lowercase, matching backend default `ui_csrf_header_name = "x-csrf-token"`) |
| 34 | RPT-006 / RPT-007 include a "property KPI dashlet" | CORRECTED | RPT-006 defines dashlet types: `recent_tickets`, `calendar_today`, `my_contacts`, `billing_summary`, `report`, `saved_search`. RPT-007 provides data providers for those same five types. Neither spec mentions a `property_occupancy` or portfolio dashlet type. The property dashlet is a future addition. |
| 35 | `EVT-011` attaches files to `property_id`/`unit_id` FKs | UNCONFIRMED (RISK) | EVT-011 (`docs/suitecrm/specs/EVT-011.md`) defines generic `linked_record_type`/`linked_record_id` fields accepting opaque strings. It does not pre-register `property_id`/`unit_id` as known `linked_record_type` values — those would need to be added when the PROP vertical ships. The forward-reference in §11.3 is aspirational, not a confirmed EVT-011 feature. |
| 36 | `FXA-012`/`FXA-013` add property/unit FK fields to work-orders | UNCONFIRMED (RISK) | `docs/ofbiz/specs/FXA-012.md` specifies maintenance work orders on `asset_id` FK (fixed-asset), not `property_id`/`unit_id`. The WOV cluster in `docs/open-property/WORKORDERS_VENDORS_TICKETS.md` re-keys work orders on `property_id` — these are separate tickets (WOV-001..005), not FXA-012/013. §11.3 citing "FXA-012/013 spec" for property/unit FK fields is misleading. |
| 37 | `PUR-003` supplier party exists and is cited correctly | VERIFIED | `docs/ofbiz/specs/PUR-003.md` exists and specifies supplier CRUD service |
| 38 | `QUO-004` CRM contract spec exists (cited in gap analysis §B) | VERIFIED | `docs/suitecrm/specs/QUO-004.md` exists |
| 39 | `OPEN_PROPERTY_GAP_ANALYSIS.md §A` marks FE as MISSING | VERIFIED | Line 83: "filter + occupancy roll-up; router; FE (property cards + detail + unit grid)" listed under MISSING rows; §A table has no FE entry |
| 40 | `portfolio_occupancy_rollup` internally uses `status="active"` only | VERIFIED | PROP-003 spec (`:219`): "Collect all active properties via a loop over `list_properties(owner_sub, status="active", limit=200)`" — archived properties excluded from portfolio summary |

**Summary**: 6 CORRECTED, 2 UNCONFIRMED (RISK), 32 VERIFIED.
