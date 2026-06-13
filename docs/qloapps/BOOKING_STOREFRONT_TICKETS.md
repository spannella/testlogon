# HTL — Public booking-engine storefront (QloApps gap analysis, Tier 2)

Source gap analysis: `docs/qloapps/QLOAPPS_GAP_ANALYSIS.md` §C row 4
("Booking-engine storefront — PARTIAL") and the Tier-2 cluster
("**Booking-engine storefront**: public room-search-by-dates+occupancy → results →
cart → guest details → checkout", §"Recommended new tickets"). QloApps
([Qloapps/QloApps](https://github.com/Qloapps/QloApps)) ships a public guest-facing
booking funnel — search by dates+occupancy → room-type results with per-night
availability and a summed multi-night price → cart → guest details → checkout/payment →
reservation. testlogon has **no hospitality storefront** today; the closest analogues are
the public booking-link reserve flow (`app/routers/calendar.py:1946-2043`) and the ECM
storefront availability-projection + reserve-on-add-to-cart specs
(`docs/ofbiz/specs/ECM-005.md`).

These four tickets cover **only** the public, unauthenticated guest funnel
(HTL-025..HTL-028): browse → search/quote → cart → guest details → checkout → reservation.
They **consume** the (forward-dependency) Tier-1/Tier-2 stay-search engine **HTL-017**
(`search_stays(...)`) and the reservation-create primitive **HTL-018**
(`create_reservation(...)`) — referenced by id, not re-specified here. The hotel/room-type
admin entities (HTL-001..HTL-004), per-date availability inventory, nightly rate plans,
reservation lifecycle/front-desk, folios, deposits, cancellation policy, and KPI reports
are out of scope (separate clusters in the gap analysis).

## Cross-cutting constraints (apply to every HTL ticket)

- **Additive + flag-gated, default OFF.** The hotel-PMS master flag `HOTEL_PMS_ENABLED`
  (default `false`) gates the whole vertical. Mirror the inventory-reservations contract:
  `_flag_on()` / `_require_enabled()` raising **404** when off, exactly like
  `app/services/inventory.py:51-58` (`_flag_on` reads `getattr(S, ..., False)`;
  `_require_enabled` raises `HTTPException(status_code=404, ...)`). Routers are always
  mounted; every handler is a 404 no-op until opt-in. With the flag off the platform is
  byte-for-byte unchanged.
- **Public (unauth) reads follow the calendar public-router pattern.** The browse, search,
  cart, and checkout endpoints are **unauthenticated** — they mirror
  `app/routers/calendar.py` `public_router` (`prefix="/booking"`,
  `app/routers/calendar.py:88`) whose handlers (`get_booking_link`,
  `list_booking_openings`, `reserve_booking_slot`, `app/routers/calendar.py:1946-2043`)
  take **no auth dependency**. The booking-engine router is a parallel `public_router`
  with its own prefix; only published hotels are readable (publication is the access gate,
  not a session).
- **Public routers register separately in `main.py`.** The new `booking_engine_router` is
  imported and `include_router`'d next to the other public routers — `calendar_public_router`
  / `calendar_public_event_router` (`app/main.py:60-61` import, `:595-596` include) and
  the `host_inventory_router` / `inventory_router` block (`app/main.py:310-311`,
  `:876-877`). It is NOT under `/ui/*` (those carry `require_ui_session`).
- **Checkout reuses the cart→order→payment money path.** Guest checkout reuses
  `app/services/shoppingcart.py` primitives (`get_cart:237`, `add_item:311`,
  `purchase_cart:474`) and `commerce_order_service` (`app/services/commerce_order_service.py`,
  imported at `shoppingcart.py:17`) — the same path the authenticated shop uses. The money
  path is NOT forked; the booking funnel feeds a cart and settles through the existing
  order/payment pipeline. On payment success it calls **HTL-018** `create_reservation(...)`
  and holds inventory (the reserve-on-checkout analogue of ECM-005's
  reservation-adjusted availability, `docs/ofbiz/specs/ECM-005.md` §1).
- **Reuse primitives, never fork.** `now_ts()` (`app/core/time.py`), the `_audit()`
  lazy-import wrapper (`app/services/inventory.py:92-98`), table handles via `T.*`
  (`app/core/tables.py`), the DDB rate-limit bucket (`app/services/rate_limit.py`
  `_bucket_limit:60`). Guests reuse Contacts (`app/services/contacts.py`).
- **Dev/prod parity (SECOPS-007).** Zero `if S.dev_mode` branches in business logic; the
  same `T.*` handles in both environments (moto intercepts boto3 in dev, real DynamoDB in
  prod). The checkout money path is identical dev/prod (stripe-mock in dev, real Stripe in
  prod) — same code, no branch.
- **FastAPI literal-before-dynamic route ordering.** Where a literal segment shares a
  prefix with a dynamic path param, the literal route MUST be declared first (FastAPI
  matches in declaration order) — same gotcha as the KYC `/templates`-before-`/{case_id}`
  and audit-export `/schedules`-before-`/{export_id}` ordering noted in CLAUDE.md. The
  literal `/search` and `/cart` routes are declared before any `/{hotel_id}` dynamic route.
- **Hermetic offline tests.** moto-bound frozen `T` (mutated via `object.__setattr__` and
  restored on cleanup), frozen `S` flags toggled via `object.__setattr__`, route coroutines
  called directly on a fresh `asyncio.new_event_loop()` — no `TestClient`, no real AWS.
  Mirrors the PROP/ECM-005 test idiom (`docs/ofbiz/specs/ECM-005.md` §9.1).

---

### HTL-025: Public hotel / room-type browse API

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Land the read-only, unauthenticated storefront browse surface: fetch a single published
hotel and list its bookable room types with photos, amenities, and base nightly rate. This
is the storefront's "shop window" — the first screen a guest sees before searching dates.
Net-new; the public booking-link `get_booking_link` (`app/routers/calendar.py:1946-1957`)
is the structural analogue (no auth, published-resource-only read), but the field set is
hospitality (hotel star rating / room-type occupancy / nightly rate), not calendar-slot.

New service `app/services/hotel_storefront.py` (new module), modeled on the read helpers in
`app/services/inventory.py` (flag/audit idiom) and the public read shape of
`app/routers/calendar.py`:

- `_flag_on()` / `_require_enabled()` → 404 when off (copy `inventory.py:51-58`, reading
  `getattr(S, "hotel_pms_enabled", False)`).
- `_audit(event, user_sub, **fields)` lazy-import wrapper (copy `inventory.py:92-98`); the
  browse path emits at most a low-cardinality `hotel.storefront.viewed` best-effort audit.
- `public_get_hotel(hotel_id) -> dict` — reads the HTL-001 hotel `META` row via `T.*`
  (the hotels table introduced by HTL-001); raises **404** unless the hotel is
  **published** (`status == "published"` / `published == True`, per the HTL-001 hotel
  model — publication is the public-access gate, exactly as a booking link is the gate in
  `_load_booking_link`, `app/routers/calendar.py:289-298`). Returns only
  storefront-safe fields: `hotel_id`, `name`, `description`, `star_rating`,
  `check_in_time`, `check_out_time`, `address`, `amenities`, `photos`, `policies`,
  `contact` (no owner_sub / internal admin fields).
- `public_list_room_types(hotel_id) -> dict` — verifies the hotel is published (404
  otherwise), then queries the HTL-002 room-type rows for that hotel
  (`begins_with(sk, "ROOMTYPE#")` on the hotel partition, the HTL-002 read access pattern),
  returns each room type's storefront projection: `room_type_id`, `name`, `description`,
  `occupancy_adults`, `occupancy_children`, `max_occupancy`, `bed_type`, `size_sqft`,
  `amenities`, `photos`, `base_rate_cents`, `currency`. Returns the
  `{"room_types": [...], "count": int}` shape (the `{items, count}` convention used by
  `host_inventory.list_hosts`, per CLAUDE.md). Only **published/bookable** room types
  appear (unpublished/archived are filtered, same publication gate).

Both functions are read-only, take no `user_sub`, and call `_require_enabled()` first. No
new DynamoDB table — they read the HTL-001 hotels table / HTL-002 room-type rows by id.

Pydantic models in `app/models.py`: `PublicHotelOut` (storefront-safe hotel fields above),
`PublicRoomTypeOut` (storefront-safe room-type fields above),
`PublicRoomTypeListOut` (`room_types: list[PublicRoomTypeOut]`, `count: int`). All
output-only; no input models (these are pure reads).

**Acceptance Criteria**
- `public_get_hotel` returns a published hotel's storefront projection and **404**s for an
  unpublished, archived, or non-existent hotel.
- `public_list_room_types` returns only published/bookable room types under a published
  hotel in the `{room_types, count}` shape; 404 for an unpublished/non-existent hotel.
- Neither function exposes internal fields (`owner_sub`, raw status, audit metadata).
- With `HOTEL_PMS_ENABLED=false`, both entrypoints raise HTTP 404 via `_require_enabled()`.
- No `if S.dev_mode` branch in `hotel_storefront.py` (SECOPS-007).

**Dependencies**: HTL-001 (hotel entity/table + `published` flag), HTL-002 (room-type
entity). Reuses: `app/services/inventory.py:51-58,92-98` (flag/audit),
`app/routers/calendar.py:289-298,1946-1957` (published-resource public read pattern),
`app/core/time.py` (`now_ts`), `host_inventory.list_hosts` `{items, count}` shape
(CLAUDE.md). Contrasts: calendar booking link models a slot, not a hotel room type.

---

### HTL-026: Public stay-search + quote endpoint

**Type**: Feature
**Priority**: P1
**Estimate**: 1.5d

**Description**

Add the public stay-search + quote endpoint — the funnel's core step: given a hotel, a
check-in/check-out date range, and occupancy (adults/children/rooms), return the available
room types with per-night availability and a summed multi-night total price. This is the
public, rate-limited HTTP wrapper around the **HTL-017** `search_stays(...)` engine
(forward dependency — the per-date availability intersection across the span + per-night
price summation lives in HTL-017; this ticket does NOT re-implement it). Net-new; mirrors
`list_booking_openings` (`app/routers/calendar.py:1960-1974`) — an unauthenticated read of
availability over a window — but returns room-type availability + price, not calendar
openings.

Service additions in `app/services/hotel_storefront.py`:

- `quote_stay(*, hotel_id, checkin, checkout, adults, children, rooms) -> dict` — calls
  `_require_enabled()`, validates the hotel is published (404 otherwise, reuses
  HTL-025 `public_get_hotel`), validates `checkout > checkin` (**400** otherwise, same
  contract as `reserve_booking_slot`'s `end_utc > start_utc` check,
  `app/routers/calendar.py:1984-1985`) and a sane max length-of-stay, then delegates to
  **HTL-017** `search_stays(hotel_id, checkin, checkout, adults, children, rooms)`.
  Returns the storefront quote shape:
  `{"hotel_id", "checkin", "checkout", "nights": int, "adults", "children", "rooms",
  "results": [{"room_type": PublicRoomTypeOut-shape, "available_rooms": int,
  "per_night": [{"date", "rooms_available", "rate_cents"}], "total_price_cents": int,
  "currency"}], "currency"}`. Room types with zero availability across the span are
  excluded from `results` (the availability intersection is HTL-017's job; this layer just
  surfaces the engine's output in the storefront projection).

Router (the new public `booking_engine_router` — declared in HTL-027, see below):

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/booking-engine/search` | none (public) | `quote_stay` (query: `hotel`, `checkin`, `checkout`, `adults`, `children`, `rooms`) |

Query params: `hotel: str` (hotel_id, required), `checkin: str` (ISO date, required),
`checkout: str` (ISO date, required), `adults: int = Query(1, ge=1)`,
`children: int = Query(0, ge=0)`, `rooms: int = Query(1, ge=1, le=...)`.

**Rate limiting.** Because the endpoint is unauthenticated and fans out to the
availability/price engine, the handler rate-limits per client before delegating, reusing
the DDB bucket `app/services/rate_limit.py` `_bucket_limit(user_sub, sid, max_n, win)`
(`rate_limit.py:60`). The "subject" is the request client host (e.g.
`request.client.host`) since there is no `user_sub`; on bucket exhaustion the handler
raises **429** (`HTTPException(429, ...)` + `Retry-After`), mirroring
`rate_limit_kyc_partner_api` usage (CLAUDE.md KYC-021). Caps are env-configurable via new
`HOTEL_BOOKING_SEARCH_RL_*` settings (e.g. max 60/hour/client, window 3600). The bucket is
fail-open (`_bucket_limit` returns `True` when the sessions table is unavailable,
`rate_limit.py:61-62`) so a backing-store hiccup never blocks search.

Pydantic models in `app/models.py`: `StayQuoteResultOut` (one room type's availability +
total), `StayQuoteOut` (the full quote envelope above). Output-only; the request is query
params, not a body.

**Acceptance Criteria**
- `GET /booking-engine/search` returns available room types with per-night availability and
  a summed multi-night `total_price_cents` for a published hotel + valid date range.
- `checkout <= checkin` → **400**; unpublished/non-existent hotel → **404**.
- The handler calls `search_stays` (HTL-017) for the availability/price computation — no
  per-date or per-night math is duplicated in `hotel_storefront.py`.
- Exceeding the per-client rate-limit bucket returns **429** with `Retry-After`; the bucket
  is fail-open when the sessions table is absent.
- `HOTEL_PMS_ENABLED=false` → endpoint 404s via `_require_enabled()`.

**Dependencies**: HTL-025 (`public_get_hotel`, models, flag, service module), **HTL-017**
(`search_stays` engine — forward dep, referenced by id), HTL-027 (router declaration — this
endpoint lives on the `booking_engine_router`). Reuses: `app/services/rate_limit.py:60`
(`_bucket_limit`), `app/routers/calendar.py:1960-1974,1984-1985` (public availability read
+ date-range validation), `app/core/time.py`. Contrasts: calendar openings are time slots,
not room-night inventory.

---

### HTL-027: Public booking cart + checkout → reservation

**Type**: Feature
**Priority**: P0
**Estimate**: 3d

**Description**

Add the transactional spine of the public funnel: select room-nights into a booking cart,
collect guest details (create/reuse a Contact), check out through the existing
cart→order→payment money path, and — on payment success — create the reservation
(**HTL-018**) and hold inventory. Declare the new **public** `booking_engine_router` and
register it in `app/main.py` next to the other public routers. This is the
reserve-on-checkout analogue of ECM-005's reservation-adjusted availability
(`docs/ofbiz/specs/ECM-005.md` §1) and clones the public booking-link reserve idiom
(`reserve_booking_slot`, `app/routers/calendar.py:1977-2043`) — but the terminal action is
a multi-night room reservation + inventory hold, not a calendar event.

**Booking cart.** Add a lightweight booking-cart on top of the shop cart primitives
(`app/services/shoppingcart.py`): each room-night selection becomes a cart line. Service
additions in `app/services/hotel_storefront.py`:

- `create_booking_cart(*, hotel_id) -> dict` — `_require_enabled()`; validates the hotel is
  published; mints a `booking_cart_id` (e.g. `uuid4().hex`) and creates the underlying
  shop cart via the existing `shoppingcart` primitives (reusing `get_cart:237` /
  `add_item:311` idioms — a booking cart IS a shop cart with hotel/stay metadata stamped on
  the parent row, keeping the money path unforked).
- `add_room_to_cart(*, booking_cart_id, hotel_id, room_type_id, checkin, checkout, adults,
  children, rooms) -> dict` — re-quotes via `quote_stay` (HTL-026) to lock the
  authoritative price + confirm availability at add-time (never trusts a client-supplied
  price — same principle as `reserve_booking_slot` re-checking openings,
  `app/routers/calendar.py:1989-1991`), then adds a cart line via `shoppingcart.add_item`
  with the stay metadata (hotel/room-type/dates/occupancy/nights/total) carried on the line
  payload. Returns the updated cart.
- `set_guest_details(*, booking_cart_id, name, email, phone, address=None) -> dict` —
  creates or reuses a **Contact** (`app/services/contacts.py`) for the guest by email and
  stamps the `contact_id` + guest snapshot onto the cart parent row. Guests reuse Contacts
  per the gap analysis ("Guests / customers ... reuse", §C row 5).
- `checkout_booking_cart(*, booking_cart_id, payment_method_token=...) -> dict` —
  `_require_enabled()`; re-validates availability for every cart line via `quote_stay`
  (final guard against a sell-out between add and checkout → **409** if a line is no longer
  available, mirroring `reserve_booking_slot`'s 409, `app/routers/calendar.py:1990-1991`);
  settles through the **existing** cart→order→payment path
  (`shoppingcart.purchase_cart:474` → `commerce_order_service`). **On payment success**:
  (1) calls **HTL-018** `create_reservation(...)` for each room-type line
  (hotel/room-type/dates/occupancy/guest-contact/assigned-total), and (2) **holds
  inventory** for the booked room-nights (the HTL-0xx per-date availability hold — the hotel
  analogue of `inventory.reserve`, decrementing per-date remaining-rooms). Both run only
  after the order settles. Emits `_audit("hotel.booking.created", ...)`. Returns
  `{"reservation_ids": [...], "order_id", "total_price_cents", "currency",
  "confirmation": {...}}`.

All write entrypoints call `_require_enabled()` first. The booking cart is the same
`carts` table the shop uses (no new table) — booking metadata rides on the cart rows.

**Router** — new public router (no `/ui` prefix, no session dependency), declared in
`app/routers/hotel_storefront.py` (new) or appended in `app/routers/booking_engine.py`
(new), exported as `booking_engine_router`:

```python
booking_engine_router = APIRouter(prefix="/booking-engine", tags=["booking_engine"])
```

| Method | Path | Auth | Service |
|---|---|---|---|
| GET | `/booking-engine/hotels/{hotel_id}` | none | `public_get_hotel` (HTL-025) |
| GET | `/booking-engine/hotels/{hotel_id}/room-types` | none | `public_list_room_types` (HTL-025) |
| GET | `/booking-engine/search` | none | `quote_stay` (HTL-026) |
| POST | `/booking-engine/cart` | none | `create_booking_cart` |
| POST | `/booking-engine/cart/{booking_cart_id}/rooms` | none | `add_room_to_cart` |
| POST | `/booking-engine/cart/{booking_cart_id}/guest` | none | `set_guest_details` |
| POST | `/booking-engine/cart/{booking_cart_id}/checkout` | none | `checkout_booking_cart` |
| GET | `/booking-engine/cart/{booking_cart_id}` | none | `get_booking_cart` |

> **Declaration order (CLAUDE.md gotcha):** declare the literal `/search` and `/cart`
> routes **before** the dynamic `/hotels/{hotel_id}` (and `/cart/{booking_cart_id}`
> before its own sub-routes), so FastAPI does not capture `search` / `cart` as a path
> param. Same rule as KYC `/templates`-before-`/{case_id}`.

Every handler calls `_require_enabled()` first (404 when off, router still mounted —
byte-for-byte unchanged platform). All endpoints are **unauthenticated** (the public-funnel
contract); ownership of a booking cart is enforced by the opaque, hard-to-guess
`booking_cart_id` (same posture as the public booking-link `link_id`,
`app/routers/calendar.py:289-298`). Mutations are public-by-design but rate-limited (reuse
HTL-026's `_bucket_limit` per client on the cart-mutation + checkout paths).

**Registration.** Import `booking_engine_router` and `include_router` it in `app/main.py`
adjacent to the public-router block — next to `calendar_public_router` /
`calendar_public_event_router` (`app/main.py:60-61` import, `:595-596` include).

**Acceptance Criteria**
- A guest can: create a booking cart → add a room-night selection (price + availability
  locked at add-time via `quote_stay`) → set guest details (Contact created/reused) →
  checkout → receive `reservation_ids` + an order/confirmation.
- Checkout settles through the existing `shoppingcart.purchase_cart` →
  `commerce_order_service` money path — NOT a forked payment path.
- On payment success (and only then) `create_reservation` (HTL-018) is called per room-type
  line and per-date inventory is held; a failed/declined payment creates no reservation and
  holds no inventory.
- A sell-out between add and checkout → **409**; unpublished hotel → **404**; client-supplied
  price is never trusted (re-quoted server-side).
- `booking_engine_router` imported + `include_router`'d in `app/main.py` next to the public
  routers; literal `/search` and `/cart` declared before dynamic `/{hotel_id}`.
- All 8 endpoints 404 when `HOTEL_PMS_ENABLED=false` (handler no-op, router still mounted).
- Cart-mutation + checkout endpoints are rate-limited per client (429 on exhaustion).

**Dependencies**: HTL-025 (browse service + models + flag), HTL-026 (`quote_stay` +
rate-limit), **HTL-018** (`create_reservation` — forward dep, by id), the per-date
availability hold primitive (HTL-0xx inventory — forward dep, by id), Contacts
(`app/services/contacts.py`). Reuses: `app/services/shoppingcart.py:237,311,474`
(cart→purchase), `app/services/commerce_order_service.py` (order/payment),
`app/routers/calendar.py:1977-2043` (public reserve idiom: re-check + 409 + put + audit),
`app/main.py:60-61,595-596` (public-router registration), `docs/ofbiz/specs/ECM-005.md` §1
(reserve-on-checkout availability). Contrasts: ECM-005 only *projects* reservation-adjusted
availability; HTL-027 *creates* the reservation + hold.

---

### HTL-028: Frontend public booking site + tests

**Type**: Feature
**Priority**: P2
**Estimate**: 3d

**Description**

Build the public, unauthenticated booking-site UI and the hermetic backend + E2E tests.
Gap analysis §C row 4 ("public date+occupancy search → results+price → cart → checkout").
Follow the established frontend feature recipe (CLAUDE.md "Adding a new feature" steps 5–9)
and the existing public-page pattern (the public event / booking pages are
**unauth, lazy-loaded routes** in `frontend/src/App.tsx`, e.g. `PublicEventPage` at
`/event/:calendarId/:eventId` — MEMORY.md "Public route ... no auth required").

Frontend (`frontend/src/`):
- **Types** — add `PublicHotel`, `PublicRoomType`, `StayQuote`, `StayQuoteResult`,
  `BookingCart`, `BookingCheckoutResult` and the search/guest input shapes to
  `frontend/src/api/types.ts` (mirror the `app/models.py` HTL public models).
- **API endpoints** — `frontend/src/api/endpoints/bookingEngine.ts` wrapping the axios
  instance (`frontend/src/api/client.ts`), but pointed at the **public** `/booking-engine/*`
  routes (no CSRF/session required — these are unauth): `getPublicHotel`,
  `listPublicRoomTypes`, `searchStays`, `createBookingCart`, `addRoomToCart`,
  `setGuestDetails`, `getBookingCart`, `checkoutBookingCart`.
- **Page** under `frontend/src/pages/booking/`:
  - `BookingEnginePage.tsx` — a single public funnel page (or a small wizard):
    1. **Search form** — date-range picker (check-in/check-out) + occupancy steppers
       (adults / children / rooms), submits to `searchStays`.
    2. **Results** — a card per available room type (name, photo, occupancy, per-night
       availability hint, formatted multi-night `total_price_cents` → currency), each with a
       **Select** action calling `createBookingCart` (first selection) + `addRoomToCart`.
    3. **Guest-details form** — name / email / phone (+ optional address), React Hook Form +
       Zod, calling `setGuestDetails`.
    4. **Checkout** — review (room/dates/total) → `checkoutBookingCart` → confirmation
       screen with `reservation_ids` / order id.
    Uses React Query `useQuery` for search + cart reads and `useMutation` for cart/guest/
    checkout writes; shadcn/ui primitives (`Card`, `Dialog`, `Button`, `Badge`,
    `components/ui/`).
- **Route** — lazy-load the page as a **public/unauth route** in `frontend/src/App.tsx`
  (cf. the `PublicEventPage` lazy import + route, outside the authenticated `AppShell`):
  `/book/:hotelId` (and/or `/book`) → `BookingEnginePage`. NOT behind the app sidebar/auth
  shell — it is a guest-facing storefront.

Tests:
- **Hermetic pytest** `tests/test_htl_booking_storefront.py` — moto-bound hotels/room-type
  + carts tables on the exact frozen `T.*` handles (`object.__setattr__`, restored on
  cleanup), frozen `S` with `hotel_pms_enabled` toggled, `search_stays` (HTL-017) and
  `create_reservation` (HTL-018) + the inventory-hold primitive **stubbed/patched at the
  source module** (forward deps — the test asserts they are *called* with the right args, it
  does not re-test their internals), `now_ts` patched, route coroutines called directly on a
  fresh `asyncio.new_event_loop()` (no `TestClient`). Cover:
  - **public browse** — `public_get_hotel` / `public_list_room_types` return the
    storefront projection for a published hotel; 404 for unpublished/non-existent.
  - **search/quote** — `quote_stay` delegates to (stubbed) `search_stays`, returns the
    quote envelope; `checkout <= checkin` → 400.
  - **cart → checkout → reservation** — create cart → add room (price re-quoted at add) →
    set guest (Contact reused) → checkout settles via (stubbed) `purchase_cart` and, on
    success, calls `create_reservation` (HTL-018) + holds inventory; a declined payment
    creates no reservation.
  - **rate-limit** — exceeding the search/checkout bucket returns 429.
  - **flag-off 404** — with `hotel_pms_enabled=false`, every browse/search/cart/checkout
    entrypoint raises 404 via `_require_enabled()`.
  - **route ordering** — `/booking-engine/search` and `/booking-engine/cart` are not
    captured by `/booking-engine/hotels/{hotel_id}`.
- **E2E** `frontend/e2e/hotel-booking-engine.spec.ts` — drives the **public** funnel with
  **no auth** (the page is unauthenticated): seed a published hotel + room type + per-date
  availability via DDB (or admin API), then visit `/book/:hotelId`, run a date+occupancy
  search, assert result cards + formatted price, select a room, fill guest details, check
  out, and assert the confirmation. Requires `HOTEL_PMS_ENABLED=1` in the E2E backend env.

**Acceptance Criteria**
- `/book/:hotelId` renders a public (unauth) search form → result cards with formatted
  multi-night price → guest-details form → checkout → confirmation, end-to-end against the
  HTL-027 router.
- The page is a public route in `App.tsx` (outside the authenticated app shell), like the
  existing public event/booking pages.
- Prices display as currency (cents → formatted); unavailable room types do not appear in
  results.
- `tests/test_htl_booking_storefront.py` passes offline (no AWS, no live stack); HTL-017 /
  HTL-018 / inventory-hold are stubbed and asserted-called.
- `frontend/e2e/hotel-booking-engine.spec.ts` passes with the flag on.

**Dependencies**: HTL-027 (router/endpoints) — transitively HTL-025/026 and forward deps
HTL-017/HTL-018 + inventory-hold. Reuses: `frontend/src/api/client.ts`,
`frontend/src/App.tsx` (public lazy route, `PublicEventPage` pattern — MEMORY.md), shadcn/ui
(`components/ui/`), React Query + RHF/Zod conventions (CLAUDE.md frontend conventions),
hermetic-test + E2E patterns (`docs/ofbiz/specs/ECM-005.md` §9, CLAUDE.md E2E section).
Contrasts: this is a guest-facing public storefront, NOT an authenticated `/ui` page.

---

## Dependency order

HTL-025 (public browse service + models + `hotel_storefront.py` + flag) → HTL-026
(public stay-search/quote endpoint + rate-limit, consumes HTL-017 `search_stays`) →
HTL-027 (booking cart + checkout → reservation + public `booking_engine_router` +
`main.py` registration, consumes HTL-018 `create_reservation` + inventory-hold) →
HTL-028 (frontend public booking site + hermetic pytest + E2E).

Forward (cross-cluster) dependencies referenced by id, not specified here: **HTL-001**
(hotel entity + `published` flag + table), **HTL-002** (room-type entity), **HTL-017**
(`search_stays` engine), **HTL-018** (`create_reservation` + reservation lifecycle), and
the per-date availability-hold inventory primitive (HTL-0xx).
