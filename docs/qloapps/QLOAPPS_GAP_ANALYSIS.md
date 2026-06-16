# QloApps → testlogon — Gap Analysis (Hotel PMS / Booking Engine)

Generated 2026-05-31 via a 4-area multi-agent gap analysis (grounded in the live
codebase + all ticket files + ~520 existing specs: docs/ofbiz/specs, docs/suitecrm/specs,
docs/opencats/specs, docs/openbankproject/specs, docs/open-property/specs,
docs/ticket-bounty/specs). Source: [Qloapps/QloApps](https://github.com/Qloapps/QloApps)
— an open-source **hotel property-management system + booking engine** (PHP/MySQL,
PrestaShop-based), an alternative to commercial PMSs (Cloudbeds/eZee/Hotelogix).

## Headline

QloApps is a full hotel stack: **multi-hotel properties, room types (the bookable
"product") with individual physical rooms, seasonal/occupancy/LOS nightly rate plans, a
per-room-type per-date availability inventory calendar, the reservation lifecycle
(search→book→confirm→check-in→check-out→cancel/no-show), a public booking-engine
storefront, a front-desk/back-office console, guest folios with taxes/fees/add-ons,
advance-deposit/partial payments, cancellation policies + refunds, a channel/OTA manager,
reviews, coupons, multi-currency/language, and hotel KPI reports (occupancy/ADR/RevPAR).**

This is the **lowest-reuse vertical we've analyzed** — testlogon has *no hospitality domain
at all* — but it is also the one where our **transactional and storefront primitives map
cleanly onto the new domain**, so the work splits sharply into a genuinely net-new
"hospitality spine" and a thick layer of reuse:

- **Reuse / HAVE (no new ticket):** Stripe + ledger **refunds** (`refund_payment`,
  `billing.py:1287`; RMA `OFB-010`), **reviews** (catalog reviews, `catalog.py`
  `CatalogReviewCreateIn`), **coupons/discounts** (`promo_codes.py`, PROMO-001), the
  **cart→order→payment** money path (`shoppingcart.py`, `commerce_order_service.py`),
  **guests** (Contacts / OBP `CUS` customer / open-property `TEN` tenant), the **public
  booking-link** pattern (`calendar.py` `/booking`), the **ECM storefront** availability
  projection + reserve-on-add-to-cart specs, and the **ORD order-lifecycle state machine**
  + **LSE lease** date-range/state-machine patterns to clone.
- **PLANNED (depend on, don't re-ticket):** invoices/line-items (FIN-001 `invoices.py`,
  richer fields INV-001), **taxes** (INV-005/006), **multi-currency/FX** (INV-002/003/004),
  **report builder + dashlets** (RPT-001..009), property **dashboard KPIs** (PMD-003),
  **escrow/hold** for deposits (TBT-001/003), **returns/RMA** for cancellation→refund
  (OFB-008/009/010), open-property **PROP/PROP-002** (Property + occupancy-tagged Units —
  the closest structural shadow of Hotel→Room), and the **JIRA-SYNC** connection/mirror/
  sync-event pattern (a template for the channel manager).

**The genuinely net-new is the hospitality spine** — and it does not exist anywhere in code
or tickets: a **Hotel** entity (star rating, check-in/out times, amenities, policies,
photos), a **Room Type** (the bookable nightly product: occupancy adults/children, bed
type, base nightly rate), individual **Rooms** (number/floor/status), **housekeeping**
(clean/dirty/inspected/out-of-service + task assignment), a **per-room-type per-date
availability inventory calendar**, **nightly rate plans** (seasonal/occupancy/LOS/advance/
weekend), a **stay-search engine** (date-range + occupancy → available room types + summed
multi-night price), the **reservation entity + lifecycle** (incl. check-in/out/no-show +
room assignment), a **front-desk console** (arrivals/departures/in-house/walk-in/room-move),
the **booking-engine storefront** (date+occupancy search funnel), **guest folios** (running
stay balance + add-ons), **deposit/partial-payment** policies, a **cancellation/no-show
policy engine**, and **hotel KPI reports** (occupancy/ADR/RevPAR). The **channel manager
(OTA sync)** is the one true greenfield with poor fit — recommended **de-scope** (or a
separately-scoped effort on the JIRA-SYNC pattern).

The two concepts that defeat every existing primitive: a **per-date remaining-rooms
inventory** (our inventory — OFB-003/004, ECM-005 — is a single scalar stock counter with
no date dimension) and a **multi-night price computation across a check-in→check-out span**
(our cart total is a naive line-item sum; pricing-rules OFB-019/020 discount a cart total,
not a stay). These are the heart of a hotel PMS and are net-new.

---

## Gap matrix (condensed)

### A. Hotels + Room Types + Rooms + Housekeeping
| Capability | Status | Evidence / note |
|---|---|---|
| Hotel/property entity (star rating, amenities, check-in/out times, policies, photos, contact) | **MISSING (PLANNED-adjacent)** | no hotel model (no `star_rating`/`check_in_time` in code); open-property **PROP-001** Property (`address`/`status` only) + OFBiz **FAC-001/002** (warehouse) are the closest shadows — neither implemented, neither carries hospitality fields |
| Room Type entity (bookable category: occupancy adults/children, max, bed type, size, amenities, photos, base nightly price) | **PARTIAL** | generic catalog item has `name`/`price_cents`/`image_urls`/free-form `attributes` (`catalog.py:353-392`); no occupancy/bed-type/per-hotel semantics; variant depth PLANNED only (PRD-006/007) |
| Individual Room entity (room number, floor, status) | **MISSING (PLANNED-adjacent)** | no room model; open-property **PROP-002** Unit (`label`/`bedrooms`/`occupancy_status`) is the structural shadow — not implemented, lacks room_number/floor/type-FK |
| Hotel features / amenities catalog (wifi/pool/parking attached to hotels+room types) | **MISSING** | no amenities catalog; catalog `attributes` map is free-form; PRD-006 feature/feature-category is the generic (unimplemented) analogue |
| Housekeeping / room-status (clean/dirty/inspected/out-of-service + task assignment) | **MISSING** | no housekeeping; only weak overlap is PROP-002 Unit `occupancy_status` (vacant/occupied/turnover) — a rental flag, not a cleaning workflow; no task-assignment entity |

### B. Rate Plans / Pricing + Availability Calendar / Inventory
| Capability | Status | Evidence / note |
|---|---|---|
| Nightly base price per room type | **PARTIAL** | scalar `price_cents` per item (`catalog.py:370`); PRD-012 adds date-windowed price components — but single per-SKU price, not a rate summed over a stay |
| Seasonal / date-range pricing | **PARTIAL** | PRD-012 `set_price_component`/`resolve_effective_price` returns ONE effective price as-of an instant, not a per-night rate across a span |
| Occupancy-based pricing (extra-adult/child surcharge) | **MISSING** | no guest-count dimension; OFB-019 tiers are on cart qty/total |
| Length-of-stay (min/max nights, stay discounts) | **MISSING** | no nights concept |
| Advance-purchase / last-minute / weekend-vs-weekday rates | **MISSING** | no lead-time or day-of-week pricing rule type |
| **Per-room-type per-date available-rooms inventory** | **MISSING** | inventory (OFB-003) is `(sku, location)` scalar `on_hand`/`reserved` — no date dimension; the distinctive hotel primitive |
| Availability calendar (bookable dates + remaining room counts) | **MISSING** | calendar (`calendar.py`) is appointment-slot/rrule-recurrence, not room-night inventory |
| Blocking / holding rooms for dates | **PARTIAL** | OFB-004 soft reservations hold scalar stock w/ TTL — no date dimension |
| Overbooking controls + min/max availability per date | **MISSING** | inventory hard-stops at `available >= qty`; no per-date caps |
| **Booking-time availability check (dates+occupancy → available types + summed multi-night price)** | **MISSING** | nothing computes availability across a date range or sums per-night prices; the core net-new hotel primitive |

### C. Reservation Lifecycle + Front Desk + Booking Engine + Guests
| Capability | Status | Evidence / note |
|---|---|---|
| Reservation entity (hotel+room-type+dates+occupancy+guest+assigned-rooms+total) | **PARTIAL** | closest is open-property **LSE** lease (date-bounded tenant↔unit) + calendar event interval; none model multi-night room-night reservation w/ occupancy + assigned rooms |
| Reservation lifecycle (search→cart→book→confirmed→checked-in→checked-out→cancel/no-show; modify) | **PARTIAL** | OFBiz **ORD** state machine + history (ORD-001/005/006) + LSE `draft→active→ended` are reusable patterns; check-in/out/no-show + date/room modify are absent |
| Front desk (arrivals/departures/in-house, walk-in, assign room, check-in/out, room-move) | **MISSING** | no front-desk console; calendar admin views + PROP occupancy roll-up are adjacent, no room-assignment/check-in actions |
| Booking-engine storefront (public date+occupancy search → results+price → cart → checkout) | **PARTIAL** | public booking-link reserve (`calendar.py:1946-2043`) + ECM storefront availability/checkout specs + real cart; no date+occupancy room-type search funnel |
| Guests / customers (profile, booking history, contact) | **HAVE (as person)** | Contacts (`contacts.py`) + OBP **CUS** customer + open-property **TEN** tenant; reuse — booking-history linkage lands with the reservation entity |

### D. Folios/Taxes/Fees/Add-ons + Payments/Deposits + Refunds/Cancellation + Channel + Reviews + Reports
| Capability | Status | Evidence / note |
|---|---|---|
| Guest folio / booking invoice (room-nights+taxes+fees+add-ons, running balance, PDF) | **PARTIAL** | `invoices.py` (FIN-001: invoice#, line items, tax, S3 PDF, `deposit` type); no folio/running-stay-balance entity; richer fields INV-001 |
| Service / ancillary add-ons (breakfast, pickup, extra bed) on a booking | **PARTIAL** | catalog + cart provide products; no "attach add-on to a booking" link |
| Payment against a booking | **PARTIAL** | ledger primitives (`billing_shared.py`); RNT-002 `record_payment` pattern; not booking-scoped |
| Advance deposit / partial / pay-at-hotel | **PLANNED** | escrow/hold TBT-001/003 (`post_bounty`) is the reusable deposit primitive; `invoices.py` has `deposit` type; no deposit-policy / pay-at-hotel |
| Refunds | **HAVE** | `refund_payment` (`billing.py:1287`); RMA `OFB-010`; self-service `refund_requests.py` |
| Cancellation policy + no-show charge (free-until-N-days, % penalty) | **PLANNED** | returns/RMA OFB-008/009/010 is closest cancel→refund machinery; no time-based penalty / no-show fee |
| Channel manager / OTA sync (push avail+rates, pull bookings) | **MISSING (pattern only) → DE-SCOPE** | no OTA code; JIRA-SYNC connection/mirror/sync-event pattern is a sound template; OTA-specific, poor fit |
| Reviews & ratings (on hotels/room types) | **HAVE** | catalog reviews (`catalog.py` `CatalogReviewCreateIn/Out`, cascade delete) |
| Coupons / discounts / cart rules | **HAVE** | `promo_codes.py` (PROMO-001: %/fixed/free-trial, redemption) |
| Reports & KPIs (occupancy, ADR, RevPAR, revenue, arrivals/departures) | **PARTIAL / PLANNED** | RPT-001..009 builder + PMD-003 property KPIs; no hotel-specific ADR/RevPAR/arrivals dashlets |
| Taxes & fees calc per booking | **PLANNED** | INV-005 tax groups + INV-006 per-line tax (design-spec, unimplemented) |
| Multi-currency / multi-language | **PLANNED** | INV-002/003/004 currency registry + FX (design-spec, unimplemented); i18n no evidence |

---

## Recommended new tickets (the net-new hospitality vertical)

Proposed prefix **`HTL`**. Decomposed into clusters (each cluster = several tickets:
model/table/flag → service → router → FE → tests). All additive + flag-gated default-off,
reusing existing primitives — never forking.

**Tier 1 — Hospitality spine (entities + inventory + rates) (~16 tickets)**
- **Hotel + amenities**: Hotel entity (star rating, check-in/out times, policies, photos,
  contact, address) reusing the PROP single-table shape; amenity/feature catalog with
  many-to-many attach to hotels + room types (reuse PRD-006 feature pattern); router; FE.
- **Room Type + Rooms + Housekeeping**: Room Type entity (per-hotel; occupancy
  adults/children + max, bed type, size, base nightly rate, amenities, photos);
  individual Room entity (number/floor/type-FK/status, extend PROP-002 Unit); housekeeping
  status enum (clean/dirty/inspected/out-of-service) + housekeeping task create/assign;
  router; FE (room grid + housekeeping board on ticket-board pattern).
- **Per-date availability inventory**: per-room-type per-date remaining-rooms ledger
  (date-keyed), block/hold for dates, overbooking allowance, min/max per date; availability
  read API (date→remaining per type); the distinctive net-new inventory model.
- **Nightly rate plans**: seasonal/date-range rates, occupancy surcharges (extra-adult/
  child), LOS (min/max nights + discounts), advance/last-minute, weekend-vs-weekday;
  multi-night + occupancy price computation.

**Tier 2 — Booking + reservations + front desk (~12 tickets)**
- **Stay-search engine**: date-range + occupancy → available room types (per-date
  availability intersection across span) + summed multi-night/occupancy price.
- **Reservation entity + lifecycle**: room-night reservation (hotel/room-type/dates/
  occupancy/guest/assigned-rooms/total) + state machine (confirmed→checked-in→checked-out→
  no-show→cancelled) cloning ORD-005 transitions/history + LSE date-range; modify dates/room.
- **Front-desk console**: arrivals/departures/in-house-today queries, walk-in create,
  assign physical room, check-in/out actions, room-move; reuse ticket boards for views.
- **Booking-engine storefront**: public room-search-by-dates+occupancy → results → cart →
  guest details → checkout, reusing the public booking-link route + ECM availability/cart
  patterns; guests reuse Contacts/CUS/TEN (add booking-history view).

**Tier 3 — Folios, money policies, reports (~8 tickets)**
- **Guest folio**: open-stay running-balance entity accumulating room-nights + add-ons +
  tax atop `invoices.py` line-items; attach catalog add-on SKUs to a folio; folio PDF.
- **Deposit / partial payment**: deposit-policy + atomic deposit hold (reuse TBT-003
  escrow) + balance-due-on-arrival; `record_payment(folio_id)` (reuse RNT-002 pattern).
- **Cancellation / no-show policy engine**: free-until-N-days + % penalty + no-show fee →
  drives `refund_payment` / RMA.
- **Hotel KPI reports**: ADR / RevPAR / occupancy / arrivals-departures dashlets on the
  RPT-006/PMD-003 framework.
- **Taxes + multi-currency wiring**: implement/consume INV-005/006 (tax) + INV-002/003/004
  (currency) for folios/invoices (depend-on, wire-in).

**De-scoped (recommended):** **Channel manager / OTA sync** (Booking.com/Expedia push-avail
+ pull-bookings) — large, OTA-specific, poor fit for a creator-economy SaaS; revisit
separately on the JIRA-SYNC connection/mirror/sync-event template if demanded.

**Already HAVE/PLANNED → NO new ticket:** refunds (`refund_payment`/OFB-010), reviews
(catalog), coupons (PROMO-001), cart→order→payment (shoppingcart/commerce_order_service),
guests (Contacts/CUS/TEN), invoices/line-items (FIN-001/INV-001), taxes (INV-005/006 —
wired-in, not re-ticketed), multi-currency (INV-002/003/004 — wired-in), report builder +
dashlets (RPT-*/PMD-003 — framework reused), escrow (TBT — reused for deposits), returns/RMA
(OFB-008/009/010 — reused for cancellation).

## Scope tiers (for the build decision)
- **Tier 1 — Hospitality spine** (hotels/room-types/rooms/housekeeping + per-date inventory
  + nightly rate plans): ~16 tickets
- **Tier 2 — Booking + reservations + front desk** (stay-search, reservation lifecycle,
  front-desk console, booking-engine storefront): ~12 tickets
- **Tier 3 — Folios, money policies, reports** (folios/add-ons, deposit/partial,
  cancellation/no-show, hotel KPIs, tax/currency wiring): ~8 tickets
- **Everything (T1–T3):** ~36 tickets (excluding the de-scoped channel manager)

All additive + flag-gated default-off, reusing existing primitives (invoices/ledger/wallet,
refund_payment/RMA, escrow TBT, promo_codes, catalog reviews, cart/order, ORD/LSE
state-machines, PROP units, ECM storefront, calendar booking-links, RPT/PMD reports, INV
tax/currency) — never forking.
