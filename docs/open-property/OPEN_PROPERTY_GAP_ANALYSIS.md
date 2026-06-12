# open-property → testlogon — Gap Analysis (Property Management)

Generated 2026-06-12 via a 3-area multi-agent gap analysis (grounded in the live
codebase + all ticket files + ~462 existing specs). Source:
[clawnify/open-property](https://github.com/clawnify/open-property) — a self-hosted
property-management platform (alternative to TenantCloud/AppFolio/Buildium) for
landlords & small PMs. Stack: React 19 + Hono on Cloudflare Workers + D1 (SQLite).

## Headline

open-property covers **Properties & Units, Tenants, Leases, a rent ledger
(automated monthly charges + manual collections), Maintenance Work Orders, Vendors,
rent-policy settings, and a portfolio dashboard**. It *deliberately excludes* online
payment processing, public portals, SMS/email automation, listing syndication, and
background screening.

This is the **highest-reuse** domain we've analyzed: testlogon has no real-estate model,
but **the workflow machinery is already here or planned**, so a property-management
vertical is largely a thin, flag-gated extension layer rather than net-new infrastructure:
- **Rent ledger & collections (~80% reuse):** the single-entry billing ledger
  (`billing_shared.new_ledger_entry`/`compute_due`), the recurring auto-charge timer
  (`compute_billing.py`, GAP-0228), subscription recurring billing, and the planned
  **OFB-015 AR-aging** engine cover automated charges + payment recording + aging.
- **Work orders (~70% reuse):** the ticket system (`tickets.py`: title/status/assignee +
  boards/status-indexes, TKB) — missing only `priority`, `scheduled_for`, `cost`; the
  planned **FXA-004/012/013** maintenance-work-order spec covers those, and **paid
  maintenance maps onto the bounty/escrow model (TBT-001..011)**.
- **Vendors → PUR-003** supplier party + a trade-category enum; **Documents → EVT-011/012**
  (record-link fields + revisions); **tabbed status views → HAVE** (ticket boards).

**The genuinely net-new is the real-estate spine:** Property, Unit, Tenant, and Lease
entities + rent-policy settings + a property-scoped rent-run + the portfolio dashboard.

---

## Gap matrix (condensed)

### A. Properties & Units + Portfolio Dashboard
| Capability | Status | Evidence / note |
|---|---|---|
| Property entity (type/address/tags/occupancy/owner) | **MISSING** | FAC facility is warehouse, not rental — net-new |
| Unit entity (beds/baths/sqft/market-rent/occupancy) | **MISSING** | FacilityLocation models bins, not dwellings — net-new |
| Property/unit list/filter + occupancy roll-up | **MISSING** | net-new |
| Portfolio KPIs (occupancy/active-leases/outstanding-rent/open-WOs) | **MISSING** | `platform_financial_dashboard` is GMV/revenue, not rent-roll |
| Monthly rent snapshot (collected/outstanding/overdue) | **MISSING** | needs rent-charge ledger |
| Generic configurable dashboard framework | **PLANNED** | RPT-006/007 dashlets — add a property dashlet once the domain exists |

### B. Tenants + Leases + Rent Ledger
| Capability | Status | Evidence / note |
|---|---|---|
| Tenant directory + basic profile | **PARTIAL** | thin `contacts.py`; PTY-003/004 PERSON party planned |
| Tenant employment / income verification | **MISSING** | net-new fields/attachments |
| Tenant emergency contacts | **MISSING** | PTY-006 relationship could model it |
| Tenant historical lease records | **MISSING** | depends on Lease |
| **Lease/tenancy entity** (term/rent/deposit/due-day/late-fee/status) | **MISSING** | QUO-004 CRM contract is the closest planned scaffold |
| Lease table + status filter + inline edit | **MISSING** | mirror QUO-004 list pattern |
| Rent — automated monthly charge per active lease | **PARTIAL** | clone `compute_billing.py` rent-run → `new_ledger_entry` |
| Rent — period totals (charged/collected/outstanding/overdue) | **PARTIAL** | reuse `compute_due` + planned OFB-015 aging |
| Rent — record payment (amount/method/date/ref) | **HAVE (primitive)** | thin wrapper over `new_ledger_entry` |
| Rent — auto status updates on payment | **PARTIAL** | derive from ledger `state` + due_day |
| Rent — payment history + void | **HAVE (primitive)** | ledger query + `settle_or_reverse_ledger` |

### C. Work Orders + Vendors + Policy + Documents
| Capability | Status | Evidence / note |
|---|---|---|
| Work-order entity (status/assignment/cost/scheduled) | **PARTIAL** | tickets.py covers ~70%; FXA-004/012/013 adds wo_status/cost/scheduled_for |
| Work-order priority (urgent/high/normal/low) | **MISSING** | add to the work-order/ticket entity |
| Tabbed status views (Kanban) | **HAVE** | ticket boards `_DEFAULT_BOARD_COLUMNS` + status indexes |
| Paid maintenance (escrow/claim/payout) | **PLANNED** | TICKET_BOUNTY (TBT-001..011) — fits paid work orders |
| Vendor directory (by trade) | **PLANNED** | PUR-003 supplier party + trade-category enum |
| Rent-policy settings (due-day/late-fee/grace/currency) | **PARTIAL** | only global currency exists — net-new entity |
| Documents linked to property/unit/lease/tenant | **PARTIAL/PLANNED** | EVT-011 record-link + EVT-012 revisions |

---

## Recommended new tickets (the property-management vertical, prefix **`PRP`**)

Clusters (each = several tickets: model/table/flag → service → router → FE → tests):

**Core real-estate spine (net-new) — ~14 tickets**
- **Property + Unit**: Property entity (type/address/tags/occupancy/owner) + Unit entity
  (beds/baths/sqft/market-rent/occupancy ∈ vacant/occupied/turnover/unavailable); list +
  filter + occupancy roll-up; router; FE (property cards + detail + unit grid).
- **Tenant**: tenant directory + profile (employment, income verification, emergency
  contacts) reusing PTY-004 PERSON / contacts; router; FE.
- **Lease**: lease entity (tenant↔unit, term, monthly rent, deposit, due-day, late-fee,
  status active/upcoming/ended) on the QUO-004 contract scaffold; list/filter/inline-edit;
  lease history per tenant; router; FE.

**Rent ledger & collections (mostly reuse) — ~6 tickets**
- Property-scoped **rent-run** timer (clone `compute_billing.py`) posting a monthly
  `new_ledger_entry` rent charge per active lease.
- **Record-payment** wrapper (amount/method/date/ref) + auto charge-status (open/paid/
  partial/overdue) from ledger `state` + due_day; payment history + void via
  `settle_or_reverse_ledger`.
- **Period summary** (charged/collected/outstanding/overdue) reusing `compute_due` +
  OFB-015 aging; FE rent-ledger page with period navigation.

**Maintenance, vendors, policy, docs, dashboard (extension) — ~8 tickets**
- **Work orders**: add `priority`/`scheduled_for`/`cost` + property/unit/vendor FKs to a
  flag-gated work-order (extend tickets or mirror FXA-012); reuse ticket boards for tabbed
  views; optional **paid-maintenance** via the TBT bounty escrow.
- **Vendors**: trade-categorized vendor directory on the PUR-003 supplier model.
- **Rent-policy settings** entity (due-day/late-fee/grace/currency) — greenfield admin CRUD.
- **Documents**: implement EVT-011 record-link fields so files attach to property/unit/
  lease/tenant (+ EVT-012 revisions for lease versions).
- **Portfolio dashboard**: KPI service (occupancy/active-leases/outstanding-rent/open-WOs)
  + monthly rent snapshot + priority items (open WOs + upcoming lease expirations);
  surface as an RPT-006/007 property dashlet.
- Tests (hermetic pytest + E2E).

**Already HAVE/PLANNED → NO new ticket:** tabbed board views (tickets), the recurring
auto-charge + ledger + AR-aging primitives (billing/compute_billing/OFB-015), paid-work
escrow (TBT), supplier party (PUR-003), document revisions (EVT-012), dashlet framework
(RPT-006/007) — these are reused/depended-on, not re-ticketed.

## Scope tiers (for the build decision)
- **Core spine** (Property/Unit/Tenant/Lease): ~14 tickets
- **+ Rent ledger & collections:** ~6
- **+ Maintenance/Vendors/Policy/Docs/Dashboard:** ~8
- **Everything:** ~28 tickets

All additive + flag-gated default-off, reusing existing primitives (billing ledger,
compute_billing rent-run pattern, tickets/boards, bounty escrow, PUR suppliers, EVT
documents, QUO contracts, RPT dashlets) — never forking.
