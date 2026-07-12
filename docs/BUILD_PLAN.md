# BUILD_PLAN.md — Consolidated cross-domain build plan

Build sequencing for the **531-spec design corpus** (530 vertical specs + 1 platform branding spec)
across 8 domains. Derived from each domain's harvested cluster dependency data and the cross-domain
edges + resolved product decisions in `docs/CROSS_TICKET_AUDIT.md` (Part A / Part D).

---

## 1. Overview & how to read

- **The whole corpus is additive + flag-gated, default-OFF.** Every vertical mounts its routers but
  every handler is a `404` no-op until its `<VERTICAL>_ENABLED` flag flips (open-property standardizes
  to 404 per audit A5-A; the platform stays byte-for-byte unchanged with all flags off).
- **Verticals are largely independent parallel workstreams** once their own foundation entity lands.
  The only true *global* blockers are the two **Wave-0** code foundations. The only *cross-domain*
  hard ordering is the **party spine** (OFBiz PTY → SuiteCRM → OpenCATS) and the **money spine**
  (Wave-0 ledger → all money readers).
- **Wave model:** Wave 0 = cross-cutting code foundations (must land first). Wave 1 = each domain's
  root entity cluster (parallel across domains). Wave 2+ = feature build-out per domain, in
  dependency order, batched for parallelism. `wave_hint` from each cluster is the within-domain wave.

**Legend**

| Symbol | Meaning |
|---|---|
| ▶ | Parallelizable group — these units have no unmet dependency on each other; fan them out concurrently |
| → | Ordered edge — left must complete before right |
| ⛓ | Cross-domain hard edge — blocks across domain boundaries |
| ⛓̃ | Cross-domain **soft** edge — lazy-import / try-except, degrades gracefully; does **not** block |
| ☐ | Already-LIVE primitive — reused, no build |

---

## 2. Wave 0 — cross-cutting foundations (must land first)

The only two true global blockers. Both `wave_hint = 0`, zero upstream deps, reuse only live primitives.

### (a) D1 — billing ledger `signed_amount_cents` + one-time backfill

| | |
|---|---|
| **Ticket** | `LEDGER-SIGNED-AMOUNT (D1)` |
| **Build order** | `billing_shared.new_ledger_entry` stamps `signed_amount_cents` at write → refund/void writers (`refund_payment`, SHP-019, INV-009, QUO-005) stamp it (all amended to **positive** `amount_cents` + reversal-typed entry) → ACC-002 reader prefers it (ACC-002 §5 type→sign fallback for legacy rows) → one-time backfill of legacy rows |
| **Touches (live)** | ☐ `app/services/billing_shared.py` `new_ledger_entry`; ☐ `app/routers/billing.py` `refund_payment` (+ `settle_or_reverse_ledger` flip) |
| **Gates (money readers)** | ⛓ OBP **ACC-002** balance reader & **TXR-004** execution; ⛓ open-property **RNT-002/003/006**; ⛓ QloApps **HTL-021/029-032/033** folio refunds; ⛓ SuiteCRM **SHP-019 / INV-009 / QUO-005**; platform financial dashboards |

> This resolves the **only correctness risk** in the corpus (sign-mismatch on SHP-019, INV-009/QUO-005 negative rows).

### (b) D6 — BRAND-001 platform branding

| | |
|---|---|
| **Ticket** | `BRAND-001` (`docs/platform/specs/BRAND-001.md`) |
| **Build order** | new `platform_settings` table + `PLATFORM#BRANDING` row → `branding.py` `get_branding()` / `invalidate_cache()` (cached, env-default fallback) → `/ui/admin/branding` GET (admin) + PUT (root) router → consumers migrate to `get_branding().platform_name` |
| **Touches (live)** | ☐ `billing_config.py` (cache idiom copied); ☐ `app/core/tables.py` / `local-ddb-init.py` TableDef; ☐ `app/auth/policy.py` (root PUT / admin GET / CSRF); ☐ `alerts.audit_event`; ☐ `app/main.py` router mount |
| **Gates** | ⛓ SuiteCRM **CMP-006** (supersedes bespoke `web_to_lead_platform_name`), **CMP-008** (`{{platform_name}}` merge tag), **ADMIN-002** notification-template send sites |

### (c) ☐ Already-LIVE shared primitives — NO build

Reused by every vertical without forking:

- ☐ `billing_shared.py` — ledger (`new_ledger_entry` / `settle_or_reverse_ledger`), wallet (`apply_wallet_delta`)
- ☐ `app/routers/billing.py` `refund_payment` — canonical refund (positive adjustment + original-row flip)
- ☐ `alerts.py` — `audit_event` (flattened `**fields`), `write_alert` (`details=`), `send_alert_email`
- ☐ `sessions.py` + `app/auth/policy.py` — `require_ui_session` / `require_admin` / `require_root` / `enforce_cookie_csrf` + MFA/SCA challenge stack
- ☐ `catalog.py` / `shoppingcart.py` (add_item allowlist) / `calendar.py` / `contacts.py` (router only — **no** `contacts.py` service; HTL-027 uses opaque `guest_party_id`)
- ☐ `mfa.py`, `api_keys.py` (+ scope registry), `webhook_service.py`, `kyc_cases.py`, `compute_billing.py` (`record_billing_tick` / timer), `tickets.py`, `filemanager.py` + `s3_client`, `questionnaires`, `rate_limit._bucket_limit`, `core/cursor`, `core/time.now_ts`, `normalize`

---

## 3. Wave 1 — domain foundation entities (parallelizable across domains)

One root cluster per domain. **All can run concurrently EXCEPT SuiteCRM's PTY-dependent clusters,
which wait on the OFBiz PTY spine.** OFBiz PTY is the **cross-domain spine root** — land it early.

| Domain | Foundation cluster | Foundation ticket | Concurrent? | Notes |
|---|---|---|:--:|---|
| **OFBiz** | OFB commerce/ERP core | **OFB-002** | ▶ yes | Owns D1 GL poster (OFB-014) + D2 pricing façade (OFB-019); underpins most OFBiz clusters |
| **OFBiz** | PTY Party/CRM spine | **PTY-001** | ▶ yes | ⛓ **SPINE ROOT** — feeds SuiteCRM (org/account) + OpenCATS (party identity) + HRM-004. No OFBiz-internal upstream. **Land early.** |
| **OpenCATS** | JOB job-order entity | **JOB-001** | ▶ yes | Net-new; lazy-imports only |
| **OpenCATS** | CND candidate entity | **CND-001** | ▶ yes | Owns ATS master flag (`candidates_enabled`); no hard dep on JOB |
| **Open Bank** | ACC banks/accounts/txns | **ACC-001** | ▶ yes | Defines umbrella `OPEN_BANK_PROJECT_ENABLED` (D4); ⛓ reads Wave-0 ledger |
| **open-property** | PROP property & unit | **PROP-001** | ▶ yes | Root FK source for TEN/LSE/RNT/WOV/PMD |
| **ticket-bounty** | TBT escrow bounty | **TBT-001** | ▶ yes | ⛓ Wave-0 ledger; TKA attachments can run in parallel |
| **QloApps** | HTL T1 spine (hotels+amenities) | **HTL-001** | ▶ yes | Owns `HOTEL_PMS_ENABLED`; HTL availability (HTL-010) + rate-plans (HTL-014) are also wave-1 self-founding |
| **SuiteCRM** | *(no single root)* — strongest-foundation clusters are **CAS-001, RPT-001, LED-001, STU-001, QUO-001, WFL-001, PRJ-001, OPP-001** | (per cluster) | ▶ mostly | These have **no** PTY dep → parallel in Wave 1. **CCT + CMP wait on PTY/MKT** (Wave 3). |

---

## 4. Wave 2+ — feature build-out, by domain

Clusters listed in dependency order, grouped into **▶ parallel batches** (clusters with no unmet
intra-domain dep run concurrently). Per-cluster: ticket range · foundation · same-domain deps · ⛓ cross-domain.

### 4.1 OFBiz (13 clusters, 209 specs) — buildout-plan phases

**Batch A (Wave 1) ▶** — no intra-domain deps:
- **OFB** core `OFB-001..022` · found **OFB-002** · intra: see file Dependency-order (inventory→returns→GL→pricing) · ⛓ Wave-0 D1 (OFB-014 GL poster), D2 (OFB-019 pricing façade)
- **PTY** `PTY-001..015` · found **PTY-001** · ⛓ **spine root** (SuiteCRM, OpenCATS, HRM-004)

**Batch B (Wave 2) ▶** — gate on OFB and/or standalone:
- **PRD** catalog depth `PRD-001..016` · found **PRD-002** · → OFB (inventory SKUs, runtime)
- **ORD** order lifecycle `ORD-001..015` · found **ORD-003** · standalone (refund/ledger are LIVE)
- **FAC** facility/fulfillment `FAC-001..015` · found **FAC-002** · → **OFB**; emits hand-off ORD consumes (try-except)

**Batch C (Wave 3) ▶** — multi-cluster gated:
- **PUR** purchasing `PUR-001..017` · found **PUR-002** · → **OFB** (inventory+GL/AR-AP); ⛓̃ PTY suppliers (soft)
- **SHP** shipping `SHP-001..019` · found **SHP-002** · → **ORD**; ☐ carrier_tracking; ⛓ Wave-0 D1 (SHP-015/019)
- **MKT** marketing `MKT-001..014` · found **MKT-002** · standalone; ⛓ PTY party segments; ☐ ads/promo/cart_reminders
- **MFG** manufacturing `MFG-001..014` · found **MFG-002** · → **OFB** (inventory + OFB-014 poster)
- **POS** point-of-sale `POS-001..014` · found **POS-003** · → **OFB**; ☐ shoppingcart/billing/refund
- **HRM** payroll `HRM-001..013` · found **HRM-002** · → **OFB** + ⛓ **PTY** (HRM-004 EMPLOYEE party)
- **FXA** fixed assets `FXA-001..017` · found **FXA-002** · → **OFB** (OFB-013/014 poster, contra_asset)
- **ECM** storefront integration `ECM-001..015` · found **ECM-002** · → **PRD + OFB + FAC + ORD + SHP** (most-gated; pure integration, all flag-gated graceful-degrade)

### 4.2 SuiteCRM (20 clusters incl. 6 EVT sub-clusters)

**Batch A (Wave 1) ▶** — self-contained:
- **LED** leads `LED-001..013` · found **LED-001** · ⛓̃ PTY/MKT (soft, inline-stub)
- **OPP** opportunities `OPP-001..006` · found **OPP-001** · ⛓̃ PTY-004 (soft)
- **CAS** cases/portal `CAS-001..017` · found **CAS-001** · ☐ tickets/SES/questionnaires
- **QUO** quotes/contracts `QUO-001..005` · found **QUO-001** · ☐ invoices; ⛓ Wave-0 D1 (QUO-003/005); ⛓̃ D6
- **RPT** reports/dashboards `RPT-001..009` · found **RPT-001** · ☐ email/search/csv/recharts
- **WFL** workflow `WFL-001..009` · found **WFL-001** · ☐ scheduler/email
- **STU** security/studio `STU-001..014` · found **STU-001** · ☐ audit_export/admin_jobs/search
- **PRJ** projects/gantt `PRJ-001..012` · found **PRJ-001** · ⛓̃ PTY-011/015 (soft)

**Batch B (Wave 2) ▶** — intra-domain or live-app deps:
- **KB** knowledge base `KB-001..012` · found **KB-001** · → **CAS** (KB-001 extends CAS-001/015); ☐ search/S3
- **EML** email `EML-001..010` · found **EML-003** · ☐ notification_templates/tickets; EML-009 upstream of MKT-009
- **INV** invoices/currency `INV-001..012` · found **INV-001** · → **QUO** (INV-009 needs QUO-005); ⛓ Wave-0 D1, D6 (INV-008 branding); ⛓̃ PTY (soft)
- **ACT** activities `ACT-001..010` · found **ACT-001** · ☐ calendar/email/activity_feed; ⛓̃ PTY (soft)
- **EVT-Events** `EVT-001..004` · found **EVT-001** · ☐ calendar/email; ⛓̃ PTY-001 (soft)
- **EVT-Surveys** `EVT-008..010` · found **EVT-008** · ☐ questionnaires/csv
- **EVT-Documents** `EVT-011..013` · found **EVT-011** · ☐ filemanager/email; ⛓̃ PTY (soft)
- **EVT-SMS** `EVT-014` · found **EVT-014** · ☐ SMS service; ⛓̃ PTY (soft)
- **EVT-Audit** `EVT-015` · found **EVT-015** · ☐ audit_event store

**Batch C (Wave 3) ▶** — hard cross-domain (PTY/MKT):
- **CCT** contacts extra `CCT-001..006` · found **CCT-001** · ⛓ **OFBiz PTY-001..012** (hard — party model)
- **CMP** campaigns extra `CMP-001..008` · found **CMP-002** · ⛓ **OFBiz MKT-003/004/005/007/009/010/011** (hard); ⛓ D6 (CMP-006/008); ☐ cart_reminders/questionnaires
- **EVT-Geo/Map** `EVT-005..007` · found **EVT-005** · ⛓̃ PTY-001 (soft, table-presence conditional)

### 4.3 OpenCATS (6 clusters, 42 specs)

**Wave 1 ▶:** **JOB** `JOB-001..008` (found JOB-001) ▶ **CND** `CND-001..007` (found CND-001) — no hard dep on each other.

**Wave 2:** **PIP** pipeline `PIP-001..010` · found **PIP-001** · → **JOB + CND** (junction; lazy-import try-except; PIP-006 pushes JOB-005 `adjust_placed_count` — the one hard JOB←PIP runtime edge per audit B2-2)

**Wave 3 ▶** — all uniformly lazy-import/degrade when Tier-1 absent:
- **PRT** career portal `PRT-001..006` · found **PRT-001** · ⛓̃ JOB/CND/PIP (soft); ⛓ D6 (portal branding); ☐ questionnaires/filemanager/rate_limit
- **RSK** résumé/skills/search `RSK-001..006` · found **RSK-001** · ⛓ **CND** (hard forward dep) + ⛓̃ JOB (soft); reuses KB-009 index / LED-008/009 import patterns
- **ATI** ATS integration `ATI-001..005` · found **ATI-001** · ⛓ JOB+CND+PIP (hard) + ⛓ CCT/PTY/RPT/ACT (extends those); intra: 001-004 independent → ATI-005

> Flag-naming: CND-001's `candidates_enabled` is the authoritative ATS gate (audit B2-1; re-point RSK-001/003).

### 4.4 Open Bank Project (8 clusters, 42 specs)

All gate on umbrella `OPEN_BANK_PROJECT_ENABLED` (D4, defined in ACC-001) AND-ed with per-series flag.

**Wave 1:** **ACC** `ACC-001..005` · found **ACC-001** · ⛓ Wave-0 D1 (ACC-002 reader); ⛓̃ VEW (soft)

**Wave 2 ▶** — independent platform/security clusters (live primitives only):
- **OAU** OAuth2/OIDC `OAU-001..006` · found **OAU-001** · ☐ api_keys/crypto/MFA
- **PLT** platform surface `PLT-001..005` · found **PLT-001** · (5 mutually independent) · ☐ rate_limit/usage_metering/webhooks
- **VEW** account views `VEW-001..005` · found **VEW-001** · ☐ delegates/crypto/webhooks; ⛓̃ STU-002 (soft)
- **CUS** customers/cards/products `CUS-001..005` · found **CUS-001** · ☐ kyc/billing/catalog/webhooks
- **TXR** transaction-requests + SCA `TXR-001..005` · found **TXR-001** · ⛓ Wave-0 D1 (TXR-004 execution); ☐ MFA/SCA stack — the **only money-out rail**
- **CSN** PSD2 consents/dynamic `CSN-001..006` · found **CSN-001** · ⛓̃ OAU/VEW/ACC/TXR (all soft, opaque refs); moves no money

**Wave 3:** **PAY** counterparties/standing-orders/mandates/FX `PAY-001..005` · found **PAY-001** · ⛓ **TXR-001 + TXR-004** (hard — never settles money itself); ☐ unified_scheduler

### 4.5 open-property (6 clusters, 29 specs)

Standardized to **404** gate (audit A5-A; was 503 on TEN/WOV-001/RNT-004).

**Wave 1:** **PROP** `PROP-001..005` · found **PROP-001** · ☐ inventory/facilities idioms

**Wave 2 ▶** (after PROP):
- **TEN** tenant `TEN-001..004` · found **TEN-001** · → **PROP** (+ LSE for history); ⛓ **PTY-004** (hard PERSON party); ☐ filemanager
- **LSE** lease `LSE-001..004` · found **LSE-001** · → **PROP + TEN**; ☐ QUO-004 contract scaffold (pattern); ☐ invoices counter/tickets state-machine
- **RNT** rent ledger `RNT-001..006` · found **RNT-001** · → **LSE + PROP + TEN**; ⛓ Wave-0 D1 (every rent row); ⛓̃ OFB-015 AR-aging (soft)

**Wave 3 ▶:**
- **WOV** work orders + vendors `WOV-001..005` · found **WOV-001** · → **PROP**; ⛓̃ **TBT-001/003/006/007** (soft — WOV-003 escrow no-op until TBT lands, D2 hybrid payout); ☐ tickets/PUR-003 supplier (standalone fallback)
- **PMD** policy/docs/dashboard `PMD-001..005` · found **PMD-001** · → **PROP + LSE + RNT + WOV** (consumes surfaces, soft graceful-degrade); ⛓ EVT-011 (hard, `_LINKED_RECORD_TYPES` extension); ⛓̃ RPT-006/007 (soft dashlet)

### 4.6 ticket-bounty (2 clusters, 14 specs)

**Wave 1 ▶** (independent of each other):
- **TBT** escrow bounty `TBT-001..011` · found **TBT-001** · strict intra-order 001→011 · ⛓ Wave-0 D1 (all bounty ledger rows); ☐ billing_shared/tickets/creator_payouts. **Repost cap = NONE** (decision D3, `docs/CROSS_TICKET_AUDIT.md` §D3): `bounty_repost_count` is tracked but **unenforced** in v1; `S.ticket_bounty_max_reposts` is reserved/unused (TBT-001/002/003 + TICKET_BOUNTY_TICKETS.md all aligned to no-cap).
- **TKA** ticket attachments `TKA-001..003` · found **TKA-001** · borrows TBT-001 settings *pattern* only (own `ticket_attachments_enabled` flag); ☐ tickets/messaging presign/license_agreements validation

### 4.7 QloApps (9 clusters, 36 specs)

All gate on `HOTEL_PMS_ENABLED` (HTL-001).

**Wave 1 ▶** — Tier-1 self-founding spine:
- **HTL T1 spine** hotels+amenities `HTL-001..004` · found **HTL-001** · owns master flag + service module
- **HTL T1 availability** per-date inventory `HTL-010..013` · found **HTL-010** · net-new primitive
- **HTL T1 rate-plans** `HTL-014..016` · found **HTL-014** · net-new multi-night price engine; ⛓̃ HTL-005 (soft forward-ref)

**Wave 2 ▶:**
- **HTL T1 room-types** rooms+housekeeping `HTL-005..009` · found **HTL-005** · → **HTL-001 spine**
- **HTL T2 stay-search + reservation** `HTL-017..021` · found **HTL-018** · → all four T1 clusters (availability + pricing + spine + room-types)
- **HTL T2 front-desk** `HTL-022..024` · found **HTL-022** · → **reservation + room-types + availability**
- **HTL T2 storefront** `HTL-025..028` · found **HTL-025** · → **spine + room-types + reservation + availability**; ☐ shoppingcart/commerce_order/calendar public-booking

**Wave 3 ▶:**
- **HTL T3 folios** `HTL-029..032` · found **HTL-029** · → **reservation**; ⛓ Wave-0 D1 (ledger); ☐ invoices PDF / TBT escrow pattern
- **HTL T3 cancellation/reports/tax** `HTL-033..036` · found **HTL-033** · → **reservation + folios + availability + rate-plans**; ⛓ Wave-0 D1 (refund); ⛓̃ **INV-002..006 DARK** (D7 — soft, ships inert via flag-gated fallbacks, never blocks)

---

## 5. Cross-domain edge list (the spine)

Only the **hard** ordering edges that cross domain boundaries. Everything else within a domain is intra-domain.

| # | Edge | Type | Meaning |
|---|---|:--:|---|
| 1 | **Wave-0 D1 ledger** → OBP ACC-002/TXR-004, open-property RNT, QloApps HTL folios/cancel, TBT, SHP-019/INV-009/QUO-005, dashboards | ⛓ HARD | Money readers/writers must use `signed_amount_cents`; land D1 first |
| 2 | **Wave-0 D6 BRAND-001** → SuiteCRM CMP-006 / CMP-008 / ADMIN-002 | ⛓ HARD | `{{platform_name}}` source |
| 3 | **OFBiz PTY** (PTY-001..012) → SuiteCRM **CCT** (CCT-001 party/org model) | ⛓ HARD | CRM contact/account hierarchy builds on party |
| 4 | **OFBiz MKT** (MKT-003/004/005/007/009/010/011) → SuiteCRM **CMP** | ⛓ HARD | Campaign model/send/tracking upstream |
| 5 | **OFBiz PTY** → SuiteCRM CRM identity → **OpenCATS** ATS (CCT-001/PTY consumed by ATI, soft elsewhere) | ⛓ HARD (ATI) | Party spine: PTY → CRM → ATS |
| 6 | **OpenCATS JOB + CND** → **PIP**; PIP-006 → JOB-005 `adjust_placed_count` | ⛓ HARD | Junction + placement-counter push (audit B2-2) |
| 7 | **OpenCATS CND** → **RSK** (hard forward dep); → **ATI** (JOB+CND+PIP hard) | ⛓ HARD | ATS depth/integration layer |
| 8 | **OBP TXR-001 + TXR-004** → **PAY** | ⛓ HARD | PAY never settles money itself |
| 9 | **open-property PTY-004** → **TEN**; **SuiteCRM EVT-011** → **PMD** | ⛓ HARD | PERSON party / `_LINKED_RECORD_TYPES` |
| 10 | **SuiteCRM QUO-005** → **INV-009**; **CAS** → **KB** | ⛓ (intra-domain, listed for completeness) | INV needs QUO; KB extends CAS |

**SOFT / dark edges (do NOT block — lazy-import + try-except, degrade to empty/404/inert):**

| Edge | Why soft |
|---|---|
| open-property **WOV-003** → ticket-bounty **TBT** | Escrow path is a no-op behind sub-flag until TBT lands (D2 hybrid payout) |
| QloApps **HTL-036** → SuiteCRM **INV-002..006** | Ships **DARK** (D7); flag-gated `getattr`/lazy fallbacks; activates when INV-* flips |
| Many SuiteCRM clusters (LED/OPP/ACT/PRJ/EVT) → **PTY** | Opaque `linked_entity_id` today; resolves once PTY ships |
| OFBiz **PUR/MKT suppliers/segments** → **PTY** | Forward-compatible, not a build prereq |
| OpenCATS **PRT/RSK/ATI** → JOB/CND/PIP | Uniform lazy-import graceful degradation |
| OBP **CSN** → OAU/VEW/ACC/TXR | Opaque refs until those land; **CUS** → ACC-001 (future card→account link) |
| open-property **RNT** → OFBiz **OFB-015** AR-aging | Graceful fallback to `derive_charge_status` |

---

## 6. Parallelism guide for a build workflow

Concrete fan-out schedule. Each **runnable unit** below = one workflow agent. **Barriers** are the
gate conditions that must be satisfied before the next wave dispatches.

### WAVE 0 (2 units, serial-ish — both must finish before any money/branding consumer)
- Unit `W0-D1` — ledger `signed_amount_cents` + backfill
- Unit `W0-D6` — BRAND-001
- **Barrier B0:** both merged. (D1 unblocks all money verticals; D6 unblocks CMP. Wave-1 entity work
  that touches **no** money/branding can start in parallel with W0 — but money readers/writers wait on B0.)

### WAVE 1 — domain foundation entities (≈12 units, ▶ fully parallel after B0)
Dispatch concurrently:
- `OFBiz/OFB-core` · `OFBiz/PTY` *(spine root — prioritize)*
- `OpenCATS/JOB` · `OpenCATS/CND`
- `OBP/ACC`
- `open-property/PROP`
- `ticket-bounty/TBT` · `ticket-bounty/TKA`
- `QloApps/HTL-spine` · `QloApps/HTL-availability` · `QloApps/HTL-rateplans`
- `SuiteCRM/{LED,OPP,CAS,QUO,RPT,WFL,STU,PRJ}` *(the 8 PTY-free CRM clusters — each its own unit)*

**Barriers out of Wave 1:**
- **B1-PTY:** OFBiz PTY merged → unblocks SuiteCRM CCT (Wave 3) + OpenCATS ATI.
- **B1-OFB:** OFB-core merged → unblocks OFBiz FAC/PUR/MFG/POS/HRM/FXA + MKT.
- **B1-ATS:** JOB + CND merged → unblocks OpenCATS PIP.
- **B1-PROP / B1-HTL1 / B1-ACC / B1-QUO etc.:** each domain's wave-2 sub-tree.

### WAVE 2 — first feature batch (▶ parallel within & across domains as barriers allow)
- OFBiz: `PRD` · `ORD` · `FAC` *(after B1-OFB)*
- OpenCATS: `PIP` *(after B1-ATS)*
- OBP: `OAU` · `PLT` · `VEW` · `CUS` · `TXR` · `CSN` *(after B1-ACC; 6-way parallel)*
- open-property: `TEN` · `LSE` *(after B1-PROP + B1-PTY for TEN); then `RNT` (after LSE)*
- QloApps: `HTL-roomtypes` → `HTL-reservation` → `HTL-frontdesk` · `HTL-storefront`
- SuiteCRM: `KB` *(after CAS)* · `EML` · `INV` *(after QUO)* · `ACT` · `EVT-{Events,Surveys,Documents,SMS,Audit}`

**Barrier B2:** money-rail (TXR), reservation entity (HTL-018), RNT, PIP merged → unblock their Wave-3 consumers.

### WAVE 3 — gated / integration clusters (▶ parallel)
- OFBiz: `PUR` · `SHP` *(after ORD)* · `MKT` · `MFG` · `POS` · `HRM` *(after PTY+OFB)* · `FXA` · `ECM` *(after PRD+FAC+ORD+SHP)*
- OpenCATS: `PRT` · `RSK` · `ATI` *(after PIP + B1-PTY)*
- OBP: `PAY` *(after TXR)*
- open-property: `WOV` *(after PROP; TBT soft)* · `PMD` *(after PROP+LSE+RNT+WOV)*
- SuiteCRM: `CCT` *(after PTY)* · `CMP` *(after MKT + D6)* · `EVT-Geo`
- QloApps: `HTL-folios` *(after reservation + D1)* · `HTL-cancellation/reports` *(after folios; INV-* dark)*

**Mapping rule for agents:** one runnable unit = one cluster (its tickets build in the cluster's
own `## 11 Dependency-order` internally). Fan out all units sharing a wave whose barriers are
satisfied; hold any unit whose ⛓ HARD upstream is unmerged. ⛓̃ SOFT upstreams never hold a unit.

---

### Counts

- **Domains:** 8 (incl. platform Wave-0) · **Specs:** 531 (530 vertical + BRAND-001)
- **Waves:** 4 (0–3) · **Clusters:** 55 buildable (OFBiz 13, SuiteCRM 20 incl. 6 EVT sub-clusters,
  OpenCATS 6, OBP 8, open-property 6, ticket-bounty 2, QloApps 9, platform Wave-0 2) + 1 informational live-primitives cluster
