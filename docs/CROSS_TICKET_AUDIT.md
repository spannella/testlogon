# Cross-Ticket Consistency Audit — All Design Specs

Generated 2026-06-13. Final consistency pass across **530 design specs in 7 domains**
(`docs/{ofbiz,suitecrm,opencats,openbankproject,open-property,ticket-bounty,qloapps}/specs/`).
This is the "are the tickets consistent with **each other**" audit requested as the final
follow-up after the four backlog explorations (OpenCATS, Open Bank Project, open-property,
QloApps) and the SuiteCRM/Bounty work.

| Domain | Specs |
|---|---|
| ofbiz | 209 |
| suitecrm | 158 |
| opencats | 42 |
| openbankproject | 42 |
| qloapps | 36 |
| open-property | 29 |
| ticket-bounty | 14 |
| **total** | **530** |

**Method.** Every spec carries a `## 12. Verification Log` from its second-pass verification
that tags claims VERIFIED / CORRECTED / FORWARD_DEP / **ESCALATED**. This audit harvests the
genuine ESCALATED items (cross-ticket inconsistencies and unowned artifacts), adds a
**cross-domain shared-primitive sweep** (audit_event, GL posting, pricing façade, the billing
ledger/refund convention, master-flag naming, shared Pydantic model names, GSI/`attr_types`,
ACL layering), and bakes a canonical resolution into each. OFBiz's 132 intra-domain
escalations already have their own reconciliation in `docs/ofbiz/specs/ESCALATIONS.md`; this
doc covers the other six domains plus everything that spans domain boundaries.

**Nothing here blocks *checking*.** It is the set that needs a resolution baked into the specs
before building. Items tagged **[FOR YOU]** want a product decision; everything else has a
determinate canonical default (mostly "align the dependent spec to the foundation spec that
owns the artifact").

---

## Part A — Cross-domain shared-primitive sweep

The highest-value half of the audit: do the specs agree with **each other** on shared
primitives and conventions? Verdicts are grounded in the live `app/services/*` signatures.

### A1. `audit_event` field nesting — ✅ CONSISTENT
Real signature `audit_event(event, user_sub, request=None, **fields)` (`app/services/alerts.py:644`)
flattens `**fields` into the persisted payload — there is no `details=` arg. All 7 domains call
it with flattened kwargs. The nested `details={...}` pattern (SuiteCRM CAS-008/CMP-001/EVT-013,
OFBiz MKT-009/OFB-005) is correctly attached to `write_alert(...)` (`alerts.py:356`), whose
signature *does* take `details=`. **No action.**

### A2. `post_journal_entry` / GL posting — ✅ CONSISTENT
OFBiz canonicalized one poster `post_journal_entry(lines, *, source_type, source_entity_id,
memo, gl_date, journal_id=None) -> str` in `gl_posting.py` (OFB-014; ESCALATIONS.md). **No
non-OFBiz spec references it.** OBP (the only other GL-adjacent domain) deliberately stays on the
single-entry billing ledger ("No new money rows are written" — ACC-002). GL double-entry is
OFBiz-internal by design. **No action** (the `contra_asset` account-class add is OFBiz-internal,
already tracked in ESCALATIONS.md row 13).

### A3. `apply_pricing_rules` cart-pricing façade — ✅ CONSISTENT
OFB-019 owns the public façade `apply_pricing_rules(user_sub, items, *, checkout_type)`;
OFB-020/ECM-009 consume it. **QloApps correctly avoids it**: HTL-014/015/016 borrow only the
ideas (rule-ordering, money-as-cents) and build a separate per-night/occupancy/LOS *stay* rate
engine, documenting that the cart façade "operates on a cart, not a stay — never called." The
cart-vs-stay separation is the right call. **No action.**

### A4. Billing ledger + refund convention — ⚠️ INCONSISTENT (highest-risk finding)
Canonical (live): `new_ledger_entry(...)` stores an **unsigned** `amount_cents`
(`int(amount_cents)`, `billing_shared.py:249`) + an `entry_type` discriminator (persisted field
is `"type"`, not `"entry_type"`, `:247`). Canonical refund `refund_payment` (`billing.py:1306-1324`)
= one **positive** `new_ledger_entry(entry_type="adjustment", amount_cents=<positive>,
state="settled", reason="refund")` **plus** `settle_or_reverse_ledger(..., "reversed")` flipping
the original row. ACC-002's reader verified `amount_cents` is "always stored as an absolute value"
and derives sign from the `type` suffix.

**Agree (no change):** OBP TXR-004 (single `_do_refund` call site, positive adjustment + flip,
double-refund prevented by `PENDING→IN_FLIGHT` claim), TBT-007 (wallet-credit refund, notes the
field is `"type"`), open-property RNT-002/003/006 (positive entries, voids via
`settle_or_reverse_ledger`), QloApps HTL-021/033 ("no money fork" — all refunds route through
`refund_payment`).

**Diverge (sign mismatch — real data-model contradiction):**
- **SHP-019** writes `new_ledger_entry(entry_type="adjustment", amount_cents=-shipping_amount_cents)`
  — a **negative** amount (test asserts `-500`).
- **SuiteCRM INV-009 / QUO-005** write `new_ledger_entry(entry_type="invoice_void_reversal",
  amount_cents=-original_total_cents, state="reversed")` — **negative** amount, explicitly choosing
  "a new negative-amount ledger row, not a state flip."

**Impact:** ACC-002's running-balance reader maps `adjustment`→positive by default, so a
negative-stored `adjustment` (SHP-019) moves the balance the wrong direction (double-negation);
INV-009's negative `invoice_void_reversal` falls through to positive and reduces the balance
incorrectly. ACC-002 already flagged the root gap: the ledger has **no `signed_amount_cents`** and
`adjustment` sign is ambiguous from `type` alone.

**Canonical resolution (bake in):**
1. `new_ledger_entry` always stores **unsigned** `amount_cents`; direction comes from `entry_type`
   + a `settle_or_reverse_ledger` flip on the original row. **Amend SHP-019 and INV-009/QUO-005**
   to positive amounts + a reversal/refund-typed entry.
2. **Amend ACC-002 §5 sign table** to enumerate every adjustment-family `entry_type`
   (`shipping_refund`, `invoice_void_reversal`, …) with an explicit credit/debit direction so no
   reader has to guess.
3. **Durable schema fix [FOR YOU]:** add a persisted `signed_amount_cents` at write time and
   require all refund/void/adjustment writers to stamp it. Recommend (1)+(2) now, (3) later.

There is **no double-refund / forked-Stripe-refund risk today** (TXR-004's single call site and
HTL-033's "no money fork" hold the line); the live risk is **sign-mismatch only**.

### A5. Master feature-flag naming + gate contract — ⚠️ INCONSISTENT (two issues)
Convention: `<VERTICAL>_ENABLED` env → `S.<vertical>_enabled`, default OFF, router-mounted but
every handler a **404** no-op via `_require_enabled()` (mirrors `inventory.py:50-56`).
Consistent: QloApps `HOTEL_PMS_ENABLED`, open-property `PROPERTY_MGMT_ENABLED`, ticket-bounty
`TICKET_BOUNTIES_ENABLED`, OFBiz per-vertical flags, OpenCATS `CANDIDATES_ENABLED`/`JOB_ORDERS_ENABLED`.

- **Issue A — open-property 503-vs-404 split.** PROP/LSE/PMD/RNT gate with **404**, but
  **TEN-001..004, WOV-001, RNT-004** gate with **HTTP 503** (they copied the `bot_auto_reply`
  503 idiom). This contradicts the domain's own foundation (PROP-001 = 404) and every other
  vertical. **Resolution: standardize open-property `_require_enabled()` on 404; amend
  TEN-001/002/003/004, WOV-001, RNT-004.**
- **Issue B — OBP has no single umbrella flag.** OpenBankProject uses per-series flags
  (`ACCOUNT_VIEWS_ENABLED`, `BANKING_ACCOUNTS_ENABLED`, `TXN_REQUESTS_ENABLED`, …), each a correct
  404-gated default-OFF "master flag for its series." Defensible (banking ships feature-by-feature).
  **[FOR YOU]:** add an umbrella `OPEN_BANK_PROJECT_ENABLED` for a single kill-switch, or document
  the per-series model. Low priority.

### A6. Shared Pydantic model collisions — ⚠️ INCONSISTENT (two live collisions + one latent)
- **`ReservationOut` — LIVE COLLISION.** Already exists at `app/models.py:618` (inventory
  reservation). **QloApps HTL-018 §2.8 wrongly claims it doesn't exist** and adds a hotel-stay
  `ReservationOut`. **Resolution: rename HTL-018's class to `StayReservationOut` (or
  `HotelReservationOut`); correct the false §2.8 claim.**
- **`TenantOut` — LIVE COLLISION.** Already exists at `app/models.py:4158` (SaaS multi-tenant
  branding). open-property TEN-003 plans another `TenantOut`; TEN-001 never flags it. **Resolution:
  rename open-property's class to `PropertyTenantOut`; update TEN-001/003 + LSE-004.**
- **`Address` — LATENT collision.** Both PROP-001 and HTL-001 independently add a same-named,
  same-shape `Address` to `app/models.py`; each verified no live `Address` but neither cross-checked
  the other. **Resolution: namespace both as `PropertyAddress` + `HotelAddress`** (or designate one
  shared owner). Each spec already has the alias fallback; make it the committed choice.

### A7. GSI naming / numeric `attr_types` — ✅ CONSISTENT (well-handled)
The flagged **RPT-004 vs RPT-001** conflict is already resolved inside RPT-001: the two logical
names (`owner-reports-index` + `rpt-schedules-due-index`) are ONE physical GSI (`GSI1PK`/`GSI1SK`),
RPT-004 queries it via a different `GSI1PK` value prefix (the `AuditExports`/`schedules-due-index`
precedent). Numeric-GSI `attr_types` discipline is uniform across domains. **No action** (minor:
a build-time guard against two different-domain tables sharing an `index_name` string would be nice).

### A8. ACL / role layering — ✅ CONSISTENT BY DESIGN
Three intentionally distinct authz layers, none reimplementing another: **STU-002/003/004** =
SuiteCRM per-module CRM ACL (`CRM_ACL_ENABLED`); **VEW** = OBP banking field-level account access
(deny-by-default `resolve_account_access`/`project_resource`); **owner-scoping** = ATS
(`require_ui_session` + owner checks). OBP and OpenCATS explicitly mark STU as "future, not
required." **No action** — worth a one-line note in a conventions doc so future specs don't assume
STU is platform-wide.

---

## Part B — Per-domain escalations (canonical resolutions)

### B1. SuiteCRM (158 specs)
| # | Spec | Inconsistency | Owner | Canonical resolution | X-domain |
|---|------|---------------|-------|----------------------|:--:|
| 1 | CCT-001 | `CrmOrgOut` (PTY-013: `org_party_id`+`owner_user_sub`) vs `CrmOrgAccountOut` (PTY-003: `party_id`, no owner field) | PTY-003/013 | Party module aligns all three: one model name, one id field, surface `owner_user_sub` (PTY-008 already accepts it) on the Out model | Y (PTY) |
| 2 | CMP-008 | `{{platform_name}}` injected but `S.platform_name` doesn't exist; siblings diverge (CMP-006 has its own `web_to_lead_platform_name`) | unowned | Add one shared `S.platform_name`/`S.app_name` in a branding ticket all MKT/CMP specs reference; until then `getattr(S,"platform_name","")` renders empty | Y (MKT+CMP) |
| 3 | INV-012 | Admin `GET /ui/admin/invoices/{number}` created by no ticket | unowned | Don't add; use the owner-facing `GET /ui/invoices/{number}`. Open product choice, deferred | N |
| 4 | INV-012 | Admin `mark-paid` (`sent→paid`) endpoint doesn't exist | QUO-005 §10.1 | Use owner-facing `/pay`; an admin pay-on-behalf stays an open QUO-005 decision **[FOR YOU]** | Y (QUO) |
| 5 | LED-005 | Assumes `create_lead(extra=)` kwarg LED-003 doesn't commit to | LED-003 | LED-003 adds optional `extra: dict` kwarg (preferred) else post-create `update_item` | N |
| 6 | LED-011 | Score-history auth hedges `require_ui_session` vs `get_authenticated_user` | LED-013 | Reconcile to LED-013: `require_ui_session` on `/ui/leads` + per-resource ownership | N |
| 7 | LED-012 | `CRM_ACTIVITY_TTL_SECONDS` default 1yr vs social activity feed 30-day TTL | LED-012 | Keep 1yr for CRM activity (intentional longer retention); tunable env, not a conflict | Y (activity_feed) |
| 8 | LED-013 | `/ui/admin/leads` vs `/ui/leads/admin` prefix | LED-013 | Adopt `/ui/admin/leads` (matches `/ui/admin/audit-exports`) | Y (admin route convention) |
| 9 | RPT-004 | Second physical GSI vs RPT-001's single value-prefixed index | RPT-001 | Already reconciled in RPT-001: one physical `GSI1` queried by `GSI1PK` prefix; declare numeric `attr_types` on `GSI1SK`/`GSI2SK` if a 2nd is kept | N |
| — | OPP-001..005, PRJ-006, KB-002..006 | Deferred intra-domain design choices (GSI projection, stage config, contact-role cascade, KB tree/rating/analytics) | each spec §10 | Documented deferrals with safe defaults; not blocking. PRJ-006 needs PRJ-003 `create_task(task_id=, skip_date_validation=)` kwargs (additive) | mostly N |

> Note: all EVT, ACT, CAS, STU, WFL, QUO (except QUO-005 admin-pay), and LED-001..010 specs
> report **0 genuine escalations** — their "ESCALATED" mentions are legend/tally text only.

### B2. OpenCATS (42 specs)
| # | Spec | Inconsistency | Owner | Canonical resolution | X-domain |
|---|------|---------------|-------|----------------------|:--:|
| 1 | RSK-001/003/004/006 | ATS master-flag named two ways: `ATS_RECRUITING_ENABLED` (placeholder) vs `CANDIDATES_ENABLED` (CND-001, authoritative) | CND-001 | **Adopt `S.candidates_enabled`** (CND-001 ships it; RSK-004/005/006 already use it); re-point RSK-001/003. Sub-flag `ats_skills_enabled` unaffected | Y (flag naming) |
| 2 | JOB-005 ↔ PIP-006 | Placement counter: JOB-005 = **push** (PIP-006 calls `adjust_placed_count(±1)`); PIP-006 = **pull** (scan `…#PLACEMENT` rows). Mutually exclusive | PIP-006 | **Adopt push**: amend PIP-006 to call `adjust_placed_count` on place/un-place (O(1) reads vs per-read scan) | Y (PIP cluster) |
| 3 | PIP-005 | Needs `get_primary_resume_item(candidate_id)` — in neither CND-003 nor CND-005 | CND-003 | **Add the wrapper to CND-003** (owns `primary_resume_id` + `ATTACHMENT#` sub-items). PIP-005 already degrades gracefully (`no_primary_resume`) | Y (CND cluster) |
| 4 | ATI-003 | Logs `calendar_event` as the `activity_type` for log-and-schedule | ACT-009 | Valid member of `_VALID_ACTIVITY_TYPES`; advisory UX note only, no change | Y (advisory) |

### B3. Open Bank Project + open-property + ticket-bounty (85 specs)
| # | Spec | Inconsistency | Owner | Canonical resolution | X-domain |
|---|------|---------------|-------|----------------------|:--:|
| 1 | ACC-002 | Ledger read can't derive sign for `adjustment` rows — ledger stores unsigned `amount_cents`, no `signed_amount_cents` | billing ledger write-side | See A4: amend the negative-amount writers + ACC-002 §5 sign table; durable fix = persist `signed_amount_cents` **[FOR YOU]** | Y (money) |
| 2 | TXR-004 | COUNTERPARTY stub debits then reverses via two non-atomic `apply_wallet_delta` calls | TXR-004 | Accepted for the stub; production wraps in `transact_write_items` (precedent `group_treasury.py:743`) | Y (money) |
| 3 | WOV-003 | `_resolve_vendor_sub` reads `vendor.user_sub` but WOV-004 `VendorOut` has only `created_by`; a PUR-003 supplier party has **no platform wallet** → every escrow release 409s | WOV-004 | **[FOR YOU]** pick: (a) WOV-004 adds optional `user_sub` linking a vendor to a platform account; (b) payout to an admin clearing account; (c) restrict release to wallet-bearing vendors | Y (money, payee identity) |
| 4 | TBT-003 | No cap on `bounty_repost_count` (unlimited reposts after cancel) | TBT-003 | **[FOR YOU]** v1 stance = no cap (per §10); a cap (e.g. 3) is a product go/no-go before ship | N (policy) |

### B4. QloApps (36 specs)
| # | Spec | Inconsistency | Owner | Canonical resolution | X-domain |
|---|------|---------------|-------|----------------------|:--:|
| 1 | HTL-001 | Shared `Address` model (also added by PROP-001) | PROP-001/HTL-001 | See A6: namespace `PropertyAddress` + `HotelAddress` | Y |
| 2 | HTL-018/022 | Reservation GSI names: FRONT_DESK prose `GSI_HOTEL_CHECKIN`/`GSI_HOTEL_CHECKOUT` vs HTL-018 authoritative `GSI_HOTEL_ARRIVALS`/`GSI_HOTEL_STATUS`/`GSI_GUEST` (no checkout index) | HTL-018 | Adopt HTL-018 names (`CHECKIN`≡`ARRIVALS`); no checkout index — derive departures from `GSI_HOTEL_STATUS` + in-memory `checkout==date`. Fix FRONT_DESK ticket prose | N |
| 3 | HTL-018 | Adds a `ReservationOut` that already exists live (`app/models.py:618`) | HTL-018 | Rename to `StayReservationOut`; correct §2.8 | Y (models) |
| 4 | HTL-025 | Publish gate reads `status=="published"` AND `published==True` but HTL-001 has only `status∈{active,archived}` | HTL-001 | Gate = `status=="active"`; `published`/`draft` only as defensive future branches | N |
| 5 | HTL-027 | Top-level `booking_meta` dropped by `shoppingcart.add_item` allowlist | shoppingcart/HTL-027 | Nest under allowlisted `scope`/`rental_metadata` (or extend the allowlist); leave `product_type` unset on room-night lines | Y (catalog/cart) |
| 6 | HTL-027 | Guest "create a Contact" — `app/services/contacts.py` doesn't exist; contacts need an authed owner | HTL-027 | Resolve guest as opaque `guest_party_id = "guest_"+sha256(email)[:24]` (HTL-018 §2.7 opaque-FK idiom); defer a real guest-CRM row | Y (contacts) |
| 7 | HTL-034 | Reservation dates are date-strings `checkin`/`checkout` (HTL-018) but the engine consumes `check_in_ts` (numeric) | HTL-033/018 seam | HTL-018 also persists `check_in_ts`/`check_out_ts` (int), or HTL-033 derives ts from the date-string | N |
| 8 | HTL-036 | Tax/currency wire-in depends on **unbuilt** INV-002..006 (zero `app/` code) | INV-002..006 | Ship with `getattr`+lazy-`try/except` + flat-bps/opaque-currency fallbacks; wire-in stays dark until INV-002..006 are built **[FOR YOU to sequence]** | Y (SuiteCRM INV) |
| 9 | HTL-006/007/019 | `set_room_status(occupied/dirty/vacant)` (HTL-019, from parent ticket) vs HTL-006 `update_room(status∈{available,out_of_service})` + HTL-007 `set_room_housekeeping_status(clean/dirty/inspected/out_of_service)` | HTL-006/007 | Reconcile when HTL-006/007 land: HTL-019 calls `update_room` for occupancy + `set_room_housekeeping_status` for cleaning; drop the unowned `set_room_status` name. (Tagged FORWARD_DEP in HTL-019, listed here for completeness) | N |

---

## Part C — Prioritized amendment list

Determinate fixes to bake into the specs (high → low leverage):

1. **Ledger sign convention (A4).** Amend **SHP-019** and **SuiteCRM INV-009/QUO-005** to write
   **positive** `amount_cents` + a reversal/refund-typed entry (not a negative row); extend
   **ACC-002 §5** sign table with `shipping_refund` / `invoice_void_reversal` directions.
   *(Durable `signed_amount_cents` schema add = [FOR YOU].)*
2. **`ReservationOut` collision (A6).** Rename **HTL-018**'s class → `StayReservationOut`; fix its
   false "does not exist" claim.
3. **`TenantOut` collision (A6).** Rename open-property's class → `PropertyTenantOut`; update
   **TEN-001/003, LSE-004**.
4. **open-property gate 503→404 (A5-A).** Standardize `_require_enabled()` on 404 in
   **TEN-001/002/003/004, WOV-001, RNT-004**.
5. **`Address` namespacing (A6).** Commit **PROP-001 → `PropertyAddress`**, **HTL-001 →
   `HotelAddress`** (drop the "reuse if present" hedge).
6. **ATS master flag (B2-1).** Re-point **RSK-001/003** to `S.candidates_enabled` (CND-001 owns).
7. **Placement counter (B2-2).** Amend **PIP-006** to push `adjust_placed_count(±1)`.
8. **`get_primary_resume_item` (B2-3).** Add to **CND-003**.
9. **Reservation GSI prose (B4-2).** Fix FRONT_DESK ticket prose to the HTL-018 names.
10. **PTY org model (B1-1).** Align **PTY-003/013** `CrmOrgOut`/`CrmOrgAccountOut` + `owner_user_sub`.
11. Smaller determinate kwargs/prefixes: LED-005 `extra=`, LED-011 auth → LED-013, LED-013
    `/ui/admin/leads`, PRJ-006 `create_task` kwargs, HTL-025 publish gate, HTL-027 `booking_meta`
    nesting + `guest_party_id`, HTL-034/018 `check_in_ts` seam, HTL-006/007/019 room-status.

**Product decisions — ✅ RESOLVED 2026-06-13 (see Part D for the canonical design baked into the specs):**
- Durable `signed_amount_cents` ledger column (A4-3) → **ADD it** (canonical; type-table fallback for legacy rows).
- WOV-003 vendor-payout identity (B3-3) → **HYBRID**: pay the linked wallet if `user_sub` exists, else a clearing account.
- TBT-003 bounty repost cap (B3-4) → **NO CAP** (explicit v1 decision; counter stays tracked-but-unenforced).
- OBP umbrella flag (A5-B) → **ADD `OPEN_BANK_PROJECT_ENABLED`** (AND-ed with each per-series flag).
- Admin invoice settlement (B1-4) → **ADD admin record-external-payment** (mark-paid + ledger entry, no Stripe charge).
- Shared branding (B1-2) → **ROOT-ADMIN CONFIGURABLE** (`PLATFORM#BRANDING` row + `/ui/admin/branding`, env default).
- HTL-036 sequencing (B4-8) → **SHIP DARK** (getattr/lazy-import fallbacks; INV-002..006 built later).

---

## Part D — Resolved product decisions (2026-06-13)

The seven `[FOR YOU]` items from Part C, decided and baked into the affected specs.

### D1. Ledger sign → add `signed_amount_cents` (canonical; type-table fallback)
`billing_shared.new_ledger_entry` stamps a **`signed_amount_cents`** at write time (credit `+`,
charge/debit `−`; `adjustment`/refund direction set explicitly by the caller). Readers sum
`signed_amount_cents` and fall back to the ACC-002 §5 type→sign table **only** for legacy/unstamped
rows; a one-time backfill stamps existing rows at build. `amount_cents` stays unsigned (display).
**Specs amended:** ACC-002 (reader prefers `signed_amount_cents`), SHP-019 / INV-009 / QUO-005 /
`refund_payment` (writers stamp it; all already positive `amount_cents` per A4).

### D2. WOV-003 vendor payout → hybrid (linked wallet, else clearing account)
**WOV-004** `VendorOut` gains an optional **`user_sub`** linking a vendor to a platform account.
**WOV-003** `_release_escrow`: if `vendor.user_sub` → `apply_wallet_delta(user_sub, +amount)`;
else → credit a platform **maintenance clearing account** (reserved system sub, e.g.
`CLEARING#maintenance`) + write a pending-disbursement marker for admin off-platform payout +
reconciliation. Both paths use the single ledger and are idempotent; no 409 dead-end.

### D3. TBT-003 repost cap → no cap (explicit v1 decision)
`bounty_repost_count` stays **tracked but unenforced** by deliberate decision; revisit only if abuse
appears. No code change — TBT-003 records this as a resolved decision, not an oversight.

### D4. OBP umbrella flag → add `OPEN_BANK_PROJECT_ENABLED`
Add `OPEN_BANK_PROJECT_ENABLED` / `S.open_bank_project_enabled` (default **OFF**). Every OBP series
`_require_enabled()` becomes `S.open_bank_project_enabled AND S.<series>_enabled` — one umbrella
kill-switch for the whole banking vertical, per-series flags still gate granular rollout. Defined
once in **ACC-001**; the AND-ing convention is noted on each series foundation
(OAU/TXR/VEW/PLT/PAY/CUS/CSN-001).

### D5. Admin invoice → record-external-payment (no Stripe charge)
Add `POST /ui/admin/invoices/{invoice_number}/record-payment` (`require_admin_or_root`), body
`{amount_cents, method:"external", reference, reason}`: writes a **positive** `new_ledger_entry`
(with `signed_amount_cents` per D1) + settles the invoice (`sent→paid`) + audits. It records an
offline/manual payment — it does **NOT** charge the user's payment method. **Owned by QUO-005**
(invoice payment/lifecycle); e2e coverage added to INV-012.

### D6. Branding → root-admin configurable
Canonical: a **`PLATFORM#BRANDING`** settings row `{name, logo_url, support_email}` with
`GET/PUT /ui/admin/branding` (**root** only); env values (`PLATFORM_NAME`, …) are the defaults; a
cached `get_branding()` helper resolves it. Templates read `{{platform_name}}` from `get_branding()`.
**CMP-006** (`web_to_lead_platform_name`) and **CMP-008** migrate to `get_branding().platform_name`.
Formalized as a first-class spec: **`docs/platform/specs/BRAND-001.md`** (new `platform_settings`
table, `branding.py` service, admin-read/root-write `/ui/admin/branding`).

### D7. HTL-036 → ship dark
HTL-036 ships with `getattr(S, …, default)` + lazy-`try/except` import fallbacks (flat
`invoices_tax_bps`, opaque currency). Tax/currency activates automatically once **INV-002..006** are
built and their default-off flags flip. No build-order dependency; nothing is gated on the unbuilt
registries.

---

## Summary

Across 530 specs the corpus is **largely self-consistent**: 4 of the 8 shared-primitive themes
(audit_event, GL posting, pricing façade, GSI/`attr_types`) and the ACL layering are already
consistent by design. The genuine cross-ticket issues cluster into a small, determinate set —
**one money-safety item** (ledger sign convention, the only correctness risk), **two live model
collisions** (`ReservationOut`, `TenantOut`), **one gate-contract split** (open-property 503 vs
404), **one flag-naming** (ATS), and a handful of owner-alignment fixes — plus seven genuine
product decisions flagged **[FOR YOU]**. Everything else is "align the dependent spec to its
foundation," with the canonical resolution recorded above.
