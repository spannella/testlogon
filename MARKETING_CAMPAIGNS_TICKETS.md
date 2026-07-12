# Marketing / Campaigns (OFBiz Marketing) — Implementation Tickets

This backlog ports Apache OFBiz's **Marketing** application — marketing campaigns, contact lists, party segments, and tracking codes — onto the existing testlogon stack, tying campaigns into the ads platform (`app/services/ad_campaigns.py`), promo codes (`app/services/promo_codes.py`), and cart-abandonment reminders (`app/services/cart_reminders.py`) rather than reinventing any of them. Everything is additive and gated behind a single default-off module flag (`MARKETING_CAMPAIGNS_ENABLED`): with the flag off, the ads platform, promo codes, and cart reminders behave byte-for-byte as they do today. The model uses DynamoDB single-table conventions (PK/SK + GSIs, numeric GSI sort keys declared with `attr_types` in `scripts/local-ddb-init.py`), deterministic-id idempotency for new write paths, SECOPS-007 dev/prod parity, and hermetic offline tests.

## Milestone 1 — Scaffolding & Data Model

### MKT-001: Marketing module scoping spike & data-model delta
**Type:** Spike  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Map OFBiz Marketing entities (`MarketingCampaign`, `ContactList`, `ContactListParty`, `SegmentGroup`/`SegmentGroupClassification`, `TrackingCode`/`TrackingCodeVisit`/`TrackingCodeOrder`) onto testlogon: the ads campaign model (`app/services/ad_campaigns.py:36` `create_campaign`, PK `ACCT#{account_id}` / SK `CAMPAIGN#{campaign_id}`, status SM `_CAMPAIGN_TRANSITIONS` at `:16`), promo codes (`app/services/promo_codes.py:85` `create_promo_code`, validation at `:239`, redemption at `:398`), cart reminders (`app/services/cart_reminders.py:325` `_send_stage_reminder`, recovery links at `:214`), and contacts (`app/routers/contacts.py:14`).
- Decide the additive surface: a **marketing campaign** as an umbrella entity that *references* (does not replace) an optional ads `campaign_id`, a set of `promo_code` ids, and zero or more contact lists / segments; a **contact list** (static membership) and a **party segment** (rule-based dynamic membership over profile/subscription/order attributes); and **tracking codes** that attribute storefront visits + orders + promo redemptions back to a campaign.
- Define new DDB tables (PK/SK/GSIs with `attr_types` for numeric sort keys), the `MARKETING_CAMPAIGNS_ENABLED` flag + settings keys, and the deterministic-id scheme for every new write path (`mktcamp_id = sha256(owner|name|created_bucket)`, `tracking_code` slug uniqueness, segment-membership snapshot ids).
- Confirm the GL/billing untouched: marketing spend attribution reads existing ledger/promo-redemption rows; it never writes money. Any campaign-driven discount flows through the *existing* `promo_codes.redeem_promo_code` path.

**Acceptance Criteria**
- A written design note enumerates each OFBiz Marketing entity, its testlogon mapping, and in/out decision (TrackingCodeVisit detail-level analytics IN; OFBiz `MarketingCampaignNote`/`CampaignRole` party-role wiring deferred and recorded).
- Data-model delta lists each new table with PK/SK/GSIs (numeric keys flagged for `attr_types`), the new `app/models.py` shapes, and the new `app/core/settings.py` keys + flag.
- Dependency graph + milestone sequencing recorded; downstream MKT tickets reference a section.

**Dependencies**
- None.

---

### MKT-002: Marketing settings, feature flag & table handles
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `marketing_campaigns_enabled: bool` (env `MARKETING_CAMPAIGNS_ENABLED`, default **off**) to `app/core/settings.py`, following the boolean pattern at `app/core/settings.py:821` (`cart_reminders_enabled`); add table-name settings (`marketing_campaigns_table_name`, `contact_lists_table_name`, `party_segments_table_name`, `tracking_codes_table_name`) mirroring `promo_codes_table_name` at `app/core/settings.py:1995`.
- Land the table definitions from MKT-001 into `scripts/local-ddb-init.py` via the `_resolve_table_name(S.<name>, "<default>")` pattern, declaring all numeric GSI sort keys with `attr_types` (per the CLAUDE.md gotcha — see existing examples at `scripts/local-ddb-init.py:725-729`).
- Wire handles in `app/core/tables.py` (`T.marketing_campaigns`, `T.contact_lists`, `T.party_segments`, `T.tracking_codes`) via `_safe_table(...)`, mirroring `T.promo_codes` at `app/core/tables.py:448`.

**Acceptance Criteria**
- `just restart` recreates the four new tables with no `ValidationException` (numeric GSI sort keys typed `N`).
- `S.marketing_campaigns_enabled` reads through the singleton and defaults to `False`; existing ads/promo/cart-reminder flags are unchanged.
- A smoke pytest imports `app.core.tables.T` and asserts each new handle resolves.

**Dependencies**
- MKT-001.

---

### MKT-003: Marketing Pydantic models
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add to `app/models.py` (alongside `CampaignCreateIn`/`CampaignUpdateIn` referenced at `app/routers/ads.py:18`): `MarketingCampaignCreateIn`/`UpdateIn`/`Out` (name, objective, status, optional linked `ad_campaign_id`, `promo_code_ids: list[str]`, `contact_list_ids`, `segment_ids`, `tracking_code`, budget/window), `ContactListCreateIn`/`Out` + `ContactListMemberIn`/`Out`, `PartySegmentCreateIn`/`Out` (rule predicates) + `SegmentMemberOut`, `TrackingCodeCreateIn`/`Out`, and `CampaignAttributionOut` (visits/orders/redemptions/spend rollup).
- Reuse the existing money-as-cents convention (`budget_cents` like `CampaignCreateIn`) and a `status` literal set matching the MKT-006 state machine; keep field names parallel to the ads models so the FE can share patterns.

**Acceptance Criteria**
- All models import cleanly and round-trip via `.model_validate`/`.model_dump`.
- Segment rule predicates validate (unknown attribute/operator → 422) and money fields are non-negative ints.
- No changes to existing `CampaignCreateIn`/promo models.

**Dependencies**
- MKT-001.

---

## Milestone 2 — Campaigns Core

### MKT-004: Marketing campaign service (CRUD + deterministic ids)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/marketing_campaigns.py` with `create_campaign` / `get_campaign` / `list_campaigns` / `update_campaign`, modeled on `app/services/ad_campaigns.py:36` but scoped per owner with PK `OWNER#{owner_id}` / SK `MKTCAMP#{campaign_id}` and a `ByOwnerCreatedAt` GSI (created_at numeric).
- Use **deterministic ids**: `campaign_id = sha256(owner_id|name|created_bucket)[:24]` so a retried create is idempotent (write with `ConditionExpression="attribute_not_exists(pk)"`; on conflict return the existing item).
- A marketing campaign may **reference** an ads `campaign_id` (validated against `ad_campaigns.get_campaign`) and a list of `promo_code_ids` (validated against `promo_codes.get_promo_code`), but owns neither — deletion/archival of the marketing campaign never mutates the linked ads campaign or promo codes.
- Gate every mutating entry point on `S.marketing_campaigns_enabled` (raise/`403` when off); reads of pre-existing data are unaffected.

**Acceptance Criteria**
- Create→get→list→update round-trips; a duplicate create with identical inputs returns the same `campaign_id` (idempotent, single row).
- Linking a non-existent ads campaign or promo code → validation error; linking valid ones stores the references and they resolve on `get`.
- With the flag off, all mutating calls are rejected and no rows are written.
- pytest covers CRUD, idempotent re-create, and link validation.

**Dependencies**
- MKT-002, MKT-003.

---

### MKT-005: Campaign ↔ ads / promo linkage & spend rollup
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- In `marketing_campaigns.py`, add `attach_ad_campaign` / `detach_ad_campaign` and `attach_promo_code` / `detach_promo_code` that maintain the reference lists on the campaign row only.
- Add `compute_attribution(campaign_id)` that rolls up: ads spend from the linked ads campaign's `lifetime_spent_cents`/`spent_today_cents` (`app/services/ad_campaigns.py:53-54`), promo redemption totals from `promo_codes.get_promo_stats` (`app/services/promo_codes.py:462`), and (from MKT-010) tracking-code visit/order counts — **read-only**, never writing to ads/promo/billing tables.
- Returns a `CampaignAttributionOut` (MKT-003); money figures are cents and reconcile to the existing ledger-derived dashboard rather than re-deriving spend.

**Acceptance Criteria**
- Attaching/detaching updates only the marketing campaign row; the linked ads campaign and promo `current_uses` are untouched.
- `compute_attribution` returns ad spend + promo redemption discount totals matching the source services exactly (cents-for-cents).
- pytest seeds an ads campaign + promo redemptions and asserts the rollup equals the source-of-truth values.

**Dependencies**
- MKT-004.

---

### MKT-006: Campaign lifecycle state machine
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add a validated status SM in `marketing_campaigns.py` mirroring `_CAMPAIGN_TRANSITIONS` (`app/services/ad_campaigns.py:16`): `draft → scheduled → active → paused/completed → archived` (illegal transitions raise; align literals with MKT-003).
- On transition to `active`, validate the campaign window (start ≤ now ≤ end if set) and that any linked promo codes are themselves active (`promo_codes.get_promo_code(...)["active"]`); emit an audit event via `app/services/alerts.audit_event` (same pattern noted for `commerce_order_service`).

**Acceptance Criteria**
- Each legal transition succeeds and writes an audit event; illegal transitions → `409`/`ValueError` and no state change.
- Activating with an expired/inactive linked promo surfaces a clear error.
- pytest covers the full legal path and representative illegal transitions.

**Dependencies**
- MKT-004, MKT-005.

---

## Milestone 3 — Contact Lists & Segments

### MKT-007: Contact lists (static membership)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add contact-list CRUD + membership to `app/services/marketing_campaigns.py` (or a sibling `app/services/marketing_lists.py`): PK `OWNER#{owner_id}` / SK `LIST#{list_id}` for the META row and `LIST#{list_id}#PARTY#{party_id}` for members, with a `ByListJoinedAt` GSI (joined_at numeric).
- Membership add/remove validates the party exists via `profile.get_profile_identity` (already used at `app/routers/contacts.py:11`) and honors per-party opt-out by reusing `cart_reminders.is_user_opted_out` (`app/services/cart_reminders.py:95`) as the shared "do-not-contact" signal so marketing respects the same opt-out as cart reminders.
- Seed-from-contacts helper: import a user's existing contacts (`T.contacts`, `app/routers/contacts.py`) into a list additively (dedup by party id).

**Acceptance Criteria**
- Create list → add/remove members → list members round-trips; duplicate add is a no-op (idempotent).
- Opted-out parties are excluded from membership-for-send queries (but still visible to the owner as "suppressed").
- Seeding from contacts imports each contact exactly once.
- pytest covers CRUD, dedup, opt-out suppression, and contacts import.

**Dependencies**
- MKT-002, MKT-003.

---

### MKT-008: Party segments (rule-based dynamic membership)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add `app/services/party_segments.py`: a segment is a stored predicate set (attribute/operator/value) over party attributes available today — subscription tier (`subscription_access`), profile fields (`profile.get_profile`), and order/spend history (existing `orders`/ledger). Store META at PK `OWNER#{owner_id}` / SK `SEGMENT#{segment_id}`.
- `evaluate_segment(segment_id)` resolves current membership by applying predicates; `snapshot_segment(segment_id)` materializes a point-in-time membership row set (`SEGMENT#{segment_id}#SNAP#{snap_ts}#PARTY#{party_id}`) with a `BySnapshotTs` GSI (numeric) for deterministic campaign sends.
- Evaluation is **read-only** over existing tables; it never writes to profile/subscription/order data. Honor the shared opt-out (MKT-007) at send-resolution time.

**Acceptance Criteria**
- A segment with tier + spend predicates returns exactly the matching parties on a seeded fixture; unknown attribute/operator → validation error.
- `snapshot_segment` writes a stable membership set queryable by snapshot ts; re-snapshotting creates a new immutable snapshot (no mutation of prior ones).
- Opted-out parties are excluded from send-resolution but counted in raw evaluation.
- pytest covers predicate matching, boundary conditions, snapshot immutability, and opt-out.

**Dependencies**
- MKT-002, MKT-003, MKT-007.

---

### MKT-009: Segment/list-targeted campaign send via existing channels
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add `send_campaign(campaign_id)` to `marketing_campaigns.py` that resolves the audience (union of linked contact-list members + a fresh segment snapshot, opt-out-suppressed), then delivers through the **existing** alert/email plumbing reused by cart reminders: `app/services/alerts.write_alert` + `send_alert_email` (imported in `app/services/cart_reminders.py:32`).
- Each send embeds the campaign's tracking-code-tagged links (MKT-010) and, where a promo is linked, the promo code — but redemption still flows through the unchanged `promo_codes.redeem_promo_code`. Sends are idempotent per `(campaign_id, snapshot_ts, party_id)` (deterministic send id; a re-run of the same snapshot does not double-send).
- Gated on `S.marketing_campaigns_enabled`; respects per-party opt-out at send time.

**Acceptance Criteria**
- Sending to a list+segment audience writes one alert/email per non-opted-out party, exactly once per snapshot (replay-safe).
- Tracking-tagged links + linked promo code appear in the message body; no new email/alert mechanism is introduced.
- With the flag off, `send_campaign` is rejected and nothing is sent.
- pytest (alerts/email patched) asserts recipient set, dedup, opt-out exclusion, and replay idempotency.

**Dependencies**
- MKT-006, MKT-007, MKT-008, MKT-010.

---

## Milestone 4 — Tracking Codes & Attribution

### MKT-010: Tracking codes (visit + order + redemption attribution)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Add `app/services/tracking_codes.py`: a tracking code is a unique slug bound to a marketing campaign (PK `TRACK#{code}` / SK `META`, `ByCampaignCreatedAt` GSI), created idempotently (`ConditionExpression="attribute_not_exists(pk)"`; slug collision → error).
- `record_visit(code, party_id?)` appends a visit row (`TRACK#{code}#VISIT#{ts}#{nonce}`, numeric ts GSI) — this is the OFBiz `TrackingCodeVisit`/`TrackingCodeOrder` analog; `record_order(code, order_id)` attributes an order, idempotent per `order_id`.
- Hook attribution non-invasively: tie a tracking code into a promo redemption by passing the campaign's promo through the **existing** `promo_codes.redeem_promo_code` (`app/services/promo_codes.py:398`) and recording the linkage on the tracking side only — promo internals stay untouched. Recovery-link clicks from cart reminders (`cart_reminders.generate_recovery_link`, `app/services/cart_reminders.py:214`) can optionally carry a tracking code for closed-loop attribution.

**Acceptance Criteria**
- Creating a duplicate tracking-code slug is rejected; create is idempotent on identical input.
- `record_visit`/`record_order` append rows queryable by campaign and time; `record_order` is idempotent per `order_id` (no double-count on replay).
- Promo redemption counts attributed to a campaign reconcile to `promo_codes.get_promo_stats` for the linked code.
- pytest covers slug uniqueness, visit/order recording, order idempotency, and the promo reconciliation.

**Dependencies**
- MKT-002, MKT-003, MKT-004.

---

### MKT-011: Marketing campaign router (registered in main.py)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Create `app/routers/marketing_campaigns.py` (`prefix="/ui/marketing"`, `tags=["marketing"]`) with endpoints for campaign CRUD + lifecycle, contact-list CRUD + membership, segment CRUD + evaluate/snapshot, tracking-code CRUD, `send`, and `attribution` — all under `Depends(require_ui_session)` (per CLAUDE.md router convention; mirror `app/routers/ads.py:53`), with admin/root-only review endpoints behind `require_admin_or_root` like `app/routers/ads.py`.
- A public, no-auth `GET /ui/marketing/t/{code}` visit endpoint (records `record_visit` then 302-redirects to the storefront), mirroring the public recovery endpoint pattern in cart reminders.
- Register the router in `app/main.py` next to the ads/promo routers (`app/main.py:178` `promo_codes_router`, `:256` `ads_router`). Every mutating route is a no-op-shaped `404`/`403` when `S.marketing_campaigns_enabled` is off so the surface vanishes with the flag.

**Acceptance Criteria**
- All endpoints reachable; auth + role gating enforced (foreign-owner access → 403/404; admin review requires admin/root).
- Public visit endpoint records a visit and redirects without auth.
- With the flag off, mutating endpoints return 404/403 and write nothing; existing ads/promo/contacts endpoints are unaffected.
- Router registered in `app/main.py` and present in `GET /openapi.json`.

**Dependencies**
- MKT-004, MKT-006, MKT-007, MKT-008, MKT-009, MKT-010.

---

## Milestone 5 — Frontend

### MKT-012: Frontend types & endpoint wrappers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add TS interfaces to `frontend/src/api/types.ts` mirroring the MKT-003 models (campaigns, contact lists, segments, tracking codes, attribution).
- Add `frontend/src/api/endpoints/marketing.ts` wrappers over the MKT-011 routes using the shared axios client, following `frontend/src/api/endpoints/ads.ts` and `promoCodes.ts`.

**Acceptance Criteria**
- Types compile (`tsc --noEmit`) and match the backend response shapes.
- Endpoint wrappers cover every MKT-011 route; CSRF header handling matches the existing client.

**Dependencies**
- MKT-011.

---

### MKT-013: Marketing campaigns page, route & nav
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add a Marketing section under `frontend/src/pages/marketing/` (sibling of `frontend/src/pages/ads/`): campaign list + editor (with ads-campaign/promo-code link pickers), contact-list manager, segment builder (predicate UI + live count via `evaluate`), tracking-code manager, and an attribution panel (ad spend + promo redemptions + visits/orders from MKT-005/MKT-010).
- Add the route to `frontend/src/App.tsx` and a nav entry (sidebar), both gated on a client-readable `marketing_campaigns_enabled` flag so the section is hidden when the module is off.

**Acceptance Criteria**
- A user can create a campaign, link an ads campaign + promo code, build a list and a segment, mint a tracking code, send, and view attribution — all from the UI.
- The section is hidden + route-guarded when the flag is off.
- Segment builder shows a live matching-party count; attribution panel reflects backend rollups.

**Dependencies**
- MKT-012.

---

## Milestone 6 — Tests

### MKT-014: Marketing module tests (hermetic pytest + E2E)
**Type:** Chore  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add hermetic offline pytest suites (`tests/test_mkt_*.py`): moto-bound frozen `T` handles for the four new tables (via `object.__setattr__`, no real AWS), covering campaign CRUD + idempotent re-create, lifecycle SM, list membership + opt-out suppression, segment evaluation + snapshot immutability, tracking-code uniqueness + order idempotency, send dedup/replay, and the attribution rollup tie-out to `promo_codes.get_promo_stats` + ads spend.
- Add a **flag-off parity** test: with `S.marketing_campaigns_enabled` False, every mutating service/router path is a no-op and the ads/promo/cart-reminder code paths are byte-for-byte unchanged.
- Add `frontend/e2e/marketing-campaigns.spec.ts` (seeded sessions + CSRF per CLAUDE.md/MEMORY.md): create campaign → link promo → build segment → mint tracking code → public visit redirect → send → view attribution; admin review path with the admin identity.

**Acceptance Criteria**
- pytest suites pass offline with no AWS/network; idempotency, opt-out, snapshot-immutability, and attribution tie-out asserted.
- Flag-off parity test confirms zero new writes and unchanged existing-subsystem behavior.
- E2E suite passes under the standard 1-worker Playwright config.

**Dependencies**
- MKT-011, MKT-013.

---
