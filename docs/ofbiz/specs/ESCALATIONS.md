# OFBiz Specs — Escalated Decisions (Pass-3 residue)

Generated 2026-06-10. The third verification pass resolved **725** unconfirmed items: 463 forward-deps (healthy), 54 verified-now, 79 corrected, and **132 escalated** (this doc). Nothing here blocks *checking* — it's the set that needs a resolution baked into the specs before building.

**46 plan-gaps** (spec-to-spec contradictions / unowned artifacts) + **86 open design decisions**. The vast majority are determinate: align the dependent spec to the foundation ticket that owns the artifact. Items tagged **[ARCH — your call]** or **FOR YOU** want your input; everything else has a recommended default I'll apply in a reconciliation pass.


## A. Plan-gaps (46) — recommended canonical resolution

| # | Spec | Contradiction | Recommended resolution |
|---|------|---------------|------------------------|
| 1 | ECM-004 | §10.4 — product_type storage location for virtual-product detection | ECM-004 self-resolves: its virtual-product gate does its own flag-gated T.product_depth TYPE lookup (PRD-002 runtime dep, not a hard PRD-008 merge prereq). |
| 2 | ECM-009 | UNCONFIRMED: OFB-019 exports `apply_pricing_rules(user_sub, items, *, checkout_type) -> Pr | **OFB-019 owns a public `apply_pricing_rules(user_sub, items, *, checkout_type) -> PricingBreakdownResult` façade** over its primitives; OFB-020 & ECM-009 consume it. [ARCH — your call] |
| 3 | ECM-009 | UNCONFIRMED (implied): `CartPricingBreakdownOut` and `AppliedRuleLineOut` model definition | ECM-003 is authoritative for models (`discount_cents`, `AppliedPricingRuleLineOut`); amend ECM-009 to adopt it. |
| 4 | ECM-010 | §10.3 / §12 — `_mirror_stock_count` needs `category_id`/`item_id` persisted on cart item D | ECM-008 (owns add-to-cart) persists `category_id`+`item_id` on cart-item rows; ECM-010 reads them. |
| 5 | ECM-011 | §12 #37 — GET /ui/shoppingcart/carts/{id}/line-availability backend endpoint | ECM-008 owns `GET /ui/shoppingcart/carts/{id}/line-availability`; amend ECM-008 spec to add it. |
| 6 | ECM-014 | §12 #23 — ShipGroupOut (ECM-003 name) vs ShipGroupFulfillmentOut (ECM-012/ECM-014 name) | ECM-003 (models ticket) is authoritative: define one class `ShipGroupFulfillmentOut`; align ECM-012/014. |
| 7 | FAC-007 | GSI_FACILITY index absent from FAC-002 receipts TableDef | Amend FAC-002 to add `GSI_FACILITY` (PK=facility_id, SK=created_at) to the receipts TableDef. |
| 8 | FAC-007 | Receipt line sort-key prefix mismatch: FAC-007 uses LINE#{n}, FAC-002 defines ITEM#{n} | FAC-002 is authoritative for keys: sort-key prefix is `ITEM#{n}`; fix FAC-007. |
| 9 | FAC-007 | GSI_STATUS partition key name mismatch: FAC-007 uses receipt_status, FAC-002 uses status | FAC-002 is authoritative: status attr/GSI key is `status` (not `receipt_status`); fix FAC-007. |
| 10 | FAC-008 | PLAN_GAP — status vocabulary mismatch between FAC-003 and FAC-008 | Adopt FAC-003 (models) vocabulary `pending`/`picking`; align FAC-008. |
| 11 | FAC-012 | PLAN_GAP — archiveFacility / archiveLocation HTTP verb mismatch between FAC-012 and FAC-00 | Canonicalize archive as `POST /ui/facilities/{id}/archive`; align FAC-005. |
| 12 | FXA-001 | 25 | **OFB-014 owns a canonical `post_journal_entry(lines, *, source_type, source_entity_id, memo, gl_date, journal_id=None) -> str`** in gl_posting.py; the billing-derived path, OFB-018, FXA-009/011/017, HRM-010, MFG-008 all call it. [ARCH — your call] |
| 13 | FXA-008 | §5.5 / Open Question 4 — `contra_asset` account_class not in OFB-013 ACCOUNT_CLASSES (BLOC | Add `contra_asset` (credit-normal) to OFB-013 ACCOUNT_CLASSES + OFB-016 sign handling (required for accumulated depreciation). [folds into ARCH GL decision] |
| 14 | FXA-017 | §10 Q1 — post_journal_entry interface | Same canonical `post_journal_entry` signature as above; reconcile OFB-018's divergent signature to it. |
| 15 | HRM-007 | §12 RISK / §10.8 — GSI1SK type conflict: HRM-007 §3.1 proposes numeric GSI1SK = created_at | HRM-002 authoritative (GSI1SK type S): fix HRM-007 to `GSI1SK=PAYROLL#{id}` + use GSI_CREATED for newest-first. |
| 16 | MFG-004 | MFG-002 not yet implemented — S.mfg_bom_max_explosion_depth missing from MFG-002 spec | Add `MFG_BOM_MAX_EXPLOSION_DEPTH` to MFG-002 settings block. |
| 17 | MFG-004 | MFG-003 not yet implemented — BomUpdateIn, ExplodedComponentOut, and several fields absent | Amend MFG-003 to add `BomUpdateIn`/`ExplodedComponentOut` + missing fields; quantities standardized to Decimal. |
| 18 | MFG-008 | RISK-5: BOM component rows and catalog key resolution | MFG-004 adds catalog `item_id` onto BOM COMP rows (resolved at BOM creation) so the GL hook can price components. |
| 19 | MFG-012 | §10 item 1 — MFG-011 exposes GET /ui/manufacturing/mrp/runs (list endpoint) | Add `list_mrp_runs` + `GET /ui/manufacturing/mrp/runs` to MFG-010/011 (GSI_RUN_STATUS already provisioned). |
| 20 | MFG-012 | §10 item 4 — MFG-011 list endpoint returns run headers only (no requirements array) | Run-list returns headers only (id, status, horizon_days, created_at, requirement_count). |
| 21 | MKT-011 | get_campaign_by_id / ByCampaignId GSI on MarketingCampaigns | MKT-004 adds `get_campaign_by_id`; if table PK≠campaign_id, add `ByCampaignId` GSI to MKT-002. |
| 22 | MKT-011 | list_campaigns_by_status function ownership | MKT-006 (owns lifecycle/status) defines `list_campaigns_by_status`. |
| 23 | OFB-017 | §12 #33b — gl_posting.py service-layer functions list_journal_entries / get_journal_entry_ | OFB-014 adds public `list_journal_entries` + `get_journal_entry_header` in gl_posting.py. |
| 24 | OFB-020 | RISK: resolve_applicable_rules (OFB-019) must accept an exclude_rule_ids parameter for OFB | OFB-019 adds `exclude_rule_ids` param to `resolve_applicable_rules` (kills the double-count). [pricing ARCH] |
| 25 | OFB-022 | Row 31 — redeem_rule export name | Canonical redemption fn is `redeem_rule` in pricing_rules.py; fix OFB-019 §7.3 naming. |
| 26 | OFB-022 | Row 32 — exclude_rule_ids parameter on resolve_applicable_rules | Duplicate of the `exclude_rule_ids` resolution above. |
| 27 | ORD-005 | §5.3 history_row_exists | ORD-006 owns `history_row_exists(order_id, event_id)`. |
| 28 | ORD-014-pass3 | §10 A1 — allowed_transitions in OrderLifecycleOut | Add `allowed_transitions: string[]` to `OrderLifecycleOut` (ORD-004/011) so the UI derives buttons from the API. |
| 29 | ORD-014-pass3 | §10 A2 — line_items embedded in OrderLifecycleOut | ORD-011 `get_order_lifecycle` joins `order_items` into `line_items: OrderLineItemOut[]` (add model to ORD-004). |
| 30 | POS-006 | §12 row 34 — TXN row field names and status value (POS-005 vs POS-006 cross-spec conflict) | POS-002/006 authoritative TXN schema (`cart_id`, `tax_cents`, `total_cents`, status `draft`); fix POS-005 to write those. |
| 31 | POS-007 | §12 row 37 — pos_default_tax_rate_bps listed as added by POS-003 | Add `pos_default_tax_rate_bps` to POS-003 settings. |
| 32 | POS-008 | 28b — S.pos_default_tax_rate_bps in settings.py | Add `pos_default_tax_rate_bps` to POS-003 settings (same owner). |
| 33 | POS-009 | OQ-3 — tax_cents / discount_cents stored on TXN row | POS-006 (tender/totals) writes `tax_cents`+`discount_cents` to the TXN row; POS-009 reads them. |
| 34 | POS-014-pass3 | S.pos_default_tax_rate_bps listed in §6 settings table as a POS-003 deliverable | Add `pos_default_tax_rate_bps` to POS-003 settings (same owner). |
| 35 | PRD-008 | §12 #22 — PRD-003 Pydantic models | Add the 5 missing input/list models to PRD-003 (models ticket). |
| 36 | PRD-009 | BundleComponentLine defined in PRD-003 spec | Add `BundleComponentLine` to PRD-003 / app/models.py. |
| 37 | PRD-013 | §12 #23 / §10 Q1 — PRD-012 service interface mismatch | Amend PRD-012 to add `set_price_components` (full-replace) + richer `resolve_effective_price` return (price+currency+component_id). |
| 38 | PRD-016 | §12 row 24 — GET /ui/catalog/categories/depth-enabled introspection endpoint | Keep the probe-GET-tree pattern; no new introspection endpoint. |
| 39 | PTY-010 | §10 item 1 — correlation_id persistence on mech items | PTY-007 `add_contact_mech` persists `correlation_id` as a mech-item attribute. **[Phase 1]** |
| 40 | PTY-010 | §10 item 2 — remove_contact_mech signature missing mech_type | PTY-007 `remove_contact_mech` resolves SK via a preceding `list_contact_mechs` query (no signature change). **[Phase 1]** |
| 41 | PUR-003 | §10.6 / §5.6 cross-claim — PUR-006 create_purchase_order raises 422 if supplier is inactiv | PUR-006 owns the supplier-inactive `get_supplier()`→422 guard; ensure PUR-006 spec includes it. |
| 42 | PUR-014 | U-06 (partial): PUR-013 §4.1 defines the supplier create-input as `SupplierIn` and the pro | PUR-013 authoritative: types are `SupplierIn`/`SupplierProductIn`; fix PUR-014 imports. |
| 43 | PUR-014 | U-07 (partial): PUR-013 §4.2.2 names the list-products-for-supplier wrapper `listSupplierP | PUR-013 authoritative: wrapper is `listSupplierProducts`; fix PUR-014 import. |
| 44 | SHP-001 | §12 #25 — RISK: `returned` status never produced by `map_carrier_status`; no SHP spec assi | SHP-012 owns adding the carrier-raw → `returned` mapping (SHP-side wrapper; stop claiming carrier_tracking.py unmodified). |
| 45 | SHP-005 | §12 #22 — service function interface mismatch between SHP-005 §2.4/§4.1 and SHP-004 spec:  | SHP-004 authoritative: add named exceptions (`CarrierNotFound`…) + `enabled_only` alias; align SHP-005 names. |
| 46 | SHP-007 | §12 #19 — estimate_rate vs estimate_rates interface mismatch | SHP-006 authoritative: `estimate_rates` (plural) with `LineItemWeightInput`; align SHP-007. |

## B. Open design decisions (86) — recommended defaults


### ECM (17)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| ECM-002 | Should `_integration_enabled` raise `RuntimeError` (or `AssertionError` in dev mode) when passed an unknown sub_flag string, rather than returning `False` with a WARNING log? | keep graceful return+WARNING (no hard raise in prod) |
| ECM-002 | Should `_safe_upstream` accept an optional `label: str` parameter so callers can embed a call-site identifier in the WARNING log line for easier production debugging? | recommended default applied during reconciliation (see spec §13) |
| ECM-005 | Should `availability_for_skus` read `T.inventory` and populate `StorefrontAvailabilityOut` even when `INVENTORY_RESERVATIONS_ENABLED` is false (i.e., the reservation lifecycle is inactive but inventory rows exist), or should a guard be added to require that flag before reading? | recommended default applied during reconciliation (see spec §13) |
| ECM-005 | Should `CatalogItemOut.availability` serialize as `"availability": null` in the JSON response when the flag is off (FastAPI default), or should the catalog router use `response_model_exclude_none=True` to omit the key entirely (which would also strip other optional scalars like `description`)? | recommended default applied during reconciliation (see spec §13) |
| ECM-006 | Should GET /ui/catalog/categories/{category_id}/items/{item_id} return 403 (informative, consistent with check_geo_access) or 404 (privacy-preserving, hides item existence) for geo-blocked items? | 404 (privacy-preserving), consistent with hiding item existence |
| ECM-006 | Should ECM-007 derive the parent browse-grid stock badge from the aggregate of all variant availabilities (e.g., out_of_stock only when every variant is unavailable), or should it keep the static _compute_stock_status scalar unchanged? | recommended default applied during reconciliation (see spec §13) |
| ECM-006 | Should the four-line enrichment block in catalog.py be extracted into a module-level _enrich_item_list helper (DRY, current spec) or inlined at list_items, search_items, and get_item_detail separately (no helper indirection)? | recommended default applied during reconciliation (see spec §13) |
| ECM-007 | Should selecting a variant swap the product image, and if so, should `image_url: Optional[str]` be added to `StorefrontVariantOut` in ECM-003, or should ECM-007 keep parent-level images only for this release? | recommended default applied during reconciliation (see spec §13) |
| ECM-007 | Should ECM-007 enforce a maximum number of option values per group (e.g. 20 with a 'show more' disclosure) or defer a per-feature-category value count limit to PRD-003? | defer to a follow-up ticket (out of MVP scope) |
| ECM-008 | Should ECM-010 (commit-on-purchase) read the reservation_id from a denormalised field on the cart item DDB row, or rederive it via _cart_sku_reservation_id(cart_id, sku) at purchase time? | recommended default applied during reconciliation (see spec §13) |
| ECM-008 | Should ECM-022 (cart indicators) treat reservation_id: null in ShoppingCartItemOut as a signal to show a 'stock may be limited' toast, or leave the silent degrade-to-no-reservation behavior as the final UX? | recommended default applied during reconciliation (see spec §13) |
| ECM-013 | Should `useStoreConfig` be a React Query hook in `hooks/useStoreConfig.ts` (per-component deduplication via `staleTime`) or a Zustand atom in `stores/storeConfigStore.ts` pre-fetched once at app startup? | React Query hook (per-component dedupe via staleTime) |
| ECM-013 | Should the optional `fulfillment_status?: OrderFulfillmentStatus | null` field be added to `CartPurchase` in this ticket (additive/zero-cost, lets ECM-014 reference it without a `types.ts` diff) or deferred to ECM-014 to keep ECM-013 strictly minimal? | defer to a follow-up ticket (out of MVP scope) |
| ECM-014 | Should useStoreConfig be hoisted into App.tsx for conditional route registration, or should OrderDetail use an in-component redirect guard instead? | recommended default applied during reconciliation (see spec §13) |
| ECM-014 | Should OrderDetail reuse the existing ShippingTimeline component (which uses purchase-transaction status vocabulary) or should a thin OrderLifecycleTimeline inline component be written for the ORD lifecycle vocabulary? | reuse the existing component |
| ECM-014 | Should the Order Tracking sidebar nav entry point to /purchases (delegating to existing purchase history) or to a new /orders list page (ECM-016)? | recommended default applied during reconciliation (see spec §13) |
| ECM-015 | Should the flag-off E2E smoke (section 804) run as a separate CI job rather than a serially-run section to avoid adding a backend-restart penalty to the main Playwright spec run? | recommended default applied during reconciliation (see spec §13) |

### FAC (9)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| FAC-004 | Should the facility address field be stored as a DDB Map (M) with the FAC-001/FAC-002 schema, or as a plain JSON string (S) as FAC-003/FAC-004 currently implement — the two predecessor specs are inconsistent and must be reconciled before FAC-004 ships? | recommended default applied during reconciliation (see spec §13) |
| FAC-004 | Should archive_facility enforce a 409 block when any location of the facility has available inventory (requiring a T.inventory scan or new GSI), or defer this guard to a follow-up ticket for MVP? | scan + FilterExpression for bounded sets (<~500 rows); add a rollup only if it grows |
| FAC-004 | Should FAC-004 implement a list_facilities_by_status(status) function (via GSI_STATUS) for admin cross-owner facility listing, or leave that to FAC-005's router as a separate admin-only endpoint? | owner + admin/root read |
| FAC-004 | Which call site should own ensure_default_facility(): the on_startup hook in app/main.py (wired by FAC-005), a lazy check inside the first public list_facilities/create_facility call, or an explicit admin-only endpoint defined in FAC-005? | recommended default applied during reconciliation (see spec §13) |
| FAC-008 | Should `generate_picklist` use a deterministic `picklist_id = sha256(order_id|facility_id)` to enforce strict single-picklist-per-order semantics, or continue with `uuid4()` + GSI pre-check to allow multiple picklists per order (for re-shipment after partial cancel)? | deterministic sha256 id (idempotent), consistent with house style |
| FAC-008 | Should `generate_picklist` reject orders whose `status` is not `processing` (or an equivalent ready-to-fulfill value), or accept any order regardless of status? | recommended default applied during reconciliation (see spec §13) |
| FAC-008 | Should `confirm_pick` accept `picked_qty = 0` as a valid explicit 100%-short confirmation, or reject it with HTTP 422? | recommended default applied during reconciliation (see spec §13) |
| FAC-014 | Should FAC-003's `LotOut` (7 simplified fields: `quantity`, `received_at`, `expires_at`, `notes`) be replaced wholesale by FAC-014's richer `LotOut` (14 fields including `lot_status`, `quantity_received`, `quantity_available`, `facility_id`, etc.) when FAC-014 ships, or should FAC-003 rename its class to `LotSummaryOut` so both can coexist without a name collision? | recommended default applied during reconciliation (see spec §13) |
| FAC-014 | Should `ReceiveLineIn` carry `lot_label: Optional[str]` (caller supplies a human label, service derives `lot_id = sha256(receipt_id+sku+lot_label)` as FAC-014 §4.2 specifies) or `lot_id: Optional[str]` (as FAC-003 line 246 currently defines it for input), since the two specs disagree on which field the caller provides? | recommended default applied during reconciliation (see spec §13) |

### FXA (2)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| FXA-006 | Should generate_schedule be triggered by an explicit admin POST /ui/fixed-assets/{id}/schedule endpoint (as assumed by FXA-007), or should it be auto-invoked inside create_asset so that a schedule always exists immediately after asset registration? | recommended default applied during reconciliation (see spec §13) |
| FXA-008 | Should FXA-008 seed one combined `Gain/Loss on Disposal` account (letting FXA-011 post net credits or debits to it) or two separate accounts (`Gain on Disposal` credit-normal, `Loss on Disposal` debit-normal)? | **FOR YOU** |

### HRM (1)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| HRM-012 | Should queryClient.clear() be called in the logout path (authStore.ts logout()) to prevent stale HR pay-rate and payroll data from flashing for a new session before the page guard redirects? | recommended default applied during reconciliation (see spec §13) |

### MFG (5)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| MFG-004 | Should get_active_bom use Limit=10 (accepting that products with more than 10 BOMs may miss the most-recent active one) or should Limit be omitted/increased, and is a separate sparse active_bom_id pointer on the product record needed for correctness? | recommended default applied during reconciliation (see spec §13) |
| MFG-010 | If explode_bom raises HTTP 409 (cycle detected) mid-run, should the MRP engine persist the partial REQ rows that were already written before marking the run status as failed? | recommended default applied during reconciliation (see spec §13) |
| MFG-010 | Is it a final product decision that the MRP engine handles only open-order demand (no forecast rows), and if forecast demand is ever needed, which future ticket will own the mrp_forecast table and model? | recommended default applied during reconciliation (see spec §13) |
| MFG-012 | Should MFG-012's Produce tab show an inline component-quantity BOM explosion preview per row, or is a flat list view without component detail sufficient for the initial release? | recommended default applied during reconciliation (see spec §13) |
| MFG-012 | Should each new MRP run trigger auto-replace the suggestions panel content (showing only the latest run), or should the panel retain the previously viewed run until the admin explicitly selects the new one from the history list? | recommended default applied during reconciliation (see spec §13) |

### MKT (1)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| MKT-008 | Should `candidate_source` be added to `PartySegmentCreateIn` in MKT-003 (model-layer validation) or remain a service-layer-only constraint enforced in MKT-008's `_validate_candidate_source` helper? | recommended default applied during reconciliation (see spec §13) |

### OFB (11)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| OFB-001 | Should refund_return (which makes no Stripe API call and only writes an internal billing ledger credit) call is_provider_enabled(provider) before posting the ledger entry? | recommended default applied during reconciliation (see spec §13) |
| OFB-013 | Should GET /ui/gl/accounts use require_admin_or_root (to allow ADMIN role read-only access for OFB-016 financial reporting) rather than remaining ROOT-only as currently specified? | recommended default applied during reconciliation (see spec §13) |
| OFB-013 | Should the GSI_ACTIVE index and gsi_active denormalized field be kept, or should list_accounts replace them with a full scan and FilterExpression given the bounded chart size (~100 accounts)? | scan + FilterExpression for bounded sets (<~500 rows); add a rollup only if it grows |
| OFB-014-pass3 | Should the GL posting engine post only state='settled' ledger rows, or also state='pending' rows, given that pending→reversed transitions via payment failure do not produce an offsetting refund/adjustment row on any provider path? | recommended default applied during reconciliation (see spec §13) |
| OFB-014-pass3 | Should the multi-line journal entry write use batch_writer (efficient, loses per-item error granularity) or individual put_item calls (simpler, independently retryable per line)? | recommended default applied during reconciliation (see spec §13) |
| OFB-015 | Should AR/AP aging be separately deployable without GL double-entry (keeping AR_AP_SUBLEDGERS_ENABLED independent), or should a single GL_DOUBLE_ENTRY_ENABLED flag gate both features? | recommended default applied during reconciliation (see spec §13) |
| OFB-015 | Should a 'paid' invoice status be added to invoices.py as a prerequisite for accurate AR aging, or is using ledger state='settled' as the AR-closed proxy acceptable to finance stakeholders? | **FOR YOU** |
| OFB-015 | Should the AP subledger include accrued creator wallet balances (owed_settled_cents on T.billing) as a second AP aging view, or restrict to explicit payout requests in T.creator_payouts only? | **FOR YOU** |
| OFB-015 | Should compute_ar_aging with no user_sub filter use a pre-computed daily rollup (similar to platform_financial_dashboard.py) rather than a paginated ADMIN_ALL GSI scan for production-scale deployments? | scan + FilterExpression for bounded sets (<~500 rows); add a rollup only if it grows |
| OFB-015 | Should a start_ar_ap_snapshot_task startup hook gated by AR_AP_SNAPSHOT_SCHEDULER_ENABLED be added (in OFB-017 or OFB-018) to enable automated daily aging snapshots without ROOT user interaction? | recommended default applied during reconciliation (see spec §13) |
| OFB-015 | Should the OFB-017 accounting UI surface a 'pagination required' warning when the AgingOut items list is capped at 500, or should the default cap be raised or removed for the drill-through view? | recommended default applied during reconciliation (see spec §13) |

### ORD (9)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| ORD-006 | Should GET /ui/orders/{order_id}/history be accessible to ADMIN/ROOT users who do not own the order, or should it be strictly owner-only? | owner + admin/root read |
| ORD-006 | Should the raw caller-supplied idempotency_key be persisted as a DDB attribute on the HIST row to enable support-tooling queries, or is the hashed event_id sufficient? | recommended default applied during reconciliation (see spec §13) |
| ORD-009 | Should ORD-009 add a per-item `ITEMASSIGN#{item_id}` DDB row with `condition_expression=attribute_not_exists` to enforce strict item-exclusivity across concurrent `create_ship_group` calls, or accept the read-then-write race at admin-only frequency and defer the guard as a follow-up? | defer to a follow-up ticket (out of MVP scope) |
| ORD-009 | Should ORD-009 require callers to explicitly create ship groups before advancing fulfillment (and have the ORD-011 router return 422 with `code=no_ship_groups` when none exist), or should an implicit single-group be auto-created at order creation when the lifecycle flag is on? | recommended default applied during reconciliation (see spec §13) |
| ORD-009 | When one or more ship groups are `cancelled` and all remaining active groups reach `shipped`, should the order header automatically advance to `shipped` via the roll-up, or should a cancelled sub-shipment require an explicit admin acknowledgment before the header advances? | recommended default applied during reconciliation (see spec §13) |
| ORD-011 | Should ORD-009 add a common `ItemAssignmentError` base class that `ShipGroupItemConflictError` and `ShipGroupItemNotFoundError` both inherit from, or should the ORD-011 router catch each exception separately with distinct HTTP codes (409 for conflict, 422 for unknown ref)? | recommended default applied during reconciliation (see spec §13) |
| ORD-011 | Which ticket or ops runbook owns the one-time migration script that writes `sk="ORDER"` onto pre-ORD-003 order rows before `ORDER_LIFECYCLE_ENABLED` is set to true in production? | recommended default applied during reconciliation (see spec §13) |
| ORD-011 | Should the E2E section 76 cancel test use `refund=false` to avoid the Stripe mock `requires_payment_method` limitation, or should it seed wallet balance directly into DynamoDB to test the `refund=true` path explicitly? | recommended default applied during reconciliation (see spec §13) |
| ORD-015 | Should the ORD-015 E2E spec document a required ORDER_LIFECYCLE_ENABLED=true line in .env.local as a hard prerequisite, or should e2e_admin_session_setup.py probe the flag via a health/config endpoint and abort with a clear message when it is off? | recommended default applied during reconciliation (see spec §13) |

### POS (5)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| POS-009 | Should POS receipts share the cashier's /billing/receipts/ file-manager folder or use a separate /pos/receipts/ prefix requiring a new upload_billing_receipt variant or folder parameter? | recommended default applied during reconciliation (see spec §13) |
| POS-009 | Should receipt access be limited to cashier + admin/root (current design) or also extend to the customer who made the purchase, given that customers may not have platform accounts in a POS context? | recommended default applied during reconciliation (see spec §13) |
| POS-009 | Should get_receipt_bytes catch the 409 from require_not_exists and fall through to S3 read, or should upload_billing_receipt gain an overwrite=True parameter to handle the partial-failure re-entry case cleanly? | recommended default applied during reconciliation (see spec §13) |
| POS-010 | Should session_report(kind='z') on an already-printed session raise HTTPException(409) to enforce 'printed exactly once, forever', or return the previously-recorded data idempotently to allow re-printing? | recommended default applied during reconciliation (see spec §13) |
| POS-013 | Should the single-page terminal live at `/pos` (flat) or at `/pos/terminal` with a future register-config page at `/pos`, given that no other POS spec defines a separate register-config frontend route? | recommended default applied during reconciliation (see spec §13) |

### PRD (14)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| PRD-001 | Should `create_variant` reject (400/409) when the parent item's `price_cents` is 0, or is a zero-priced virtual product (free variant) acceptable? | recommended default applied during reconciliation (see spec §13) |
| PRD-001 | Should feature categories (e.g., 'Color', 'Size') be scoped per-creator (current default, `creator_id` on FTCAT row) or shared globally across all creators, and if global, who governs them? | **FOR YOU** |
| PRD-005 | Should GET /tree and GET /breadcrumb enforce the can_access_creator subscription gate that GET /categories/{id}/items enforces at catalog.py:404? | recommended default applied during reconciliation (see spec §13) |
| PRD-005 | Must the caller also own the new_parent_category_id target to move a category under it, or is ownership of the moved category sufficient? | recommended default applied during reconciliation (see spec §13) |
| PRD-005 | Should the router perform O(N) _get_category_meta lookups per node for GET /tree to populate name, or should CategoryTreeNodeOut.name be Optional[str] and left null for tree-node results? | recommended default applied during reconciliation (see spec §13) |
| PRD-006 | Should a ByCreator GSI (partition=creator_id, sort=created_at) be added to product_depth in PRD-002 before shipping, or is a full-table scan with FilterExpression acceptable for early usage? | scan + FilterExpression for bounded sets (<~500 rows); add a rollup only if it grows |
| PRD-006 | Should feature categories be scoped strictly to their creator_id (current design), or should a marketplace-shared category model be designed now to avoid a future breaking schema change? | **FOR YOU** |
| PRD-006 | Does PRD-008 explicitly commit to calling _find_item_by_id and an item-ownership check before attach_feature_category_to_product, and should PRD-006 enforce it defensively at the service layer too? | recommended default applied during reconciliation (see spec §13) |
| PRD-008 | Should `GET /items/{item_id}/variants` be relaxed to allow unauthenticated storefront access, or does requiring `require_ui_session` remain the intended design for the initial release? | recommended default applied during reconciliation (see spec §13) |
| PRD-008 | When a variant is deleted, should its orphaned SKU in `T.inventory` (owned by OFB-003) be proactively cleaned up, or is a non-cascading delete acceptable per the OFBiz convention? | recommended default applied during reconciliation (see spec §13) |
| PRD-013 | Should `GET /items/{item_id}/effective-price` be owner-only (call `_require_item_owner`, matching AVERAGE_COST confidentiality concern) or subscription-gated read-only (matching the `GET /bundle` convention from PRD-011 §4.2)? | owner + admin/root read |
| PRD-013 | Should `GET /items/{item_id}/price-components` omit pagination (assuming bounded row counts, as currently designed) or include a `page_size`/`next_token` cursor from the start to handle potential large historical price logs? | recommended default applied during reconciliation (see spec §13) |
| PRD-013 | Should `PUT /items/{item_id}/price-components` be extended to accept components for multiple price types in a single call, or should the single-type-per-call constraint remain as a deliberate simplification for Milestone 5? | recommended default applied during reconciliation (see spec §13) |
| PRD-014 | Should the existing `CatalogCategory` TypeScript interface gain optional `parent_category_id`, `path`, and `position` fields, or should PRD-005 return a distinct `DepthCatalogCategory` (CategoryTreeNodeOut mirror) so that `addChildCategory` and `moveCategory` use a different return type than existing `getCategories` consumers? | recommended default applied during reconciliation (see spec §13) |

### PTY (1)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| PTY-012 | Should `POST /ui/admin/party/migrate-contacts` return a job ID and run the backfill asynchronously (like `app/services/audit_export_worker.py`), or remain synchronous with the documented 504 risk for large contact sets? | recommended default applied during reconciliation (see spec §13) |

### PUR (6)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| PUR-011 | When multiple supplier-product records for the same SKU all carry `preferred=True`, should the business rule be 'cheapest among preferred' (current spec: GSI returns them ascending by cost so `candidates[0]` is cheapest), 'first-registered preferred supplier', or should the PUR-005 router enforce at most one `preferred=True` per SKU to make tie-breaking moot? | recommended default applied during reconciliation (see spec §13) |
| PUR-012 | Should GET /reorder-suggestions return a flat list sorted by supplier_id+sku (current design) or a grouped dict keyed by supplier_id, and if grouped, should that be done in PUR-012 or deferred to PUR-013? | defer to a follow-up ticket (out of MVP scope) |
| PUR-012 | Should reorder-suggestion background scan alerts be stored only under user_sub="system" (audit-log-only, not visible in any admin's alert feed) or should they be broadcast to all ADMIN/ROOT users? | recommended default applied during reconciliation (see spec §13) |
| PUR-012 | Is it acceptable to write REORDER_ALERT_SENTINEL# rows into T.purchase_orders to avoid a new table, or should the dedup sentinel live in T.alerts or a dedicated table to keep T.purchase_orders clean? | recommended default applied during reconciliation (see spec §13) |
| PUR-012 | Should compute_suggestions() remain synchronous and be wrapped in asyncio.to_thread at every call site (including inside the background loop), or should it be refactored to be natively async? | recommended default applied during reconciliation (see spec §13) |
| PUR-016 | Both PUR-014 §6.1 and PUR-015 §6.2 claim to add the same `purchasingScmEnabled` / `isPurchasingScmEnabled()` exports (and `VITE_PURCHASING_SCM_ENABLED` in `.env.local.example`) to `featureFlags.ts` — which ticket should canonically own these additions so the other ticket's spec can be updated to say 'this was already added by PUR-0XX'? | recommended default applied during reconciliation (see spec §13) |

### SHP (5)

| Spec | Decision | Recommended default |
|------|----------|---------------------|
| SHP-001 | How is `purchase_txn_id` populated on a Shipment row — passed explicitly by the checkout caller, looked up via a new `order_id` GSI on `purchase_transactions`, or left permanently `None` (making the legacy-sync path in §5.2/§5.3 effectively dead until manually linked)? | recommended default applied during reconciliation (see spec §13) |
| SHP-013 | Does the SHP-010 transition_shipment implementation write the carrier identifier to DynamoDB as `carrier` (as SHP-010 spec lines 172/299 and SHP-012 §2.6 table show) or as `carrier_code` (as SHP-002 §3.2 schema table shows), and which name should poll_shipment's shipment.get() call use? | recommended default applied during reconciliation (see spec §13) |
| SHP-013 | Should the polling budget be split evenly (cap//2 each for orders and shipments) or should orders retain full priority (orders consume up to cap slots; shipments only fill leftover capacity after orders are fetched)? | recommended default applied during reconciliation (see spec §13) |
| SHP-014 | Should create_shipment (SHP-008) receive purchase_txn_id from the checkout caller to guarantee direct txn linkage, or is the §5.6 external_ref fallback scan sufficient for all expected order flows? | recommended default applied during reconciliation (see spec §13) |
| SHP-019 | Should section 74 flag-off E2E tests be implemented as pytest-only (using object.__setattr__ on S.shipping_enabled), or should a new runtime toggle endpoint be created as part of SHP-002/SHP-005? | recommended default applied during reconciliation (see spec §13) |

## C. Genuine decisions needing your input

Beyond the per-row defaults above, these are cross-cutting architecture/policy choices where your call materially shapes the build:

1. **GL posting interface (ARCH).** Define one canonical `post_journal_entry(lines, …)` in `gl_posting.py` (OFB-014) used by the billing-derived path, OFB-018, FXA depreciation/disposal, HR payroll, and MFG costed-production — plus add `contra_asset` to the OFB-013 chart. *Recommend: yes — single multi-line poster.*
2. **Pricing façade (ARCH).** OFB-019 exports a public `apply_pricing_rules(...)` façade (+ `exclude_rule_ids`, canonical `redeem_rule`) consumed by cart/checkout/ECM. *Recommend: yes.*
3. **AR/AP semantics (FINANCE).** Ship AR/AP aging on the ledger `state='settled'` proxy + payout-only AP for MVP, deferring a new `paid` invoice status and a creator-wallet-accrual AP view? *Recommend: MVP proxy.*
4. **Asset-disposal accounts (ACCOUNTING).** One combined `Gain/Loss on Disposal` account, or split `Gain` (credit-normal) / `Loss` (debit-normal)? *Recommend: split.*
5. **Feature-category scope (SCHEMA, hard to reverse).** Product feature categories (Color, Size) scoped per-creator, or global marketplace-shared? *Recommend: per-creator.*
