# Catalog / Product Depth — Implementation Tickets

This backlog adds OFBiz-style **product depth** — virtual↔variant products, multi-level category trees, product features/options, configurable bundles/kits, product associations, and product-level price components — additively on top of the existing flat catalog item (`app/routers/catalog.py` scalar `ITEM#`/`CAT#` rows, `_compute_stock_status` at `:94`, `_catalog_item_out` at `:107`). Everything ships behind a single default-off `PRODUCT_DEPTH_ENABLED` flag: with it off, the existing shop/cart/orders/billing/inventory paths and the scalar catalog item are byte-for-byte unchanged. New relational entities are single-table modeled (PK/SK + GSIs, numeric GSI sort keys declared with `attr_types` in `scripts/local-ddb-init.py`); all new write paths use deterministic-id idempotency, SECOPS-007 dev/prod parity, and hermetic offline tests.

## Milestone 1 — Scaffolding & Data Model

### PRD-001: Product-depth scoping spike & single-table key design
**Type:** Spike  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Map OFBiz Catalog entities (Product with `productTypeId` VIRTUAL/VARIANT/FINISHED_GOOD/DIGITAL_GOOD, ProductCategory + ProductCategoryRollup tree, ProductFeature/ProductFeatureCategory/ProductFeatureAppl, ProductAssoc PRODUCT_VARIANT/MANUF/SUBSTITUTE/COMPLEMENT, configurable ProductConfig/ProductConfigOption, ProductPrice components) onto the existing scalar catalog model: `CAT#{id}`/`ITEM#{id}` rows on `T.catalog` (`scripts/local-ddb-init.py:118`, GSIs `GSI1` + `ByItemId` at `:122`), `_catalog_item_out` (`app/routers/catalog.py:107`), `_compute_stock_status` (`:94`), and `CatalogItemOut`/`CatalogItemCreateIn` (`app/models.py:538`, `:672`).
- Decide the single-table key plan for new entities (whether they live on `T.catalog` as new `entity` discriminators or on a dedicated `T.product_depth` table) — recommend a dedicated table so the existing `ByItemId` GSI and scan filters (`entity == "item"` at `app/routers/catalog.py:485`) stay untouched.
- Define how a VIRTUAL product references its VARIANT children, how a feature/option set maps to a chosen variant SKU, how bundles/kits expand to component lines, and how product-level price components layer onto the scalar `price_cents` without breaking cart/checkout.

**Acceptance Criteria**
- A written design doc (`docs/catalog-product-depth-plan.md`) enumerates each OFBiz catalog entity, its testlogon mapping, and PK/SK/GSI layout (with `attr_types` noted for numeric keys).
- Back-compat statement: with `PRODUCT_DEPTH_ENABLED` off, every existing catalog/shop/cart endpoint returns identical responses; the scalar item remains the source of truth.
- Idempotency strategy (deterministic ids for variants/associations/config selections) and the variant→inventory-SKU mapping are documented.
- Reviewer signs off that the variant/bundle expansion does not fork cart pricing or inventory reservation logic.

**Dependencies**
- None.

---

### PRD-002: Product-depth tables, settings & feature flag
**Type:** Chore  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add the table(s) agreed in PRD-001 to `scripts/local-ddb-init.py` next to the existing catalog `TableDef` (`:118`): a `product_depth` table (PK/SK) with GSIs for (a) virtual→variant lookup, (b) category-tree parent→children, (c) feature-category→features, and (d) product-association source→targets. Declare any numeric GSI sort keys (e.g. `position`/`sequence_num`) with `attr_types={"...": "N"}` per the CLAUDE.md gotcha.
- Add `app/core/settings.py` keys near the existing catalog block (`:832`): `product_depth_enabled` (`PRODUCT_DEPTH_ENABLED`, default **off**), `product_depth_table_name` (`PRODUCT_DEPTH_TABLE_NAME`, default `product_depth`), and sub-flags for variants/bundles/features/price-components if PRD-001 calls for independent gating.
- Wire the table handle in `app/core/tables.py` (`T.product_depth`).

**Acceptance Criteria**
- `just restart` recreates the new table(s) with no `ValidationException` (numeric GSI keys validated).
- `S.product_depth_enabled` reads through the singleton and defaults to `False`; existing catalog flags (`catalog_default_low_stock_threshold` etc.) are untouched.
- A smoke pytest imports `app.core.tables.T` and asserts `T.product_depth` resolves.

**Dependencies**
- PRD-001.

---

### PRD-003: Product-depth Pydantic models
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add Pydantic shapes to `app/models.py` alongside the existing catalog models (`CatalogCategoryCreateIn` `:520`, `CatalogItemCreateIn` `:538`, `CatalogItemOut` `:672`): `ProductTypeEnum` (virtual/variant/standalone/bundle/kit/digital), `VariantCreateIn`/`VariantOut` (parent `item_id`, variant SKU, feature-value selections, price delta, stock SKU), `ProductFeatureCreateIn`/`ProductFeatureOut` + `ProductFeatureCategoryOut`, `BundleComponentIn`/`BundleOut`, `ProductAssocIn`/`ProductAssocOut` (assoc type enum), and `ProductPriceComponentIn`/`ProductPriceComponentOut`.
- Extend `CatalogItemOut` (`:672`) **additively** with optional fields — `product_type`, `variant_count`, `has_features`, `bundle_component_count` — all defaulting to back-compat values so existing serialization is unchanged when depth rows are absent.

**Acceptance Criteria**
- New models validate enums and required keys; `CatalogItemOut` round-trips an existing scalar item unchanged (new fields default/omit).
- `mypy`/pydantic import-time validation passes; models are importable from `app.models`.
- pytest asserts a legacy `CatalogItemOut` dict (pre-depth) still deserializes.

**Dependencies**
- PRD-001.

---

## Milestone 2 — Category Trees

### PRD-004: Category-tree service (parent/child rollup)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/product_categories.py` extending the flat `CAT#{id}`/`META` model (`app/routers/catalog.py:55`, `create_category` at `:260`) into a tree: each category gains an optional `parent_category_id`, a `path` materialized ancestry key, and a `position`. Use the parent→children GSI from PRD-002 so listing a subtree is a single query, not a scan (the current `_scan_categories` fallback at `app/routers/catalog.py:211`).
- Provide `add_child`, `move_category` (re-parent with cycle detection), `list_children`, `get_ancestry`/`get_breadcrumb`, and `list_descendants`. Reject cycles and depth beyond a configured max.
- Keep the existing `GSI1PK="CATS"` flat listing (`:202`) working so legacy `list_categories` is unaffected when depth is off.

**Acceptance Criteria**
- A category can be created under a parent; children/ancestry/breadcrumb resolve via GSI query (no scan).
- Re-parenting into a descendant is rejected (cycle detection); max-depth is enforced.
- With `PRODUCT_DEPTH_ENABLED` off, `list_categories` returns the identical flat list as today.
- pytest covers add-child, move, cycle rejection, and ancestry materialization.

**Dependencies**
- PRD-002, PRD-003.

---

### PRD-005: Category-tree router endpoints
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add tree endpoints to the catalog router (`app/routers/catalog.py`, prefix `/ui/catalog`, `require_ui_session` + ownership via `_require_category_owner` at `:247`): `POST /categories/{id}/children`, `PATCH /categories/{id}/move`, `GET /categories/{id}/tree`, `GET /categories/{id}/breadcrumb`. Gate all behind `S.product_depth_enabled` (404/501 when off so the surface stays invisible).
- Reuse the existing pagination helpers (`encode_next_token`/`decode_next_token` at `:158`) and owner checks; emit audit events via the existing alert plumbing.

**Acceptance Criteria**
- Tree/breadcrumb endpoints return correct ordering; non-owners get 403 (via `_require_category_owner`).
- All new routes return 404/501 when the flag is off; existing `/categories` routes are unchanged.
- Router already registered in `app/main.py` (no new registration needed — endpoints added to existing `catalog.router`).

**Dependencies**
- PRD-004.

---

## Milestone 3 — Variants & Features/Options

### PRD-006: Product feature & feature-category model
**Type:** Feature  
**Priority:** P0  
**Estimate:** 4 days

**Description**
- Create `app/services/product_features.py`: feature categories (e.g. "Color", "Size") and their feature values (e.g. "Red", "XL"), each value carrying an optional `price_delta_cents` and `position` (OFBiz ProductFeature + ProductFeatureCategory). Store on `T.product_depth` keyed for feature-category→features GSI lookups (PRD-002).
- Provide `create_feature_category`, `add_feature_value`, `list_feature_categories`, `attach_feature_category_to_product` (ProductFeatureAppl), and `list_product_features(item_id)`.

**Acceptance Criteria**
- A feature category with N values attaches to a product; `list_product_features` returns them ordered by `position`.
- `price_delta_cents` validates as a signed int; deleting an in-use feature category is blocked.
- pytest covers create/attach/list and ordered retrieval.

**Dependencies**
- PRD-002, PRD-003.

---

### PRD-007: Virtual↔variant product service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 5 days

**Description**
- Create `app/services/product_variants.py`: mark a catalog item as VIRTUAL (parent) and create VARIANT children, each a distinct SKU mapping to a unique combination of feature values from PRD-006. Persist a ProductAssoc-style `VARIANT#{parent}#{variant}` row and a virtual→variant GSI (PRD-002) so the parent's variants resolve in one query.
- Compute each variant's effective price as the parent `price_cents` (`app/routers/catalog.py:370`) plus the sum of its feature `price_delta_cents` (PRD-006). Variant SKU is the inventory key (reconciles to `app/services/inventory.py` SKUs from OFB-003 — variant stock lives in inventory, NOT the scalar `stock_count`).
- Use deterministic variant ids (`sha256(parent_id + sorted feature-value tuple)`) so re-creating the same combination is idempotent and duplicate combinations are rejected.

**Acceptance Criteria**
- Creating a VIRTUAL product + variants yields one row per feature combination; duplicate combinations are rejected (deterministic id).
- Variant effective price = parent price + Σ feature deltas; computed in a pure, unit-tested function.
- Listing a virtual product's variants is a single GSI query; a standalone (non-virtual) item has zero variants and behaves exactly as today.
- pytest covers variant creation, dedupe idempotency, price computation, and the standalone no-op path.

**Dependencies**
- PRD-006.

---

### PRD-008: Variant & feature router endpoints
**Type:** Feature  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add endpoints to `app/routers/catalog.py` (flag-gated): `POST /items/{id}/feature-categories` (attach), `GET /items/{id}/features`, `POST /items/{id}/variants` (create variant from feature selections), `GET /items/{id}/variants`, `DELETE /items/{id}/variants/{variant_id}`, and `POST /feature-categories` + `POST /feature-categories/{id}/values` for the catalog owner.
- Reuse `_find_item_by_id` (`:702`) / `_require_category_owner` (`:247`) for ownership; `_catalog_item_out` returns the additive `product_type`/`variant_count` (PRD-003) for virtual parents.

**Acceptance Criteria**
- Owner can create feature categories/values, attach them, and create/list/delete variants; non-owners 403.
- `GET /items/{id}/variants` returns each variant's SKU, selected feature values, and effective price.
- All endpoints 404/501 with the flag off; existing item endpoints unchanged.

**Dependencies**
- PRD-007.

---

## Milestone 4 — Bundles / Kits & Associations

### PRD-009: Bundle/kit composition service
**Type:** Feature  
**Priority:** P0  
**Estimate:** 5 days

**Description**
- Create `app/services/product_bundles.py`: a BUNDLE/KIT product references component items (each with a quantity) via `BUNDLE#{bundle}#{component}` rows on `T.product_depth` (OFBiz ProductAssoc PRODUCT_COMPONENT). Distinguish a **kit** (price = sum of component prices, components shippable separately) from a **bundle** (fixed bundle price overriding component sum).
- Provide `set_components`, `list_components`, `expand_bundle(item_id, qty)` returning the flattened component line list + computed price, and `compute_bundle_price` (kit = Σ component price × qty; bundle = override `price_cents`). `expand_bundle` is the integration seam the cart will call so bundle stock reserves each component (reconciles to OFB-004 reservations) without forking cart logic.

**Acceptance Criteria**
- A bundle/kit can declare N components with quantities; `expand_bundle` returns the correct flattened lines and price.
- Kit price = Σ component prices × qty; bundle uses the fixed override; both unit-tested.
- A circular bundle (bundle containing itself) is rejected; nesting depth is bounded.
- pytest covers component CRUD, expansion, kit vs bundle pricing, and cycle rejection.

**Dependencies**
- PRD-007.

---

### PRD-010: Product associations service
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Create `app/services/product_associations.py` for non-variant/non-bundle associations (OFBiz ProductAssoc types SUBSTITUTE, COMPLEMENT/cross-sell, UPGRADE/upsell, MANUF). Store `ASSOC#{type}#{from}#{to}` rows with a source→targets GSI (PRD-002); deterministic id = `sha256(from + type + to)`.
- Provide `add_association`, `remove_association`, `list_associations(item_id, type=None)` returning hydrated target items (via `_find_item_by_id`). These power "related/substitute/upsell" surfaces in the storefront (consumed by the ECM eCommerce-integration module later).

**Acceptance Criteria**
- Associations create/list/remove per type; duplicate (same from/type/to) is idempotent (deterministic id).
- `list_associations` hydrates target item summaries and filters by type.
- pytest covers add/remove/list, type filtering, and dedupe.

**Dependencies**
- PRD-007.

---

### PRD-011: Bundle & association router endpoints
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add to `app/routers/catalog.py` (flag-gated): `PUT /items/{id}/bundle-components`, `GET /items/{id}/bundle`, `GET /items/{id}/expand`, `POST /items/{id}/associations`, `GET /items/{id}/associations`, `DELETE /items/{id}/associations/{assoc_id}`. Owner-gated via `_require_category_owner`/`_find_item_by_id`.

**Acceptance Criteria**
- Owner manages bundle components and associations; `GET /items/{id}/expand` returns the flattened component lines + price.
- Non-owners 403; all routes 404/501 with the flag off.

**Dependencies**
- PRD-009, PRD-010.

---

## Milestone 5 — Product Price Components

### PRD-012: Product-level price components
**Type:** Feature  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Create `app/services/product_price_components.py` modeling OFBiz ProductPrice rows: per-product price components by `price_type` (LIST_PRICE, DEFAULT_PRICE, PROMO_PRICE, COMPETITIVE_PRICE, MINIMUM_PRICE, AVERAGE_COST) with optional date-effective windows and currency. Stored as `PRICE#{item_id}#{type}#{effective_at}` rows (numeric `effective_at` GSI sort key declared with `attr_types` per PRD-002).
- Provide `set_price_component`, `list_price_components`, and `resolve_effective_price(item_id, as_of, price_type=DEFAULT_PRICE)` returning the active component for a date. The scalar `price_cents` (`app/routers/catalog.py:370`) remains the authoritative DEFAULT_PRICE fallback so cart/checkout is unchanged when no components exist — this layer is read-only enrichment, NOT a new charge path (money still flows through the existing ledger/billing).

**Acceptance Criteria**
- Multiple dated price components per type resolve to the correct active one for a given `as_of`.
- With no components, `resolve_effective_price` returns the scalar `price_cents` (back-compat); cart pricing is byte-for-byte unchanged.
- pytest covers date-window resolution, type fallback, and the scalar fallback path.

**Dependencies**
- PRD-003, PRD-002.

---

### PRD-013: Price-component router endpoints
**Type:** Feature  
**Priority:** P2  
**Estimate:** 2 days

**Description**
- Add to `app/routers/catalog.py` (flag-gated): `PUT /items/{id}/price-components`, `GET /items/{id}/price-components`, `GET /items/{id}/effective-price`. Owner-gated; `effective-price` accepts an optional `as_of` query param and a `price_type`.

**Acceptance Criteria**
- Owner sets/lists price components; `effective-price` returns the resolved component or the scalar fallback.
- Non-owners 403; routes 404/501 with the flag off.

**Dependencies**
- PRD-012.

---

## Milestone 6 — Frontend & Tests

### PRD-014: Frontend types & endpoint wrappers
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add TypeScript interfaces to `frontend/src/api/types.ts` mirroring the PRD-003 models (ProductType, Variant, ProductFeature, FeatureCategory, BundleComponent, ProductAssoc, PriceComponent, category-tree node), keeping the existing `CatalogItem` type additive.
- Add endpoint wrappers in `frontend/src/api/endpoints/` (extend the existing catalog endpoints file) for category-tree, variants/features, bundles/associations, and price-component routes, using the axios instance in `frontend/src/api/client.ts` (CSRF header auto-attached).

**Acceptance Criteria**
- TS types compile and mirror the backend shapes; existing `CatalogItem` consumers are unaffected (new fields optional).
- Endpoint wrappers cover all PRD-005/008/011/013 routes and return typed responses.

**Dependencies**
- PRD-003, PRD-005, PRD-008, PRD-011, PRD-013.

---

### PRD-015: Catalog-depth admin UI (variants, features, bundles, tree)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 5 days

**Description**
- Extend the existing catalog admin pages under `frontend/src/pages/shop/admin/` (alongside `AdminCatalog.tsx`/`ItemEditor.tsx`) with: a category-tree manager (drag/move, breadcrumb), a feature-category/value editor, a variant matrix builder (feature combinations → SKUs with effective price), a bundle/kit composer, and an associations panel — all using React Query + shadcn/ui per repo conventions.
- Add a price-components editor (dated rows). Gate the entire depth UI behind a runtime flag exposed from the backend (mirrors `S.product_depth_enabled`) so it's hidden when off; add the route/nav entry in `frontend/src/App.tsx`.

**Acceptance Criteria**
- Admin can build a category tree, define features, generate variants, compose a bundle, add associations, and set price components — all persisting via the PRD-014 endpoints.
- The depth UI is hidden/disabled when the flag is off; the existing flat catalog editor is unchanged.
- Variant matrix shows each combination's effective price live (parent + feature deltas).

**Dependencies**
- PRD-014.

---

### PRD-016: Hermetic offline pytest + E2E tests
**Type:** Chore  
**Priority:** P1  
**Estimate:** 4 days

**Description**
- Add hermetic offline pytest suites (`tests/test_prd_product_depth_*.py`) for: category-tree move/cycle/ancestry, feature attach/order, variant dedupe-idempotency + price computation, bundle/kit expansion + cycle rejection, association dedupe, and price-component date resolution + scalar fallback. Follow the repo pattern: moto in-memory tables bound to the frozen `T.product_depth`/`T.catalog` handles via `object.__setattr__`, `S` flag toggled via `object.__setattr__`, no real AWS/network.
- Add `frontend/e2e/catalog-depth.spec.ts` covering the admin flow (create virtual product → features → variants → bundle → tree) under the seeded-session + CSRF patterns (CLAUDE.md / MEMORY.md), gated on the flag being enabled in the test env.
- Add a flag-off regression assertion: with `PRODUCT_DEPTH_ENABLED` off, the existing catalog endpoints and a representative `CatalogItemOut` serialization are byte-for-byte unchanged.

**Acceptance Criteria**
- pytest covers every service from PRD-004/006/007/009/010/012 (tree, features, variants, bundles, associations, prices) including idempotency and back-compat.
- The flag-off regression test asserts existing catalog responses are unchanged.
- `catalog-depth.spec.ts` passes under the standard 1-worker Playwright config.

**Dependencies**
- PRD-005, PRD-008, PRD-011, PRD-013, PRD-015.

---
