package com.testlogon.android.data.sellerstore

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * ECOM (catalog depth) — wire DTOs for the advanced seller product endpoints (OFBiz catalog depth:
 * variants, price components, bundle components, per-item product features, category tree). All under
 * the /ui/catalog router. Mirrors the LIVE Pydantic models in app/models.py and the web contract in
 * frontend/src/api/endpoints/productDepth.ts. These endpoints are feature-gated on the backend
 * (product_depth_enabled): reads return 404/501 when off — the repository degrades those to empty.
 */

// ── Product type (PRD-007) ───────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class ProductTypeRespDto(
    @Json(name = "item_id") val itemId: String,
    @Json(name = "product_type") val productType: String,
)

@JsonClass(generateAdapter = true)
data class SetProductTypeReqDto(
    @Json(name = "product_type") val productType: String,
)

// ── Variants (PRD-007) ───────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class VariantDto(
    @Json(name = "variant_id") val variantId: String,
    @Json(name = "parent_item_id") val parentItemId: String,
    @Json(name = "sku") val sku: String,
    @Json(name = "feature_values") val featureValues: Map<String, String> = emptyMap(),
    @Json(name = "price_delta_cents") val priceDeltaCents: Long = 0,
    @Json(name = "effective_price_cents") val effectivePriceCents: Long = 0,
    @Json(name = "creator_id") val creatorId: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class VariantListDto(
    @Json(name = "item_id") val itemId: String,
    @Json(name = "variants") val variants: List<VariantDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class CreateVariantReqDto(
    @Json(name = "feature_values") val featureValues: Map<String, String>,
    @Json(name = "sku_override") val skuOverride: String? = null,
)

// ── Price components (PRD-012) ───────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class PriceComponentDto(
    @Json(name = "price_component_id") val priceComponentId: String,
    @Json(name = "item_id") val itemId: String,
    @Json(name = "price_type") val priceType: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "effective_at") val effectiveAt: Long,
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "is_active") val isActive: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class PriceComponentListDto(
    @Json(name = "item_id") val itemId: String,
    @Json(name = "components") val components: List<PriceComponentDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class AddPriceComponentReqDto(
    @Json(name = "price_type") val priceType: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "effective_at") val effectiveAt: Long,
    @Json(name = "expires_at") val expiresAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class EffectivePriceDto(
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "price_component_id") val priceComponentId: String? = null,
    @Json(name = "source") val source: String,
)

// ── Bundle components (product_depth_bundles) ────────────────────────────────

@JsonClass(generateAdapter = true)
data class BundleComponentDto(
    @Json(name = "parent_item_id") val parentItemId: String,
    @Json(name = "component_item_id") val componentItemId: String,
    @Json(name = "quantity") val quantity: Int = 1,
    @Json(name = "component_sku") val componentSku: String? = null,
    @Json(name = "component_name") val componentName: String? = null,
    @Json(name = "component_price_cents") val componentPriceCents: Long? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class BundleComponentListDto(
    @Json(name = "parent_item_id") val parentItemId: String,
    @Json(name = "components") val components: List<BundleComponentDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class AddBundleComponentReqDto(
    @Json(name = "component_item_id") val componentItemId: String,
    @Json(name = "quantity") val quantity: Int = 1,
)

// ── Per-item product features (PRD-006) ──────────────────────────────────────

@JsonClass(generateAdapter = true)
data class ProductFeatureCategoryDto(
    @Json(name = "feature_category_id") val featureCategoryId: String,
    @Json(name = "name") val name: String,
    @Json(name = "position") val position: Int = 0,
    @Json(name = "item_id") val itemId: String,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class ProductFeatureValueDto(
    @Json(name = "feature_value_id") val featureValueId: String,
    @Json(name = "feature_category_id") val featureCategoryId: String,
    @Json(name = "value") val value: String,
    @Json(name = "price_delta_cents") val priceDeltaCents: Long = 0,
    @Json(name = "position") val position: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class ProductFeaturesDto(
    @Json(name = "item_id") val itemId: String,
    @Json(name = "feature_categories") val featureCategories: List<ProductFeatureCategoryDto> = emptyList(),
    @Json(name = "values") val values: List<ProductFeatureValueDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class CreateProductFeatureCategoryReqDto(
    @Json(name = "name") val name: String,
    @Json(name = "position") val position: Int = 0,
)

@JsonClass(generateAdapter = true)
data class AddProductFeatureValueReqDto(
    @Json(name = "value") val value: String,
    @Json(name = "price_delta_cents") val priceDeltaCents: Long = 0,
    @Json(name = "position") val position: Int = 0,
)

// ── Category tree (PRD-004 / PRD-005 / PRD-014) ──────────────────────────────

@JsonClass(generateAdapter = true)
data class CategoryTreeNodeDto(
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "name") val name: String,
    @Json(name = "children") val children: List<CategoryTreeNodeDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class CategoryBreadcrumbCrumbDto(
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "name") val name: String,
)

@JsonClass(generateAdapter = true)
data class CategoryBreadcrumbDto(
    @Json(name = "breadcrumb") val breadcrumb: List<CategoryBreadcrumbCrumbDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AddCategoryChildReqDto(
    @Json(name = "child_category_id") val childCategoryId: String,
    @Json(name = "position") val position: Int = 0,
)

@JsonClass(generateAdapter = true)
data class MoveCategoryReqDto(
    @Json(name = "new_parent_id") val newParentId: String,
)

// ── Bulk operations (UX-004) ─────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class BulkDeleteReqDto(
    @Json(name = "item_ids") val itemIds: List<String>,
)

@JsonClass(generateAdapter = true)
data class BulkUpdateReqDto(
    @Json(name = "item_ids") val itemIds: List<String>,
    @Json(name = "updates") val updates: Map<String, String>,
)

@JsonClass(generateAdapter = true)
data class BulkResultRowDto(
    @Json(name = "item_id") val itemId: String,
    @Json(name = "ok") val ok: Boolean,
    @Json(name = "error") val error: String? = null,
)

@JsonClass(generateAdapter = true)
data class BulkResultDto(
    @Json(name = "results") val results: List<BulkResultRowDto> = emptyList(),
    @Json(name = "succeeded") val succeeded: Int = 0,
    @Json(name = "failed") val failed: Int = 0,
)
