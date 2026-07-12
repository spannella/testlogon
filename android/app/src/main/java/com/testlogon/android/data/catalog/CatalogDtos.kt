package com.testlogon.android.data.catalog

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-204 — wire DTOs for the storefront catalog (shop) surface.
 *
 * Verified against the backend OpenAPI (CatalogCategoryOut / CatalogItemOut / CatalogCategoryListOut /
 * CatalogItemListOut) and reference/src/api/types.ts (CatalogCategory, CatalogItem, PaginatedList).
 * Distinct from the VOD video gallery (data/vod, data/gallery -> ui/videos/...): catalog lives at
 * ui/catalog/... and models products with flat money fields.
 *
 * Contract notes:
 *  - One item shape (CatalogItemOut) serves both list and detail; there is no single-item GET.
 *  - Money is flat: price_cents (Long minor units) + currency (ISO-4217). No nested price / display.
 *  - Media is a flat image_urls array; there is no per-image alt text.
 *  - attributes is additionalProperties:true (arbitrary JSON values) -> Map of String to nullable Any.
 *  - Paged envelopes carry exactly items + next_token (no total/page/limit/has_more); next_token null
 *    on the last page.
 */

/** A storefront category (schema CatalogCategoryOut). required: category_id, name, created_at. */
@JsonClass(generateAdapter = true)
data class CatalogCategoryDto(
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "name") val name: String,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "creator_id") val creatorId: String? = null,
)

/** Paged category list (schema CatalogCategoryListOut): items + next_token. */
@JsonClass(generateAdapter = true)
data class CatalogCategoryListDto(
    @Json(name = "items") val items: List<CatalogCategoryDto> = emptyList(),
    @Json(name = "next_token") val nextToken: String? = null,
)

/**
 * A catalog item — ONE shape for both list and (client-derived) detail (schema CatalogItemOut).
 * required: category_id, item_id, name, price_cents, currency, image_urls, attributes, created_at,
 * updated_at. Optional fields default for resilience.
 */
@JsonClass(generateAdapter = true)
data class CatalogItemDto(
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "item_id") val itemId: String,
    @Json(name = "name") val name: String,
    @Json(name = "price_cents") val priceCents: Long,
    @Json(name = "currency") val currency: String,
    @Json(name = "image_urls") val imageUrls: List<String> = emptyList(),
    @Json(name = "attributes") val attributes: Map<String, Any?> = emptyMap(),
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "updated_at") val updatedAt: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "creator_id") val creatorId: String? = null,
    @Json(name = "position") val position: Int? = null,
    @Json(name = "stock_count") val stockCount: Int? = null,
    @Json(name = "stock_status") val stockStatus: String = "unlimited",
    @Json(name = "low_stock_threshold") val lowStockThreshold: Int = 5,
    @Json(name = "stock_updated_at") val stockUpdatedAt: String? = null,
)

/**
 * Paged item list AND search envelope (schema CatalogItemListOut): items + next_token. Search returns
 * this same shape — there is no distinct search-result DTO and no query/total fields.
 */
@JsonClass(generateAdapter = true)
data class CatalogItemListDto(
    @Json(name = "items") val items: List<CatalogItemDto> = emptyList(),
    @Json(name = "next_token") val nextToken: String? = null,
)

// ─── Reviews (ECOM) ──────────────────────────────────────────────────────────

/**
 * One catalog item review (schema CatalogReviewOut). The server stores a free-form `reviewer` string
 * (there is no user_sub on the row); the client writes its own user_sub there so it can detect
 * delete-own. required: item_id, review_id, rating, created_at.
 */
@JsonClass(generateAdapter = true)
data class CatalogReviewDto(
    @Json(name = "item_id") val itemId: String,
    @Json(name = "review_id") val reviewId: String,
    @Json(name = "rating") val rating: Int,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "body") val body: String? = null,
    @Json(name = "reviewer") val reviewer: String? = null,
)

/** POST body (schema CatalogReviewCreateIn). rating is 1..5; the rest are optional. */
@JsonClass(generateAdapter = true)
data class CatalogReviewCreateDto(
    @Json(name = "rating") val rating: Int,
    @Json(name = "title") val title: String? = null,
    @Json(name = "body") val body: String? = null,
    @Json(name = "reviewer") val reviewer: String? = null,
)

/** Paged review list (schema CatalogReviewListOut): items + next_token. */
@JsonClass(generateAdapter = true)
data class CatalogReviewListDto(
    @Json(name = "items") val items: List<CatalogReviewDto> = emptyList(),
    @Json(name = "next_token") val nextToken: String? = null,
)

/** Generic { ok: true } acknowledgement (review delete). */
@JsonClass(generateAdapter = true)
data class OkRespCatalogDto(
    @Json(name = "ok") val ok: Boolean = true,
)
