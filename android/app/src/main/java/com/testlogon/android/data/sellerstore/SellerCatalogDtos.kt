package com.testlogon.android.data.sellerstore

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * ECOM (seller store) — write-only request DTOs for catalog CRUD. Read/response shapes reuse
 * [com.testlogon.android.data.catalog.CatalogCategoryDto] / [CatalogItemDto] (one item shape serves
 * list, detail and mutation responses). Verified against the backend catalog router
 * (CatalogCategoryCreateIn / CatalogItemCreateIn / CatalogItemPatchIn).
 */

/** POST ui/catalog/categories body. */
@JsonClass(generateAdapter = true)
data class SellerCategoryCreateDto(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
)

/** POST ui/catalog/categories/{category_id}/items body. */
@JsonClass(generateAdapter = true)
data class SellerItemCreateDto(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "price_cents") val priceCents: Long,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "image_urls") val imageUrls: List<String> = emptyList(),
    @Json(name = "stock_count") val stockCount: Int? = null,
)

/** PATCH ui/catalog/categories/{category_id}/items/{item_id} body (server requires >=1 field). */
@JsonClass(generateAdapter = true)
data class SellerItemPatchDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "price_cents") val priceCents: Long? = null,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "stock_count") val stockCount: Int? = null,
)
