package com.testlogon.android.data.catalog

/**
 * AND-204 / AND-205 — immutable domain models for the storefront catalog.
 *
 * Mapping (DTO -> domain) lives here; the repository / paging source never expose raw DTOs. Money is
 * carried as integer minor units (priceCents) + ISO-4217 currency so locale formatting is applied in
 * the presentation layer with no float drift. The first image_url is the thumbnail (the wire provides
 * no dedicated thumbnail field and no per-image alt text).
 */

/** One storefront category. The bar/list API provides no image or item-count field. */
data class CatalogCategory(
    val categoryId: String,
    val name: String,
    val description: String? = null,
    val creatorId: String? = null,
    val createdAt: String,
)

/** One catalog item (product). Same shape for list and detail. */
data class CatalogItem(
    val itemId: String,
    val categoryId: String,
    val name: String,
    val priceCents: Long,
    val currency: String,
    val imageUrls: List<String> = emptyList(),
    val description: String? = null,
    val stockCount: Int? = null,
    val stockStatus: String = "unlimited",
    val position: Int? = null,
    /** Free-form product attributes (AND-206 detail). Stringified values; insertion order preserved. */
    val attributes: List<Pair<String, String>> = emptyList(),
) {
    /** First image is the grid/detail thumbnail; null when the item has no images. */
    val thumbnailUrl: String? get() = imageUrls.firstOrNull()
}

/** One mapped page plus the opaque next-page cursor (null/absent = last page). */
data class CatalogCategoryPage(
    val categories: List<CatalogCategory>,
    val nextToken: String?,
)

/** One mapped page of items plus the opaque next-page cursor (null/absent = last page). */
data class CatalogItemPage(
    val items: List<CatalogItem>,
    val nextToken: String?,
)

// ---- Mappers (DTO -> domain) ----

internal fun CatalogCategoryDto.toDomain(): CatalogCategory = CatalogCategory(
    categoryId = categoryId,
    name = name,
    description = description,
    creatorId = creatorId,
    createdAt = createdAt,
)

internal fun CatalogItemDto.toDomain(): CatalogItem = CatalogItem(
    itemId = itemId,
    categoryId = categoryId,
    name = name,
    priceCents = priceCents,
    currency = currency,
    imageUrls = imageUrls,
    description = description,
    stockCount = stockCount,
    stockStatus = stockStatus,
    position = position,
    // Drop null-valued attributes; stringify the rest, preserving the wire order.
    attributes = attributes.mapNotNull { (k, v) -> v?.let { k to it.toString() } },
)

internal fun CatalogCategoryListDto.toDomain(): CatalogCategoryPage = CatalogCategoryPage(
    categories = items.map { it.toDomain() },
    nextToken = nextToken,
)

internal fun CatalogItemListDto.toDomain(): CatalogItemPage = CatalogItemPage(
    items = items.map { it.toDomain() },
    nextToken = nextToken,
)
