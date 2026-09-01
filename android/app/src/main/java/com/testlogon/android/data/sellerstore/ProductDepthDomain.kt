package com.testlogon.android.data.sellerstore

/**
 * ECOM (catalog depth) — UI-facing domain models for the advanced seller product editor + wire→domain
 * mappers. Money is integer minor units (cents). Kept free of Moshi/Retrofit annotations so the UI layer
 * never sees the wire shapes.
 */

data class Variant(
    val variantId: String,
    val parentItemId: String,
    val sku: String,
    val featureValues: Map<String, String>,
    val priceDeltaCents: Long,
    val effectivePriceCents: Long,
)

data class PriceComponent(
    val priceComponentId: String,
    val itemId: String,
    val priceType: String,
    val amountCents: Long,
    val currency: String,
    val effectiveAt: Long,
    val expiresAt: Long?,
    val isActive: Boolean,
)

data class EffectivePrice(
    val amountCents: Long,
    val currency: String,
    val priceComponentId: String?,
    val source: String,
)

data class BundleComponent(
    val parentItemId: String,
    val componentItemId: String,
    val quantity: Int,
    val componentSku: String?,
    val componentName: String?,
    val componentPriceCents: Long?,
)

data class ProductFeatureCategory(
    val featureCategoryId: String,
    val name: String,
    val position: Int,
    val itemId: String,
)

data class ProductFeatureValue(
    val featureValueId: String,
    val featureCategoryId: String,
    val value: String,
    val priceDeltaCents: Long,
    val position: Int,
)

data class ProductFeatures(
    val itemId: String,
    val categories: List<ProductFeatureCategory>,
    val values: List<ProductFeatureValue>,
) {
    /** Values grouped under their owning feature category id (for a "Color: Red/Blue" style layout). */
    fun valuesFor(featureCategoryId: String): List<ProductFeatureValue> =
        values.filter { it.featureCategoryId == featureCategoryId }.sortedBy { it.position }
}

data class CategoryTreeNode(
    val categoryId: String,
    val name: String,
    val children: List<CategoryTreeNode>,
)

// ── mappers ──────────────────────────────────────────────────────────────────

fun VariantDto.toDomain(): Variant = Variant(
    variantId = variantId,
    parentItemId = parentItemId,
    sku = sku,
    featureValues = featureValues,
    priceDeltaCents = priceDeltaCents,
    effectivePriceCents = effectivePriceCents,
)

fun PriceComponentDto.toDomain(): PriceComponent = PriceComponent(
    priceComponentId = priceComponentId,
    itemId = itemId,
    priceType = priceType,
    amountCents = amountCents,
    currency = currency,
    effectiveAt = effectiveAt,
    expiresAt = expiresAt,
    isActive = isActive,
)

fun EffectivePriceDto.toDomain(): EffectivePrice = EffectivePrice(
    amountCents = amountCents,
    currency = currency,
    priceComponentId = priceComponentId,
    source = source,
)

fun BundleComponentDto.toDomain(): BundleComponent = BundleComponent(
    parentItemId = parentItemId,
    componentItemId = componentItemId,
    quantity = quantity,
    componentSku = componentSku,
    componentName = componentName,
    componentPriceCents = componentPriceCents,
)

fun ProductFeatureCategoryDto.toDomain(): ProductFeatureCategory = ProductFeatureCategory(
    featureCategoryId = featureCategoryId,
    name = name,
    position = position,
    itemId = itemId,
)

fun ProductFeatureValueDto.toDomain(): ProductFeatureValue = ProductFeatureValue(
    featureValueId = featureValueId,
    featureCategoryId = featureCategoryId,
    value = value,
    priceDeltaCents = priceDeltaCents,
    position = position,
)

fun ProductFeaturesDto.toDomain(): ProductFeatures = ProductFeatures(
    itemId = itemId,
    categories = featureCategories.map { it.toDomain() },
    values = values.map { it.toDomain() },
)

fun CategoryTreeNodeDto.toDomain(): CategoryTreeNode = CategoryTreeNode(
    categoryId = categoryId,
    name = name,
    children = children.map { it.toDomain() },
)
