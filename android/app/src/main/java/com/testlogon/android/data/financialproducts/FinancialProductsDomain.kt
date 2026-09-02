package com.testlogon.android.data.financialproducts

/**
 * Framework-free domain models + total DTO -> domain mappers for CUS-004 Financial Products.
 * Timestamps are epoch-seconds.
 */

data class FinancialProduct(
    val code: String,
    val name: String,
    val parentCode: String?,
    val category: String?,
    val family: String?,
    val superFamily: String?,
    val description: String?,
    val version: Int,
    val updatedAtSeconds: Long,
) {
    val familyLabel: String get() = FinancialProductsMath.familyLabel(category, family, superFamily)
}

data class ProductAttribute(
    val id: String,
    val name: String,
    val type: FinancialProductsMath.AttributeType?,
    val typeRaw: String,
    val value: String,
) {
    val typeLabel: String get() = type?.label ?: typeRaw
}

data class ProductCollection(
    val code: String,
    val name: String,
    val productCodes: List<String>,
    val updatedAtSeconds: Long,
) {
    val memberCountLabel: String
        get() = when (val n = productCodes.size) {
            0 -> "No products"
            1 -> "1 product"
            else -> "$n products"
        }
}

// ---- Mappers (DTO -> domain) ----

internal fun FinancialProductDto.toDomain(): FinancialProduct = FinancialProduct(
    code = productCode,
    name = name.ifBlank { productCode },
    parentCode = parentProductCode?.takeIf { it.isNotBlank() },
    category = category?.takeIf { it.isNotBlank() },
    family = family?.takeIf { it.isNotBlank() },
    superFamily = superFamily?.takeIf { it.isNotBlank() },
    description = description?.takeIf { it.isNotBlank() },
    version = version,
    updatedAtSeconds = updatedAt,
)

internal fun ProductAttributeDto.toDomain(): ProductAttribute = ProductAttribute(
    id = attributeId,
    name = name,
    type = FinancialProductsMath.AttributeType.from(type),
    typeRaw = type,
    value = value,
)

internal fun ProductCollectionDto.toDomain(): ProductCollection = ProductCollection(
    code = collectionCode,
    name = name.ifBlank { collectionCode },
    productCodes = productCodes,
    updatedAtSeconds = updatedAt,
)
