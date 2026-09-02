package com.testlogon.android.data.financialproducts

/**
 * Framework-free pure logic for the CUS-004 Financial Products surface:
 *  - the product-code pattern gate (a 1:1 mirror of the backend `FinancialProductCreateIn.product_code`
 *    regex `^[a-zA-Z0-9_\-]{1,64}$`),
 *  - attribute-type enumeration + typed VALUE validation (mirrors `ProductAttributeSetIn.type`
 *    `Literal["STRING","INTEGER","DOUBLE","DATE_WITH_DAY"]` and the 2048-char value cap),
 *  - create-form validators used to gate submit.
 *
 * Nothing here touches Android, Retrofit or coroutines, so it is fully unit-testable on the JVM.
 */
object FinancialProductsMath {

    const val PRODUCT_CODE_MAX = 64
    const val ATTRIBUTE_VALUE_MAX = 2048

    private val PRODUCT_CODE_RE = Regex("[a-zA-Z0-9_\\-]{1,$PRODUCT_CODE_MAX}")
    private val DATE_RE = Regex("\\d{4}-\\d{2}-\\d{2}")

    /** The server-supported attribute value types (mirrors the backend Literal). */
    enum class AttributeType(val wire: String, val label: String) {
        STRING("STRING", "Text"),
        INTEGER("INTEGER", "Integer"),
        DOUBLE("DOUBLE", "Decimal"),
        DATE_WITH_DAY("DATE_WITH_DAY", "Date");

        companion object {
            val ALL: List<AttributeType> = entries

            fun from(raw: String?): AttributeType? = when (raw?.uppercase()) {
                "STRING" -> STRING
                "INTEGER" -> INTEGER
                "DOUBLE" -> DOUBLE
                "DATE_WITH_DAY" -> DATE_WITH_DAY
                else -> null
            }
        }
    }

    /** True when [code] matches the backend product-code pattern (alnum + `_` + `-`, 1..64). */
    fun isValidProductCode(code: String): Boolean = PRODUCT_CODE_RE.matches(code)

    /**
     * True when [value] is a valid literal for the attribute [type] and within the length cap.
     * STRING accepts anything non-empty (<= cap); INTEGER a signed integer; DOUBLE a finite number;
     * DATE_WITH_DAY an ISO `YYYY-MM-DD` date. Blank is always invalid (server requires a value).
     */
    fun isValidAttributeValue(type: AttributeType, value: String): Boolean {
        val trimmed = value.trim()
        if (trimmed.isEmpty() || trimmed.length > ATTRIBUTE_VALUE_MAX) return false
        return when (type) {
            AttributeType.STRING -> true
            AttributeType.INTEGER -> trimmed.toLongOrNull() != null
            AttributeType.DOUBLE -> trimmed.toDoubleOrNull()?.let { it.isFinite() } == true
            AttributeType.DATE_WITH_DAY -> isValidIsoDate(trimmed)
        }
    }

    /** ISO `YYYY-MM-DD` with real month/day ranges (no full calendar check; matches the web widget). */
    fun isValidIsoDate(value: String): Boolean {
        if (!DATE_RE.matches(value)) return false
        val month = value.substring(5, 7).toIntOrNull() ?: return false
        val day = value.substring(8, 10).toIntOrNull() ?: return false
        return month in 1..12 && day in 1..31
    }

    /** Reasons a create-product form is not submittable (empty when valid). */
    fun productFormErrors(productCode: String, name: String): List<String> {
        val errors = mutableListOf<String>()
        val code = productCode.trim()
        when {
            code.isEmpty() -> errors.add("Product code is required")
            !isValidProductCode(code) -> errors.add("Invalid product code (a-z, 0-9, _ , -; max $PRODUCT_CODE_MAX)")
        }
        if (name.trim().isEmpty()) errors.add("Name is required")
        return errors
    }

    fun canSubmitProduct(productCode: String, name: String): Boolean =
        productFormErrors(productCode, name).isEmpty()

    /** Reasons a create-collection form is not submittable (empty when valid). */
    fun collectionFormErrors(collectionCode: String, name: String): List<String> {
        val errors = mutableListOf<String>()
        val code = collectionCode.trim()
        when {
            code.isEmpty() -> errors.add("Collection code is required")
            !isValidProductCode(code) -> errors.add("Invalid collection code (a-z, 0-9, _ , -; max $PRODUCT_CODE_MAX)")
        }
        if (name.trim().isEmpty()) errors.add("Name is required")
        return errors
    }

    fun canSubmitCollection(collectionCode: String, name: String): Boolean =
        collectionFormErrors(collectionCode, name).isEmpty()

    /** Reasons a set-attribute form is not submittable (empty when valid). */
    fun attributeFormErrors(name: String, type: AttributeType, value: String): List<String> {
        val errors = mutableListOf<String>()
        if (name.trim().isEmpty()) errors.add("Attribute name is required")
        if (!isValidAttributeValue(type, value)) errors.add("Value is not a valid ${type.label}")
        return errors
    }

    fun canSubmitAttribute(name: String, type: AttributeType, value: String): Boolean =
        attributeFormErrors(name, type, value).isEmpty()

    /** Human label for a product's family chain (e.g. "Deposits › Savings"), or "—" when empty. */
    fun familyLabel(category: String?, family: String?, superFamily: String?): String {
        val parts = listOfNotNull(
            superFamily?.takeIf { it.isNotBlank() },
            family?.takeIf { it.isNotBlank() },
            category?.takeIf { it.isNotBlank() },
        )
        return if (parts.isEmpty()) "—" else parts.joinToString(" › ")
    }
}
