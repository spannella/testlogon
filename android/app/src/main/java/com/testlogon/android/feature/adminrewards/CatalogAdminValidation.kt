package com.testlogon.android.feature.adminrewards

/**
 * PURE, framework-free validation for the rewards-catalog admin form. No Android deps, integer-only money
 * (cents) + integer points, so it is fully exercisable by plain JVM unit tests and shared by the ViewModel
 * to disable submit while the draft is invalid + surface per-field inline errors.
 *
 * A catalog item is {name, description, cost_points, value_cents, kind(cash|perk), active}. Rules:
 *  - name        : non-empty (trimmed)
 *  - cost_points : > 0 (a redeemable reward must cost some points)
 *  - value_cents : >= 0 (never negative)
 *  - kind        : one of cash | perk
 *  - a CASH reward must carry a positive value_cents (otherwise it redeems to $0)
 */

/** The canonical reward kinds. */
val CATALOG_KINDS: List<String> = listOf("cash", "perk")

/** Per-field validation errors, keyed by field name; empty when the draft is valid. */
data class CatalogValidationResult(
    val errors: Map<String, String>,
) {
    val ok: Boolean get() = errors.isEmpty()
    fun errorFor(field: String): String? = errors[field]
}

/** An editable catalog draft (integer money/points; kind kept as a raw string for the picker). */
data class CatalogDraft(
    val name: String = "",
    val description: String = "",
    val costPoints: Long = 0L,
    val valueCents: Long = 0L,
    val kind: String = "perk",
    val active: Boolean = true,
)

/** A blank draft for the CREATE form (a sensible default kind + active). */
fun emptyDraft(): CatalogDraft = CatalogDraft()

/**
 * Validate the four core inputs. Pure: takes primitives so it is trivially unit-testable and reusable from
 * the ViewModel without constructing a draft.
 */
fun validateCatalogItem(
    name: String,
    costPoints: Long,
    valueCents: Long,
    kind: String,
): CatalogValidationResult {
    val errors = LinkedHashMap<String, String>()

    if (name.trim().isEmpty()) {
        errors["name"] = "Name is required"
    }
    if (costPoints <= 0L) {
        errors["costPoints"] = "Cost must be greater than 0 points"
    }
    if (valueCents < 0L) {
        errors["valueCents"] = "Value cannot be negative"
    }

    val normalizedKind = kind.trim().lowercase()
    if (normalizedKind !in CATALOG_KINDS) {
        errors["kind"] = "Kind must be cash or perk"
    } else if (normalizedKind == "cash" && valueCents <= 0L) {
        // A cash reward with no value would redeem to $0.
        errors["valueCents"] = "Cash rewards need a value above $0"
    }

    return CatalogValidationResult(errors)
}

/** Convenience overload validating a whole [CatalogDraft]. */
fun validateCatalogItem(draft: CatalogDraft): CatalogValidationResult =
    validateCatalogItem(draft.name, draft.costPoints, draft.valueCents, draft.kind)
