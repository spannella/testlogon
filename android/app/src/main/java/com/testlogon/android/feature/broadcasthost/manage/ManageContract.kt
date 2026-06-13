package com.testlogon.android.feature.broadcasthost.manage

import com.testlogon.android.data.broadcast.shelf.ShelfProduct
import com.testlogon.android.data.broadcast.tips.Goal

/**
 * AND-314 — presentation contract for the host goals + products authoring surface (two tabs). Holds a Goals
 * sub-state and a Products sub-state (each its own Loading / Content / Empty / Error / Offline + isRefreshing),
 * a per-entity [inFlight] set (the triggering control is disabled while its mutation runs, FR-X1), one-shot
 * events (snackbar), and the goal-create + set-price form/validation state.
 */
data class ManageUiState(
    val selectedTab: ManageTab = ManageTab.GOALS,
    val goals: GoalsState = GoalsState.Loading,
    val products: ProductsState = ProductsState.Loading,
    /** Keys of in-flight mutations, e.g. "goal_delete:g1", "product_remove:i1", "price:i1". */
    val inFlight: Set<String> = emptySet(),
    /** The goal-create form (client validation mirrors the server bounds). */
    val goalForm: GoalForm = GoalForm(),
    /** The open set-price dialog target (item + form), or null when closed. */
    val priceForm: PriceForm? = null,
    /** A pending delete/remove confirmation, or null when no dialog is open. */
    val confirm: ConfirmTarget? = null,
    /** One-shot event surfaced as a snackbar; cleared via consumeEvent(). */
    val event: ManageEvent? = null,
) {
    fun isInFlight(key: String): Boolean = inFlight.contains(key)
}

/** Which authoring tab is selected. */
enum class ManageTab { GOALS, PRODUCTS }

/** Loadable state for the Goals tab. */
sealed interface GoalsState {
    data object Loading : GoalsState
    data class Content(val goals: List<Goal>, val isRefreshing: Boolean = false) : GoalsState
    data object Empty : GoalsState
    data class Error(val message: String, val offline: Boolean = false) : GoalsState
}

/** Loadable state for the Products tab. */
sealed interface ProductsState {
    data object Loading : ProductsState
    data class Content(val products: List<ShelfProduct>, val isRefreshing: Boolean = false) : ProductsState
    data object Empty : ProductsState
    data class Error(val message: String, val offline: Boolean = false) : ProductsState
}

/**
 * AND-314 — goal-create form with client validation mirroring the server bounds (FR-G4): label 1..200 chars,
 * target 100..10_000_000 cents, sort_order 0..4. [targetDollars] is the raw user text (dollars.cents); it is
 * parsed to cents for submission + validation.
 */
data class GoalForm(
    val label: String = "",
    val targetDollars: String = "",
    val sortOrder: Int = 0,
) {
    /** Parsed target in cents, or null when the input is not a usable amount. */
    val targetCents: Long? get() = parseDollarsToCents(targetDollars)

    val labelValid: Boolean get() = label.trim().length in LABEL_MIN..LABEL_MAX
    val targetValid: Boolean get() = targetCents?.let { it in TARGET_MIN_CENTS..TARGET_MAX_CENTS } == true
    val sortOrderValid: Boolean get() = sortOrder in SORT_MIN..SORT_MAX
    val isValid: Boolean get() = labelValid && targetValid && sortOrderValid

    companion object {
        const val LABEL_MIN = 1
        const val LABEL_MAX = 200
        const val TARGET_MIN_CENTS = 100L
        const val TARGET_MAX_CENTS = 10_000_000L
        const val SORT_MIN = 0
        const val SORT_MAX = 4
    }
}

/**
 * AND-314 — set-price dialog form for a single item. [catalogPriceCents] is the item's base price; the new
 * broadcast price must be > 0 and strictly < catalog (FR pre-check). [priceDollars] is the raw user text;
 * [expiresMinutes] is the optional auto-expiry in minutes (blank -> no expiry).
 */
data class PriceForm(
    val itemId: String,
    val catalogPriceCents: Long,
    val currency: String = "USD",
    val priceDollars: String = "",
    val expiresMinutes: String = "",
) {
    /** Parsed broadcast price in cents, or null when the input is not a usable amount. */
    val priceCents: Long? get() = parseDollarsToCents(priceDollars)

    /** Parsed expiry in seconds (60..86400), or null when blank/invalid (server treats absent as no expiry). */
    val expiresInSeconds: Long? get() = expiresMinutes.trim().toLongOrNull()?.let { it * 60L }

    /** Client pre-check: > 0 and strictly below the catalog price (server validates again). */
    val priceValid: Boolean
        get() = priceCents?.let { it > 0L && it < catalogPriceCents } == true

    /** Expiry is optional; when present it must fall within the server bounds (60s..24h). */
    val expiresValid: Boolean
        get() = expiresMinutes.isBlank() || expiresInSeconds?.let { it in EXPIRY_MIN_SECONDS..EXPIRY_MAX_SECONDS } == true

    val isValid: Boolean get() = priceValid && expiresValid

    companion object {
        const val EXPIRY_MIN_SECONDS = 60L
        const val EXPIRY_MAX_SECONDS = 86_400L
    }
}

/** A pending confirmation for a destructive action (delete goal / remove product). */
sealed interface ConfirmTarget {
    data class DeleteGoal(val goalId: String, val label: String) : ConfirmTarget
    data class RemoveProduct(val itemId: String, val name: String) : ConfirmTarget
}

/** A one-shot authoring outcome surfaced to the user (snackbar). */
sealed interface ManageEvent {
    data class GoalCreated(val label: String) : ManageEvent
    data object GoalDeleted : ManageEvent
    data class ProductAdded(val itemId: String) : ManageEvent
    data object ProductRemoved : ManageEvent
    data object Reordered : ManageEvent
    data object PriceSet : ManageEvent
    data object PriceCleared : ManageEvent
    data class Failure(val message: String) : ManageEvent
}

/**
 * AND-314 — parses a "dollars.cents" string to integer minor units (cents). Tolerates an optional leading "$"
 * and surrounding whitespace; rejects negatives, non-numeric input, and more than two fractional digits.
 * Returns null for an unusable input. Pure / JVM-unit-testable.
 */
fun parseDollarsToCents(raw: String): Long? {
    val trimmed = raw.trim().removePrefix("$").trim()
    if (trimmed.isEmpty()) return null
    if (!Regex("^\\d+(\\.\\d{1,2})?$").matches(trimmed)) return null
    val parts = trimmed.split(".")
    val dollars = parts[0].toLongOrNull() ?: return null
    val centsPart = if (parts.size > 1) parts[1].padEnd(2, '0') else "00"
    val cents = centsPart.toLongOrNull() ?: return null
    return dollars * 100L + cents
}
