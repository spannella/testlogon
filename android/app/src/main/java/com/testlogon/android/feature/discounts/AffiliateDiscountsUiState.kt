package com.testlogon.android.feature.discounts

import androidx.annotation.StringRes
import com.testlogon.android.data.discounts.AffiliateDiscounts
import com.testlogon.android.data.discounts.DiscountKind

/**
 * AND-267 — single render-ready affiliate-discounts state.
 *
 * One immutable data class (matching the AND-264/265/266 convention) so content persists across refresh.
 * [phase] enumerates the mutually-exclusive top-level surfaces. [filterKind] is an optional client-side
 * chip filter applied over the loaded list (best-effort derived kind; the dataset is small + fully
 * fetched, no server paging).
 */
data class AffiliateDiscountsUiState(
    val phase: Phase = Phase.Loading,
    val discounts: AffiliateDiscounts? = null,
    val filterKind: DiscountKind? = null,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error, Offline }

    val canRetry: Boolean get() = phase == Phase.Error || phase == Phase.Offline

    /** The discounts to render after applying the (best-effort) client-side kind filter. */
    val visibleItems get() = discounts?.items.orEmpty().let { items ->
        filterKind?.let { k -> items.filter { it.derivedKind == k } } ?: items
    }
}

/**
 * One-shot side effects (AND-267). Channel-backed so they are not replayed on rotation. Copy/share carry
 * the already-resolved string; messages are [StringRes] ids so the ViewModel stays locale-agnostic
 * (resolved in composable scope).
 */
sealed interface AffiliateDiscountsEffect {
    data class CopyCode(val code: String) : AffiliateDiscountsEffect
    data class ShareLink(val text: String) : AffiliateDiscountsEffect
    data class ShowMessage(@StringRes val resId: Int) : AffiliateDiscountsEffect
}
