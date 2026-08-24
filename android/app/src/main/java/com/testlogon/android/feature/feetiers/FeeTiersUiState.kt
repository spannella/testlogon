package com.testlogon.android.feature.feetiers

/** One row in the rendered tier table. [isCurrent] highlights the user's tier. */
data class FeeTierRow(
    val id: String,
    val name: String,
    val minVolumeCents: Long,
    val makerBps: Int,
    val takerBps: Int,
    val isCurrent: Boolean,
)

/** UI state for the maker/taker fee-tier (VIP schedule) screen. */
data class FeeTiersUiState(
    val loading: Boolean = true,
    val error: String? = null,
    /** True when there are no fills at all and no authoritative read -> honest empty state. */
    val empty: Boolean = false,
    /** True when the tier/volume come from the client estimate (fills feed), not the backend. */
    val estimated: Boolean = true,
    /** 30-day rolling trading volume, USD cents. */
    val volume30dCents: Long = 0L,
    val currentTierId: String = "standard",
    val currentTierName: String = "Standard",
    val makerBps: Int = 10,
    val takerBps: Int = 15,
    /** null when already at the top tier. */
    val nextTierName: String? = null,
    val nextTierMinVolumeCents: Long? = null,
    /** cents of additional 30d volume to reach the next tier (0 at top). */
    val volumeToNextCents: Long = 0L,
    /** progress 0..1 toward the next tier (1.0 at top). */
    val progressToNext: Float = 0f,
    val isTopTier: Boolean = false,
    val tiers: List<FeeTierRow> = emptyList(),
)
