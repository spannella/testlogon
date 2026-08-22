package com.testlogon.android.feature.portfolioanalytics

/**
 * Read-only Portfolio Analytics UI state ("how am I positioned / what is my risk").
 *
 * The ViewModel normalizes every holding across custody / spot / margin / creator tokens / strategy
 * funds / staking into a [NormalizedPosition] list (indicative USD cents), then folds the pure
 * [PortfolioAnalyticsMath] outputs into this snapshot. Each SOURCE degrades independently: a source
 * that could not be read is recorded in [sourceIssues] and simply contributes nothing, while the
 * sections that CAN be computed still render. Nothing here moves money.
 */
data class PortfolioAnalyticsUiState(
    val loading: Boolean = true,
    /** The normalized cross-venue positions the analytics are computed from. */
    val positions: List<NormalizedPosition> = emptyList(),
    /** Total indicative gross USD value (cents) across all normalized positions. */
    val totalValueCents: Long = 0L,
    /** The currently-selected allocation grouping. */
    val allocationBy: AllocationBy = AllocationBy.ASSET,
    /** The allocation breakdown for [allocationBy] (weighted slices, descending). */
    val allocation: List<AllocationSlice> = emptyList(),
    /** Concentration read over the ASSET-level weights (HHI + topN). */
    val concentration: Concentration? = null,
    /** Gross/net/long/short exposure + leverage. */
    val exposure: Exposure? = null,
    /** Portfolio volatility in bps (covariance combine), null when insufficient history. */
    val portfolioVolBps: Int? = null,
    /** Parametric VaR (95%) in cents. */
    val parametricVar95Cents: Long = 0L,
    /** Parametric VaR (99%) in cents. */
    val parametricVar99Cents: Long = 0L,
    /** Historical VaR (95%) in cents from the blended portfolio return series. */
    val historicalVar95Cents: Long = 0L,
    /** 0..100 diversification score. */
    val diversificationScore: Int = 0,
    /** How many priced assets had a usable return series backing the risk math. */
    val riskAssetsCovered: Int = 0,
    /** True when at least one asset's history was DEGRADED to the recent window (stub) — show banner. */
    val limitedHistory: Boolean = false,
    /** True when risk could not be computed at all (no usable per-asset return series yet). */
    val riskUnavailable: Boolean = false,
    /** Per-source read problems (e.g. "Margin: not available on this deployment"). */
    val sourceIssues: List<String> = emptyList(),
    /** True when the indicative USD marks are the edge STUB placeholders. */
    val pricesStub: Boolean = false,
    /** True when no priced holdings could be normalized at all (whole-screen empty state). */
    val allEmpty: Boolean = false,
)
