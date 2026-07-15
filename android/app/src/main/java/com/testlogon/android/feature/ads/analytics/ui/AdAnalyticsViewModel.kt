package com.testlogon.android.feature.ads.analytics.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAnalyticsSummary
import com.testlogon.android.core.model.ads.AdBreakdownEntry
import com.testlogon.android.core.model.ads.AdRoasReport
import com.testlogon.android.core.model.ads.AdTimeSeriesPoint
import com.testlogon.android.core.model.ads.BreakdownDimension
import com.testlogon.android.core.model.ads.DateRange
import com.testlogon.android.core.model.ads.DateRangePreset
import com.testlogon.android.feature.ads.analytics.data.AdAnalyticsRepository
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import com.testlogon.android.navigation.AdAnalyticsDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.time.LocalDate
import javax.inject.Inject

/**
 * AND-368 - presentation logic for the READ-ONLY ad-analytics dashboard.
 *
 * accountId arrives as a nav arg via [SavedStateHandle] (survives process death). The default range is
 * [DateRangePreset.LAST_28]; [onRangeChanged] re-queries with the new window. A refresh failure that has
 * prior content keeps the content + flags it stale (in-memory ONLY - there is NO Room cache this wave, so the
 * staleness does not survive process death; that is DEFERRED). A pull-to-refresh bypasses nothing
 * persistent (there is no cache) - it simply re-reads and shows the refreshing affordance.
 *
 * STUB ENTRY: the More-hub opens a placeholder sample account id (no ads-accounts list yet), so the load
 * resolves [AdAnalyticsDest.SAMPLE_ACCOUNT_ID] to the caller's first real ad account via
 * [AdsBillingRepository.listAccounts] (mirrors the AND-367 AdsBillingViewModel / AND-369 AdsCampaignsViewModel)
 * before reading analytics; downstream this destination is reached from an ads-accounts list with a real id
 * and the resolve is a no-op.
 *
 * The breakdown groups by [BreakdownDimension.CREATIVE] for this wave. READ-ONLY: there are NO mutations and
 * NO polling loop.
 *
 * Clock seam: [today] is a settable property defaulting to [LocalDate.now] (Hilt cannot inject a bare value /
 * honor a ctor default), so range tests set a fixed today for deterministic from/to assertions.
 */
@HiltViewModel
class AdAnalyticsViewModel @Inject constructor(
    private val repository: AdAnalyticsRepository,
    private val accountsRepository: AdsBillingRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    var accountId: String =
        checkNotNull(savedState[ARG_ACCOUNT_ID]) { "missing $ARG_ACCOUNT_ID nav arg" }
        private set

    /** Clock seam: the inclusive end-of-range day. Defaults to today; tests set a fixed date. */
    var today: LocalDate = LocalDate.now()

    private val _uiState = MutableStateFlow<AdAnalyticsUiState>(AdAnalyticsUiState.Loading)
    val uiState: StateFlow<AdAnalyticsUiState> = _uiState.asStateFlow()

    /** The currently-selected preset (kept across state transitions). */
    private var currentRange: DateRangePreset = DateRangePreset.LAST_28

    /** ADV3-9 (D6): the currently-selected breakdown dimension (kept across loads). */
    private var currentDimension: BreakdownDimension = BreakdownDimension.CREATIVE

    init {
        load(currentRange)
    }

    /**
     * Loads (or retries) the dashboard for [preset]. The summary + timeseries + breakdown are read together;
     * a summary failure is fatal (-> Error or stale), while the timeseries / breakdown fall back to empty
     * lists so a partial-data response still renders. When the summary has zero impressions AND there is no
     * timeseries / breakdown data, the screen shows [AdAnalyticsUiState.Empty].
     *
     * A refresh ([refresh] = true) keeps the existing content visible (with the refreshing affordance) and,
     * on failure, retains it as stale rather than dropping to a fatal Error.
     */
    fun load(preset: DateRangePreset, refresh: Boolean = false) {
        currentRange = preset
        val prior = _uiState.value as? AdAnalyticsUiState.Content
        when {
            refresh && prior != null -> _uiState.value = prior.copy(range = preset, isRefreshing = true)
            prior == null -> _uiState.value = AdAnalyticsUiState.Loading
            else -> _uiState.value = prior.copy(range = preset)
        }

        viewModelScope.launch {
            // The More-hub stub opens a placeholder sample id; resolve it to the caller's first real ad
            // account so the dashboard shows real analytics instead of "Account not found" (cf. AdsBilling).
            if (accountId == AdAnalyticsDest.SAMPLE_ACCOUNT_ID) {
                (accountsRepository.listAccounts() as? ApiResult.Success)?.data
                    ?.firstOrNull()?.accountId?.let { accountId = it }
            }
            val range = DateRange.of(preset, today)
            when (val summaryResult = repository.getSummary(accountId, range)) {
                is ApiResult.Success -> {
                    val timeseries = (repository.getTimeseries(accountId, range)
                        as? ApiResult.Success)?.data ?: emptyList()
                    val breakdown = (repository.getBreakdown(accountId, currentDimension, range)
                        as? ApiResult.Success)?.data ?: emptyList()
                    // ADV-503: best-effort ROAS (spend vs attributed conversion value); a failure
                    // simply omits the ROAS card and never fails the dashboard.
                    val roas = (repository.getRoas(accountId, preset.days)
                        as? ApiResult.Success)?.data
                    _uiState.value = contentOrEmpty(summaryResult.data, timeseries, breakdown, roas, preset)
                }
                is ApiResult.Failure -> keepStaleOrTerminal(prior, summaryResult.error, preset)
                is ApiResult.NetworkError -> keepStaleOrTerminal(
                    prior,
                    ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
                    preset,
                )
            }
        }
    }

    /** Re-queries when the user picks a different range preset (no-op when unchanged). */
    fun onRangeChanged(preset: DateRangePreset) {
        if (preset == currentRange) return
        load(preset)
    }

    /**
     * ADV3-9 (D6): re-reads ONLY the breakdown for a newly-picked dimension (the KPI
     * summary / charts / ROAS are unaffected), updating the visible Content in place.
     */
    fun onDimensionChanged(dimension: BreakdownDimension) {
        if (dimension == currentDimension) return
        currentDimension = dimension
        val prior = _uiState.value as? AdAnalyticsUiState.Content ?: return
        _uiState.value = prior.copy(dimension = dimension)
        viewModelScope.launch {
            val range = DateRange.of(currentRange, today)
            val breakdown = (repository.getBreakdown(accountId, dimension, range)
                as? ApiResult.Success)?.data ?: emptyList()
            val cur = _uiState.value as? AdAnalyticsUiState.Content ?: return@launch
            _uiState.value = cur.copy(breakdown = breakdown, dimension = dimension)
        }
    }

    /** Pull-to-refresh / retry: re-reads the current range, keeping content visible while in flight. */
    fun refresh() = load(currentRange, refresh = true)

    /** Retry from the Error state: a fresh load of the current range. */
    fun onRetry() = load(currentRange)

    // ---- internals ----

    /** Empty when the summary + series + breakdown carry no signal, else Content. */
    private fun contentOrEmpty(
        summary: AdAnalyticsSummary,
        timeseries: List<AdTimeSeriesPoint>,
        breakdown: List<AdBreakdownEntry>,
        roas: AdRoasReport?,
        preset: DateRangePreset,
    ): AdAnalyticsUiState {
        val noData = summary.impressions == 0L &&
            summary.clicks == 0L &&
            summary.spendCents == 0L &&
            timeseries.isEmpty() &&
            breakdown.isEmpty()
        return if (noData) {
            AdAnalyticsUiState.Empty(range = preset)
        } else {
            AdAnalyticsUiState.Content(
                summary = summary,
                timeseries = timeseries,
                breakdown = breakdown,
                range = preset,
                dimension = currentDimension,
                roas = roas,
                isStale = false,
                isRefreshing = false,
            )
        }
    }

    /** Keeps prior content (flagged stale, refresh cleared) on a failed refresh, else a terminal Error. */
    private fun keepStaleOrTerminal(
        prior: AdAnalyticsUiState.Content?,
        error: ApiError,
        preset: DateRangePreset,
    ) {
        _uiState.value = prior?.copy(range = preset, isStale = true, isRefreshing = false)
            ?: AdAnalyticsUiState.Error(error = error, range = preset)
    }

    companion object {
        /** Nav arg carrying the ad account id. */
        const val ARG_ACCOUNT_ID = "accountId"

        /** The breakdown dimension shown this wave. */
        private val DIMENSION = BreakdownDimension.CREATIVE

        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
