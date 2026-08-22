package com.testlogon.android.feature.activity

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.activity.ActivityLastSeenStore
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.TradingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * UI state for the Activity Center. [days] is the day-grouped, category-filtered timeline; [total] is
 * the unfiltered event count (so the empty state can distinguish "no events at all" from "none in this
 * filter"); [degradedSources] names any feed that failed this load (surfaced as an honest banner).
 */
data class ActivityUiState(
    val loading: Boolean = true,
    val days: List<ActivityDay> = emptyList(),
    val total: Int = 0,
    val selected: ActivityCategory? = null,
    val degradedSources: List<String> = emptyList(),
)

/**
 * Drives the consolidated Activity Center. Aggregates the existing exchange feed reads CLIENT-SIDE
 * (fills / funding / liquidations / margin-distress / PM-resolutions), each degrading independently to
 * empty on 404 / error, normalizes them through the pure [ActivityModel], and exposes a filterable,
 * day-grouped timeline plus a DataStore-persisted unread count.
 *
 * No new backend route: this works today off the shipped trader feeds and simply shows less when a
 * source is unavailable.
 */
@HiltViewModel
class ActivityCenterViewModel @Inject constructor(
    private val trading: TradingRepository,
    private val lastSeenStore: ActivityLastSeenStore,
) : ViewModel() {

    private val allEvents = MutableStateFlow<List<ActivityEvent>>(emptyList())
    private val selectedCategory = MutableStateFlow<ActivityCategory?>(null)
    private val degraded = MutableStateFlow<List<String>>(emptyList())
    private val loading = MutableStateFlow(true)

    val state: StateFlow<ActivityUiState> =
        combine(allEvents, selectedCategory, degraded, loading) { events, cat, deg, isLoading ->
            val filtered = ActivityModel.filterByCategory(events, cat)
            ActivityUiState(
                loading = isLoading,
                days = ActivityModel.groupByDay(filtered),
                total = events.size,
                selected = cat,
                degradedSources = deg,
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ActivityUiState())

    /** Unread count (events strictly newer than the persisted last-seen mark). */
    val unreadCount: StateFlow<Int> =
        combine(allEvents, lastSeenStore.lastSeen) { events, seen ->
            ActivityModel.unreadCount(events, seen)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)

    init {
        refresh()
    }

    fun selectCategory(category: ActivityCategory?) {
        selectedCategory.value = category
    }

    /** Advance the last-seen mark to the newest event so the unread badge clears. */
    fun markAllRead() {
        viewModelScope.launch {
            lastSeenStore.setLastSeen(ActivityModel.newestTs(allEvents.value))
        }
    }

    fun refresh() {
        viewModelScope.launch {
            loading.value = true
            val nowMs = System.currentTimeMillis()
            val failed = ArrayList<String>()

            val fillsData = (trading.fillsFees() as? ApiResult.Success)?.data
            if (fillsData == null) failed += "Trades"
            val fundingData = (trading.fundingPayments() as? ApiResult.Success)?.data
            if (fundingData == null) failed += "Funding"
            val liqData = (trading.liquidations() as? ApiResult.Success)?.data
            if (liqData == null) failed += "Liquidations"
            // Margin is 403 for a non-trading account -> null (no risk signal), not a degraded source.
            val margin = (trading.marginAccount() as? ApiResult.Success)?.data
            val pmData = (trading.pmResolutions() as? ApiResult.Success)?.data
            if (pmData == null) failed += "System"

            allEvents.value = ActivityModel.mergeEvents(
                ActivityModel.fromFills(fillsData ?: FillsFees(emptyList(), 0), nowMs),
                ActivityModel.fromFunding(fundingData ?: FundingPayments(emptyList(), 0), nowMs),
                ActivityModel.fromLiquidations(liqData ?: Liquidations(emptyList(), 0), nowMs),
                ActivityModel.fromMargin(margin, nowMs),
                ActivityModel.fromPmResolutions(pmData ?: emptyList(), nowMs),
            )
            degraded.value = failed
            loading.value = false
        }
    }
}
