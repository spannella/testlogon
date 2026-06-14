package com.testlogon.android.feature.syndicates.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.RevenueSplitPolicy
import com.testlogon.android.core.model.syndicates.SyndicateFeedItem
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.model.syndicates.TreasuryEntry
import com.testlogon.android.core.model.syndicates.TreasurySummary
import com.testlogon.android.feature.syndicates.data.SyndicateRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-356 - drives the [SyndicateOverviewUiState] for the READ-ONLY 3-tab syndicate overview.
 *
 * syndicateId arrives as a nav arg via [SavedStateHandle] (survives process death). load() reads the
 * overview, the treasury summary and the revenue-split policy concurrently. NotMember (FR-7) is derived when
 * the overview returns is_member == false OR a 403. Each non-paged tab carries its own [TabState] so a
 * single failing tab does not blank the whole screen.
 *
 * STALE (FR-6, in-memory only): refresh() re-reads everything but, on a failure, KEEPS the last-good
 * [SyndicateOverviewUiState.Content] and flips isStale true (the snapshot lives only in this StateFlow - it
 * is NOT persisted to disk; Room persistence across process death is DEFERRED, no migration this wave).
 *
 * The FEED and the treasury LEDGER are network Paging-3 Flows ([feed] / [ledger]), cached in
 * [viewModelScope] so a tab switch / rotation does not re-fetch; pull-to-refresh on the feed is driven by
 * the LazyPagingItems.refresh() at the UI. There is NO poll loop.
 */
@HiltViewModel
class SyndicateOverviewViewModel @Inject constructor(
    private val repository: SyndicateRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val syndicateId: String =
        checkNotNull(savedState[ARG_SYNDICATE_ID]) { "missing $ARG_SYNDICATE_ID nav arg" }

    private val _uiState = MutableStateFlow<SyndicateOverviewUiState>(SyndicateOverviewUiState.Loading)
    val uiState: StateFlow<SyndicateOverviewUiState> = _uiState.asStateFlow()

    /** The reverse-chronological feed (network Paging-3); cached so a tab switch does not re-fetch. */
    val feed: Flow<PagingData<SyndicateFeedItem>> =
        repository.feedPager(syndicateId).cachedIn(viewModelScope)

    /** The treasury ledger (network Paging-3); cached so a tab switch does not re-fetch. */
    val ledger: Flow<PagingData<TreasuryEntry>> =
        repository.treasuryLedgerPager(syndicateId).cachedIn(viewModelScope)

    init {
        load()
    }

    /** First load (no cached content): goes through Loading and may resolve to NotMember / Error. */
    fun load() {
        _uiState.value = SyndicateOverviewUiState.Loading
        refreshInternal(isRefresh = false)
    }

    fun onRetry() = load()

    /**
     * Pull-to-refresh of the non-paged surfaces. On failure the last-good Content is kept with isStale=true
     * (the paged feed / ledger refresh independently at the UI via LazyPagingItems.refresh()).
     */
    fun refresh() = refreshInternal(isRefresh = true)

    private fun refreshInternal(isRefresh: Boolean) {
        viewModelScope.launch {
            val overviewResult = repository.getOverview(syndicateId)

            // FR-7: a 403 OR is_member == false -> NotMember empty-state.
            when (overviewResult) {
                is ApiResult.Success ->
                    if (!overviewResult.data.isMember) {
                        _uiState.value = SyndicateOverviewUiState.NotMember
                        return@launch
                    }
                is ApiResult.Failure ->
                    if (overviewResult.error.status == STATUS_FORBIDDEN) {
                        _uiState.value = SyndicateOverviewUiState.NotMember
                        return@launch
                    }
                is ApiResult.NetworkError -> Unit
            }

            val overview: SyndicateOverview? = (overviewResult as? ApiResult.Success)?.data
            if (overview == null) {
                // Overview itself failed (non-403). Keep stale content on refresh, else surface Error.
                val prior = _uiState.value as? SyndicateOverviewUiState.Content
                _uiState.value = if (isRefresh && prior != null) {
                    prior.copy(isStale = true)
                } else {
                    SyndicateOverviewUiState.Error(overviewResult.toError())
                }
                return@launch
            }

            // Header is good; load the two non-paged tab snapshots.
            val treasury = repository.getTreasury(syndicateId).toTabState()
            val split = repository.getRevenueSplit(syndicateId).toTabState()
            _uiState.value = SyndicateOverviewUiState.Content(
                overview = overview,
                treasury = treasury,
                split = split,
                isStale = false,
            )
        }
    }

    private fun <T> ApiResult<T>.toTabState(): TabState<T> = when (this) {
        is ApiResult.Success -> TabState.Content(data)
        else -> TabState.Error(toError())
    }

    private fun ApiResult<*>.toError(): ApiError = when (this) {
        is ApiResult.Failure -> error
        is ApiResult.NetworkError -> ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)
        is ApiResult.Success -> ApiError(status = ApiError.STATUS_PARSE, message = OFFLINE_FALLBACK)
    }

    companion object {
        const val ARG_SYNDICATE_ID = "syndicateId"

        private const val STATUS_FORBIDDEN = 403
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
