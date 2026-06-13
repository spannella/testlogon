package com.testlogon.android.feature.sponsorship.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.sponsorship.SponsorshipDeal
import com.testlogon.android.feature.sponsorship.data.SponsorshipRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-365 - drives the READ-ONLY [SponsorshipInboxUiState] for the inbound-deals inbox.
 *
 * A SINGLE GET loads the full deal array into memory; sort (newest-first by created_at desc) and the
 * status-group filter are applied CLIENT-SIDE here over [allDeals] (the unfiltered last-good snapshot). There
 * is NO server paging, NO poll loop, and NO write action (accept / reject etc. are AND-366).
 *
 * STALE (in-memory only): refresh() re-reads the array but, on a failure, KEEPS the last-good list and flips
 * isStale true (the snapshot lives only in this VM - it is NOT persisted to disk; Room persistence across
 * process death is DEFERRED, no migration this wave).
 *
 * A row tap emits a one-shot [SponsorshipInboxEffect.OpenDeal] on [effects] so the screen performs the
 * guarded navigate to the deal-detail route (owned downstream by AND-366).
 */
@HiltViewModel
class SponsorshipInboxViewModel @Inject constructor(
    private val repository: SponsorshipRepository,
) : ViewModel() {

    /** The full, unfiltered last-good deal list (already sorted newest-first); the filter windows this. */
    private var allDeals: List<SponsorshipDeal> = emptyList()
    private var filter: SponsorshipFilter = SponsorshipFilter.ALL

    private val _uiState = MutableStateFlow<SponsorshipInboxUiState>(SponsorshipInboxUiState.Loading)
    val uiState: StateFlow<SponsorshipInboxUiState> = _uiState.asStateFlow()

    private val _effects = Channel<SponsorshipInboxEffect>(Channel.BUFFERED)
    val effects: Flow<SponsorshipInboxEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    /** First load (no cached content): goes through Loading and may resolve to Empty / Error. */
    fun load() {
        _uiState.value = SponsorshipInboxUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    /** Pull-to-refresh. On failure the last-good Content is kept with isStale=true (FR-6 stale banner). */
    fun refresh() = fetch(isRefresh = true)

    /** Re-windows the in-memory list CLIENT-SIDE (no re-fetch). */
    fun setFilter(filter: SponsorshipFilter) {
        this.filter = filter
        val current = _uiState.value
        if (current is SponsorshipInboxUiState.Content) {
            _uiState.value = current.copy(deals = applyFilter(), filter = filter)
        }
    }

    /** A row tap -> one-shot OpenDeal effect (the screen guards the navigate; AND-366 owns the detail). */
    fun onDealClick(dealId: String) {
        viewModelScope.launch { _effects.send(SponsorshipInboxEffect.OpenDeal(dealId)) }
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val result = repository.listDeals()) {
                is ApiResult.Success -> {
                    allDeals = result.data.sortedByDescending { it.createdAt ?: Long.MIN_VALUE }
                    _uiState.value = if (allDeals.isEmpty()) {
                        SponsorshipInboxUiState.Empty
                    } else {
                        SponsorshipInboxUiState.Content(deals = applyFilter(), filter = filter)
                    }
                }
                else -> {
                    // Keep last-good Content on a refresh failure (stale banner), else surface Error.
                    val prior = _uiState.value as? SponsorshipInboxUiState.Content
                    _uiState.value = if (isRefresh && prior != null) {
                        prior.copy(isStale = true)
                    } else {
                        SponsorshipInboxUiState.Error(result.toError())
                    }
                }
            }
        }
    }

    /** The current filter applied over the in-memory (already sorted) list. */
    private fun applyFilter(): List<SponsorshipDeal> = allDeals.filter { filter.matches(it) }

    private fun ApiResult<*>.toError(): ApiError = when (this) {
        is ApiResult.Failure -> error
        is ApiResult.NetworkError -> ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)
        is ApiResult.Success -> ApiError(status = ApiError.STATUS_PARSE, message = OFFLINE_FALLBACK)
    }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
