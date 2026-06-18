package com.testlogon.android.feature.ads.campaigns.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
import com.testlogon.android.navigation.AdsCampaignsDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * AND-369 - presentation logic for the READ-ONLY campaigns list under one account.
 *
 * accountId arrives as a nav arg via [SavedStateHandle] (survives process death). Backed by the AND-367
 * [AdsBillingRepository] (extended this ticket with getCampaigns) - the one ads repo over the AND-363
 * AdsAccountsApi; no second repo is created. The first read runs on init; [refresh] keeps the current content
 * visible (with the refreshing affordance) and, on failure, retains it as stale rather than dropping to a
 * fatal Error (in-memory ONLY - there is no Room cache this wave).
 *
 * STUB ENTRY: the More-hub opens a placeholder sample account id (no ads-accounts list yet), so the load
 * resolves [AdsCampaignsDest.SAMPLE_ACCOUNT_ID] to the caller's first real ad account via
 * [AdsBillingRepository.listAccounts] (mirrors the AND-367 AdsBillingViewModel) before reading campaigns;
 * downstream this destination is reached from an ads-accounts list with a real id and the resolve is a no-op.
 *
 * Dispatcher seam: [ioDispatcher] defaults to [Dispatchers.IO] (Hilt cannot inject a bare CoroutineDispatcher
 * / honor a ctor default) and is read INSIDE the load coroutine (NOT synchronously in init) so a test can swap
 * it via apply after construction. READ-ONLY: no mutations, no polling loop.
 */
@HiltViewModel
class AdsCampaignsViewModel @Inject constructor(
    private val repository: AdsBillingRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    var accountId: String =
        checkNotNull(savedState[ARG_ACCOUNT_ID]) { "missing $ARG_ACCOUNT_ID nav arg" }
        private set

    /** Dispatcher seam: defaults to IO; a test sets a test dispatcher via apply after construction. */
    var ioDispatcher: CoroutineDispatcher = Dispatchers.IO

    private val _uiState = MutableStateFlow<AdsCampaignsUiState>(AdsCampaignsUiState.Loading)
    val uiState: StateFlow<AdsCampaignsUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    /**
     * Loads (or retries) the campaigns for [accountId]. A [refresh] keeps any prior content visible with the
     * refreshing affordance and, on failure, retains it flagged stale; a first-load failure (no content) is a
     * terminal Error. An empty list maps to [AdsCampaignsUiState.Empty].
     */
    fun load(refresh: Boolean = false) {
        val prior = _uiState.value as? AdsCampaignsUiState.Content
        when {
            refresh && prior != null -> _uiState.value = prior.copy(isRefreshing = true)
            prior == null -> _uiState.value = AdsCampaignsUiState.Loading
            else -> Unit
        }

        viewModelScope.launch {
            // The More-hub stub opens a placeholder sample id; resolve it to the caller's first real ad
            // account so the entry shows real campaigns instead of a "not found" error (cf. AdsBilling).
            if (accountId == AdsCampaignsDest.SAMPLE_ACCOUNT_ID) {
                (withContext(ioDispatcher) { repository.listAccounts() } as? ApiResult.Success)?.data
                    ?.firstOrNull()?.accountId?.let { accountId = it }
            }
            when (val result = withContext(ioDispatcher) { repository.getCampaigns(accountId) }) {
                is ApiResult.Success ->
                    _uiState.value = if (result.data.isEmpty()) {
                        AdsCampaignsUiState.Empty
                    } else {
                        AdsCampaignsUiState.Content(campaigns = result.data)
                    }
                is ApiResult.Failure -> keepStaleOrTerminal(prior, result.error)
                is ApiResult.NetworkError -> keepStaleOrTerminal(
                    prior,
                    ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
                )
            }
        }
    }

    /** Pull-to-refresh / retry from content: re-reads, keeping content visible while in flight. */
    fun refresh() = load(refresh = true)

    /** Retry from the Error state: a fresh load. */
    fun onRetry() = load()

    // ---- internals ----

    /** Keeps prior content (flagged stale, refresh cleared) on a failed refresh, else a terminal Error. */
    private fun keepStaleOrTerminal(prior: AdsCampaignsUiState.Content?, error: ApiError) {
        _uiState.value = prior?.copy(isStale = true, isRefreshing = false)
            ?: AdsCampaignsUiState.Error(error = error)
    }

    companion object {
        /** Nav arg carrying the ad account id. */
        const val ARG_ACCOUNT_ID = "accountId"

        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
