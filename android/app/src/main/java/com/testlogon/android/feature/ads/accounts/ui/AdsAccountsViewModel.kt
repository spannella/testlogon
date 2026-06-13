package com.testlogon.android.feature.ads.accounts.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.feature.adsbilling.data.AdsBillingRepository
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
 * AND-369 - presentation logic for the advertiser-accounts LIST.
 *
 * Backed by the AND-367 [AdsBillingRepository] (extended this ticket with listAccounts) - the one ads repo
 * over the AND-363 AdsAccountsApi; no second repo is created. The first read runs on init; [refresh] keeps the
 * current content visible (with the refreshing affordance) and, on failure, retains it as stale rather than
 * dropping to a fatal Error (in-memory ONLY - there is no Room cache this wave). [onAccountSelected] records
 * the selection in local state and performs NO network I/O.
 *
 * Dispatcher seam: [ioDispatcher] is a settable property defaulting to [Dispatchers.IO] (Hilt cannot inject a
 * bare CoroutineDispatcher / honor a ctor default), and it is read INSIDE the load coroutine (NOT synchronously
 * in init) so a test can swap it via apply after construction. READ-ONLY: no mutations, no polling loop.
 */
@HiltViewModel
class AdsAccountsViewModel @Inject constructor(
    private val repository: AdsBillingRepository,
) : ViewModel() {

    /** Dispatcher seam: defaults to IO; a test sets a test dispatcher via apply after construction. */
    var ioDispatcher: CoroutineDispatcher = Dispatchers.IO

    private val _uiState = MutableStateFlow<AdsAccountsUiState>(AdsAccountsUiState.Loading)
    val uiState: StateFlow<AdsAccountsUiState> = _uiState.asStateFlow()

    /** The locally-selected account id, kept across reloads (never sent to the server). */
    private var selectedAccountId: String? = null

    init {
        load()
    }

    /**
     * Loads (or retries) the accounts list. A [refresh] keeps any prior content visible with the refreshing
     * affordance and, on failure, retains it flagged stale; a first-load failure (no content) is a terminal
     * Error. An empty list maps to [AdsAccountsUiState.Empty].
     */
    fun load(refresh: Boolean = false) {
        val prior = _uiState.value as? AdsAccountsUiState.Content
        when {
            refresh && prior != null -> _uiState.value = prior.copy(isRefreshing = true)
            prior == null -> _uiState.value = AdsAccountsUiState.Loading
            else -> Unit
        }

        viewModelScope.launch {
            when (val result = withContext(ioDispatcher) { repository.listAccounts() }) {
                is ApiResult.Success -> _uiState.value = contentOrEmpty(result.data)
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

    /**
     * Records the user's account selection in local state. NO network I/O (downstream screens read the
     * selection from the state). A selection while not in Content is remembered for the next Content emission.
     */
    fun onAccountSelected(accountId: String) {
        selectedAccountId = accountId
        val current = _uiState.value
        if (current is AdsAccountsUiState.Content) {
            _uiState.value = current.copy(selectedAccountId = accountId)
        }
    }

    // ---- internals ----

    /** Empty when the list has no rows, else Content carrying the remembered selection (cleared flags). */
    private fun contentOrEmpty(accounts: List<AdAccountSummary>): AdsAccountsUiState =
        if (accounts.isEmpty()) {
            AdsAccountsUiState.Empty
        } else {
            AdsAccountsUiState.Content(
                accounts = accounts,
                selectedAccountId = selectedAccountId,
                isRefreshing = false,
                isStale = false,
            )
        }

    /** Keeps prior content (flagged stale, refresh cleared) on a failed refresh, else a terminal Error. */
    private fun keepStaleOrTerminal(prior: AdsAccountsUiState.Content?, error: ApiError) {
        _uiState.value = prior?.copy(isStale = true, isRefreshing = false)
            ?: AdsAccountsUiState.Error(error = error)
    }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}
