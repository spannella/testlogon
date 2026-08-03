package com.testlogon.android.feature.billing.wallet

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.billing.BillingApi
import com.testlogon.android.data.billing.BillingBalance
import com.testlogon.android.data.billing.BillingRepository
import com.testlogon.android.data.billing.LedgerEntry
import com.testlogon.android.data.billing.WalletBalance
import com.testlogon.android.feature.billing.error.BillingError
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** PW18 — the wallet-transactions load outcome (the ledger list is the primary surface). */
sealed interface WalletTransactionsLoadState {
    data object Loading : WalletTransactionsLoadState
    data class Loaded(val transactions: List<LedgerEntry>) : WalletTransactionsLoadState

    /** The failure carries a mapped [BillingError] (localizable message + retryable flag). */
    data class Error(val error: BillingError) : WalletTransactionsLoadState {
        val message: UiText get() = error.message
        val retryable: Boolean get() = error.retryable
    }
}

/**
 * PW18 — fully-derived wallet screen state. [wallet] is the optional balance header (best-effort; a
 * balance failure never blocks the transactions list); [balance] is the PAR-20 account-balance
 * breakdown (also best-effort — a failure leaves it null and never touches the load state);
 * [isRefreshing] drives pull-to-refresh.
 */
data class WalletTransactionsUiState(
    val load: WalletTransactionsLoadState = WalletTransactionsLoadState.Loading,
    val wallet: WalletBalance? = null,
    val balance: BillingBalance? = null,
    val isRefreshing: Boolean = false,
) {
    val transactions: List<LedgerEntry>
        get() = (load as? WalletTransactionsLoadState.Loaded)?.transactions.orEmpty()
    val isEmpty: Boolean
        get() = load is WalletTransactionsLoadState.Loaded && transactions.isEmpty()
}

/**
 * PW18 — Wallet transactions presentation logic.
 *
 * Loads the wallet balance header + the transaction ledger (BK3: GET /ui/billing/wallet and
 * GET /ui/billing/ledger, both already exposed by [BillingRepository]). The ledger is the source of
 * truth for the list; the balance is a best-effort header that never blocks the list. Empty/loading/
 * error states are derived from [load]; a refresh keeps the existing list on a transient failure.
 *
 * PAR-20: the account-balance breakdown (GET /ui/billing/balance) is fetched in the SAME parallel pass
 * and folded best-effort — a balance failure leaves [WalletTransactionsUiState.balance] null and never
 * affects the ledger load state (parity with the iOS WalletScreen concurrent+best-effort load).
 */
@HiltViewModel
class WalletTransactionsViewModel @Inject constructor(
    private val repository: BillingRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _state = MutableStateFlow(WalletTransactionsUiState())
    val uiState: StateFlow<WalletTransactionsUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        _state.update { it.copy(load = WalletTransactionsLoadState.Loading) }
        viewModelScope.launch { fetch(refreshing = false) }
    }

    fun retry() = load()

    fun refresh() {
        if (_state.value.isRefreshing) return
        _state.update { it.copy(isRefreshing = true) }
        viewModelScope.launch { fetch(refreshing = true) }
    }

    private suspend fun fetch(refreshing: Boolean) {
        // Fetch the balance header + account-balance breakdown + ledger in parallel; only the ledger
        // result decides the load state. The header + breakdown are best-effort.
        val walletDeferred = viewModelScope.async { repository.getWallet() }
        val balanceDeferred = viewModelScope.async { repository.getBalance() }
        val ledgerResult = repository.getLedger(BillingApi.DEFAULT_LIMIT)
        val walletResult = walletDeferred.await()
        val balanceResult = balanceDeferred.await()

        _state.update { current ->
            val newWallet = (walletResult as? ApiResult.Success)?.data ?: current.wallet
            val newBalance = (balanceResult as? ApiResult.Success)?.data ?: current.balance
            val newLoad = when (ledgerResult) {
                is ApiResult.Success -> WalletTransactionsLoadState.Loaded(ledgerResult.data.items)
                else ->
                    // On a refresh failure keep the existing list; otherwise surface the error.
                    if (refreshing && current.load is WalletTransactionsLoadState.Loaded) current.load
                    else WalletTransactionsLoadState.Error(errorMapper.map(ledgerResult))
            }
            current.copy(load = newLoad, wallet = newWallet, balance = newBalance, isRefreshing = false)
        }
    }
}
