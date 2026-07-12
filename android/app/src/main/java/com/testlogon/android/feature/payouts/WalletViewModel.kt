package com.testlogon.android.feature.payouts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.payouts.PayoutsRepository
import com.testlogon.android.data.payouts.WalletSummary
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * PAY-52 — the money-OUT Wallet home.
 *
 * Consumes the REAL PAY-50 GET /ui/payouts/wallet (WalletSummaryOut): available (reconciles to PAY-A
 * get_available_balance) + held(+release date) + pending + lifetime paid + total earned. The screen's
 * "Withdraw" CTA routes through the existing PAY-C gate (the setup/withdraw screen owns the gate). The
 * wallet [refresh]es on resume so the available/held figures reflect a just-made withdraw's real debit.
 */
@HiltViewModel
class WalletViewModel @Inject constructor(
    private val repository: PayoutsRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    data class UiState(
        val isLoading: Boolean = true,
        val summary: WalletSummary? = null,
        /** Full-screen error when the first load fails and there is nothing to show. */
        val error: UiText? = null,
        /** True while a pull-to-refresh / resume refresh is in flight over existing content. */
        val isRefreshing: Boolean = false,
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        _state.update { it.copy(isLoading = it.summary == null, error = null) }
        fetch()
    }

    /** Silent refresh over existing content (resume / pull-to-refresh). */
    fun refresh() {
        _state.update { it.copy(isRefreshing = true, error = null) }
        fetch()
    }

    private fun fetch() {
        viewModelScope.launch {
            when (val result = repository.getWallet()) {
                is ApiResult.Success -> _state.update {
                    it.copy(isLoading = false, isRefreshing = false, summary = result.data, error = null)
                }
                else -> _state.update {
                    it.copy(
                        isLoading = false,
                        isRefreshing = false,
                        // Keep any previously loaded summary; only show the full-screen error on cold fail.
                        error = if (it.summary == null) errorMapper.map(result).message else null,
                    )
                }
            }
        }
    }
}
