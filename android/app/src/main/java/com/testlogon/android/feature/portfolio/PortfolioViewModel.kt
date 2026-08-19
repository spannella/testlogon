package com.testlogon.android.feature.portfolio

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.custody.CustodyRepository
import com.testlogon.android.data.exchange.TradingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Read-only Portfolio ViewModel: fans the four independent venue reads out in parallel (custody
 * balances + staking via [CustodyRepository]; spot balance + margin account via [TradingRepository]),
 * then folds them into a single [PortfolioUiState] via the pure [PortfolioAggregator]. No writes.
 *
 * The reads are launched concurrently with [async] and awaited together; each already folds its own
 * transport failure into an [com.testlogon.android.core.model.ApiResult] variant, so the aggregator
 * degrades any broken/undeployed venue to an "unavailable" card without failing the others.
 */
@HiltViewModel
class PortfolioViewModel @Inject constructor(
    private val custody: CustodyRepository,
    private val trading: TradingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(PortfolioUiState())
    val uiState: StateFlow<PortfolioUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        _uiState.value = PortfolioUiState(loading = true)
        viewModelScope.launch {
            val snapshot = coroutineScope {
                val custodyDef = async { custody.getBalance() }
                val stakingDef = async { custody.getStaking() }
                val spotDef = async { trading.spotBalance() }
                val marginDef = async { trading.marginAccount() }
                PortfolioAggregator.aggregate(
                    custody = custodyDef.await(),
                    staking = stakingDef.await(),
                    spot = spotDef.await(),
                    margin = marginDef.await(),
                )
            }
            _uiState.value = snapshot
        }
    }
}
