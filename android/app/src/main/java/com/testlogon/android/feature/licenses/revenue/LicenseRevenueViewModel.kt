package com.testlogon.android.feature.licenses.revenue

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.licenses.FullRevenuePage
import com.testlogon.android.data.licenses.LicensesSubRepository
import com.testlogon.android.data.licenses.RevenueSplitPreview
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

enum class RevenueTab { EARNED, PAID, CALCULATOR }

val REVENUE_SOURCE_OPTIONS = listOf("all", "tip", "subscription", "sale", "unlock")

data class LicenseRevenueUiState(
    val tab: RevenueTab = RevenueTab.EARNED,
    val sourceFilter: String = "all",
    val earnedPhase: Phase = Phase.Loading,
    val paidPhase: Phase = Phase.Loading,
    val earned: FullRevenuePage? = null,
    val paid: FullRevenuePage? = null,
    val isRefreshing: Boolean = false,
    val earnedError: String? = null,
    val paidError: String? = null,
    // calculator
    val calcAmountCents: Long = 1000,
    val calcRevenuePct: Int = 5,
    val calcProfitPct: Int = 10,
    val calcResult: RevenueSplitPreview? = null,
    val calcLoading: Boolean = false,
    val calcError: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error }
}

@HiltViewModel
class LicenseRevenueViewModel @Inject constructor(
    private val repository: LicensesSubRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LicenseRevenueUiState())
    val uiState: StateFlow<LicenseRevenueUiState> = _uiState.asStateFlow()

    init {
        loadEarned(fromUser = false)
    }

    fun selectTab(tab: RevenueTab) {
        if (tab == _uiState.value.tab) return
        _uiState.update { it.copy(tab = tab) }
        when (tab) {
            RevenueTab.EARNED -> if (_uiState.value.earned == null) loadEarned(fromUser = false)
            RevenueTab.PAID -> if (_uiState.value.paid == null) loadPaid(fromUser = false)
            RevenueTab.CALCULATOR -> if (_uiState.value.calcResult == null) calculate()
        }
    }

    fun selectSource(source: String) {
        if (source == _uiState.value.sourceFilter) return
        _uiState.update { it.copy(sourceFilter = source) }
        when (_uiState.value.tab) {
            RevenueTab.EARNED -> loadEarned(fromUser = true)
            RevenueTab.PAID -> loadPaid(fromUser = true)
            RevenueTab.CALCULATOR -> Unit
        }
    }

    fun refresh() {
        when (_uiState.value.tab) {
            RevenueTab.EARNED -> loadEarned(fromUser = true)
            RevenueTab.PAID -> loadPaid(fromUser = true)
            RevenueTab.CALCULATOR -> calculate()
        }
    }

    private fun loadEarned(fromUser: Boolean) {
        val src = _uiState.value.sourceFilter.takeIf { it != "all" }
        val has = _uiState.value.earned != null
        _uiState.update {
            it.copy(
                earnedPhase = if (has) it.earnedPhase else LicenseRevenueUiState.Phase.Loading,
                isRefreshing = fromUser,
                earnedError = null,
            )
        }
        viewModelScope.launch {
            when (val r = repository.loadEarned(src)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        earned = r.data,
                        earnedPhase = phaseFor(r.data),
                        isRefreshing = false,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(isRefreshing = false, earnedPhase = errPhase(it.earned), earnedError = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(isRefreshing = false, earnedPhase = errPhase(it.earned), earnedError = OFFLINE)
                }
            }
        }
    }

    private fun loadPaid(fromUser: Boolean) {
        val src = _uiState.value.sourceFilter.takeIf { it != "all" }
        val has = _uiState.value.paid != null
        _uiState.update {
            it.copy(
                paidPhase = if (has) it.paidPhase else LicenseRevenueUiState.Phase.Loading,
                isRefreshing = fromUser,
                paidError = null,
            )
        }
        viewModelScope.launch {
            when (val r = repository.loadPaid(src)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(paid = r.data, paidPhase = phaseFor(r.data), isRefreshing = false)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(isRefreshing = false, paidPhase = errPhase(it.paid), paidError = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(isRefreshing = false, paidPhase = errPhase(it.paid), paidError = OFFLINE)
                }
            }
        }
    }

    private fun phaseFor(page: FullRevenuePage): LicenseRevenueUiState.Phase =
        if (page.transactions.isEmpty() && page.summary.totalTransactions == 0) {
            LicenseRevenueUiState.Phase.Empty
        } else {
            LicenseRevenueUiState.Phase.Content
        }

    private fun errPhase(existing: FullRevenuePage?): LicenseRevenueUiState.Phase =
        if (existing != null) LicenseRevenueUiState.Phase.Content else LicenseRevenueUiState.Phase.Error

    // ---- calculator ----

    fun setCalcAmount(cents: Long) = _uiState.update { it.copy(calcAmountCents = cents.coerceAtLeast(0)) }
    fun setCalcRevenue(pct: Int) = _uiState.update { it.copy(calcRevenuePct = pct.coerceIn(0, 100)) }
    fun setCalcProfit(pct: Int) = _uiState.update { it.copy(calcProfitPct = pct.coerceIn(0, 100)) }

    fun calculate() {
        val s = _uiState.value
        _uiState.update { it.copy(calcLoading = true, calcError = null) }
        viewModelScope.launch {
            when (val r = repository.calculate(s.calcAmountCents, s.calcRevenuePct, s.calcProfitPct)) {
                is ApiResult.Success -> _uiState.update { it.copy(calcResult = r.data, calcLoading = false) }
                is ApiResult.Failure -> _uiState.update { it.copy(calcLoading = false, calcError = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(calcLoading = false, calcError = OFFLINE) }
            }
        }
    }

    private companion object {
        private const val OFFLINE = "Could not reach the server. Pull down to retry."
    }
}
