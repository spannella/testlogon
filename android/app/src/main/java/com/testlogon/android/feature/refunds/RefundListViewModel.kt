package com.testlogon.android.feature.refunds

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.refunds.RefundRequest
import com.testlogon.android.data.refunds.RefundsRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-244 — refund-requests list state. A single bounded fetch (no Paging 3 — the endpoint returns
 * `{items}` with no cursor). A failed refresh with cached rows keeps them and flips [isStale].
 */
data class RefundListUiState(
    val refunds: List<RefundRequest> = emptyList(),
    val isLoading: Boolean = false,
    val isRefreshing: Boolean = false,
    val isStale: Boolean = false,
    val error: UiText? = null,
)

/**
 * AND-244 — refund-requests list presentation logic. Loads once on construction; [refresh] re-fetches.
 * Failures map through [BillingErrorMapper] (AND-232) for a sanitized, localizable message.
 */
@HiltViewModel
class RefundListViewModel @Inject constructor(
    private val repository: RefundsRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _uiState = MutableStateFlow(RefundListUiState(isLoading = true))
    val uiState: StateFlow<RefundListUiState> = _uiState.asStateFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() = load(isRefresh = true)

    private fun load(isRefresh: Boolean) {
        val hadData = _uiState.value.refunds.isNotEmpty()
        _uiState.update {
            it.copy(
                isLoading = !isRefresh && !hadData,
                isRefreshing = isRefresh,
                error = if (hadData) it.error else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.listRefunds()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        refunds = result.data,
                        isLoading = false,
                        isRefreshing = false,
                        isStale = false,
                        error = null,
                    )
                }
                else -> {
                    val message = errorMapper.map(result).message
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            isRefreshing = false,
                            // Keep cached rows and mark stale; only surface a full error with no cache.
                            isStale = hadData,
                            error = if (hadData) null else message,
                        )
                    }
                }
            }
        }
    }
}
