package com.testlogon.android.feature.disputes

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.disputes.Dispute
import com.testlogon.android.data.disputes.DisputesRepository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-245 — disputes list state (single bounded fetch; no Paging 3 — the endpoint returns `{items}`). */
sealed interface DisputesListUiState {
    data object Loading : DisputesListUiState
    data object Empty : DisputesListUiState
    data class Content(val disputes: List<Dispute>) : DisputesListUiState
    data class Failure(val message: UiText) : DisputesListUiState
}

/**
 * AND-245 — disputes list presentation logic. Loads once on construction; [load] re-fetches. Failures
 * map through [BillingErrorMapper] (AND-232) for a sanitized, localizable message.
 */
@HiltViewModel
class DisputesListViewModel @Inject constructor(
    private val repository: DisputesRepository,
    private val errorMapper: BillingErrorMapper,
) : ViewModel() {

    private val _state = MutableStateFlow<DisputesListUiState>(DisputesListUiState.Loading)
    val state: StateFlow<DisputesListUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        _state.value = DisputesListUiState.Loading
        viewModelScope.launch {
            _state.value = when (val result = repository.listDisputes()) {
                is ApiResult.Success ->
                    if (result.data.isEmpty()) DisputesListUiState.Empty
                    else DisputesListUiState.Content(result.data)
                else -> DisputesListUiState.Failure(errorMapper.map(result).message)
            }
        }
    }
}
