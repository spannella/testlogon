package com.testlogon.android.feature.groups

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.groups.data.GroupsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-355 (sub-pages) - drives the read-only TREASURY screen. groupId arrives as a nav arg via
 * [SavedStateHandle]. load() fetches the balance (required), then best-effort the ledger + contributors
 * (a contributors failure does NOT fail the screen - it just renders empty). 401 -> Error (the shared
 * app-level session handling redirects). No poll loop.
 */
@HiltViewModel
class GroupTreasuryViewModel @Inject constructor(
    private val repository: GroupsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val groupId: String = checkNotNull(savedState[ARG_GROUP_ID]) { "missing $ARG_GROUP_ID nav arg" }

    private val _uiState = MutableStateFlow<GroupTreasuryUiState>(GroupTreasuryUiState.Loading)
    val uiState: StateFlow<GroupTreasuryUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun load() {
        _uiState.value = GroupTreasuryUiState.Loading
        viewModelScope.launch {
            when (val balance = repository.getTreasuryBalance(groupId)) {
                is ApiResult.Success -> {
                    val ledger = repository.getTreasuryLedger(groupId).let {
                        (it as? ApiResult.Success)?.data.orEmpty()
                    }
                    val contributors = repository.getTreasuryContributors(groupId).let {
                        (it as? ApiResult.Success)?.data.orEmpty()
                    }
                    _uiState.value = GroupTreasuryUiState.Content(
                        balance = balance.data,
                        ledger = ledger,
                        contributors = contributors,
                    )
                }
                is ApiResult.Failure -> _uiState.value = GroupTreasuryUiState.Error(balance.error)
                is ApiResult.NetworkError ->
                    _uiState.value = GroupTreasuryUiState.Error(networkError())
            }
        }
    }

    private fun networkError(): ApiError =
        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        const val ARG_GROUP_ID = "groupId"
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
