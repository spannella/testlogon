package com.testlogon.android.feature.settings.account

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.AccountState
import com.testlogon.android.core.model.AccountStatus
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.preferences.AccountStatusRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** Destructive entries that require a confirm gate before deep-linking (handoff). */
enum class DestructiveAction { CLOSE_ACCOUNT }

sealed interface AccountUiState {
    data object Loading : AccountUiState
    data class Error(val message: String) : AccountUiState
    data class Ready(
        val status: AccountStatus,
        val isRefreshing: Boolean = false,
        val pendingConfirm: DestructiveAction? = null,
    ) : AccountUiState {
        /** Lifecycle row visibility derived purely from state (FR-4/FR-5). */
        val showClose: Boolean
            get() = status.state == AccountState.ACTIVE || status.state == AccountState.SUSPENDED

        /** AND-387 FR-4: suspend is a self-service hold offered only from an ACTIVE account. */
        val showSuspend: Boolean
            get() = status.state == AccountState.ACTIVE
        val showReactivate: Boolean
            get() = status.state == AccountState.SUSPENDED ||
                status.state == AccountState.CLOSURE_PENDING ||
                status.state == AccountState.CLOSED
    }
}

/**
 * AND-082 — account status & status entry. Read-and-route: shows `GET /ui/account/status` and gates
 * destructive entries behind a confirm before handing off (no closure/deletion executed here).
 */
@HiltViewModel
class AccountSettingsViewModel @Inject constructor(
    private val repository: AccountStatusRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AccountUiState>(AccountUiState.Loading)
    val state: StateFlow<AccountUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        _state.value = AccountUiState.Loading
        fetch()
    }

    fun refresh() {
        val ready = _state.value as? AccountUiState.Ready ?: run { load(); return }
        _state.value = ready.copy(isRefreshing = true)
        fetch()
    }

    private fun fetch() {
        viewModelScope.launch {
            when (val result = repository.getStatus()) {
                is ApiResult.Success ->
                    _state.value = AccountUiState.Ready(status = result.data)
                is ApiResult.Failure -> _state.value = AccountUiState.Error(result.error.message)
                is ApiResult.NetworkError -> _state.value = AccountUiState.Error(NETWORK_MESSAGE)
            }
        }
    }

    fun requestDestructive(action: DestructiveAction) =
        _state.update { (it as? AccountUiState.Ready)?.copy(pendingConfirm = action) ?: it }

    fun dismissConfirm() =
        _state.update { (it as? AccountUiState.Ready)?.copy(pendingConfirm = null) ?: it }

    private companion object {
        const val NETWORK_MESSAGE = "Couldn't reach the server. Check your connection and try again."
    }
}
