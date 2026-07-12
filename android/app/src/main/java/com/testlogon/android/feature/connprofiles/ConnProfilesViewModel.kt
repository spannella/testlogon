package com.testlogon.android.feature.connprofiles

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.connprofiles.ConnProfileDto
import com.testlogon.android.data.connprofiles.ConnProfilesRepository
import com.testlogon.android.data.connprofiles.CreateConnProfileReq
import com.testlogon.android.data.connprofiles.QuickConnectDto
import com.testlogon.android.data.connprofiles.UpdateConnProfileReq
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Remote-Access: Connection-profile management. Full CRUD + quick-connect (returns computed
 * connection info). Mirrors ConnectionProfilesPage.tsx. A 403 renders Forbidden. Reuses AdminOpsErrorType.
 */
sealed interface ConnProfilesDataState {
    data object Loading : ConnProfilesDataState
    data class Content(val profiles: List<ConnProfileDto>, val isRefreshing: Boolean = false) : ConnProfilesDataState
    data object Empty : ConnProfilesDataState
    data object Forbidden : ConnProfilesDataState
    data class Error(val type: AdminOpsErrorType) : ConnProfilesDataState
}

data class ConnProfilesUiState(
    val data: ConnProfilesDataState = ConnProfilesDataState.Loading,
    val mutating: Boolean = false,
    val actionInFlightId: String? = null,
    val quickConnect: QuickConnectDto? = null,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class ConnProfilesViewModel @Inject constructor(
    private val repo: ConnProfilesRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(ConnProfilesUiState())
    val state: StateFlow<ConnProfilesUiState> = _state.asStateFlow()

    init { load() }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur.data is ConnProfilesDataState.Content) {
            _state.value = cur.copy(data = cur.data.copy(isRefreshing = true), transientError = null)
        }
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = _state.value.copy(data = ConnProfilesDataState.Loading)
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> {
                    val items = r.data.profiles
                    _state.value = _state.value.copy(
                        data = if (items.isEmpty()) ConnProfilesDataState.Empty else ConnProfilesDataState.Content(items),
                    )
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun create(req: CreateConnProfileReq) {
        if (_state.value.mutating || req.label.isBlank()) return
        _state.value = _state.value.copy(mutating = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.create(req)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(mutating = false, message = "Created ${r.data.label}")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceMutateError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceMutateError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun update(profileId: String, req: UpdateConnProfileReq) {
        if (_state.value.mutating) return
        _state.value = _state.value.copy(mutating = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.update(profileId, req)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(mutating = false, message = "Updated ${r.data.label}")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceMutateError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceMutateError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun delete(profileId: String) {
        if (_state.value.actionInFlightId != null) return
        _state.value = _state.value.copy(actionInFlightId = profileId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.delete(profileId)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(actionInFlightId = null, message = "Profile deleted")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun quickConnect(profileId: String) {
        _state.value = _state.value.copy(actionInFlightId = profileId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.quickConnect(profileId)) {
                is ApiResult.Success -> _state.value = _state.value.copy(actionInFlightId = null, quickConnect = r.data)
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun dismissQuickConnect() { _state.value = _state.value.copy(quickConnect = null) }

    fun clearMessage() { _state.value = _state.value.copy(message = null, transientError = null) }

    private fun reduceMutateError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(mutating = false, transientError = type)
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(actionInFlightId = null, transientError = type)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = _state.value.copy(data = ConnProfilesDataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is ConnProfilesDataState.Content
        _state.value = if (isRefresh && hasData) {
            cur.copy(data = (cur.data as ConnProfilesDataState.Content).copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(data = ConnProfilesDataState.Error(type))
        }
    }
}
