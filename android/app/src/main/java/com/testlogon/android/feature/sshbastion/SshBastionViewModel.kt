package com.testlogon.android.feature.sshbastion

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.sshbastion.BastionPathDto
import com.testlogon.android.data.sshbastion.BastionResolvedDto
import com.testlogon.android.data.sshbastion.CreateBastionPathReq
import com.testlogon.android.data.sshbastion.UpdateBastionPathReq
import com.testlogon.android.data.sshbastion.SshBastionRepository
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Remote-Access: SSH bastion (jump-host chain) management. Lists paths, creates a new chain, resolves
 * the computed ProxyJump/ssh command (read-only), deletes. Mirrors SshBastionPage.tsx. A 403 renders
 * Forbidden. Reuses AdminOpsErrorType.
 */
sealed interface SshBastionDataState {
    data object Loading : SshBastionDataState
    data class Content(val paths: List<BastionPathDto>, val isRefreshing: Boolean = false) : SshBastionDataState
    data object Empty : SshBastionDataState
    data object Forbidden : SshBastionDataState
    data class Error(val type: AdminOpsErrorType) : SshBastionDataState
}

data class SshBastionUiState(
    val data: SshBastionDataState = SshBastionDataState.Loading,
    val mutating: Boolean = false,
    val actionInFlightId: String? = null,
    val resolved: BastionResolvedDto? = null,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class SshBastionViewModel @Inject constructor(
    private val repo: SshBastionRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(SshBastionUiState())
    val state: StateFlow<SshBastionUiState> = _state.asStateFlow()

    init { load() }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur.data is SshBastionDataState.Content) {
            _state.value = cur.copy(data = cur.data.copy(isRefreshing = true), transientError = null)
        }
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = _state.value.copy(data = SshBastionDataState.Loading)
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> {
                    val items = r.data.paths
                    _state.value = _state.value.copy(
                        data = if (items.isEmpty()) SshBastionDataState.Empty else SshBastionDataState.Content(items),
                    )
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun create(req: CreateBastionPathReq) {
        if (_state.value.mutating || req.label.isBlank() || req.target.hostname.isBlank()) return
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
    fun update(pathId: String, req: UpdateBastionPathReq) {
        if (_state.value.mutating) return
        _state.value = _state.value.copy(mutating = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.update(pathId, req)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(mutating = false, message = "Updated ${r.data.label}")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceMutateError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceMutateError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun resolve(pathId: String) {
        _state.value = _state.value.copy(actionInFlightId = pathId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.resolve(pathId)) {
                is ApiResult.Success -> _state.value = _state.value.copy(actionInFlightId = null, resolved = r.data)
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun delete(pathId: String) {
        if (_state.value.actionInFlightId != null) return
        _state.value = _state.value.copy(actionInFlightId = pathId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.delete(pathId)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(actionInFlightId = null, message = "Path deleted")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun dismissResolved() { _state.value = _state.value.copy(resolved = null) }

    fun clearMessage() { _state.value = _state.value.copy(message = null, transientError = null) }

    private fun reduceMutateError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(mutating = false, transientError = type)
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(actionInFlightId = null, transientError = type)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = _state.value.copy(data = SshBastionDataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is SshBastionDataState.Content
        _state.value = if (isRefresh && hasData) {
            cur.copy(data = (cur.data as SshBastionDataState.Content).copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(data = SshBastionDataState.Error(type))
        }
    }
}
