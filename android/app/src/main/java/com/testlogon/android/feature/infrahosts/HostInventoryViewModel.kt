package com.testlogon.android.feature.infrahosts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.infrahosts.HostDto
import com.testlogon.android.data.infrahosts.HostInventoryRepository
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Cloud-Infra: Host inventory list with a protocol filter. Mirrors HostInventoryPage.tsx (read half).
 * 403 -> Forbidden.
 */
sealed interface HostsDataState {
    data object Loading : HostsDataState
    data class Content(val hosts: List<HostDto>, val isRefreshing: Boolean = false) : HostsDataState
    data object Empty : HostsDataState
    data object Forbidden : HostsDataState
    data class Error(val type: AdminOpsErrorType) : HostsDataState
}

data class HostsUiState(
    val data: HostsDataState = HostsDataState.Loading,
    val protocols: List<String> = emptyList(),
    val protocolFilter: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class HostInventoryViewModel @Inject constructor(
    private val repo: HostInventoryRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(HostsUiState())
    val state: StateFlow<HostsUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur.data is HostsDataState.Content) {
            _state.value = cur.copy(data = cur.data.copy(isRefreshing = true), transientError = null)
        }
        fetch(isRefresh = true)
    }

    fun setProtocolFilter(protocol: String?) {
        _state.value = _state.value.copy(protocolFilter = protocol, data = HostsDataState.Loading)
        fetch(isRefresh = false)
    }

    private fun load() {
        _state.value = _state.value.copy(data = HostsDataState.Loading)
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list(_state.value.protocolFilter, null)) {
                is ApiResult.Success -> {
                    val hosts = r.data.hosts
                    val cur = _state.value
                    val protocols = if (cur.protocolFilter == null) {
                        hosts.map { it.protocol }.filter { it.isNotBlank() }.distinct().sorted()
                    } else {
                        cur.protocols
                    }
                    _state.value = cur.copy(
                        data = if (hosts.isEmpty()) HostsDataState.Empty else HostsDataState.Content(hosts),
                        protocols = protocols,
                    )
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun clearMessage() {
        _state.value = _state.value.copy(transientError = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = _state.value.copy(data = HostsDataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is HostsDataState.Content
        _state.value = if (isRefresh && hasData) {
            cur.copy(data = (cur.data as HostsDataState.Content).copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(data = HostsDataState.Error(type))
        }
    }
}
