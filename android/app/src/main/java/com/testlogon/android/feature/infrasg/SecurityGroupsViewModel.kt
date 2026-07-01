package com.testlogon.android.feature.infrasg

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.infrasg.SecurityGroupDto
import com.testlogon.android.data.infrasg.SecurityGroupsRepository
import com.testlogon.android.data.infrasg.SecurityRuleReq
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Cloud-Infra: Security Groups management. List of groups (master); tapping one opens a detail sheet
 * of its rules with add/edit/remove; plus create/rename/delete a group. Mirrors SecurityGroupsPage.tsx.
 * Every mutation returns the full updated group, which is written through into the list. 403 -> Forbidden.
 */
sealed interface SgDataState {
    data object Loading : SgDataState
    data class Content(val groups: List<SecurityGroupDto>, val isRefreshing: Boolean = false) : SgDataState
    data object Empty : SgDataState
    data object Forbidden : SgDataState
    data class Error(val type: AdminOpsErrorType) : SgDataState
}

data class SgUiState(
    val data: SgDataState = SgDataState.Loading,
    val selectedSgId: String? = null,
    val busy: Boolean = false,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
) {
    val selected: SecurityGroupDto?
        get() = (data as? SgDataState.Content)?.groups?.firstOrNull { it.sgId == selectedSgId }
}

@HiltViewModel
class SecurityGroupsViewModel @Inject constructor(
    private val repo: SecurityGroupsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(SgUiState())
    val state: StateFlow<SgUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur.data is SgDataState.Content) {
            _state.value = cur.copy(data = cur.data.copy(isRefreshing = true), transientError = null)
        }
        fetch(isRefresh = true)
    }

    fun select(sgId: String?) {
        _state.value = _state.value.copy(selectedSgId = sgId)
    }

    private fun load() {
        _state.value = _state.value.copy(data = SgDataState.Loading)
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> {
                    val items = r.data
                    _state.value = _state.value.copy(
                        data = if (items.isEmpty()) SgDataState.Empty else SgDataState.Content(items),
                    )
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun createGroup(name: String, description: String) {
        if (_state.value.busy || name.isBlank()) return
        runCreate(msg = "Group created") { repo.create(name, description) }
    }

    fun renameGroup(sgId: String, name: String, description: String) {
        if (_state.value.busy || name.isBlank()) return
        runUpdate(sgId, "Group updated") { repo.update(sgId, name, description) }
    }

    fun deleteGroup(sgId: String) {
        if (_state.value.busy) return
        _state.value = _state.value.copy(busy = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.delete(sgId)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(busy = false, selectedSgId = null, message = "Group deleted")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceBusyError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceBusyError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun addRule(sgId: String, rule: SecurityRuleReq) {
        if (_state.value.busy) return
        runUpdate(sgId, "Rule added") { repo.addRule(sgId, rule) }
    }

    fun updateRule(sgId: String, ruleId: String, rule: SecurityRuleReq) {
        if (_state.value.busy) return
        runUpdate(sgId, "Rule updated") { repo.updateRule(sgId, ruleId, rule) }
    }

    fun removeRule(sgId: String, ruleId: String) {
        if (_state.value.busy) return
        runUpdate(sgId, "Rule removed") { repo.removeRule(sgId, ruleId) }
    }

    /** Create path: refetches the whole list on success (no group id to write through yet). */
    private fun runCreate(msg: String, block: suspend () -> ApiResult<SecurityGroupDto>) {
        _state.value = _state.value.copy(busy = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(busy = false, message = msg)
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceBusyError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceBusyError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    /** Update/rule paths: the mutation returns the full updated group, written through into the list. */
    private fun runUpdate(sgId: String, msg: String, block: suspend () -> ApiResult<SecurityGroupDto>) {
        _state.value = _state.value.copy(busy = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    val cur = _state.value
                    val d = cur.data as? SgDataState.Content
                    val updated = d?.groups?.map { if (it.sgId == sgId) r.data else it }
                    _state.value = cur.copy(
                        data = updated?.let { d.copy(groups = it) } ?: cur.data,
                        busy = false,
                        message = msg,
                    )
                }
                is ApiResult.Failure -> reduceBusyError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceBusyError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun clearMessage() {
        _state.value = _state.value.copy(message = null, transientError = null)
    }

    private fun reduceBusyError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(busy = false, transientError = type)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = _state.value.copy(data = SgDataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is SgDataState.Content
        _state.value = if (isRefresh && hasData) {
            cur.copy(data = (cur.data as SgDataState.Content).copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(data = SgDataState.Error(type))
        }
    }
}
