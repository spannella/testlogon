package com.testlogon.android.feature.instancetemplates

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.instancetemplates.InstanceTemplatesRepository
import com.testlogon.android.data.instancetemplates.LaunchFromTemplateDto
import com.testlogon.android.data.instancetemplates.LaunchFromTemplateReq
import com.testlogon.android.data.instancetemplates.TemplateDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Remote-Access: instance-template management. Lists templates (system + owner), applies (launch),
 * clones, and deletes owner templates. Mirrors TemplateBrowserPage.tsx. The whole surface is behind
 * INSTANCE_TEMPLATES_ENABLED (a 400 on load -> Disabled), launch behind TEMPLATE_LAUNCH_ENABLED. A 403
 * renders Forbidden. Reuses AdminOpsErrorType.
 */
sealed interface TemplatesDataState {
    data object Loading : TemplatesDataState
    data class Content(val templates: List<TemplateDto>, val isRefreshing: Boolean = false) : TemplatesDataState
    data object Empty : TemplatesDataState
    data object Forbidden : TemplatesDataState
    data object Disabled : TemplatesDataState
    data class Error(val type: AdminOpsErrorType) : TemplatesDataState
}

data class TemplatesUiState(
    val data: TemplatesDataState = TemplatesDataState.Loading,
    val actionInFlightId: String? = null,
    val launchResult: LaunchFromTemplateDto? = null,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class InstanceTemplatesViewModel @Inject constructor(
    private val repo: InstanceTemplatesRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(TemplatesUiState())
    val state: StateFlow<TemplatesUiState> = _state.asStateFlow()

    init { load() }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur.data is TemplatesDataState.Content) {
            _state.value = cur.copy(data = cur.data.copy(isRefreshing = true), transientError = null)
        }
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = _state.value.copy(data = TemplatesDataState.Loading)
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> {
                    val items = r.data.templates
                    _state.value = _state.value.copy(
                        data = if (items.isEmpty()) TemplatesDataState.Empty else TemplatesDataState.Content(items),
                    )
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun launch(templateId: String, label: String) {
        if (_state.value.actionInFlightId != null) return
        _state.value = _state.value.copy(actionInFlightId = templateId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.launch(templateId, LaunchFromTemplateReq(label = label.trim()))) {
                is ApiResult.Success -> _state.value = _state.value.copy(
                    actionInFlightId = null,
                    launchResult = r.data,
                    message = "Launched from template",
                )
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun clone(templateId: String, newName: String) {
        if (_state.value.actionInFlightId != null || newName.isBlank()) return
        _state.value = _state.value.copy(actionInFlightId = templateId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.clone(templateId, newName.trim())) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(actionInFlightId = null, message = "Cloned as ${r.data.name}")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun delete(templateId: String) {
        if (_state.value.actionInFlightId != null) return
        _state.value = _state.value.copy(actionInFlightId = templateId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.delete(templateId)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(actionInFlightId = null, message = "Template deleted")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceActionError(
                    when (r.error.status) {
                        401 -> AdminOpsErrorType.AUTH
                        else -> AdminOpsErrorType.SERVER // 403 = system template immutable
                    },
                )
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun dismissLaunchResult() { _state.value = _state.value.copy(launchResult = null) }

    fun clearMessage() { _state.value = _state.value.copy(message = null, transientError = null) }

    private fun reduceActionError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(actionInFlightId = null, transientError = type)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        400 -> _state.value = _state.value.copy(data = TemplatesDataState.Disabled)
        403 -> _state.value = _state.value.copy(data = TemplatesDataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is TemplatesDataState.Content
        _state.value = if (isRefresh && hasData) {
            cur.copy(data = (cur.data as TemplatesDataState.Content).copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(data = TemplatesDataState.Error(type))
        }
    }
}
