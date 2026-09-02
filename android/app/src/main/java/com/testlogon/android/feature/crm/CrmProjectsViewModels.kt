package com.testlogon.android.feature.crm

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.crm.CrmProject
import com.testlogon.android.data.crm.CrmProjectCreateInDto
import com.testlogon.android.data.crm.CrmProjectTask
import com.testlogon.android.data.crm.CrmProjectsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

// ─── Projects list ────────────────────────────────────────────────────────────

data class CrmProjectsUiState(
    val phase: Phase = Phase.Loading,
    val projects: List<CrmProject> = emptyList(),
    val moduleDisabled: Boolean = false,
    val isRefreshing: Boolean = false,
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
    val createSubmitting: Boolean = false,
    val createError: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * CRM-AND-PEC — CRM projects list + inline create. Pulls GET /v1/crm/projects; a 404 (module
 * disabled) degrades to an empty, non-error state with a banner. Create posts then re-loads.
 */
@HiltViewModel
class CrmProjectsViewModel @Inject constructor(
    private val repository: CrmProjectsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CrmProjectsUiState())
    val uiState: StateFlow<CrmProjectsUiState> = _uiState.asStateFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val hasContent = _uiState.value.projects.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else CrmProjectsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val r = repository.list()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = CrmProjectsUiState.Phase.Content,
                        projects = r.data.projects,
                        moduleDisabled = r.data.moduleDisabled,
                        isRefreshing = false,
                        isOffline = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.projects.isNotEmpty()) CrmProjectsUiState.Phase.Content else CrmProjectsUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = false,
                        errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.projects.isNotEmpty()) CrmProjectsUiState.Phase.Content else CrmProjectsUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = true,
                        errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }

    fun createProject(
        name: String,
        description: String?,
        status: String?,
        onCreated: (String) -> Unit,
    ) {
        if (name.isBlank()) {
            _uiState.update { it.copy(createError = "A project name is required.") }
            return
        }
        _uiState.update { it.copy(createSubmitting = true, createError = null) }
        viewModelScope.launch {
            val body = CrmProjectCreateInDto(
                name = name.trim(),
                description = description?.trim()?.ifBlank { null },
                status = status?.ifBlank { null },
            )
            when (val r = repository.create(body)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(createSubmitting = false, createError = null) }
                    onCreated(r.data.id)
                    load(fromUser = false)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(createSubmitting = false, createError = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(createSubmitting = false, createError = "You're offline. Try again.")
                }
            }
        }
    }

    fun clearCreateError() = _uiState.update { it.copy(createError = null) }
}

// ─── Project detail ───────────────────────────────────────────────────────────

data class CrmProjectDetailUiState(
    val phase: Phase = Phase.Loading,
    val project: CrmProject? = null,
    val tasks: List<CrmProjectTask> = emptyList(),
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

@HiltViewModel
class CrmProjectDetailViewModel @Inject constructor(
    private val repository: CrmProjectsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val projectId: String = checkNotNull(savedStateHandle[ARG_PROJECT_ID]) {
        "CrmProjectDetailViewModel requires a $ARG_PROJECT_ID nav arg"
    }

    private val _uiState = MutableStateFlow(CrmProjectDetailUiState())
    val uiState: StateFlow<CrmProjectDetailUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    private fun load() {
        _uiState.update {
            it.copy(phase = if (it.project == null) CrmProjectDetailUiState.Phase.Loading else it.phase)
        }
        viewModelScope.launch {
            when (val r = repository.detail(projectId)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = CrmProjectDetailUiState.Phase.Content,
                        project = r.data.project,
                        tasks = r.data.tasks,
                        isOffline = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.project != null) CrmProjectDetailUiState.Phase.Content else CrmProjectDetailUiState.Phase.Error,
                        isOffline = false,
                        errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.project != null) CrmProjectDetailUiState.Phase.Content else CrmProjectDetailUiState.Phase.Error,
                        isOffline = true,
                        errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }

    companion object {
        const val ARG_PROJECT_ID: String = "projectId"
    }
}
