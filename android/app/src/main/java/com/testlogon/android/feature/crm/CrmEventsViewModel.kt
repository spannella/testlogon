package com.testlogon.android.feature.crm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.crm.CrmEvent
import com.testlogon.android.data.crm.CrmEventCreateInDto
import com.testlogon.android.data.crm.CrmEventsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class CrmEventsUiState(
    val phase: Phase = Phase.Loading,
    val events: List<CrmEvent> = emptyList(),
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
 * CRM-AND-PEC — CRM events list + inline create. Pulls GET /ui/crm/events; a 404 (module disabled)
 * degrades to an empty, non-error state with a banner. Create posts then re-loads.
 */
@HiltViewModel
class CrmEventsViewModel @Inject constructor(
    private val repository: CrmEventsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CrmEventsUiState())
    val uiState: StateFlow<CrmEventsUiState> = _uiState.asStateFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val hasContent = _uiState.value.events.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else CrmEventsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val r = repository.list()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = CrmEventsUiState.Phase.Content,
                        events = r.data.events,
                        moduleDisabled = r.data.moduleDisabled,
                        isRefreshing = false,
                        isOffline = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.events.isNotEmpty()) CrmEventsUiState.Phase.Content else CrmEventsUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = false,
                        errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.events.isNotEmpty()) CrmEventsUiState.Phase.Content else CrmEventsUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = true,
                        errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }

    fun createEvent(
        name: String,
        description: String?,
        maxAttendance: Int?,
        onCreated: (String) -> Unit,
    ) {
        if (name.isBlank()) {
            _uiState.update { it.copy(createError = "An event name is required.") }
            return
        }
        _uiState.update { it.copy(createSubmitting = true, createError = null) }
        viewModelScope.launch {
            val body = CrmEventCreateInDto(
                name = name.trim(),
                description = description?.trim()?.ifBlank { null },
                maxAttendance = maxAttendance,
            )
            when (val r = repository.create(body)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(createSubmitting = false, createError = null) }
                    onCreated(r.data.eventId)
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
