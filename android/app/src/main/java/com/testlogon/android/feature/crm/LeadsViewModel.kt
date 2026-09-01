package com.testlogon.android.feature.crm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.crm.Lead
import com.testlogon.android.data.crm.LeadCreateInDto
import com.testlogon.android.data.crm.LeadsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class LeadsListUiState(
    val phase: Phase = Phase.Loading,
    val leads: List<Lead> = emptyList(),
    val moduleDisabled: Boolean = false,
    val isRefreshing: Boolean = false,
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
    // create-lead sheet
    val createSubmitting: Boolean = false,
    val createError: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * CRM-AND-1 — drives the leads list + inline create.
 *
 * A load pulls GET /ui/leads; a 404 (module disabled) degrades to an empty, non-error state with a
 * `moduleDisabled` banner rather than an error screen. Create posts then re-loads.
 */
@HiltViewModel
class LeadsListViewModel @Inject constructor(
    private val repository: LeadsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(LeadsListUiState())
    val uiState: StateFlow<LeadsListUiState> = _uiState.asStateFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val hasContent = _uiState.value.leads.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else LeadsListUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val r = repository.list()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = LeadsListUiState.Phase.Content,
                        leads = r.data.leads,
                        moduleDisabled = r.data.moduleDisabled,
                        isRefreshing = false,
                        isOffline = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.leads.isNotEmpty()) LeadsListUiState.Phase.Content else LeadsListUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = false,
                        errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.leads.isNotEmpty()) LeadsListUiState.Phase.Content else LeadsListUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = true,
                        errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }

    /** Submit a new lead. Invokes [onCreated] with the new lead id on success. */
    fun createLead(
        firstName: String,
        lastName: String,
        email: String,
        company: String?,
        leadSource: String?,
        onCreated: (String) -> Unit,
    ) {
        if (firstName.isBlank() || lastName.isBlank() || email.isBlank()) {
            _uiState.update { it.copy(createError = "First name, last name and email are required.") }
            return
        }
        _uiState.update { it.copy(createSubmitting = true, createError = null) }
        viewModelScope.launch {
            val body = LeadCreateInDto(
                firstName = firstName.trim(),
                lastName = lastName.trim(),
                email = email.trim(),
                company = company?.trim()?.ifBlank { null },
                leadSource = leadSource?.ifBlank { null },
            )
            when (val r = repository.create(body)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(createSubmitting = false, createError = null) }
                    onCreated(r.data.leadId)
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
