package com.testlogon.android.feature.crm

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.crm.Lead
import com.testlogon.android.data.crm.LeadActivity
import com.testlogon.android.data.crm.LeadConversionInDto
import com.testlogon.android.data.crm.LeadConversionResult
import com.testlogon.android.data.crm.LeadLogActivityInDto
import com.testlogon.android.data.crm.LeadsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class LeadDetailUiState(
    val phase: Phase = Phase.Loading,
    val lead: Lead? = null,
    val activities: List<LeadActivity> = emptyList(),
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
    val actionInProgress: Boolean = false,
    val actionMessage: String? = null,
    val conversion: LeadConversionResult? = null,
    // CRM-AND-LED: duplicate/merge picker
    val duplicates: List<Lead> = emptyList(),
    val duplicatesLoading: Boolean = false,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * CRM-AND-1 / CRM-AND-LED — lead detail: the lead + its activity timeline, plus convert / score /
 * log-activity / assign / merge / find-duplicates / delete actions. Keyed by the [ARG_LEAD_ID] nav
 * arg via [SavedStateHandle].
 */
@HiltViewModel
class LeadDetailViewModel @Inject constructor(
    private val repository: LeadsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val leadId: String = checkNotNull(savedStateHandle[ARG_LEAD_ID]) {
        "LeadDetailViewModel requires a $ARG_LEAD_ID nav arg"
    }

    private val _uiState = MutableStateFlow(LeadDetailUiState())
    val uiState: StateFlow<LeadDetailUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    private fun load() {
        _uiState.update {
            it.copy(phase = if (it.lead == null) LeadDetailUiState.Phase.Loading else it.phase)
        }
        viewModelScope.launch {
            coroutineScope {
                val leadDeferred = async { repository.get(leadId) }
                val activitiesDeferred = async { repository.listActivities(leadId) }
                when (val leadR = leadDeferred.await()) {
                    is ApiResult.Success -> {
                        val activities =
                            (activitiesDeferred.await() as? ApiResult.Success)?.data ?: emptyList()
                        _uiState.update {
                            it.copy(
                                phase = LeadDetailUiState.Phase.Content,
                                lead = leadR.data,
                                activities = activities,
                                isOffline = false,
                                errorMessage = null,
                            )
                        }
                    }
                    is ApiResult.Failure -> _uiState.update {
                        it.copy(
                            phase = if (it.lead != null) LeadDetailUiState.Phase.Content else LeadDetailUiState.Phase.Error,
                            errorMessage = leadR.error.message,
                            isOffline = false,
                        )
                    }
                    is ApiResult.NetworkError -> _uiState.update {
                        it.copy(
                            phase = if (it.lead != null) LeadDetailUiState.Phase.Content else LeadDetailUiState.Phase.Error,
                            errorMessage = "You're offline. Try again.",
                            isOffline = true,
                        )
                    }
                }
            }
        }
    }

    fun recomputeScore() = runAction {
        when (val r = repository.computeScore(leadId)) {
            is ApiResult.Success -> "Lead score updated to ${r.data}."
            is ApiResult.Failure -> r.error.message
            is ApiResult.NetworkError -> "You're offline. Try again."
        }
    }

    fun logActivity(type: String, subject: String, description: String) {
        if (subject.isBlank() && description.isBlank()) return
        runAction {
            val body = LeadLogActivityInDto(
                activityType = type,
                subject = subject.ifBlank { null },
                description = description.ifBlank { null },
            )
            when (val r = repository.logActivity(leadId, body)) {
                is ApiResult.Success -> "Activity logged."
                is ApiResult.Failure -> r.error.message
                is ApiResult.NetworkError -> "You're offline. Try again."
            }
        }
    }

    /** LED-010: assign this lead to another user by sub. */
    fun assign(assigneeSub: String) {
        if (assigneeSub.isBlank()) return
        runAction {
            when (val r = repository.assign(leadId, assigneeSub.trim())) {
                is ApiResult.Success -> "Lead assigned."
                is ApiResult.Failure -> r.error.message
                is ApiResult.NetworkError -> "You're offline. Try again."
            }
        }
    }

    /** LED-009: merge a secondary lead into this (primary) lead. */
    fun merge(secondaryLeadId: String) {
        if (secondaryLeadId.isBlank()) return
        runAction {
            when (val r = repository.merge(leadId, secondaryLeadId.trim())) {
                is ApiResult.Success -> "Leads merged."
                is ApiResult.Failure -> r.error.message
                is ApiResult.NetworkError -> "You're offline. Try again."
            }
        }
    }

    /** LED-009: fetch potential duplicates (by email) for the merge picker. */
    fun loadDuplicates() {
        _uiState.update { it.copy(duplicatesLoading = true) }
        viewModelScope.launch {
            when (val r = repository.duplicates(leadId)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(duplicatesLoading = false, duplicates = r.data)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(duplicatesLoading = false, actionMessage = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(duplicatesLoading = false, actionMessage = "You're offline. Try again.")
                }
            }
        }
    }

    /** LED-013: delete this lead. Invokes [onDeleted] on success so the caller can pop. */
    fun delete(onDeleted: () -> Unit) {
        _uiState.update { it.copy(actionInProgress = true, actionMessage = null) }
        viewModelScope.launch {
            when (val r = repository.delete(leadId)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(actionInProgress = false) }
                    onDeleted()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(actionInProgress = false, actionMessage = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(actionInProgress = false, actionMessage = "You're offline. Try again.")
                }
            }
        }
    }

    /** Convert to account + opportunity. On success the conversion result is surfaced. */
    fun convert(accountName: String?, createOpportunity: Boolean, opportunityName: String?) {
        _uiState.update { it.copy(actionInProgress = true, actionMessage = null) }
        viewModelScope.launch {
            val body = LeadConversionInDto(
                createAccount = true,
                accountName = accountName?.ifBlank { null },
                createOpportunity = createOpportunity,
                opportunityName = opportunityName?.ifBlank { null },
            )
            when (val r = repository.convert(leadId, body)) {
                is ApiResult.Success -> {
                    _uiState.update {
                        it.copy(
                            actionInProgress = false,
                            conversion = r.data,
                            actionMessage = "Lead converted.",
                        )
                    }
                    load()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(actionInProgress = false, actionMessage = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(actionInProgress = false, actionMessage = "You're offline. Try again.")
                }
            }
        }
    }

    fun clearActionMessage() = _uiState.update { it.copy(actionMessage = null) }

    private fun runAction(block: suspend () -> String?) {
        _uiState.update { it.copy(actionInProgress = true, actionMessage = null) }
        viewModelScope.launch {
            val message = block()
            _uiState.update { it.copy(actionInProgress = false, actionMessage = message) }
            load()
        }
    }

    companion object {
        const val ARG_LEAD_ID = "leadId"
    }
}
