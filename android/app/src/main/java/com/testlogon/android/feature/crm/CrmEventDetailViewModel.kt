package com.testlogon.android.feature.crm

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.crm.CrmEvent
import com.testlogon.android.data.crm.CrmEventCapacity
import com.testlogon.android.data.crm.CrmEventUpdateInDto
import com.testlogon.android.data.crm.CrmEventsRepository
import com.testlogon.android.data.crm.CrmInvitee
import com.testlogon.android.data.crm.CrmPecMath
import com.testlogon.android.data.crm.CrmRegistration
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * CRM-AND-PEC / EVT-002-004 — event detail: metadata + capacity + invitee management + registration /
 * RSVP / check-in. Mirrors frontend/src/api/endpoints/crmEvents.ts. Every sub-resource load degrades on
 * 404 (module disabled) or failure to an empty section rather than failing the whole screen.
 */
data class CrmEventDetailUiState(
    val phase: Phase = Phase.Loading,
    val event: CrmEvent? = null,
    val capacity: CrmEventCapacity? = null,
    val invitees: List<CrmInvitee> = emptyList(),
    val registrations: List<CrmRegistration> = emptyList(),
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
    // transient action feedback
    val actionInProgress: Boolean = false,
    val actionError: String? = null,
    val actionMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }

    val pendingInviteCount: Int
        get() = CrmPecMath.pendingInviteCount(invitees.map { it.inviteStatus })

    val canSendInvitations: Boolean
        get() = CrmPecMath.canSendInvitations(pendingInviteCount)
}

@HiltViewModel
class CrmEventDetailViewModel @Inject constructor(
    private val repository: CrmEventsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val eventId: String = checkNotNull(savedStateHandle[ARG_EVENT_ID]) {
        "CrmEventDetailViewModel requires a $ARG_EVENT_ID nav arg"
    }

    private val _uiState = MutableStateFlow(CrmEventDetailUiState())
    val uiState: StateFlow<CrmEventDetailUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()

    private fun load() {
        _uiState.update {
            it.copy(phase = if (it.event == null) CrmEventDetailUiState.Phase.Loading else it.phase)
        }
        viewModelScope.launch {
            when (val r = repository.get(eventId)) {
                is ApiResult.Success -> {
                    val capacity = (repository.capacity(eventId) as? ApiResult.Success)?.data
                    val invitees = (repository.listInvitees(eventId) as? ApiResult.Success)?.data?.invitees ?: emptyList()
                    val registrations =
                        (repository.listRegistrations(eventId) as? ApiResult.Success)?.data?.registrations ?: emptyList()
                    _uiState.update {
                        it.copy(
                            phase = CrmEventDetailUiState.Phase.Content,
                            event = r.data,
                            capacity = capacity,
                            invitees = invitees,
                            registrations = registrations,
                            isOffline = false,
                            errorMessage = null,
                        )
                    }
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.event != null) CrmEventDetailUiState.Phase.Content else CrmEventDetailUiState.Phase.Error,
                        isOffline = false,
                        errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.event != null) CrmEventDetailUiState.Phase.Content else CrmEventDetailUiState.Phase.Error,
                        isOffline = true,
                        errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }

    // ── EVT-002: event update ─────────────────────────────────────────────────

    fun updateEvent(name: String?, description: String?, maxAttendance: Int?) {
        runAction("Event updated.") {
            repository.update(
                eventId,
                CrmEventUpdateInDto(
                    name = name?.trim()?.ifBlank { null },
                    description = description?.trim(),
                    maxAttendance = maxAttendance,
                ),
            )
        }
    }

    // ── EVT-002: invitee management ───────────────────────────────────────────

    fun addInvitee(inviteeSub: String) {
        if (inviteeSub.isBlank()) {
            _uiState.update { it.copy(actionError = "A user id is required.") }
            return
        }
        runAction("Invitee added.") { repository.addInvitee(eventId, inviteeSub.trim()) }
    }

    fun removeInvitee(inviteeSub: String) {
        runAction("Invitee removed.") { repository.removeInvitee(eventId, inviteeSub) }
    }

    fun bulkImport(userSubs: List<String>) {
        val cleaned = userSubs.map { it.trim() }.filter { it.isNotBlank() }.distinct()
        if (cleaned.isEmpty()) {
            _uiState.update { it.copy(actionError = "Enter at least one user id.") }
            return
        }
        runAction("Invitees imported.") { repository.bulkImportInvitees(eventId, cleaned) }
    }

    fun sendInvitations() {
        runAction("Invitations sent.") { repository.sendInvitations(eventId) }
    }

    // ── EVT-003: registration / RSVP / check-in ───────────────────────────────

    fun register() {
        runAction("Registered.") { repository.register(eventId) }
    }

    fun respond(registrantSub: String, newStatus: String) {
        runAction("RSVP updated.") { repository.respond(eventId, registrantSub, newStatus) }
    }

    fun checkIn(registrantSub: String) {
        runAction("Checked in.") { repository.checkIn(eventId, registrantSub) }
    }

    fun cancelRegistration(registrantSub: String) {
        runAction("Registration cancelled.") { repository.cancelRegistration(eventId, registrantSub) }
    }

    fun clearActionFeedback() = _uiState.update { it.copy(actionError = null, actionMessage = null) }

    /** Runs a mutating action, then re-loads on success so every derived section refreshes. */
    private fun <T> runAction(successMessage: String, block: suspend () -> ApiResult<T>) {
        _uiState.update { it.copy(actionInProgress = true, actionError = null, actionMessage = null) }
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(actionInProgress = false, actionMessage = successMessage) }
                    load()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(actionInProgress = false, actionError = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(actionInProgress = false, actionError = "You're offline. Try again.")
                }
            }
        }
    }

    companion object {
        const val ARG_EVENT_ID: String = "eventId"
    }
}
