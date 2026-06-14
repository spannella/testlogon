package com.testlogon.android.feature.broadcast.host

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.broadcast.BroadcastSession
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-307 — "Go Live" create + schedule view-state for a host broadcast session.
 *
 * The title maps to the wire `name` (NOT `title`); `scheduledAtEpochSeconds` is a Unix epoch-SECOND
 * integer. [createdSession] is the most recent server result and drives the cancel-schedule affordance
 * (visible once a scheduled session exists). [fieldErrors] holds server 422 messages keyed by the wire
 * field name ("scheduled_at" / "name"); [error] is a non-field, screen-level message.
 */
data class CreateBroadcastUiState(
    val title: String = "",
    val description: String = "",
    val scheduleForLater: Boolean = false,
    val scheduledAtEpochSeconds: Long? = null,
    val isSubmitting: Boolean = false,
    val createdSession: BroadcastSession? = null,
    val error: String? = null,
    val fieldErrors: Map<String, String> = emptyMap(),
) {
    /** Submit is gated on a non-blank title and not already in flight. */
    val canSubmit: Boolean get() = title.isNotBlank() && !isSubmitting

    /** A scheduled session exists -> the cancel-schedule action is offered. */
    val canCancelSchedule: Boolean
        get() = createdSession?.scheduleStatus?.equals("scheduled", ignoreCase = true) == true
}

/** AND-307 — one-shot navigation/finish effects (Channel, consumed exactly once by the screen). */
sealed interface CreateBroadcastEffect {
    /** Create/schedule succeeded -> leave the Go-Live screen. */
    data class Finished(val sessionId: String) : CreateBroadcastEffect
}

/**
 * AND-307 — host session create/schedule presentation logic (control-plane only; no media/WebRTC —
 * that is AND-308). Sources the broadcast `profile_id` from the [SavedStateHandle] nav arg
 * [ARG_PROFILE_ID]; if it is absent the screen surfaces a "no broadcast profile" error rather than
 * fabricating one. [create] POSTs create then, when [CreateBroadcastUiState.scheduleForLater] is set,
 * POSTs schedule; otherwise the freshly-created draft is left as-is.
 */
@HiltViewModel
class CreateBroadcastViewModel @Inject constructor(
    private val repo: BroadcastRepository,
    private val errorParser: ApiErrorParser,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val profileId: String? = savedState.get<String>(ARG_PROFILE_ID)?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow(CreateBroadcastUiState())
    val uiState: StateFlow<CreateBroadcastUiState> = _uiState.asStateFlow()

    private val _effects = Channel<CreateBroadcastEffect>(Channel.BUFFERED)
    val effects: Flow<CreateBroadcastEffect> = _effects.receiveAsFlow()

    fun setTitle(value: String) = _uiState.update {
        it.copy(title = value, error = null, fieldErrors = it.fieldErrors - FIELD_NAME)
    }

    fun setDescription(value: String) = _uiState.update {
        it.copy(description = value, error = null)
    }

    fun toggleScheduleLater(enabled: Boolean) = _uiState.update {
        it.copy(
            scheduleForLater = enabled,
            scheduledAtEpochSeconds = if (enabled) it.scheduledAtEpochSeconds else null,
            fieldErrors = it.fieldErrors - FIELD_SCHEDULED_AT,
        )
    }

    fun setScheduledAt(epochSeconds: Long?) = _uiState.update {
        it.copy(scheduledAtEpochSeconds = epochSeconds, fieldErrors = it.fieldErrors - FIELD_SCHEDULED_AT)
    }

    /**
     * Creates the session (draft) then — if scheduling for later — schedules it. No auto-retry of the
     * non-idempotent writes. Server 422 `detail[{loc}]` entries map to [CreateBroadcastUiState.fieldErrors]
     * by the trailing `loc` segment ("scheduled_at" / "name").
     */
    fun create() {
        val state = _uiState.value
        if (!state.canSubmit) return
        val profile = profileId
        if (profile == null) {
            _uiState.update { it.copy(error = NO_PROFILE) }
            return
        }
        _uiState.update { it.copy(isSubmitting = true, error = null, fieldErrors = emptyMap()) }
        viewModelScope.launch {
            when (val created = repo.create(profile)) {
                is ApiResult.Success -> afterCreate(created.data, state)
                is ApiResult.Failure -> reduceFailure(created.error)
                is ApiResult.NetworkError -> reduceNetworkError()
            }
        }
    }

    /** Cancels the pending schedule on the current session and finishes. */
    fun cancelSchedule() {
        val sessionId = _uiState.value.createdSession?.id ?: return
        _uiState.update { it.copy(isSubmitting = true, error = null) }
        viewModelScope.launch {
            when (val result = repo.cancelSchedule(sessionId)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(isSubmitting = false, createdSession = result.data) }
                    _effects.send(CreateBroadcastEffect.Finished(result.data.id))
                }
                is ApiResult.Failure -> reduceFailure(result.error)
                is ApiResult.NetworkError -> reduceNetworkError()
            }
        }
    }

    private suspend fun afterCreate(session: BroadcastSession, state: CreateBroadcastUiState) {
        if (!state.scheduleForLater) {
            _uiState.update { it.copy(isSubmitting = false, createdSession = session) }
            _effects.send(CreateBroadcastEffect.Finished(session.id))
            return
        }
        val at = state.scheduledAtEpochSeconds
        if (at == null) {
            _uiState.update {
                it.copy(
                    isSubmitting = false,
                    createdSession = session,
                    fieldErrors = it.fieldErrors + (FIELD_SCHEDULED_AT to SCHEDULE_REQUIRED),
                )
            }
            return
        }
        when (
            val scheduled = repo.schedule(
                sessionId = session.id,
                scheduledAtEpochSeconds = at,
                name = state.title.trim(),
                description = state.description.trim().ifBlank { null },
            )
        ) {
            is ApiResult.Success -> {
                _uiState.update { it.copy(isSubmitting = false, createdSession = scheduled.data) }
                _effects.send(CreateBroadcastEffect.Finished(scheduled.data.id))
            }
            // The draft already exists; retain it so cancel/retry stays coherent.
            is ApiResult.Failure -> reduceFailure(scheduled.error, createdSession = session)
            is ApiResult.NetworkError -> reduceNetworkError(createdSession = session)
        }
    }

    private fun reduceFailure(error: ApiError, createdSession: BroadcastSession? = null) {
        if (error.status == 422) {
            val fieldErrors = mapServerFieldErrors(error)
            if (fieldErrors.isNotEmpty()) {
                _uiState.update {
                    it.copy(
                        isSubmitting = false,
                        fieldErrors = fieldErrors,
                        createdSession = createdSession ?: it.createdSession,
                    )
                }
                return
            }
        }
        _uiState.update {
            it.copy(
                isSubmitting = false,
                error = error.message,
                createdSession = createdSession ?: it.createdSession,
            )
        }
    }

    private fun reduceNetworkError(createdSession: BroadcastSession? = null) {
        _uiState.update {
            it.copy(
                isSubmitting = false,
                error = OFFLINE,
                createdSession = createdSession ?: it.createdSession,
            )
        }
    }

    /** Routes FastAPI 422 `detail[{loc,msg}]` to fields by the trailing `loc` segment. */
    private fun mapServerFieldErrors(error: ApiError): Map<String, String> {
        val detail = (error.raw as? String)?.let { errorParser.parseDetail(it) } as? List<*> ?: return emptyMap()
        val out = mutableMapOf<String, String>()
        for (item in detail) {
            val map = item as? Map<*, *> ?: continue
            val loc = (map["loc"] as? List<*>)?.lastOrNull() as? String ?: continue
            when (loc) {
                FIELD_SCHEDULED_AT -> out[FIELD_SCHEDULED_AT] = SCHEDULE_PAST
                FIELD_NAME -> out[FIELD_NAME] = NAME_INVALID
            }
        }
        return out
    }

    companion object {
        /** Nav arg carrying the host's broadcast profile id (supplied by the entry point). */
        const val ARG_PROFILE_ID = "profileId"

        // Wire field names (also the 422 loc segments and fieldErrors keys).
        const val FIELD_SCHEDULED_AT = "scheduled_at"
        const val FIELD_NAME = "name"

        // Non-resource fallbacks (the screen prefers stringResource where it has a Context).
        private const val NO_PROFILE = "No broadcast profile is available."
        private const val SCHEDULE_REQUIRED = "Pick a date and time."
        private const val SCHEDULE_PAST = "Pick a time further in the future."
        private const val NAME_INVALID = "That title is too long."
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
