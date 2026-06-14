package com.testlogon.android.feature.messaging.groupsettings

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.group.GroupRepository
import com.testlogon.android.data.messaging.group.GroupSettings
import com.testlogon.android.data.messaging.group.MembershipStatus
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

/** AND-159 — mute duration presets. */
enum class MuteDuration { EIGHT_HOURS, ONE_WEEK, FOREVER }

/** AND-159 — in-flight action guard (one action at a time). */
enum class ActionKind { MUTE, LEAVE, ACCEPT }

/** AND-159 — group settings screen state. */
data class GroupSettingsUiState(
    val phase: Phase = Phase.Loading,
    val conversationId: String = "",
    val groupName: String = "",
    val iconUrl: String? = null,
    val membership: MembershipStatus = MembershipStatus.UNKNOWN,
    val muted: Boolean = false,
    val actionInFlight: ActionKind? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, NotFound, Error }
}

/** AND-159 — one-shot events. */
sealed interface GroupSettingsEvent {
    data object LeftGroup : GroupSettingsEvent
    data class ShowSnackbar(val text: String) : GroupSettingsEvent
}

/**
 * AND-159 — group settings (mute / leave / accept-invite) presentation logic.
 *
 * `load()` reads the conversation (membership derived from the current user's participants[] entry,
 * mute from `muted_until`). Mute is OPTIMISTIC (toggle immediately, revert on failure); leave/accept
 * are NON-optimistic (UI updates only after a 2xx). [actionInFlight] guards against double-submit.
 */
@HiltViewModel
class GroupSettingsViewModel @Inject constructor(
    private val repo: GroupRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val conversationId: String =
        checkNotNull(savedStateHandle[ARG_CONVERSATION_ID]) { "missing $ARG_CONVERSATION_ID" }

    /** Epoch-SECONDS clock; overridable in tests (NOT injected — Hilt provides no Function0<Long>). */
    internal var clock: () -> Long = { System.currentTimeMillis() / 1000 }

    private val _uiState = MutableStateFlow(GroupSettingsUiState(conversationId = conversationId))
    val uiState: StateFlow<GroupSettingsUiState> = _uiState.asStateFlow()

    private val _events = Channel<GroupSettingsEvent>(Channel.BUFFERED)
    val events: Flow<GroupSettingsEvent> = _events.receiveAsFlow()

    init { load() }

    fun load() {
        _uiState.update { it.copy(phase = GroupSettingsUiState.Phase.Loading) }
        viewModelScope.launch {
            when (val r = repo.getGroupSettings(conversationId)) {
                is ApiResult.Success -> applySettings(r.data)
                is ApiResult.Failure ->
                    _uiState.update {
                        it.copy(
                            phase = if (r.error.status == HTTP_NOT_FOUND) {
                                GroupSettingsUiState.Phase.NotFound
                            } else {
                                GroupSettingsUiState.Phase.Error
                            },
                            errorMessage = r.error.message,
                        )
                    }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(phase = GroupSettingsUiState.Phase.Error, errorMessage = OFFLINE_MESSAGE)
                    }
            }
        }
    }

    private fun applySettings(s: GroupSettings) {
        _uiState.update {
            it.copy(
                phase = GroupSettingsUiState.Phase.Content,
                groupName = s.title,
                iconUrl = s.iconUrl,
                membership = s.membership,
                muted = s.isMuted(clock()),
                errorMessage = null,
            )
        }
    }

    fun setMuted(muted: Boolean, duration: MuteDuration = MuteDuration.FOREVER) {
        if (_uiState.value.actionInFlight != null) return
        val prior = _uiState.value.muted
        // Optimistic toggle.
        _uiState.update { it.copy(muted = muted, actionInFlight = ActionKind.MUTE) }
        viewModelScope.launch {
            val until = if (muted) durationToEpochSeconds(duration) else null
            when (val r = repo.setMute(conversationId, muted, until)) {
                is ApiResult.Success -> { applySettings(r.data); clearAction() }
                is ApiResult.Failure -> revertMute(prior, r.error.message)
                is ApiResult.NetworkError -> revertMute(prior, OFFLINE_MESSAGE)
            }
        }
    }

    private fun revertMute(prior: Boolean, message: String) {
        _uiState.update { it.copy(muted = prior, actionInFlight = null, errorMessage = message) }
        viewModelScope.launch { _events.send(GroupSettingsEvent.ShowSnackbar(message)) }
    }

    fun leave() {
        if (_uiState.value.actionInFlight != null) return
        _uiState.update { it.copy(actionInFlight = ActionKind.LEAVE) }
        viewModelScope.launch {
            when (val r = repo.leaveGroup(conversationId)) {
                is ApiResult.Success -> { clearAction(); _events.send(GroupSettingsEvent.LeftGroup) }
                is ApiResult.Failure -> failAction(r.error.message)
                is ApiResult.NetworkError -> failAction(OFFLINE_MESSAGE)
            }
        }
    }

    fun acceptInvite() {
        if (_uiState.value.actionInFlight != null) return
        _uiState.update { it.copy(actionInFlight = ActionKind.ACCEPT) }
        viewModelScope.launch {
            when (val r = repo.acceptInvite(conversationId)) {
                is ApiResult.Success -> { applySettings(r.data); clearAction() }
                is ApiResult.Failure -> failAction(r.error.message)
                is ApiResult.NetworkError -> failAction(OFFLINE_MESSAGE)
            }
        }
    }

    fun dismissError() = _uiState.update { it.copy(errorMessage = null) }

    private fun clearAction() = _uiState.update { it.copy(actionInFlight = null) }

    private fun failAction(message: String) {
        _uiState.update { it.copy(actionInFlight = null, errorMessage = message) }
        viewModelScope.launch { _events.send(GroupSettingsEvent.ShowSnackbar(message)) }
    }

    private fun durationToEpochSeconds(duration: MuteDuration): Long? = when (duration) {
        MuteDuration.EIGHT_HOURS -> clock() + EIGHT_HOURS_SECONDS
        MuteDuration.ONE_WEEK -> clock() + ONE_WEEK_SECONDS
        MuteDuration.FOREVER -> null // "forever" => muted_until null (server persists a sentinel)
    }

    companion object {
        const val ARG_CONVERSATION_ID = "conversationId"
        const val HTTP_NOT_FOUND = 404
        const val OFFLINE_MESSAGE = "You're offline. Try again when you're back online."
        const val EIGHT_HOURS_SECONDS = 8L * 60 * 60
        const val ONE_WEEK_SECONDS = 7L * 24 * 60 * 60
    }
}
