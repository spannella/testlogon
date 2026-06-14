package com.testlogon.android.feature.broadcast.moderation

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.chat.ChatMessage
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-313 - presentation logic for broadcast chat moderation.
 *
 * Mutations (mute / ban / unban / delete / pin / unpin) are OPTIMISTIC: the action key goes into inFlight,
 * the repo runs, and on success a Success event is emitted (the pinnedMessage is reconciled from the pin
 * response) while on failure the key is rolled back and a typed Failure event is emitted. A 403/401 emits an
 * AuthDenied event (the screen then HIDES the controls).
 *
 * The DELETE optimistic removal is reconciled in the chat panel by the AND-281 `chat:delete` SSE frame, which
 * the LiveChatViewModel reducer ALREADY handles (ChatStreamEvent.MessageDeleted -> removeMessage). This VM is
 * therefore SELF-CONTAINED for delete: it issues the mutation and reports the outcome; the chat panel removes
 * the row when the server echoes chat:delete. There are NO SSE frames for mute / ban / pin.
 *
 * The moderation LOG is a one-shot [ModerationLogUiState] loaded on demand + refresh() (pull-to-refresh only;
 * NO Paging, NO poll loop, so NO delay loop at all). uiState is a plain MutableStateFlow so optimistic state
 * is reflected synchronously (no combine().stateIn window).
 *
 * ROUTING / DECOUPLING (AND-359 not implemented): [creatorId] arrives as a nav arg (the broadcast's creator
 * id). ban / unban / pin / unpin / log ALWAYS use the delegate path (require creatorId). mute / delete use the
 * HOST path unless a delegate creatorId is present. AuthStateStore does NOT expose managingCreator today, so
 * the nav-arg creatorId is the only delegate signal; a future managingCreator override would slot in here.
 */
@HiltViewModel
class ModerationViewModel @Inject constructor(
    private val repository: ModerationRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    /** The broadcast's creator id (nav arg). Blank when host-only (no delegate routing available). */
    val creatorId: String = savedState.get<String>(ARG_CREATOR_ID).orEmpty()

    /**
     * Whether the current principal may moderate this broadcast. Defaults true (host or managingCreator); a
     * 403 from any mutation flips it false so the screen hides the controls. The host/delegate decision lives
     * on the server - this gate is the CLIENT reflection of it.
     */
    private val _canModerate = MutableStateFlow(true)
    val canModerate: StateFlow<Boolean> = _canModerate.asStateFlow()

    private val _uiState = MutableStateFlow(ModerationUiState())
    val uiState: StateFlow<ModerationUiState> = _uiState.asStateFlow()

    private val _logState = MutableStateFlow<ModerationLogUiState>(ModerationLogUiState.Loading)
    val logState: StateFlow<ModerationLogUiState> = _logState.asStateFlow()

    /** True when delegate-scoped actions (ban / unban / pin / unpin / log) are available (creatorId present). */
    val delegateAvailable: Boolean get() = creatorId.isNotBlank()

    // ---- sheet control ----

    fun openMessageSheet(message: ChatMessage) {
        _uiState.update { it.copy(sheet = ModerationSheet.Message(message)) }
    }

    fun openUserSheet(userId: String, displayName: String) {
        _uiState.update { it.copy(sheet = ModerationSheet.User(userId, displayName)) }
    }

    fun dismissSheet() {
        _uiState.update { it.copy(sheet = null) }
    }

    fun consumeEvent() {
        _uiState.update { it.copy(event = null) }
    }

    // ---- mutations (optimistic; key into inFlight, repo call, event + reconcile / rollback) ----

    /** Mute [userId] for [spec]. HOST path unless a delegate [creatorId] is present. */
    fun confirmMute(userId: String, spec: MuteSpec) {
        val key = key(ModerationActionType.MUTE, userId)
        runMutation(key, ModerationActionType.MUTE) {
            repository.mute(sessionId, creatorId.ifBlank { null }, userId, spec)
        }
    }

    /** Ban [userId] (optional [reason]). DELEGATE path (requires creatorId). */
    fun confirmBan(userId: String, reason: String?) {
        val key = key(ModerationActionType.BAN, userId)
        runMutation(key, ModerationActionType.BAN) {
            repository.ban(sessionId, creatorId, userId, reason?.takeIf { it.isNotBlank() })
        }
    }

    /** Unban [userId]. DELEGATE path (requires creatorId). On success refreshes the log/bans. */
    fun unban(userId: String) {
        val key = key(ModerationActionType.UNBAN, userId)
        runMutation(key, ModerationActionType.UNBAN, onSuccess = { refresh() }) {
            repository.unban(sessionId, creatorId, userId)
        }
    }

    /** Delete [messageId]. HOST path unless a delegate [creatorId] is present. */
    fun deleteMessage(messageId: String) {
        val key = key(ModerationActionType.DELETE, messageId)
        runMutation(key, ModerationActionType.DELETE) {
            repository.deleteMessage(sessionId, creatorId.ifBlank { null }, messageId)
        }
    }

    /** Pin [message]. DELEGATE path (requires creatorId). On success reconciles pinnedMessage. */
    fun pin(message: ChatMessage) {
        val key = key(ModerationActionType.PIN, message.id)
        if (!begin(key)) return
        viewModelScope.launch {
            when (val result = repository.pin(sessionId, creatorId, message.id)) {
                is ApiResult.Success -> {
                    _uiState.update {
                        it.copy(
                            inFlight = it.inFlight - key,
                            sheet = null,
                            pinnedMessage = if (result.data) message else null,
                            event = ModerationEvent.Success(ModerationActionType.PIN),
                        )
                    }
                }
                is ApiResult.Failure -> fail(key, result.error)
                is ApiResult.NetworkError -> fail(key, null)
            }
        }
    }

    /** Unpin [messageId]. DELEGATE path (requires creatorId). On success clears the banner. */
    fun unpin(messageId: String) {
        val key = key(ModerationActionType.UNPIN, messageId)
        runMutation(
            key,
            ModerationActionType.UNPIN,
            onSuccess = { _uiState.update { it.copy(pinnedMessage = null) } },
        ) {
            repository.unpin(sessionId, creatorId, messageId)
        }
    }

    // ---- moderation log (one-shot load + pull-to-refresh; NO paging, NO poll loop) ----

    /** Load the moderation log + current bans (cold). No-op gate when delegate routing is unavailable. */
    fun loadLog() {
        if (!delegateAvailable) {
            _logState.value = ModerationLogUiState.Error(MISSING_CREATOR_MESSAGE)
            return
        }
        _logState.value = ModerationLogUiState.Loading
        fetchLog(refreshing = false)
    }

    /** Pull-to-refresh the log. Keeps the current content visible while refreshing. */
    fun refresh() {
        if (!delegateAvailable) return
        val current = _logState.value
        if (current is ModerationLogUiState.Content) {
            _logState.value = current.copy(isRefreshing = true)
        }
        fetchLog(refreshing = true)
    }

    private fun fetchLog(refreshing: Boolean) {
        viewModelScope.launch {
            val logResult = repository.moderationLog(sessionId, creatorId)
            val bansResult = repository.listBans(sessionId, creatorId)
            when (logResult) {
                is ApiResult.Success -> {
                    val bans = (bansResult as? ApiResult.Success)?.data.orEmpty()
                    _logState.value = if (logResult.data.isEmpty() && bans.isEmpty()) {
                        ModerationLogUiState.Empty
                    } else {
                        ModerationLogUiState.Content(entries = logResult.data, bans = bans)
                    }
                }
                is ApiResult.Failure -> {
                    if (logResult.error.isAuth) _canModerate.value = false
                    _logState.value = ModerationLogUiState.Error(logResult.error.message)
                }
                is ApiResult.NetworkError ->
                    _logState.value = ModerationLogUiState.Error(OFFLINE_MESSAGE, offline = true)
            }
        }
    }

    // ---- shared optimistic runner ----

    private fun runMutation(
        key: String,
        action: ModerationActionType,
        onSuccess: () -> Unit = {},
        block: suspend () -> ApiResult<*>,
    ) {
        if (!begin(key)) return
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> {
                    _uiState.update {
                        it.copy(
                            inFlight = it.inFlight - key,
                            sheet = null,
                            event = ModerationEvent.Success(action),
                        )
                    }
                    onSuccess()
                }
                is ApiResult.Failure -> fail(key, result.error)
                is ApiResult.NetworkError -> fail(key, null)
            }
        }
    }

    /** Adds [key] to inFlight unless already running. Returns false if the action is a no-op (dup / blocked). */
    private fun begin(key: String): Boolean {
        if (sessionId.isBlank()) return false
        if (_uiState.value.inFlight.contains(key)) return false
        _uiState.update { it.copy(inFlight = it.inFlight + key) }
        return true
    }

    /** Rolls back [key] and emits a typed failure (or AuthDenied + hide on a 403/401). */
    private fun fail(key: String, error: ApiError?) {
        if (error != null && error.isAuth) {
            _canModerate.value = false
            _uiState.update {
                it.copy(inFlight = it.inFlight - key, sheet = null, event = ModerationEvent.AuthDenied)
            }
            return
        }
        _uiState.update {
            it.copy(
                inFlight = it.inFlight - key,
                event = ModerationEvent.Failure(error?.message ?: OFFLINE_MESSAGE),
            )
        }
    }

    /** Stable inFlight / testTag key for an action on a target, e.g. "mute:usr_9". */
    private fun key(action: ModerationActionType, target: String): String =
        "${action.name.lowercase()}:$target"

    companion object {
        /** Nav arg carrying the broadcast session id. */
        const val ARG_SESSION_ID = "sessionId"

        /** Nav arg carrying the broadcast's creator id (delegate routing); blank for host-only. */
        const val ARG_CREATOR_ID = "creatorId"

        // Non-resource fallbacks (the screen prefers stringResource where it has a Context).
        private const val OFFLINE_MESSAGE = "Couldn't reach the server. Try again."
        private const val MISSING_CREATOR_MESSAGE = "Moderation log is unavailable for this broadcast."
    }
}
