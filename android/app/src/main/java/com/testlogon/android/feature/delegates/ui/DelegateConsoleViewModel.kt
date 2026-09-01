package com.testlogon.android.feature.delegates.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.delegates.data.DelegateBroadcastRepository
import com.testlogon.android.feature.delegates.data.DelegateFeedRepository
import com.testlogon.android.feature.delegates.data.DelegateMessagingRepository
import com.testlogon.android.feature.delegates.data.DelegationContextProvider
import com.testlogon.android.feature.delegates.data.DelegationRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-360 - the focused demonstration ViewModel: in delegate mode it loads the managed creator's delegate
 * feed posts (feed_read) + conversations (chat_read) and offers create-post (feed_post) / send-message
 * (chat_respond), each gated by the delegate repositories. It ALSO hosts the broadcast MODERATION console
 * (broadcast_moderate / broadcast_control): register-as-moderator, moderators / bans / moderation-log
 * reads (degrade-on-404 to empty), and the mutations (ban / unban / mute / pin / delete / announce / start
 * / stop). This proves "a delegate can act in delegated surfaces" without retrofitting the mature screens.
 *
 * It observes the typed delegation context; when there is no active context the UI shows the enter prompt.
 * The repositories already block a permission-less action WITHOUT calling the API and AUTO-EXIT on a 403,
 * so a blocked / revoked action surfaces a notice and the banner disappears once the context clears.
 */
@HiltViewModel
class DelegateConsoleViewModel @Inject constructor(
    private val contextProvider: DelegationContextProvider,
    private val delegationRepository: DelegationRepository,
    private val feedRepository: DelegateFeedRepository,
    private val messagingRepository: DelegateMessagingRepository,
    private val broadcastRepository: DelegateBroadcastRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DelegateConsoleUiState())
    val uiState: StateFlow<DelegateConsoleUiState> = _uiState.asStateFlow()

    init {
        observeContext()
    }

    /** Re-projects the typed context into the base UI state and (re)loads when a context becomes active. */
    private fun observeContext() {
        viewModelScope.launch {
            contextProvider.delegationContext.collect { ctx ->
                if (ctx == null) {
                    _uiState.value = DelegateConsoleUiState(active = false)
                    // T4 — NOT a dead-end: load the managed creators so the user can pick one to act for.
                    loadManagedCreators()
                } else {
                    _uiState.value = _uiState.value.copy(
                        active = true,
                        creatorName = ctx.creatorName,
                        canReadFeed = feedRepository.canRead(),
                        canPostFeed = feedRepository.canPost(),
                        canReadChat = messagingRepository.canRead(),
                        canRespond = messagingRepository.canRespond(),
                        entering = null,
                        moderation = _uiState.value.moderation.copy(
                            canModerate = broadcastRepository.canModerate(),
                            canControl = broadcastRepository.canControl(),
                        ),
                    )
                    load()
                }
            }
        }
    }

    /**
     * T4 — GET the creators the current user may act for (ui/delegates/managed) and surface them as the
     * Enter picker. Only meaningful while NOT in delegate mode; a failure sets [managedError] so the screen
     * shows a retry rather than a dead "you are not a delegate" wall.
     */
    fun loadManagedCreators() {
        _uiState.value = _uiState.value.copy(managedLoading = true, managedError = false)
        viewModelScope.launch {
            when (val result = delegationRepository.managedCreators()) {
                is ApiResult.Success -> _uiState.value = _uiState.value.copy(
                    managedLoading = false,
                    managedError = false,
                    managedCreators = result.data,
                )
                else -> _uiState.value = _uiState.value.copy(
                    managedLoading = false,
                    managedError = true,
                )
            }
        }
    }

    /**
     * T4 — ENTER delegate context for [creatorId] via [DelegationContextProvider.enterAsCreator], which
     * resolves the creator's granted permissions and writes the process-global managing-creator flag. The
     * observed context flow then flips [active] to true and loads the delegate feed / conversations, so the
     * console stops being a dead-end. A failure surfaces a notice and leaves the picker in place.
     */
    fun enter(creatorId: String) {
        if (_uiState.value.entering != null) return
        _uiState.value = _uiState.value.copy(entering = creatorId, notice = null)
        viewModelScope.launch {
            when (contextProvider.enterAsCreator(creatorId)) {
                // On success the delegationContext flow emits -> observeContext() flips active + clears entering.
                is ApiResult.Success -> Unit
                else -> _uiState.value = _uiState.value.copy(entering = null, notice = NOTICE_ACTION_FAILED)
            }
        }
    }

    /** Loads the delegate feed posts + conversations the context is permitted to read. */
    fun load() {
        if (!_uiState.value.active) return
        _uiState.value = _uiState.value.copy(loading = true, loadFailed = false)
        viewModelScope.launch {
            val posts = if (feedRepository.canRead()) {
                (feedRepository.listPosts() as? ApiResult.Success)?.data
            } else {
                emptyList()
            }
            val conversations = if (messagingRepository.canRead()) {
                (messagingRepository.conversations() as? ApiResult.Success)?.data
            } else {
                emptyList()
            }
            _uiState.value = _uiState.value.copy(
                loading = false,
                posts = posts.orEmpty(),
                conversations = conversations.orEmpty(),
                loadFailed = (feedRepository.canRead() && posts == null) ||
                    (messagingRepository.canRead() && conversations == null),
            )
        }
    }

    /** Creates a delegate post (gated by feed_post in the repository); refreshes the feed on success. */
    fun createPost(text: String) {
        if (text.isBlank()) return
        viewModelScope.launch {
            when (feedRepository.createPost(text.trim())) {
                is ApiResult.Success -> load()
                else -> _uiState.value = _uiState.value.copy(notice = NOTICE_ACTION_FAILED)
            }
        }
    }

    /** Sends a delegate message into [conversationId] (gated by chat_respond in the repository). */
    fun sendMessage(conversationId: String, text: String) {
        if (text.isBlank()) return
        viewModelScope.launch {
            when (messagingRepository.send(conversationId, text.trim())) {
                is ApiResult.Success -> _uiState.value = _uiState.value.copy(notice = null)
                else -> _uiState.value = _uiState.value.copy(notice = NOTICE_ACTION_FAILED)
            }
        }
    }

    // ---- AND-360 broadcast moderation console ----

    /** Updates the session id the moderation console acts on. Does not fetch (the user taps Load). */
    fun setModerationSession(sessionId: String) {
        _uiState.value = _uiState.value.copy(
            moderation = _uiState.value.moderation.copy(sessionId = sessionId),
        )
    }

    /** Loads the moderators / bans / moderation-log for the entered session (reads degrade-on-404 to empty). */
    fun loadModeration() {
        val session = _uiState.value.moderation.sessionId.trim()
        if (session.isBlank() || !broadcastRepository.canModerate()) return
        _uiState.value = _uiState.value.copy(
            moderation = _uiState.value.moderation.copy(loading = true, readFailed = false),
        )
        viewModelScope.launch {
            val mods = broadcastRepository.moderators(session)
            val bans = broadcastRepository.bans(session)
            val log = broadcastRepository.moderationLog(session)
            _uiState.value = _uiState.value.copy(
                moderation = _uiState.value.moderation.copy(
                    loading = false,
                    moderators = (mods as? ApiResult.Success)?.data.orEmpty(),
                    bans = (bans as? ApiResult.Success)?.data.orEmpty(),
                    log = (log as? ApiResult.Success)?.data.orEmpty(),
                    readFailed = mods !is ApiResult.Success ||
                        bans !is ApiResult.Success ||
                        log !is ApiResult.Success,
                ),
            )
        }
    }

    /** REGISTER the caller as an active moderator for the entered session; reloads on success. */
    fun registerAsModerator() {
        runModeration { session ->
            broadcastRepository.registerModerator(session).also {
                if (it is ApiResult.Success) {
                    _uiState.value = _uiState.value.copy(
                        moderation = _uiState.value.moderation.copy(registered = true),
                    )
                }
            }
        }
    }

    /** BAN a viewer, then reload the console lists. */
    fun banViewer(userId: String, reason: String?) =
        runModeration { session -> broadcastRepository.banViewer(session, userId.trim(), reason?.trim()) }

    /** UNBAN a viewer, then reload the console lists. */
    fun unbanViewer(userId: String) =
        runModeration { session -> broadcastRepository.unbanViewer(session, userId) }

    /** MUTE a viewer, then reload the console lists. */
    fun muteViewer(userId: String, reason: String?) =
        runModeration { session -> broadcastRepository.muteViewer(session, userId.trim(), reason?.trim()) }

    /** PIN a chat message, then reload the console lists. */
    fun pinMessage(messageId: String) =
        runModeration { session -> broadcastRepository.pinMessage(session, messageId.trim()) }

    /** DELETE a chat message, then reload the console lists. */
    fun deleteChatMessage(messageId: String) =
        runModeration { session -> broadcastRepository.deleteChatMessage(session, messageId.trim()) }

    /** POST an announcement, then reload the console lists. */
    fun postAnnouncement(text: String) {
        if (text.isBlank()) return
        runModeration { session -> broadcastRepository.postAnnouncement(session, text.trim()) }
    }

    /** START the broadcast (gated by broadcast_control). */
    fun startBroadcast() =
        runModeration(reload = false) { session -> broadcastRepository.startSession(session) }

    /** STOP the broadcast (gated by broadcast_control). */
    fun stopBroadcast() =
        runModeration(reload = false) { session -> broadcastRepository.stopSession(session) }

    /**
     * Shared runner for a moderation mutation: guards against a blank session / busy state, runs [action]
     * with the trimmed session id, surfaces a notice on failure, and (when [reload]) refreshes the lists on
     * success. A permission-less / revoked action is already blocked (or auto-exits) inside the repository.
     */
    private fun runModeration(
        reload: Boolean = true,
        action: suspend (session: String) -> ApiResult<Unit>,
    ) {
        val session = _uiState.value.moderation.sessionId.trim()
        if (session.isBlank() || _uiState.value.moderation.busy) return
        _uiState.value = _uiState.value.copy(moderation = _uiState.value.moderation.copy(busy = true))
        viewModelScope.launch {
            val result = action(session)
            _uiState.value = _uiState.value.copy(moderation = _uiState.value.moderation.copy(busy = false))
            if (result is ApiResult.Success) {
                if (reload) loadModeration()
            } else {
                _uiState.value = _uiState.value.copy(notice = NOTICE_ACTION_FAILED)
            }
        }
    }

    /** EXIT delegate mode (AND-359 pure-local exit). */
    fun exit() {
        viewModelScope.launch { contextProvider.exit() }
    }

    /** Clears a transient notice after it has been surfaced. */
    fun consumeNotice() {
        if (_uiState.value.notice != null) _uiState.value = _uiState.value.copy(notice = null)
    }

    private companion object {
        const val NOTICE_ACTION_FAILED = "action_failed"
    }
}
