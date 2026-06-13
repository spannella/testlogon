package com.testlogon.android.feature.tickets.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.tickets.Ticket
import com.testlogon.android.core.model.tickets.TicketMessage
import com.testlogon.android.core.model.tickets.TicketSendState
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.tickets.TicketConstants
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.tickets.data.TicketsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/**
 * AND-372 / AND-373 - drives the [TicketThreadUiState] for the ticket THREAD (screen 3) and, as of AND-373, the
 * REPLY composer.
 *
 * spaceId + ticketId arrive as nav args via [SavedStateHandle] (survive process death). [load] fetches the
 * ticket (named {ticket} envelope unwrap) whose embedded messages are the thread (oldest-first) AND resolves the
 * ADVISORY [TicketThreadUiState.Content.composer] canPost from GET ticket-spaces/{spaceId} membership.
 * [currentSub] is the viewer's own user_sub (from [AuthStateStore]) so the screen distinguishes the viewer's own
 * messages (sender_sub == currentSub) visually.
 *
 * STALE (in-memory only): [refresh] re-reads but, on a NON-401 failure, KEEPS the last-good Content and flips
 * isStale true (the snapshot lives only in this StateFlow - NOT persisted; Room persistence is DEFERRED). A
 * TERMINAL 401 -> one-shot [TicketsEffect.NavigateToLogin] (re-auth handoff).
 *
 * AND-373 RECONCILIATION NOTE: the AND-372 thread already renders the core-model [TicketMessage], so the
 * optimistic send REUSES that type (augmented with sendState / clientId) rather than rewriting the thread onto
 * the AND-126 messaging Message model. [onSend] optimistically inserts a SENDING [TicketMessage] (generated
 * clientId, senderSub = currentSub, createdAt = [clock]) at the bottom and clears the composer, POSTs the reply,
 * then REPLACES the optimistic message with the canonical server message (the whole-ticket envelope's
 * messages.last(), de-duplicated by message_id). On failure the optimistic message flips to FAILED with a
 * retryable error - there is NO auto-retry (the POST is non-idempotent); the user taps retry. A double-send of
 * the same in-flight draft is guarded by the per-clientId in-flight set.
 */
@HiltViewModel
class TicketThreadViewModel @Inject constructor(
    private val repository: TicketsRepository,
    savedState: SavedStateHandle,
    authStateStore: AuthStateStore,
    private val errorParser: ApiErrorParser,
) : ViewModel() {

    val spaceId: String =
        checkNotNull(savedState[ARG_SPACE_ID]) { "missing $ARG_SPACE_ID nav arg" }
    val ticketId: String =
        checkNotNull(savedState[ARG_TICKET_ID]) { "missing $ARG_TICKET_ID nav arg" }

    /** The viewer's own user_sub (may be null when unresolved); used to align the viewer's own bubbles. */
    val currentSub: String? = authStateStore.userSub.value?.takeIf { it.isNotBlank() }

    /**
     * AND-373 - epoch-seconds clock seam for deterministic optimistic timestamps. Hilt cannot inject a bare
     * Long / honor a ctor default, so this is a settable property read INSIDE the coroutine (NOT at construction).
     */
    var clock: () -> Long = { System.currentTimeMillis() / 1000 }

    /** AND-373 - per-clientId in-flight guard: a draft already being sent (or re-sent) is not re-fired. */
    private val inFlight = mutableSetOf<String>()

    /** AND-373 - the original draft text per optimistic clientId, so a retry can re-send the same body. */
    private val draftsByClientId = mutableMapOf<String, String>()

    /** AND-373 - the ADVISORY canPost resolved at [load] (editor / owner membership AND non-terminal status). */
    private var canPost: Boolean = false

    private val _uiState = MutableStateFlow<TicketThreadUiState>(TicketThreadUiState.Loading)
    val uiState: StateFlow<TicketThreadUiState> = _uiState.asStateFlow()

    private val _effects = Channel<TicketsEffect>(Channel.BUFFERED)
    val effects: Flow<TicketsEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    /** First load (no cached content): goes through Loading and may resolve to Empty / Error / NavigateToLogin. */
    fun load() {
        _uiState.value = TicketThreadUiState.Loading
        fetch(isRefresh = false)
    }

    fun onRetry() = load()

    /** Pull-to-refresh. On a non-401 failure the last-good Content is kept with isStale=true. */
    fun refresh() = fetch(isRefresh = true)

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            // Resolve the ADVISORY canPost from space membership (best-effort; a failure leaves canPost=false).
            canPost = resolveCanPost()
            when (val result = repository.getTicket(spaceId, ticketId)) {
                is ApiResult.Success -> emitLoaded(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _effects.send(TicketsEffect.NavigateToLogin)
                    } else {
                        emitFailure(isRefresh, result.error)
                    }
                }
                is ApiResult.NetworkError ->
                    emitFailure(
                        isRefresh,
                        ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK),
                    )
            }
        }
    }

    /**
     * AND-373 - the ADVISORY canPost: editor / owner membership in the space AND a non-terminal ticket status.
     * The ticket status is checked in [emitLoaded]; here we resolve only the membership half (a non-member or a
     * getSpace failure -> false). The server 403 remains authoritative.
     */
    private suspend fun resolveCanPost(): Boolean =
        when (val spaceResult = repository.getSpace(spaceId)) {
            is ApiResult.Success ->
                TicketsRepository.canPostInSpace(spaceResult.data, currentSub)
            else -> false
        }

    /**
     * Emits the loaded ticket. A ticket with NO messages renders [TicketThreadUiState.Empty] ONLY when the
     * viewer cannot post; when the viewer can post we render [TicketThreadUiState.Content] (empty list) so the
     * composer shows. Terminal status (done) disables the composer regardless of membership.
     */
    private fun emitLoaded(ticket: Ticket) {
        val composerEnabled = canPost && !isTerminal(ticket.status)
        _uiState.value = if (ticket.messages.isEmpty() && !composerEnabled) {
            TicketThreadUiState.Empty
        } else {
            val prior = _uiState.value as? TicketThreadUiState.Content
            TicketThreadUiState.Content(
                ticket = ticket,
                currentSub = currentSub,
                isStale = false,
                composer = (prior?.composer ?: ComposerState()).copy(
                    canPost = composerEnabled,
                    maxLength = TicketsRepository.REPLY_MAX_LENGTH,
                ),
            )
        }
    }

    /** A non-401 failure: keep stale content on a refresh that has prior content, else surface Error. */
    private fun emitFailure(isRefresh: Boolean, error: ApiError) {
        val prior = _uiState.value as? TicketThreadUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isStale = true)
        } else {
            TicketThreadUiState.Error(error)
        }
    }

    // ---- AND-373: reply composer ----

    /** Composer text change. Clears a prior error; over-limit is reflected via [ComposerState.sendEnabled]. */
    fun onDraftChanged(text: String) {
        updateComposer { it.copy(draft = text, sendError = null, fieldError = null) }
    }

    /**
     * AND-373 - send the current draft as an OPTIMISTIC reply. Validates 1..maxLength + canPost + idle, inserts a
     * SENDING [TicketMessage] at the bottom (generated clientId), clears the composer, then POSTs and reconciles
     * to the canonical server message. NON-idempotent -> the per-clientId [inFlight] set guards a double-send.
     */
    fun onSend() {
        val content = _uiState.value as? TicketThreadUiState.Content ?: return
        val composer = content.composer
        val body = composer.draft.trim()
        if (!composer.canPost || composer.sending) return
        if (body.length !in TicketsRepository.REPLY_MIN_LENGTH..composer.maxLength) return

        val clientId = UUID.randomUUID().toString()
        draftsByClientId[clientId] = body

        val optimistic = TicketMessage(
            messageId = null,
            senderSub = currentSub,
            senderRole = null,
            body = body,
            createdAt = clock(),
            sendState = TicketSendState.SENDING,
            clientId = clientId,
        )
        // Insert at the bottom + clear the composer immediately.
        _uiState.value = content.copy(
            ticket = content.ticket.copy(messages = content.ticket.messages + optimistic),
            composer = composer.copy(draft = "", sending = true, sendError = null, fieldError = null),
        )
        fire(clientId, body)
    }

    /** AND-373 - user-driven retry of a FAILED optimistic message (re-send the SAME body; NO auto-retry). */
    fun onRetry(clientId: String) {
        val body = draftsByClientId[clientId] ?: return
        // Flip the failed bubble back to SENDING.
        updateContent { content ->
            content.copy(
                ticket = content.ticket.copy(
                    messages = content.ticket.messages.map {
                        if (it.clientId == clientId) {
                            it.copy(sendState = TicketSendState.SENDING)
                        } else {
                            it
                        }
                    },
                ),
            )
        }
        fire(clientId, body)
    }

    /** Fires the POST for [clientId] once (double-send guard) and reconciles or marks FAILED. */
    private fun fire(clientId: String, body: String) {
        if (!inFlight.add(clientId)) return
        viewModelScope.launch {
            try {
                when (val result = repository.reply(spaceId, ticketId, body)) {
                    is ApiResult.Success -> reconcile(clientId, result.data)
                    is ApiResult.Failure -> {
                        if (result.error.status == HTTP_UNAUTHORIZED) {
                            markFailed(clientId, null)
                            _effects.send(TicketsEffect.NavigateToLogin)
                        } else {
                            val field = errorParser.fieldErrorForLocTail(result.error, FIELD_BODY)
                            markFailed(clientId, field ?: result.error.message, field != null)
                        }
                    }
                    is ApiResult.NetworkError -> markFailed(clientId, OFFLINE_FALLBACK)
                }
            } finally {
                inFlight.remove(clientId)
            }
        }
    }

    /**
     * Replaces the optimistic message (matched by [clientId]) with the canonical server message - the
     * whole-ticket envelope's messages.last() - de-duplicated by message_id so a refresh that already merged the
     * server message does not double it. The composer's sending flag is cleared.
     */
    private fun reconcile(clientId: String, serverTicket: Ticket) {
        draftsByClientId.remove(clientId)
        updateContent { content ->
            val canonical = serverTicket.messages.lastOrNull()
            val canonicalId = canonical?.messageId
            // Drop our optimistic placeholder AND any pre-existing copy of the canonical message (by id).
            val pruned = content.ticket.messages.filterNot { msg ->
                msg.clientId == clientId ||
                    (canonicalId != null && msg.messageId == canonicalId && msg.clientId == null)
            }
            val appended = if (canonical != null) {
                pruned + canonical.copy(sendState = TicketSendState.SENT)
            } else {
                pruned
            }
            content.copy(
                ticket = content.ticket.copy(messages = appended),
                composer = content.composer.copy(sending = false, sendError = null, fieldError = null),
            )
        }
    }

    /** Marks the optimistic message FAILED and surfaces a retryable error (field error pins to the composer). */
    private fun markFailed(clientId: String, message: String?, isFieldError: Boolean = false) {
        updateContent { content ->
            content.copy(
                ticket = content.ticket.copy(
                    messages = content.ticket.messages.map {
                        if (it.clientId == clientId) {
                            it.copy(sendState = TicketSendState.FAILED)
                        } else {
                            it
                        }
                    },
                ),
                composer = content.composer.copy(
                    sending = false,
                    sendError = if (isFieldError) null else message,
                    fieldError = if (isFieldError) message else null,
                ),
            )
        }
    }

    private fun isTerminal(status: String?): Boolean = status == TicketConstants.TicketStatus.DONE

    private inline fun updateContent(transform: (TicketThreadUiState.Content) -> TicketThreadUiState.Content) {
        val content = _uiState.value as? TicketThreadUiState.Content ?: return
        _uiState.value = transform(content)
    }

    private inline fun updateComposer(transform: (ComposerState) -> ComposerState) {
        updateContent { it.copy(composer = transform(it.composer)) }
    }

    companion object {
        const val ARG_SPACE_ID = "spaceId"
        const val ARG_TICKET_ID = "ticketId"

        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."

        /** AND-373 - the 422 validation loc tail that targets the reply body field. */
        private const val FIELD_BODY = "body"
    }
}
