package com.testlogon.android.feature.messaging.helpdesk

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/** AND-162 — distinct claim-error outcomes (defensive: only 422 is documented; others are best-effort). */
enum class ClaimError { ALREADY_CLAIMED, CLOSED, FORBIDDEN, NOT_AVAILABLE, NOT_FOUND, NETWORK, UNKNOWN }

/** AND-162 — claim button state machine. */
sealed interface ClaimState {
    data object Idle : ClaimState
    data object Claiming : ClaimState
    data class Failed(val error: ClaimError, val retryable: Boolean) : ClaimState
}

/**
 * AND-162 — maps a transport [ApiError] to a [ClaimError]. VERIFIED codes come from the reply-side
 * mapAuthorizationError (client.ts): `helpdesk_claim_not_available`, `role_required*`. Conflict/closed/
 * not-found are UNVERIFIED for the claim endpoint (OQ-1) and handled defensively by HTTP status.
 */
object ClaimErrorMapper {
    fun map(error: ApiError): Pair<ClaimError, Boolean> = when {
        error.isNetwork -> ClaimError.NETWORK to true
        error.code == "helpdesk_claim_not_available" -> ClaimError.NOT_AVAILABLE to false
        error.code == "role_required" ||
            error.code == "role_required_scope" ||
            error.code == "role_required_admin_profile_type" -> ClaimError.FORBIDDEN to false
        error.status == 403 -> ClaimError.FORBIDDEN to false
        error.status == 409 -> ClaimError.ALREADY_CLAIMED to false
        error.status == 404 -> ClaimError.NOT_FOUND to false
        error.status in 500..599 -> ClaimError.NETWORK to true
        else -> ClaimError.UNKNOWN to false
    }
}

data class HelpdeskDetailUiState(
    val conversationId: String,
    val assignment: HelpdeskAssignment = HelpdeskAssignment.UNCLAIMED,
    val assignedAgentUserId: String? = null,
    val claim: ClaimState = ClaimState.Idle,
    val messages: List<Message> = emptyList(),
    val draft: String = "",
) {
    /** Derived; never stored independently so it cannot drift from [assignment]. */
    val replyEnabled: Boolean get() = assignment == HelpdeskAssignment.ASSIGNED_TO_ME
}

/** One-shot effects for the helpdesk detail screen. */
sealed interface HelpdeskDetailEvent {
    data object QueueChanged : HelpdeskDetailEvent
    data class ErrorSnack(val message: String) : HelpdeskDetailEvent
}

/**
 * AND-162 — helpdesk conversation detail (claim + reply).
 *
 * Reuses the EXISTING thread observe/send path ([MessagingRepository.observeThread] +
 * [MessagingRepository.sendOutbox]) — no composer/outbox logic is re-implemented. Adds the claim
 * action + assignment gate: reply is enabled only when ASSIGNED_TO_ME. Claim is a non-idempotent POST
 * that is never auto-retried; the concurrent-claim loser ends in ASSIGNED_TO_OTHER (not a generic error).
 */
@HiltViewModel
class HelpdeskDetailViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val repository: HelpdeskRepository,
    private val messagingRepository: MessagingRepository,
    private val authStateStore: AuthStateStore,
) : ViewModel() {

    private val conversationId: String =
        requireNotNull(savedState.get<String>(ARG_CONVERSATION_ID)) { "missing $ARG_CONVERSATION_ID" }

    /** Initial assignment passed from the queue row (so no extra fetch is needed to render). */
    private val initialClaimState: String? = savedState.get<String>(ARG_CLAIM_STATE)

    private val _uiState = MutableStateFlow(
        HelpdeskDetailUiState(
            conversationId = conversationId,
            assignment = decodeAssignment(initialClaimState),
        ),
    )
    val uiState: StateFlow<HelpdeskDetailUiState> = _uiState.asStateFlow()

    private val _events = Channel<HelpdeskDetailEvent>(Channel.BUFFERED)
    val events: Flow<HelpdeskDetailEvent> = _events.receiveAsFlow()

    init {
        observeThread()
        loadHistory()
        reconcileOnEntry()
    }

    private fun observeThread() {
        viewModelScope.launch {
            messagingRepository.observeThread(conversationId).collect { messages ->
                _uiState.update { it.copy(messages = messages) }
            }
        }
    }

    private fun loadHistory() {
        viewModelScope.launch {
            messagingRepository.loadHistory(conversationId, before = null, limit = HISTORY_LIMIT)
        }
    }

    /** Best-effort queue re-fetch on entry to correct a stale cached assignment (no single-conv GET). */
    private fun reconcileOnEntry() {
        viewModelScope.launch {
            val me = authStateStore.userSub.value
            when (val r = repository.refreshAssignment(conversationId)) {
                is ApiResult.Success -> {
                    val item = r.data ?: return@launch
                    val assignment = when {
                        item.activeAgentUserId.isNullOrBlank() -> HelpdeskAssignment.UNCLAIMED
                        item.activeAgentUserId == me -> HelpdeskAssignment.ASSIGNED_TO_ME
                        else -> HelpdeskAssignment.ASSIGNED_TO_OTHER
                    }
                    _uiState.update {
                        it.copy(assignment = assignment, assignedAgentUserId = item.activeAgentUserId)
                    }
                }
                else -> Unit // keep the row-provided initial state; never blank the screen on a refresh miss
            }
        }
    }

    fun onDraftChange(value: String) = _uiState.update { it.copy(draft = value) }

    fun onClaimClick() {
        val s = _uiState.value
        if (s.claim is ClaimState.Claiming || s.assignment == HelpdeskAssignment.ASSIGNED_TO_ME) return
        _uiState.update { it.copy(claim = ClaimState.Claiming) }
        viewModelScope.launch {
            when (val r = repository.claim(conversationId)) {
                is ApiResult.Success -> {
                    _uiState.update {
                        it.copy(
                            assignment = r.data.assignment,
                            assignedAgentUserId = r.data.assignedAgentUserId,
                            claim = ClaimState.Idle,
                        )
                    }
                    // Either we claimed it or learned someone else holds it; both invalidate the queue.
                    _events.send(HelpdeskDetailEvent.QueueChanged)
                }
                is ApiResult.Failure -> handleClaimError(r.error)
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(claim = ClaimState.Failed(ClaimError.NETWORK, retryable = true)) }
            }
        }
    }

    private suspend fun handleClaimError(error: ApiError) {
        val (mapped, retryable) = ClaimErrorMapper.map(error)
        if (mapped == ClaimError.ALREADY_CLAIMED) {
            // Loser path: learn the true assignee via the queue, render ASSIGNED_TO_OTHER (not generic error).
            when (val r = repository.refreshAssignment(conversationId)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        assignment = HelpdeskAssignment.ASSIGNED_TO_OTHER,
                        assignedAgentUserId = r.data?.activeAgentUserId,
                        claim = ClaimState.Failed(mapped, retryable),
                    )
                }
                else -> _uiState.update {
                    it.copy(
                        assignment = HelpdeskAssignment.ASSIGNED_TO_OTHER,
                        claim = ClaimState.Failed(mapped, retryable),
                    )
                }
            }
            _events.send(HelpdeskDetailEvent.QueueChanged)
        } else {
            val closed = mapped == ClaimError.CLOSED
            _uiState.update {
                it.copy(
                    assignment = if (closed) HelpdeskAssignment.CLOSED else it.assignment,
                    claim = ClaimState.Failed(mapped, retryable),
                )
            }
        }
    }

    fun onRetryClaim() {
        if ((_uiState.value.claim as? ClaimState.Failed)?.retryable == true) {
            _uiState.update { it.copy(claim = ClaimState.Idle) }
            onClaimClick()
        }
    }

    fun onDismissClaimError() {
        if (_uiState.value.claim is ClaimState.Failed) {
            _uiState.update { it.copy(claim = ClaimState.Idle) }
        }
    }

    fun onSendReply() {
        val s = _uiState.value
        val text = s.draft.trim()
        if (!s.replyEnabled || text.isEmpty()) return
        _uiState.update { it.copy(draft = "") }
        viewModelScope.launch {
            val clientId = UUID.randomUUID().toString()
            when (val r = messagingRepository.sendOutbox(conversationId, clientId, text)) {
                is ApiResult.Success -> Unit // outbox + observeThread reconcile the bubble
                is ApiResult.Failure -> _events.send(HelpdeskDetailEvent.ErrorSnack(r.error.message))
                is ApiResult.NetworkError ->
                    _events.send(HelpdeskDetailEvent.ErrorSnack(HelpdeskQueueViewModel.OFFLINE_MESSAGE))
            }
        }
    }

    companion object {
        const val ARG_CONVERSATION_ID = "conversationId"
        const val ARG_CLAIM_STATE = "claimState"
        private const val HISTORY_LIMIT = 30

        /** Encode the queue row's claim state into a nav arg so the detail renders without a fetch. */
        fun encodeAssignment(assignment: HelpdeskAssignment): String = assignment.name

        private fun decodeAssignment(raw: String?): HelpdeskAssignment =
            HelpdeskAssignment.entries.firstOrNull { it.name == raw } ?: HelpdeskAssignment.UNCLAIMED
    }
}
