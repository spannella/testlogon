package com.testlogon.android.feature.messaging.helpdesk

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.helpdesk.ClaimState
import com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment
import com.testlogon.android.data.messaging.helpdesk.HelpdeskClaimResult
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepository
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepositoryImpl
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRoutingState
import com.testlogon.android.data.messaging.helpdesk.isClaimable
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
 * AND-161 — helpdesk queue UI state. The agent-role check IS the queue call (200 ⇒ agent, 403 ⇒ not):
 * there is no readable role field, so [NotAuthorized] is the 403 outcome.
 *
 * AND-378 — adds inline CLAIM from the queue row (FR-1 / AC-1: claim from both the queue list and the
 * detail screen). [Ready.inFlight] holds the conversation ids whose claim is mutating; rows in that set
 * disable their Claim button (double-submit guard, AC-6). Optimistic update marks the row claimed-by-me
 * immediately and reconciles from the server `HelpdeskClaimOut`, rolling back on error/timeout (AC-4/AC-5).
 */
sealed interface HelpdeskQueueUiState {
    data object Loading : HelpdeskQueueUiState
    data object NotAuthorized : HelpdeskQueueUiState
    data class Ready(
        val items: List<HelpdeskQueueItem>,
        val isRefreshing: Boolean = false,
        /** Conversation ids with a claim mutation in flight (drives per-row spinner + disabled button). */
        val inFlight: Set<String> = emptySet(),
    ) : HelpdeskQueueUiState
    data class Error(val message: String, val retryable: Boolean) : HelpdeskQueueUiState
}

/** AND-378 — one-shot snackbar feedback for queue-row claim attempts (FR-8). */
sealed interface HelpdeskQueueEvent {
    /** Claim succeeded for the current agent. */
    data object Claimed : HelpdeskQueueEvent

    /** Claim resolved to a different agent (contention reconcile, not a hard error). */
    data object AlreadyClaimed : HelpdeskQueueEvent

    /** Claim failed (network/offline/unknown); the optimistic change was rolled back. */
    data class ClaimFailed(val message: String) : HelpdeskQueueEvent
}

/**
 * AND-161 / AND-378 — helpdesk queue presentation logic. Single bounded fetch (no Paging). On init /
 * refresh / retry it calls [HelpdeskRepository.loadQueue], mapping: Success([]) -> Ready([]) (empty),
 * Success(list) -> Ready(list), 403 Failure -> NotAuthorized, other errors -> Error. Inline claim is a
 * non-idempotent POST (never auto-retried); contention is detected by comparing the returned assignee to
 * the current agent (no reliance on a 409 body — see spec section 16).
 */
@HiltViewModel
class HelpdeskQueueViewModel @Inject constructor(
    private val repository: HelpdeskRepository,
    private val authStateStore: AuthStateStore,
) : ViewModel() {

    private val _uiState = MutableStateFlow<HelpdeskQueueUiState>(HelpdeskQueueUiState.Loading)
    val uiState: StateFlow<HelpdeskQueueUiState> = _uiState.asStateFlow()

    private val _events = Channel<HelpdeskQueueEvent>(Channel.BUFFERED)
    val events: Flow<HelpdeskQueueEvent> = _events.receiveAsFlow()

    init {
        load(isRefresh = false)
    }

    fun refresh() {
        // Keep showing existing rows under a refreshing flag where possible.
        val current = _uiState.value
        if (current is HelpdeskQueueUiState.Ready) {
            _uiState.update { current.copy(isRefreshing = true) }
        }
        load(isRefresh = true)
    }

    fun retry() = load(isRefresh = false)

    /**
     * AND-378 — claim a queued conversation inline. Guards against double-submit (id already in flight),
     * applies an optimistic claimed-by-me update, then reconciles from the server payload. On error the
     * snapshot row is restored. Claim is server-idempotent, so re-claiming one's own row is a no-op.
     */
    fun onClaim(conversationId: String) {
        val ready = _uiState.value as? HelpdeskQueueUiState.Ready ?: return
        if (conversationId in ready.inFlight) return
        val snapshot = ready.items.firstOrNull { it.conversationId == conversationId } ?: return
        // UX guard: only act on rows the matrix considers claimable.
        if (!snapshot.isClaimable()) return

        val me = authStateStore.userSub.value
        val optimistic = snapshot.copy(
            routingState = HelpdeskRoutingState.ASSIGNED,
            claimState = ClaimState.CLAIMED_BY_ME,
            activeAgentUserId = me ?: snapshot.activeAgentUserId,
        )
        _uiState.update {
            (it as? HelpdeskQueueUiState.Ready)?.copy(
                items = it.items.replaceRow(optimistic),
                inFlight = it.inFlight + conversationId,
            ) ?: it
        }

        viewModelScope.launch {
            when (val r = repository.claim(conversationId)) {
                is ApiResult.Success -> reconcileClaim(conversationId, snapshot, r.data, me)
                is ApiResult.Failure -> failClaim(conversationId, snapshot, r.error.message)
                is ApiResult.NetworkError -> failClaim(conversationId, snapshot, OFFLINE_MESSAGE)
            }
        }
    }

    private suspend fun reconcileClaim(
        conversationId: String,
        snapshot: HelpdeskQueueItem,
        result: HelpdeskClaimResult,
        me: String?,
    ) {
        val mine = result.assignment == HelpdeskAssignment.ASSIGNED_TO_ME ||
            (result.assignedAgentUserId.isNotBlank() && result.assignedAgentUserId == me)
        val reconciled = snapshot.copy(
            routingState = if (result.assignment == HelpdeskAssignment.CLOSED) {
                HelpdeskRoutingState.CLOSED
            } else {
                HelpdeskRoutingState.ASSIGNED
            },
            claimState = if (mine) ClaimState.CLAIMED_BY_ME else ClaimState.CLAIMED_BY_OTHER,
            activeAgentUserId = result.assignedAgentUserId,
        )
        _uiState.update {
            (it as? HelpdeskQueueUiState.Ready)?.copy(
                items = it.items.replaceRow(reconciled),
                inFlight = it.inFlight - conversationId,
            ) ?: it
        }
        _events.send(if (mine) HelpdeskQueueEvent.Claimed else HelpdeskQueueEvent.AlreadyClaimed)
    }

    private suspend fun failClaim(conversationId: String, snapshot: HelpdeskQueueItem, message: String) {
        // Roll back to the pre-claim snapshot and drop the in-flight marker.
        _uiState.update {
            (it as? HelpdeskQueueUiState.Ready)?.copy(
                items = it.items.replaceRow(snapshot),
                inFlight = it.inFlight - conversationId,
            ) ?: it
        }
        _events.send(HelpdeskQueueEvent.ClaimFailed(message))
    }

    private fun List<HelpdeskQueueItem>.replaceRow(row: HelpdeskQueueItem): List<HelpdeskQueueItem> =
        map { if (it.conversationId == row.conversationId) row else it }

    private fun load(isRefresh: Boolean) {
        if (!isRefresh) _uiState.value = HelpdeskQueueUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val r = repository.loadQueue()) {
                is ApiResult.Success -> HelpdeskQueueUiState.Ready(items = r.data, isRefreshing = false)
                is ApiResult.Failure ->
                    if (r.error.status == HelpdeskRepositoryImpl.HTTP_FORBIDDEN) {
                        HelpdeskQueueUiState.NotAuthorized
                    } else {
                        HelpdeskQueueUiState.Error(message = r.error.message, retryable = true)
                    }
                is ApiResult.NetworkError ->
                    HelpdeskQueueUiState.Error(message = OFFLINE_MESSAGE, retryable = true)
            }
        }
    }

    companion object {
        const val OFFLINE_MESSAGE = "You're offline. Try again when you're back online."
    }
}
