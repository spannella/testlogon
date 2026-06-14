package com.testlogon.android.feature.messaging.helpdesk

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.helpdesk.HelpdeskMetrics
import com.testlogon.android.core.ui.i18n.UiText
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.messaging.Message
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.helpdesk.ClaimState
import com.testlogon.android.data.messaging.helpdesk.HelpdeskAssignment
import com.testlogon.android.data.messaging.helpdesk.HelpdeskClaimResult
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepository
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepositoryImpl
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRoutingState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/**
 * AND-380 — client-side filter over the helpdesk queue (an Android-app UX construct; not a backend
 * filter — see spec §16 open assumptions). The filter is derived state and never triggers a network
 * call (FR-3).
 */
enum class QueueFilter { ALL, UNCLAIMED, MINE }

/**
 * AND-380 — the single typed entry point for the helpdesk agent surface so the UI cannot mutate state
 * directly (AC-2) and tests enumerate the surface exhaustively.
 */
sealed interface HelpdeskIntent {
    data object Refresh : HelpdeskIntent
    data class SetFilter(val filter: QueueFilter) : HelpdeskIntent
    data class Claim(val conversationId: String) : HelpdeskIntent
    data class Select(val conversationId: String?) : HelpdeskIntent
    data class SendReply(val conversationId: String, val body: String) : HelpdeskIntent
    data object DismissError : HelpdeskIntent
}

/**
 * AND-380 — single immutable UI state for the unified helpdesk agent surface (queue + derived metrics
 * + the selected conversation's reply composer).
 *
 * Metrics are DERIVED from [queue] (there is NO `/messaging/helpdesk/metrics` endpoint — spec §5/§16),
 * so [metrics] and [filteredQueue] are computed getters, never stored, so they cannot drift (FR-9).
 * [currentAgentId] is the injected session user id used by the MINE filter / metrics (spec §6/§13-R2);
 * when null, MINE falls back to "assigned to anyone" so the surface never throws.
 *
 * No message bodies or requester PII are persisted by this layer (spec §8). State is in-memory and
 * re-fetched on process death.
 */
data class HelpdeskUiState(
    val isLoading: Boolean = true,
    val isRefreshing: Boolean = false,
    val queue: List<HelpdeskQueueItem> = emptyList(),
    val filter: QueueFilter = QueueFilter.ALL,
    val claimingIds: Set<String> = emptySet(),
    val selectedConversation: HelpdeskQueueItem? = null,
    val thread: List<Message> = emptyList(),
    val isSending: Boolean = false,
    val replyDraft: String = "",
    val isStale: Boolean = false,
    val banner: UiText? = null,
    /** Injected current-agent id used by the MINE filter / derived metrics (spec §6); not PII-logged. */
    val currentAgentId: String? = null,
) {
    /** Derived: filtered view over [queue] + [filter]; never stored so it cannot drift (FR-3/FR-9). */
    val filteredQueue: List<HelpdeskQueueItem>
        get() = when (filter) {
            QueueFilter.ALL -> queue
            QueueFilter.UNCLAIMED -> queue.filter { it.activeAgentUserId.isNullOrBlank() }
            QueueFilter.MINE -> queue.filter {
                if (currentAgentId == null) {
                    !it.activeAgentUserId.isNullOrBlank()
                } else {
                    it.activeAgentUserId == currentAgentId
                }
            }
        }

    /**
     * Derived client-side projection of [queue] (no metrics endpoint — spec §5/§16). The fixed
     * [HelpdeskMetrics] shape is reused (AND-377): unclaimed -> [HelpdeskMetrics.unassignedCount],
     * mine -> [HelpdeskMetrics.assignedToMeCount], total -> [HelpdeskMetrics.openCount].
     */
    val metrics: HelpdeskMetrics
        get() {
            val unclaimed = queue.count { it.activeAgentUserId.isNullOrBlank() }
            val mine = if (currentAgentId == null) {
                0
            } else {
                queue.count { it.activeAgentUserId == currentAgentId }
            }
            return HelpdeskMetrics(
                openCount = queue.size,
                unassignedCount = unclaimed,
                assignedToMeCount = mine,
                slaAtRiskCount = queue.count { it.routingState == HelpdeskRoutingState.AWAITING_AGENT },
                generatedAtEpochSeconds = 0L,
            )
        }
}

/**
 * AND-380 — state-holding layer for the helpdesk agent experience: a single
 * [StateFlow]<[HelpdeskUiState]> driven by a single [onIntent] entry point.
 *
 * REUSES the AND-161/162 [HelpdeskRepository] (queue + claim) and the AND-120 [MessagingRepository]
 * (thread observe/history/send) rather than re-implementing transport. Metrics are derived from the
 * loaded queue (there is no metrics endpoint — spec §5/§16). Coroutines launch on [viewModelScope]
 * (whose Main dispatcher unit tests swap for a TestDispatcher via MainDispatcherRule); the IO hop
 * itself lives in the repositories (this project has NO `@IoDispatcher` qualifier and Hilt cannot
 * inject a bare CoroutineDispatcher).
 *
 * Long-running intents are cancellation- and re-entrancy-safe: [refresh] cancels the prior load job
 * and per-id [HelpdeskUiState.claimingIds] guard double claims (FR-8). Emissions are distinct because
 * [StateFlow] conflates equal consecutive values (FR-9). No PII is logged.
 */
@HiltViewModel
class HelpdeskViewModel @Inject constructor(
    private val repository: HelpdeskRepository,
    private val messagingRepository: MessagingRepository,
    private val authStateStore: AuthStateStore,
) : ViewModel() {

    // StateFlow already conflates equal consecutive values (FR-9: distinct emissions, AC-2: read-only).
    private val _state = MutableStateFlow(HelpdeskUiState())
    val state: StateFlow<HelpdeskUiState> = _state.asStateFlow()

    private var loadJob: Job? = null

    init {
        // Seed the current agent id (read inside no coroutine: it is a synchronous StateFlow value).
        _state.update { it.copy(currentAgentId = authStateStore.userSub.value) }
        refresh()
    }

    /** Single typed entry point (AC-2). */
    fun onIntent(intent: HelpdeskIntent) {
        when (intent) {
            HelpdeskIntent.Refresh -> refresh()
            is HelpdeskIntent.SetFilter -> setFilter(intent.filter)
            is HelpdeskIntent.Claim -> claim(intent.conversationId)
            is HelpdeskIntent.Select -> selectConversation(intent.conversationId)
            is HelpdeskIntent.SendReply -> sendReply(intent.conversationId, intent.body)
            HelpdeskIntent.DismissError -> dismissError()
        }
    }

    /**
     * FR-1/FR-2 — (re)fetch the queue and recompute derived metrics. Stale-while-revalidate: the prior
     * queue is retained on a transport failure. Re-entrancy-safe: cancels the prior load job (FR-8).
     */
    fun refresh() {
        loadJob?.cancel()
        loadJob = viewModelScope.launch { reloadQueue() }
    }

    /** The actual queue fetch + reduce; shared by [refresh] and the claim-conflict path. */
    private suspend fun reloadQueue() {
        _state.update { it.copy(isRefreshing = true) }
        // The repository performs its own withContext(Dispatchers.IO) hop.
        reduceQueue(repository.loadQueue())
        _state.update { it.copy(isRefreshing = false, isLoading = false) }
    }

    private fun reduceQueue(result: ApiResult<List<HelpdeskQueueItem>>) = when (result) {
        is ApiResult.Success -> _state.update {
            it.copy(queue = result.data, isStale = false, banner = null)
        }
        is ApiResult.Failure ->
            if (result.error.status == HelpdeskRepositoryImpl.HTTP_FORBIDDEN) {
                // Non-agent: surface a permission banner, never a crash (spec §8, AC-5).
                _state.update { it.copy(banner = UiText.Res(R.string.helpdesk_permission_denied)) }
            } else if (_state.value.queue.isNotEmpty()) {
                // Keep prior data, flag stale, show a dismissible banner (FR-2/§7).
                _state.update { it.copy(isStale = true, banner = result.error.toBanner()) }
            } else {
                _state.update { it.copy(banner = result.error.toBanner()) }
            }
        is ApiResult.NetworkError ->
            if (_state.value.queue.isNotEmpty()) {
                _state.update { it.copy(isStale = true, banner = UiText.Res(R.string.helpdesk_offline)) }
            } else {
                _state.update { it.copy(banner = UiText.Res(R.string.helpdesk_offline)) }
            }
    }

    /** FR-3 — client-side filter; derived state, no network call. */
    fun setFilter(filter: QueueFilter) = _state.update { it.copy(filter = filter) }

    /**
     * FR-4 — claim an unclaimed conversation. The row is marked `claiming` in flight (double-submit
     * guarded). On success the row is patched from [HelpdeskClaimResult] and becomes the selection. A
     * lost race (assigned to another agent) or a 422 triggers a refresh + a non-fatal banner; there is
     * NO 409 (spec §5/§16). Claiming a conversation you already own is idempotent and treated as success.
     */
    fun claim(conversationId: String) {
        if (conversationId in _state.value.claimingIds) return
        _state.update { it.copy(claimingIds = it.claimingIds + conversationId) }
        viewModelScope.launch {
            val me = authStateStore.userSub.value
            when (val r = repository.claim(conversationId)) {
                is ApiResult.Success ->
                    if (isMine(r.data, me)) {
                        reconcileClaim(conversationId, r.data)
                    } else {
                        // Lost race detected from the success payload (assigned elsewhere) — no 409.
                        onClaimConflict(conversationId)
                    }
                is ApiResult.Failure ->
                    // A 422 (or any non-success answer) is treated as a lost race per spec §7.
                    onClaimConflict(conversationId)
                is ApiResult.NetworkError ->
                    _state.update {
                        it.copy(
                            claimingIds = it.claimingIds - conversationId,
                            banner = UiText.Res(R.string.helpdesk_offline),
                        )
                    }
            }
        }
    }

    /** True when the claim result is owned by the current agent (success / idempotent re-claim). */
    private fun isMine(result: HelpdeskClaimResult, me: String?): Boolean =
        result.assignment == HelpdeskAssignment.ASSIGNED_TO_ME ||
            (result.assignedAgentUserId.isNotBlank() && result.assignedAgentUserId == me)

    private fun reconcileClaim(conversationId: String, result: HelpdeskClaimResult) {
        _state.update { s ->
            val patched = s.queue.map { row ->
                if (row.conversationId == conversationId) {
                    row.copy(
                        routingState = HelpdeskRoutingState.ASSIGNED,
                        claimState = ClaimState.CLAIMED_BY_ME,
                        activeAgentUserId = result.assignedAgentUserId,
                    )
                } else {
                    row
                }
            }
            s.copy(
                queue = patched,
                claimingIds = s.claimingIds - conversationId,
                selectedConversation = patched.firstOrNull { it.conversationId == conversationId },
                banner = null,
            )
        }
        selectConversation(conversationId)
    }

    /**
     * Lost-race handling: clear the in-flight marker, re-fetch the queue to learn the true assignment,
     * then surface a non-fatal banner. The banner is set AFTER the reload so the successful reload's
     * banner-clear cannot clobber it.
     */
    private suspend fun onClaimConflict(conversationId: String) {
        _state.update { it.copy(claimingIds = it.claimingIds - conversationId) }
        loadJob?.cancel()
        loadJob = viewModelScope.launch { reloadQueue() }
        loadJob?.join()
        _state.update { it.copy(banner = UiText.Res(R.string.helpdesk_claim_conflict)) }
    }

    /** FR-5 — set/clear the detail pane target. Selecting loads the thread; null returns to queue-only. */
    fun selectConversation(conversationId: String?) {
        if (conversationId == null) {
            _state.update { it.copy(selectedConversation = null, thread = emptyList(), replyDraft = "") }
            return
        }
        val row = _state.value.queue.firstOrNull { it.conversationId == conversationId }
        _state.update { it.copy(selectedConversation = row ?: it.selectedConversation) }
        loadThread(conversationId)
    }

    private fun loadThread(conversationId: String) {
        viewModelScope.launch {
            messagingRepository.loadHistory(conversationId, before = null, limit = HISTORY_LIMIT)
            val thread = currentThreadSnapshot(conversationId)
            _state.update { it.copy(thread = thread) }
        }
    }

    /**
     * FR-6 — post a reply to a claimed conversation. Blank bodies are rejected locally (no network
     * call). While sending, `isSending = true`; on success the composer clears and the thread reloads.
     * Reuses the existing outbox send path (a local clientId is the outbox key only).
     */
    fun sendReply(conversationId: String, body: String) {
        val text = body.trim()
        if (text.isEmpty()) {
            _state.update { it.copy(banner = UiText.Res(R.string.helpdesk_reply_empty)) }
            return
        }
        if (_state.value.isSending) return
        _state.update { it.copy(isSending = true, banner = null) }
        viewModelScope.launch {
            val clientId = UUID.randomUUID().toString()
            when (val r = messagingRepository.sendOutbox(conversationId, clientId, text)) {
                is ApiResult.Success -> {
                    val thread = currentThreadSnapshot(conversationId)
                    _state.update {
                        it.copy(isSending = false, replyDraft = "", thread = thread, banner = null)
                    }
                }
                is ApiResult.Failure ->
                    _state.update { it.copy(isSending = false, banner = r.error.toBanner()) }
                is ApiResult.NetworkError ->
                    _state.update { it.copy(isSending = false, banner = UiText.Res(R.string.helpdesk_offline)) }
            }
        }
    }

    /** Update the draft composer text (persisted via SavedStateHandle by the screen, not PII). */
    fun onDraftChange(value: String) = _state.update { it.copy(replyDraft = value) }

    /** FR-7 — clear the transient banner without affecting data. */
    fun dismissError() = _state.update { it.copy(banner = null) }

    /** Read one snapshot of the observable thread (history ∪ outbox). */
    private suspend fun currentThreadSnapshot(conversationId: String): List<Message> =
        messagingRepository.observeThread(conversationId).first()

    private fun ApiError.toBanner(): UiText =
        if (message.isNotBlank()) UiText.Raw(message) else UiText.Res(R.string.helpdesk_claim_err_unknown)

    companion object {
        private const val HISTORY_LIMIT = 30
    }
}
