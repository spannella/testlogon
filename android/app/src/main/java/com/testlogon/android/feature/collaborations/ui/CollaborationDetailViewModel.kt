package com.testlogon.android.feature.collaborations.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.collaborations.data.CollaborationsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-358 / PAR-04 - drives the [CollaborationDetailUiState] for the collaboration detail.
 *
 * collabId arrives as a nav arg via [SavedStateHandle] (survives process death). [load] reads the
 * collaboration and (best-effort) its split history + negotiation revisions; a split-history / revisions
 * failure is TOLERATED (folds to an empty list) since those sections are optional. An unrecoverable 401 (after
 * the shared client's one auth refresh) -> [CollaborationDetailUiState.SessionExpired] SIGNAL (routing is
 * owned elsewhere).
 *
 * STALE (in-memory only): [refresh] re-reads but, on a failure, KEEPS the last-good
 * [CollaborationDetailUiState.Content] and flips isStale true (the snapshot lives only in this StateFlow - it
 * is NOT persisted to disk; Room persistence across process death is DEFERRED, no migration this wave). There
 * is NO poll loop.
 *
 * PAR-04 (deal actions): [accept] / [reject] / [counter] / [cancel] / [terminate] are STATE-only mutations
 * (NOT money-bearing, NOT routed through BillingAuthorizer). Each sets [CollaborationDetailUiState.Content.busy]
 * true, calls the repo, emits a one-shot [CollaborationDetailEffect] (success localized per [CollabAction], or
 * the raw failure message), then RELOADS the detail (the backend is the source of truth). A 401 during an
 * action -> SessionExpired. Actions no-op when there is no content or a mutation is already in flight.
 *
 * [viewerId] is the viewer's own user id (from [AuthStateStore]); the screen uses it to gate which actions
 * show (awaiting-response / active / pending-and-initiator) and to highlight the viewer's own split row.
 */
@HiltViewModel
class CollaborationDetailViewModel @Inject constructor(
    private val repository: CollaborationsRepository,
    savedState: SavedStateHandle,
    authStateStore: AuthStateStore,
) : ViewModel() {

    val collabId: String =
        checkNotNull(savedState[ARG_COLLAB_ID]) { "missing $ARG_COLLAB_ID nav arg" }

    /** The viewer's own user id (may be null); used for action gating + to highlight the viewer's split row. */
    val viewerId: String? = authStateStore.userSub.value?.takeIf { it.isNotBlank() }

    private val _uiState = MutableStateFlow<CollaborationDetailUiState>(CollaborationDetailUiState.Loading)
    val uiState: StateFlow<CollaborationDetailUiState> = _uiState.asStateFlow()

    private val _effects = Channel<CollaborationDetailEffect>(Channel.BUFFERED)
    val effects: Flow<CollaborationDetailEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    /** First load (no cached content): goes through Loading and may resolve to SessionExpired / Error. */
    fun load() {
        _uiState.value = CollaborationDetailUiState.Loading
        refreshInternal(isRefresh = false)
    }

    fun retry() = load()

    /**
     * Pull-to-refresh. On failure with prior content the last-good Content is kept with isStale=true; a 401
     * always wins (-> SessionExpired) even with prior content.
     */
    fun refresh() = refreshInternal(isRefresh = true)

    private fun refreshInternal(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val result = repository.getCollaboration(collabId)) {
                is ApiResult.Success -> {
                    // The split history + revisions are OPTIONAL: a failure folds to an empty list.
                    val distributions =
                        (repository.getSplits(collabId) as? ApiResult.Success)?.data ?: emptyList()
                    val revisions =
                        (repository.getRevisions(collabId) as? ApiResult.Success)?.data ?: emptyList()
                    _uiState.value = CollaborationDetailUiState.Content(
                        collab = result.data,
                        distributions = distributions,
                        revisions = revisions,
                        isStale = false,
                        busy = false,
                    )
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.value = CollaborationDetailUiState.SessionExpired
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

    /** A non-401 failure: keep stale content on a refresh that has prior content, else surface Error. */
    private fun emitFailure(isRefresh: Boolean, error: ApiError) {
        val prior = _uiState.value as? CollaborationDetailUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isStale = true, busy = false)
        } else {
            CollaborationDetailUiState.Error(error)
        }
    }

    // ---- PAR-04 deal actions (STATE-only; NOT money-bearing) --------------------------------------------

    /** Accept the current proposal, then reload. */
    fun accept() = mutate(CollabAction.ACCEPT) { repository.accept(collabId) }

    /** Reject the current proposal, then reload. */
    fun reject() = mutate(CollabAction.REJECT) { repository.reject(collabId) }

    /** Send a counter-offer ([splitPct] = the initiator's new percent, 1..99), then reload. */
    fun counter(splitPct: Int) = mutate(CollabAction.COUNTER) { repository.counter(collabId, splitPct) }

    /** Cancel the pending request (initiator only), then reload. */
    fun cancel() = mutate(CollabAction.CANCEL) { repository.cancel(collabId) }

    /** Terminate the active agreement (optional [reason]), then reload. */
    fun terminate(reason: String? = null) = mutate(CollabAction.TERMINATE) { repository.terminate(collabId, reason) }

    /**
     * Runs a state-only deal action: flips busy on the current Content, calls the repo, emits a one-shot
     * success / failure effect, and RELOADS the detail on success (the backend is the source of truth). No-ops
     * when there is no content or a mutation is already in flight. A 401 -> SessionExpired.
     */
    private fun mutate(action: CollabAction, block: suspend () -> ApiResult<Collaboration>) {
        val current = _uiState.value as? CollaborationDetailUiState.Content ?: return
        if (current.busy) return
        _uiState.value = current.copy(busy = true)
        viewModelScope.launch {
            when (val result = block()) {
                is ApiResult.Success -> {
                    _effects.send(CollaborationDetailEffect.ActionSucceeded(action))
                    // Re-read from the source of truth; refreshInternal clears busy on the new Content.
                    refreshInternal(isRefresh = true)
                }
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.value = CollaborationDetailUiState.SessionExpired
                    } else {
                        clearBusy()
                        _effects.send(CollaborationDetailEffect.ActionFailed(result.error.message))
                    }
                }
                is ApiResult.NetworkError -> {
                    clearBusy()
                    _effects.send(CollaborationDetailEffect.ActionFailed(OFFLINE_FALLBACK))
                }
            }
        }
    }

    /** Clears the in-flight flag on the current Content (keeps everything else). */
    private fun clearBusy() {
        val current = _uiState.value as? CollaborationDetailUiState.Content ?: return
        _uiState.value = current.copy(busy = false)
    }

    companion object {
        const val ARG_COLLAB_ID = "collabId"

        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
