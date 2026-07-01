package com.testlogon.android.feature.broadcast

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.broadcast.BroadcastReminderRepository
import com.testlogon.android.data.broadcast.BroadcastViewerCountRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.time.Instant
import javax.inject.Inject

/** AND-279 — taxonomy of browse errors mapped from [ApiResult] failures. */
sealed interface BroadcastError {
    data object Network : BroadcastError
    data class Server(val message: String) : BroadcastError
    data object Auth : BroadcastError
    data object Unknown : BroadcastError
}

/** AND-279 — the browse screen view-state. */
sealed interface BroadcastUiState {
    data object Loading : BroadcastUiState
    data class Content(
        val selected: BroadcastBucket,
        val live: List<BroadcastItem>,
        val upcoming: List<BroadcastItem>,
        val past: List<BroadcastItem>,
        val isStale: Boolean,
        val isRefreshing: Boolean,
    ) : BroadcastUiState

    data class Error(val cause: BroadcastError, val cached: Content?) : BroadcastUiState
}

/** AND-279 — one-shot effects (transient inline reminder errors), Channel + receiveAsFlow. */
sealed interface BroadcastBrowseEvent {
    data object ReminderFailed : BroadcastBrowseEvent
}

/**
 * AND-279 — broadcast browse presentation logic.
 *
 * Loads sessions via the AND-278 [BroadcastRepository] (base list + dedicated scheduled/upcoming
 * routes), bucketizes them with the pure [BroadcastBucketizer], best-effort enriches LIVE rows with
 * a viewer count, and owns the optimistic remind-me toggle with rollback (no auto-retry of the
 * non-idempotent write). The selected bucket persists via [SavedStateHandle].
 */
@HiltViewModel
class BroadcastBrowseViewModel @Inject constructor(
    private val repo: BroadcastRepository,
    private val reminderRepo: BroadcastReminderRepository,
    private val viewerCountRepo: BroadcastViewerCountRepository,
    private val savedState: SavedStateHandle,
    private val clock: Clock,
) : ViewModel() {

    private val _uiState = MutableStateFlow<BroadcastUiState>(BroadcastUiState.Loading)
    val uiState: StateFlow<BroadcastUiState> = _uiState.asStateFlow()

    private val _events = Channel<BroadcastBrowseEvent>(Channel.BUFFERED)
    val events: Flow<BroadcastBrowseEvent> = _events.receiveAsFlow()

    /** Local-only reminder state (no server flag), keyed by sessionId; survives re-bucketization. */
    private val reminders = mutableSetOf<String>()

    init {
        selectBucket(persistedBucket())
        refresh()
    }

    fun selectBucket(bucket: BroadcastBucket) {
        savedState[KEY_BUCKET] = bucket.name
        _uiState.update { state ->
            when (state) {
                is BroadcastUiState.Content -> state.copy(selected = bucket)
                is BroadcastUiState.Error -> state.copy(cached = state.cached?.copy(selected = bucket))
                BroadcastUiState.Loading -> state
            }
        }
    }

    fun refresh() {
        viewModelScope.launch {
            markRefreshing()
            val now = Instant.ofEpochMilli(clock.now())

            // T3 — the LIVE bucket is sourced from the PUBLIC live-discovery feed (GET broadcast/live) so a
            // second-user VIEWER can find any creator's live broadcast. The base sessions list is
            // operator-scoped (a non-operator only sees their own sessions) and cannot surface other hosts.
            val liveResult = repo.liveSessions(limit = LIST_LIMIT)
            // Upcoming / past still come from the (own/scheduled) sessions list.
            val baseResult = repo.sessions(limit = LIST_LIMIT)

            // Bucketize the public feed's currently-live sessions; keep only the LIVE bucket from it.
            val publicLive: List<BroadcastItem> = when (liveResult) {
                is ApiResult.Success -> BroadcastBucketizer.bucketize(liveResult.data.items, now).first
                else -> emptyList()
            }

            when (baseResult) {
                is ApiResult.Success -> {
                    val (ownLive, upcoming, past) = BroadcastBucketizer.bucketize(baseResult.data.items, now)
                    // Merge public-live with any of the viewer's own live sessions, deduped by sessionId
                    // (public feed wins its own entries; own-live is appended for the host's self-view).
                    val mergedLive = mergeLive(publicLive, ownLive)
                    val enrichedLive = enrichViewerCounts(mergedLive)
                    publishContent(enrichedLive, upcoming, past)
                }
                // The base list is unavailable (e.g. a non-operator 403), but the public live feed is not:
                // still show whatever is live so a pure viewer is never blocked from discovering broadcasts.
                is ApiResult.Failure ->
                    if (publicLive.isNotEmpty()) {
                        publishContent(enrichViewerCounts(publicLive), emptyList(), emptyList())
                    } else {
                        publishError(baseResult.error.toBroadcastError())
                    }
                is ApiResult.NetworkError ->
                    if (publicLive.isNotEmpty()) {
                        publishContent(enrichViewerCounts(publicLive), emptyList(), emptyList())
                    } else {
                        publishError(BroadcastError.Network)
                    }
            }
        }
    }

    /** T3 — union of the public-live feed and the viewer's own live sessions, deduped by sessionId. */
    private fun mergeLive(
        publicLive: List<BroadcastItem>,
        ownLive: List<BroadcastItem>,
    ): List<BroadcastItem> {
        if (ownLive.isEmpty()) return publicLive
        val seen = publicLive.mapTo(HashSet()) { it.sessionId }
        return publicLive + ownLive.filter { it.sessionId !in seen }
    }

    fun retry() = refresh()

    fun dismissError() {
        _uiState.update { state ->
            if (state is BroadcastUiState.Error && state.cached != null) state.cached else state
        }
    }

    /**
     * Optimistically flips the reminder for [sessionId], fires the (non-idempotent) mutation once,
     * and rolls back on failure. Applied across all three buckets so the item stays consistent if the
     * user switches tabs mid-flight.
     */
    fun toggleReminder(sessionId: String, enable: Boolean) {
        val prior = reminders.contains(sessionId)
        applyReminder(sessionId, set = enable, pending = true)
        viewModelScope.launch {
            val result: ApiResult<*> = if (enable) {
                reminderRepo.setReminder(sessionId)
            } else {
                reminderRepo.clearReminder(sessionId)
            }
            when (result) {
                is ApiResult.Success -> {
                    if (enable) reminders.add(sessionId) else reminders.remove(sessionId)
                    applyReminder(sessionId, set = enable, pending = false)
                }
                else -> {
                    // Roll back to the prior state; do NOT auto-retry the write.
                    if (prior) reminders.add(sessionId) else reminders.remove(sessionId)
                    applyReminder(sessionId, set = prior, pending = false)
                    _events.trySend(BroadcastBrowseEvent.ReminderFailed)
                }
            }
        }
    }

    // ---- internal state plumbing ----

    private fun markRefreshing() {
        _uiState.update { state ->
            when (state) {
                is BroadcastUiState.Content -> state.copy(isStale = true, isRefreshing = true)
                else -> state
            }
        }
    }

    private fun publishContent(
        live: List<BroadcastItem>,
        upcoming: List<BroadcastItem>,
        past: List<BroadcastItem>,
    ) {
        val selected = currentBucket()
        _uiState.value = BroadcastUiState.Content(
            selected = selected,
            live = live.withReminderState(),
            upcoming = upcoming.withReminderState(),
            past = past.withReminderState(),
            isStale = false,
            isRefreshing = false,
        )
    }

    private fun publishError(cause: BroadcastError) {
        val cached = (_uiState.value as? BroadcastUiState.Content)
            ?: (_uiState.value as? BroadcastUiState.Error)?.cached
        _uiState.value = BroadcastUiState.Error(cause, cached?.copy(isRefreshing = false))
    }

    private fun applyReminder(sessionId: String, set: Boolean, pending: Boolean) {
        _uiState.update { state ->
            when (state) {
                is BroadcastUiState.Content -> state.copy(
                    live = state.live.mapReminder(sessionId, set, pending),
                    upcoming = state.upcoming.mapReminder(sessionId, set, pending),
                    past = state.past.mapReminder(sessionId, set, pending),
                )
                is BroadcastUiState.Error -> state.copy(
                    cached = state.cached?.copy(
                        live = state.cached.live.mapReminder(sessionId, set, pending),
                        upcoming = state.cached.upcoming.mapReminder(sessionId, set, pending),
                        past = state.cached.past.mapReminder(sessionId, set, pending),
                    ),
                )
                BroadcastUiState.Loading -> state
            }
        }
    }

    private fun List<BroadcastItem>.mapReminder(
        sessionId: String,
        set: Boolean,
        pending: Boolean,
    ): List<BroadcastItem> = map {
        if (it.sessionId == sessionId) it.copy(reminderSet = set, reminderPending = pending) else it
    }

    private fun List<BroadcastItem>.withReminderState(): List<BroadcastItem> =
        map { it.copy(reminderSet = reminders.contains(it.sessionId), reminderPending = false) }

    private suspend fun enrichViewerCounts(live: List<BroadcastItem>): List<BroadcastItem> =
        live.map { item ->
            when (val count = viewerCountRepo.viewerCount(item.sessionId)) {
                is ApiResult.Success -> item.copy(viewerCount = count.data)
                else -> item // best-effort: leave null, never block the list
            }
        }

    private fun currentBucket(): BroadcastBucket = when (val state = _uiState.value) {
        is BroadcastUiState.Content -> state.selected
        is BroadcastUiState.Error -> state.cached?.selected ?: persistedBucket()
        BroadcastUiState.Loading -> persistedBucket()
    }

    private fun persistedBucket(): BroadcastBucket =
        savedState.get<String>(KEY_BUCKET)?.let { runCatching { BroadcastBucket.valueOf(it) }.getOrNull() }
            ?: BroadcastBucket.LIVE

    private fun com.testlogon.android.core.model.ApiError.toBroadcastError(): BroadcastError = when (status) {
        401, 403 -> BroadcastError.Auth
        com.testlogon.android.core.model.ApiError.STATUS_NETWORK -> BroadcastError.Network
        else -> BroadcastError.Server(message)
    }

    private companion object {
        const val KEY_BUCKET = "broadcast_bucket"
        const val LIST_LIMIT = 50
    }
}
