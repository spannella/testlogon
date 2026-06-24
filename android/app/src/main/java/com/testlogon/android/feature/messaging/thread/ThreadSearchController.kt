package com.testlogon.android.feature.messaging.thread

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.MessageSearchMatch
import com.testlogon.android.data.messaging.MessagingRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** AND-151 — phase of the in-conversation search request. */
sealed interface SearchPhase {
    data object Idle : SearchPhase
    data object Loading : SearchPhase
    data object Loaded : SearchPhase
    data class Error(val message: String) : SearchPhase
}

/**
 * AND-151 — in-conversation search sub-state. Held inside [ThreadUiState] so the Thread screen renders
 * the search bar + highlights from a single source of truth.
 */
data class ThreadSearchUiState(
    val active: Boolean = false,
    val query: String = "",
    val phase: SearchPhase = SearchPhase.Idle,
    /** ordered oldest->newest, one entry per occurrence. */
    val matches: List<MessageSearchMatch> = emptyList(),
    /** index into [matches]; -1 == none. */
    val activeIndex: Int = -1,
    /** true when the query is non-blank but shorter than [ThreadSearchController.MIN_QUERY_LENGTH]. */
    val tooShort: Boolean = false,
) {
    val total: Int get() = matches.size
    val activeMatch: MessageSearchMatch? get() = matches.getOrNull(activeIndex)
    val hasMatches: Boolean get() = matches.isNotEmpty()

    /** "M of N" / "" — formatting only; the @Composable supplies localized strings for 0/1 results. */
    val cursorLabel: String
        get() = if (matches.isEmpty()) "" else "${activeIndex + 1} of $total"
}

/**
 * AND-151 — owns the in-conversation search lifecycle for a single thread. A plain class (NOT a
 * ViewModel) held by [ThreadViewModel] so it can share the thread's [conversationId], [SavedStateHandle]
 * and [scope] while keeping search concerns isolated.
 *
 * Query input is debounced (300 ms) via the shared [debounceCompat] helper (the same one used for
 * draft autosave) and routed through [flatMapLatest] so only the latest query's result is applied
 * (stale in-flight calls are cancelled). Highlight offsets come from the repository (computed locally
 * from text — the backend has none). One-shot scroll effects are NOT owned here; the screen observes
 * [activeMatch] and reuses the existing [ThreadEvent.ScrollToMessage] path.
 */
class ThreadSearchController(
    private val conversationId: String,
    private val repository: MessagingRepository,
    private val saved: SavedStateHandle,
    private val scope: CoroutineScope,
) {
    private val _state = MutableStateFlow(
        ThreadSearchUiState(
            active = saved.get<Boolean>(KEY_ACTIVE) ?: false,
            query = saved.get<String>(KEY_QUERY).orEmpty(),
            activeIndex = saved.get<Int>(KEY_ACTIVE_INDEX) ?: -1,
        ),
    )
    val state: StateFlow<ThreadSearchUiState> = _state.asStateFlow()

    /** Raw (debounced) query stream — the engine consumes this; the UI state mirrors it for display. */
    private val queries = MutableStateFlow(_state.value.query)

    /** True until the first result arrives, so a restored activeIndex is honoured exactly once. */
    private var restorePending = (saved.get<Int>(KEY_ACTIVE_INDEX) ?: -1) >= 0

    init {
        startEngine()
        // Re-issue on restore when search was active with a valid query (matches are not persisted).
        if (_state.value.active && _state.value.query.trim().length >= MIN_QUERY_LENGTH) {
            queries.value = _state.value.query
        }
    }

    fun open() {
        _state.update { it.copy(active = true) }
        saved[KEY_ACTIVE] = true
    }

    fun close() {
        _state.value = ThreadSearchUiState(active = false)
        queries.value = ""
        saved[KEY_ACTIVE] = false
        saved[KEY_QUERY] = ""
        saved[KEY_ACTIVE_INDEX] = -1
    }

    fun onQueryChange(raw: String) {
        val trimmed = raw.trim()
        _state.update {
            it.copy(
                query = raw,
                tooShort = trimmed.isNotEmpty() && trimmed.length < MIN_QUERY_LENGTH,
                // Clear results immediately for blank/too-short so highlights vanish without waiting.
                matches = if (trimmed.length < MIN_QUERY_LENGTH) emptyList() else it.matches,
                activeIndex = if (trimmed.length < MIN_QUERY_LENGTH) -1 else it.activeIndex,
                phase = if (trimmed.length < MIN_QUERY_LENGTH) SearchPhase.Idle else it.phase,
            )
        }
        saved[KEY_QUERY] = raw
        queries.value = raw
    }

    /** Advance to the next match (wraps last -> first). No-op with zero matches. */
    fun next() = move(+1)

    /** Go to the previous match (wraps first -> last). No-op with zero matches. */
    fun prev() = move(-1)

    /**
     * #17 — jump straight to a match the user TAPPED in the results list (sets the active cursor to the
     * first occurrence of [messageId]); the screen's activeMatch effect then scrolls to it.
     */
    fun selectMatch(messageId: String) {
        val idx = _state.value.matches.indexOfFirst { it.messageId == messageId }
        if (idx < 0) return
        _state.update { it.copy(activeIndex = idx) }
        saved[KEY_ACTIVE_INDEX] = idx
    }

    private fun move(delta: Int) {
        val n = _state.value.total
        if (n == 0) return
        val current = _state.value.activeIndex.coerceAtLeast(0)
        val nextIndex = ((current + delta) % n + n) % n
        _state.update { it.copy(activeIndex = nextIndex) }
        saved[KEY_ACTIVE_INDEX] = nextIndex
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun startEngine() {
        scope.launch {
            queries
                .debounceCompat(DEBOUNCE_MS)
                .map { it.trim().take(MAX_QUERY_LENGTH) }
                .distinctUntilChanged()
                .filter { it.length >= MIN_QUERY_LENGTH }
                .onEach { _state.update { s -> s.copy(phase = SearchPhase.Loading) } }
                .flatMapLatest { query ->
                    kotlinx.coroutines.flow.flow {
                        emit(repository.searchInConversation(conversationId, query))
                    }
                }
                .collect { result -> applyResult(result) }
        }
    }

    private fun applyResult(result: ApiResult<List<MessageSearchMatch>>) {
        when (result) {
            is ApiResult.Success -> {
                val matches = result.data
                val restored = saved.get<Int>(KEY_ACTIVE_INDEX) ?: -1
                // Honour a restored cursor exactly once (config-change), else reset to 0 on new results.
                val activeIndex = when {
                    matches.isEmpty() -> -1
                    restorePending && restored in matches.indices -> restored
                    else -> 0
                }
                restorePending = false
                _state.update {
                    it.copy(phase = SearchPhase.Loaded, matches = matches, activeIndex = activeIndex)
                }
                saved[KEY_ACTIVE_INDEX] = activeIndex
            }
            is ApiResult.Failure ->
                _state.update {
                    it.copy(phase = SearchPhase.Error(result.error.message), matches = emptyList(), activeIndex = -1)
                }
            is ApiResult.NetworkError ->
                _state.update {
                    it.copy(phase = SearchPhase.Error(OFFLINE_SEARCH_MESSAGE), matches = emptyList(), activeIndex = -1)
                }
        }
    }

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LENGTH = 2
        const val MAX_QUERY_LENGTH = 200
        const val OFFLINE_SEARCH_MESSAGE = "Couldn't search — tap to retry"

        private const val KEY_ACTIVE = "search_active"
        private const val KEY_QUERY = "search_query"
        private const val KEY_ACTIVE_INDEX = "search_active_index"
    }
}
