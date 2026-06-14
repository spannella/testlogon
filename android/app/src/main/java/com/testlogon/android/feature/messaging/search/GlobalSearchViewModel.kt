package com.testlogon.android.feature.messaging.search

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.MessageSearchResultItem
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.feature.messaging.thread.debounceCompat
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** AND-152 — non-list screen status for global message search; rows themselves live in [GlobalSearchUiState.groups]. */
sealed interface GlobalSearchPhase {
    data object Idle : GlobalSearchPhase
    data object TooShort : GlobalSearchPhase
    data object Searching : GlobalSearchPhase
    data object Results : GlobalSearchPhase
    data object Empty : GlobalSearchPhase
    data class Error(val message: String, val offline: Boolean) : GlobalSearchPhase
}

/**
 * AND-152 — one conversation group of results (cross-conversation results are grouped by conversation
 * with each member rendered as a snippet row).
 */
data class GlobalSearchGroup(
    val conversationId: String,
    val items: List<MessageSearchResultItem>,
)

data class GlobalSearchUiState(
    val query: String = "",
    val senderId: String? = null,
    /** epoch-seconds floor (after_ts), null = no floor. */
    val afterTs: Long? = null,
    val phase: GlobalSearchPhase = GlobalSearchPhase.Idle,
    val groups: List<GlobalSearchGroup> = emptyList(),
) {
    val hasActiveFilters: Boolean get() = senderId != null || afterTs != null
    val isQueryValid: Boolean get() = query.trim().length >= GlobalSearchViewModel.MIN_QUERY_LENGTH
    val resultCount: Int get() = groups.sumOf { it.items.size }
}

internal data class SearchCriteria(
    val query: String,
    val senderId: String?,
    val afterTs: Long?,
)

/**
 * AND-152 — cross-conversation message search.
 *
 * The endpoint returns a single bounded array (no pagination), so results flow through a plain
 * [StateFlow] (idle / too-short / searching / results / empty / error). The query leg is debounced
 * (300 ms) via the shared [debounceCompat] helper (authored for AND-141/AND-151); filter changes apply
 * immediately. [flatMapLatest] cancels stale searches so only the newest criteria's result is applied.
 * Tapping a result deep-links into the thread at the matched message (the Route owns navigation).
 */
@HiltViewModel
class GlobalSearchViewModel @Inject constructor(
    private val repository: MessagingRepository,
    private val saved: SavedStateHandle,
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        GlobalSearchUiState(
            query = saved.get<String>(KEY_QUERY).orEmpty(),
            senderId = saved.get<String>(KEY_SENDER_ID),
            afterTs = saved.get<Long>(KEY_AFTER_TS),
        ),
    )
    val uiState: StateFlow<GlobalSearchUiState> = _uiState

    /** Drives the search engine; emits whenever query (debounced) or filters change. */
    private val criteria = MutableStateFlow(
        SearchCriteria(_uiState.value.query, _uiState.value.senderId, _uiState.value.afterTs),
    )

    init {
        startEngine()
        // Re-issue on restore when a valid query survived config change.
        if (_uiState.value.isQueryValid) criteria.value = currentCriteria()
    }

    fun onQueryChange(raw: String) {
        _uiState.update { it.copy(query = raw) }
        saved[KEY_QUERY] = raw
        val trimmed = raw.trim()
        if (trimmed.length < MIN_QUERY_LENGTH) {
            _uiState.update {
                it.copy(
                    phase = if (trimmed.isEmpty()) GlobalSearchPhase.Idle else GlobalSearchPhase.TooShort,
                    groups = emptyList(),
                )
            }
        }
        criteria.value = currentCriteria()
    }

    fun onSenderChange(senderId: String?) {
        _uiState.update { it.copy(senderId = senderId) }
        saved[KEY_SENDER_ID] = senderId
        criteria.value = currentCriteria()
    }

    fun onAfterChange(afterTs: Long?) {
        _uiState.update { it.copy(afterTs = afterTs) }
        saved[KEY_AFTER_TS] = afterTs
        criteria.value = currentCriteria()
    }

    fun clearFilters() {
        _uiState.update { it.copy(senderId = null, afterTs = null) }
        saved[KEY_SENDER_ID] = null
        saved[KEY_AFTER_TS] = null
        criteria.value = currentCriteria()
    }

    /** Re-issue the current query/filters. [distinctUntilChanged] would drop an identical re-emit, so run directly. */
    fun retry() = runSearchOnce(currentCriteria())

    private fun currentCriteria() =
        SearchCriteria(_uiState.value.query, _uiState.value.senderId, _uiState.value.afterTs)

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun startEngine() {
        // Debounce only the query leg: build a stream keyed on the trimmed/capped criteria.
        criteria
            .debounceCompat(DEBOUNCE_MS)
            .map { it.copy(query = it.query.trim().take(MAX_QUERY_LENGTH)) }
            .distinctUntilChanged()
            .flatMapLatest { c ->
                if (c.query.length < MIN_QUERY_LENGTH) {
                    flowOf<SearchEmission>(SearchEmission.Skipped)
                } else {
                    flow<SearchEmission> {
                        emit(SearchEmission.Loading)
                        emit(SearchEmission.Done(repository.searchAllMessages(c.query, c.senderId, c.afterTs)))
                    }
                }
            }
            .onEach { applyEmission(it) }
            .launchIn(viewModelScope)
    }

    /** Used by [retry] to force a re-run without relying on distinctUntilChanged. */
    private fun runSearchOnce(c: SearchCriteria) {
        val trimmed = c.query.trim().take(MAX_QUERY_LENGTH)
        if (trimmed.length < MIN_QUERY_LENGTH) return
        _uiState.update { it.copy(phase = GlobalSearchPhase.Searching) }
        viewModelScope.launch {
            applyResult(repository.searchAllMessages(trimmed, c.senderId, c.afterTs))
        }
    }

    private fun applyEmission(emission: SearchEmission) {
        when (emission) {
            SearchEmission.Skipped -> Unit // phase already set in onQueryChange
            SearchEmission.Loading -> _uiState.update { it.copy(phase = GlobalSearchPhase.Searching) }
            is SearchEmission.Done -> applyResult(emission.result)
        }
    }

    private fun applyResult(result: ApiResult<List<MessageSearchResultItem>>) {
        when (result) {
            is ApiResult.Success -> {
                val groups = groupByConversation(result.data)
                _uiState.update {
                    it.copy(
                        groups = groups,
                        phase = if (groups.isEmpty()) GlobalSearchPhase.Empty else GlobalSearchPhase.Results,
                    )
                }
            }
            is ApiResult.Failure ->
                _uiState.update {
                    it.copy(groups = emptyList(), phase = GlobalSearchPhase.Error(result.error.message, offline = false))
                }
            is ApiResult.NetworkError ->
                _uiState.update {
                    it.copy(groups = emptyList(), phase = GlobalSearchPhase.Error(OFFLINE_MESSAGE, offline = true))
                }
        }
    }

    private sealed interface SearchEmission {
        data object Skipped : SearchEmission
        data object Loading : SearchEmission
        data class Done(val result: ApiResult<List<MessageSearchResultItem>>) : SearchEmission
    }

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MIN_QUERY_LENGTH = 2
        const val MAX_QUERY_LENGTH = 200
        const val OFFLINE_MESSAGE = "You're offline. Tap to retry."

        private const val KEY_QUERY = "search_query"
        private const val KEY_SENDER_ID = "search_sender_id"
        private const val KEY_AFTER_TS = "search_after_ts"

        /**
         * AND-152 — groups results by conversation, preserving server order for the FIRST appearance of
         * each conversation (recency-desc assumption), and the in-group order within each. Pure / testable.
         */
        internal fun groupByConversation(items: List<MessageSearchResultItem>): List<GlobalSearchGroup> {
            val order = LinkedHashMap<String, MutableList<MessageSearchResultItem>>()
            for (item in items) order.getOrPut(item.conversationId) { mutableListOf() }.add(item)
            return order.map { (cid, list) -> GlobalSearchGroup(cid, list) }
        }
    }
}
