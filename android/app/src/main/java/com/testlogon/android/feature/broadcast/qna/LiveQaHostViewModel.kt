package com.testlogon.android.feature.broadcast.qna

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.qna.LiveQaRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [LiveQaHostUiState] for the live-QA HOST console (web LiveQaPage host view). Loads mode + stats +
 * the moderation queue, toggles Q&A mode, switches the queue filter, and applies the per-question host
 * actions (feature / answer / dismiss / pin / remove). After each mutation it reloads the queue + stats so
 * the surface reflects the authoritative server state. sessionId comes from the route via SavedStateHandle.
 */
@HiltViewModel
class LiveQaHostViewModel @Inject constructor(
    private val repo: LiveQaRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    private val _uiState = MutableStateFlow<LiveQaHostUiState>(LiveQaHostUiState.Loading)
    val uiState: StateFlow<LiveQaHostUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = LiveQaHostUiState.Loading
        viewModelScope.launch {
            when (val mode = repo.mode(sessionId)) {
                is ApiResult.Success -> {
                    _uiState.value = LiveQaHostUiState.Content(qaModeEnabled = mode.data)
                    refreshQueueAndStats()
                }
                is ApiResult.Failure -> _uiState.value = LiveQaHostUiState.Error(mode.error.message)
                is ApiResult.NetworkError -> _uiState.value = LiveQaHostUiState.Error(NETWORK_MESSAGE)
            }
        }
    }

    fun setMode(enabled: Boolean) {
        val current = content() ?: return
        _uiState.value = current.copy(togglingMode = true, message = null)
        viewModelScope.launch {
            when (val r = repo.setMode(sessionId, enabled)) {
                is ApiResult.Success -> {
                    val c = content() ?: return@launch
                    _uiState.value = c.copy(qaModeEnabled = r.data, togglingMode = false)
                    refreshQueueAndStats()
                }
                is ApiResult.Failure -> failOnContent(r.error.message) { it.copy(togglingMode = false) }
                is ApiResult.NetworkError -> failOnContent(NETWORK_MESSAGE) { it.copy(togglingMode = false) }
            }
        }
    }

    fun selectFilter(filter: QaQueueFilter) {
        val current = content() ?: return
        if (current.filter == filter) return
        _uiState.value = current.copy(filter = filter, message = null)
        viewModelScope.launch { refreshQueueAndStats() }
    }

    fun feature(id: String) = act(id) { repo.feature(sessionId, id) }
    fun answer(id: String) = act(id) { repo.answer(sessionId, id) }
    fun dismiss(id: String) = act(id) { repo.dismiss(sessionId, id) }
    fun togglePin(id: String, pinned: Boolean) = act(id) { repo.pin(sessionId, id, pinned) }

    fun remove(id: String) {
        val current = content() ?: return
        if (current.actingOnId != null) return
        _uiState.value = current.copy(actingOnId = id, message = null)
        viewModelScope.launch {
            when (val r = repo.remove(sessionId, id)) {
                is ApiResult.Success -> {
                    clearActing()
                    refreshQueueAndStats()
                }
                is ApiResult.Failure -> failOnContent(r.error.message) { it.copy(actingOnId = null) }
                is ApiResult.NetworkError -> failOnContent(NETWORK_MESSAGE) { it.copy(actingOnId = null) }
            }
        }
    }

    private fun act(id: String, block: suspend () -> ApiResult<*>) {
        val current = content() ?: return
        if (current.actingOnId != null) return
        _uiState.value = current.copy(actingOnId = id, message = null)
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    clearActing()
                    refreshQueueAndStats()
                }
                is ApiResult.Failure -> failOnContent(r.error.message) { it.copy(actingOnId = null) }
                is ApiResult.NetworkError -> failOnContent(NETWORK_MESSAGE) { it.copy(actingOnId = null) }
            }
        }
    }

    private suspend fun refreshQueueAndStats() {
        val current = content() ?: return
        _uiState.value = current.copy(loadingQueue = true)
        val questions = when (val q = repo.hostQuestions(sessionId, current.filter.status)) {
            is ApiResult.Success -> q.data
            else -> emptyList()
        }
        val stats = when (val s = repo.stats(sessionId)) {
            is ApiResult.Success -> s.data
            else -> content()?.stats
        }
        val c = content() ?: return
        _uiState.value = c.copy(questions = questions, stats = stats, loadingQueue = false)
    }

    private fun clearActing() {
        val c = content() ?: return
        _uiState.value = c.copy(actingOnId = null)
    }

    private fun failOnContent(message: String, transform: (LiveQaHostUiState.Content) -> LiveQaHostUiState.Content) {
        val c = content() ?: return
        _uiState.value = transform(c).copy(message = message)
    }

    private fun content(): LiveQaHostUiState.Content? = _uiState.value as? LiveQaHostUiState.Content

    companion object {
        const val ARG_SESSION_ID = "sessionId"
        private const val NETWORK_MESSAGE =
            "Couldn't reach the server. Check your connection and try again."
    }
}
