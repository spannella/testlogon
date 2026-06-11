package com.testlogon.android.feature.broadcast.qna

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.qna.LiveQaRepository
import com.testlogon.android.data.broadcast.qna.QaQuestion
import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** AND-284 — the Q&A panel view-state. */
data class LiveQaUiState(
    val phase: Phase = Phase.Loading,
    val qaModeEnabled: Boolean = true,
    val featured: QaQuestion? = null,
    val questions: List<QaQuestion> = emptyList(),
    val upvotedIds: Set<String> = emptySet(),
    val composerText: String = "",
    val isSubmitting: Boolean = false,
    val isRefreshing: Boolean = false,
    val transientMessage: String? = null,
) {
    val canSubmit: Boolean
        get() = composerText.isNotBlank() && composerText.length <= MAX_LEN && !isSubmitting

    enum class Phase { Loading, Content, Error, Disabled }

    companion object {
        const val MAX_LEN = 280
    }
}

/**
 * AND-284 — live Q&A presentation logic for a single broadcast session.
 *
 * Loads the viewer-visible question list + featured banner, gates the surface on the qa_mode_enabled
 * flag, submits questions, and toggles upvotes OPTIMISTICALLY with rollback on failure (per-viewer voted
 * state is tracked locally in [LiveQaUiState.upvotedIds] since the wire has no such field; the server
 * vote_count in the response is authoritative). Bounded polling refreshes the list while the panel is
 * resumed (driven by the screen via [startPolling]/[stopPolling]); a poll preserves any in-flight
 * optimistic vote. Built with AssistedInject so the sessionId is supplied at the call site.
 */
@HiltViewModel(assistedFactory = LiveQaViewModel.Factory::class)
class LiveQaViewModel @AssistedInject constructor(
    @Assisted private val sessionId: String,
    private val repo: LiveQaRepository,
) : ViewModel() {

    @AssistedFactory
    interface Factory {
        fun create(sessionId: String): LiveQaViewModel
    }

    private val _uiState = MutableStateFlow(LiveQaUiState())
    val uiState: StateFlow<LiveQaUiState> = _uiState.asStateFlow()

    private var pollJob: Job? = null

    /** Per-question in-flight vote jobs (latest-wins; a new tap cancels the prior request). */
    private val voteJobs = mutableMapOf<String, Job>()

    init {
        load()
    }

    /** Loads the mode gate, then (if enabled) the question list + featured banner. */
    fun load() {
        viewModelScope.launch {
            when (val mode = repo.mode(sessionId)) {
                is ApiResult.Success -> {
                    if (!mode.data) {
                        _uiState.update { it.copy(phase = LiveQaUiState.Phase.Disabled, qaModeEnabled = false) }
                        return@launch
                    }
                    _uiState.update { it.copy(qaModeEnabled = true) }
                    refresh(initial = true)
                }
                // Mode unknown: attempt the list anyway (the GET will 403 if truly disabled).
                else -> refresh(initial = true)
            }
        }
    }

    fun refresh(initial: Boolean = false) {
        viewModelScope.launch {
            _uiState.update { it.copy(isRefreshing = !initial) }
            when (val result = repo.questions(sessionId)) {
                is ApiResult.Success -> _uiState.update { current ->
                    current.copy(
                        phase = LiveQaUiState.Phase.Content,
                        featured = result.data.featured,
                        // Preserve any in-flight optimistic vote by re-applying local upvote deltas.
                        questions = result.data.questions,
                        isRefreshing = false,
                    )
                }
                else -> _uiState.update { current ->
                    if (current.questions.isEmpty() && current.featured == null) {
                        current.copy(phase = LiveQaUiState.Phase.Error, isRefreshing = false)
                    } else {
                        current.copy(
                            isRefreshing = false,
                            transientMessage = (result as? ApiResult.Failure)?.error?.message,
                        )
                    }
                }
            }
        }
    }

    fun onComposerChange(text: String) {
        _uiState.update { it.copy(composerText = text) }
    }

    fun submitQuestion() {
        val state = _uiState.value
        val text = state.composerText.trim()
        if (text.isEmpty() || text.length > LiveQaUiState.MAX_LEN || state.isSubmitting) return
        _uiState.update { it.copy(isSubmitting = true) }
        viewModelScope.launch {
            when (val result = repo.ask(sessionId, text)) {
                is ApiResult.Success -> _uiState.update { current ->
                    val merged = (listOf(result.data) + current.questions).distinctBy { it.id }
                    current.copy(
                        isSubmitting = false,
                        composerText = "",
                        questions = merged,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(isSubmitting = false, transientMessage = result.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(isSubmitting = false, transientMessage = null)
                }
            }
        }
    }

    /**
     * Optimistically toggles the vote (count +/-1, local voted state flips immediately), then calls the
     * server. On success the server vote_count is adopted; on failure the prior count/state is restored.
     * Rapid taps on the same question coalesce to one in-flight request (latest-wins).
     */
    fun toggleUpvote(questionId: String) {
        val before = _uiState.value
        val wasVoted = questionId in before.upvotedIds
        val nowVoted = !wasVoted
        val delta = if (nowVoted) 1 else -1

        _uiState.update { current ->
            current.copy(
                upvotedIds = if (nowVoted) current.upvotedIds + questionId else current.upvotedIds - questionId,
                questions = current.questions.map {
                    if (it.id == questionId) it.copy(upvotes = (it.upvotes + delta).coerceAtLeast(0)) else it
                },
                featured = current.featured?.let {
                    if (it.id == questionId) it.copy(upvotes = (it.upvotes + delta).coerceAtLeast(0)) else it
                },
            )
        }

        voteJobs[questionId]?.cancel()
        voteJobs[questionId] = viewModelScope.launch {
            when (val result = repo.setUpvote(sessionId, questionId, nowVoted)) {
                is ApiResult.Success -> applyServerCount(questionId, result.data.upvotes)
                else -> rollbackVote(questionId, wasVoted, before)
            }
        }
    }

    private fun applyServerCount(questionId: String, serverCount: Int) {
        _uiState.update { current ->
            current.copy(
                questions = current.questions.map {
                    if (it.id == questionId) it.copy(upvotes = serverCount) else it
                },
                featured = current.featured?.let {
                    if (it.id == questionId) it.copy(upvotes = serverCount) else it
                },
            )
        }
    }

    private fun rollbackVote(questionId: String, wasVoted: Boolean, before: LiveQaUiState) {
        val priorCount = before.questions.firstOrNull { it.id == questionId }?.upvotes
            ?: before.featured?.takeIf { it.id == questionId }?.upvotes
        _uiState.update { current ->
            current.copy(
                upvotedIds = if (wasVoted) current.upvotedIds + questionId else current.upvotedIds - questionId,
                questions = current.questions.map {
                    if (it.id == questionId && priorCount != null) it.copy(upvotes = priorCount) else it
                },
                featured = current.featured?.let {
                    if (it.id == questionId && priorCount != null) it.copy(upvotes = priorCount) else it
                },
                transientMessage = current.transientMessage ?: VOTE_FAILED,
            )
        }
    }

    fun onTransientMessageShown() {
        _uiState.update { it.copy(transientMessage = null) }
    }

    /** Starts bounded polling (default 8s) while the panel is resumed. Safe to call repeatedly. */
    fun startPolling() {
        if (_uiState.value.phase == LiveQaUiState.Phase.Disabled) return
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            while (true) {
                delay(POLL_INTERVAL_MS)
                refresh()
            }
        }
    }

    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    override fun onCleared() {
        pollJob?.cancel()
        voteJobs.values.forEach { it.cancel() }
    }

    companion object {
        const val POLL_INTERVAL_MS = 8_000L
        const val VOTE_FAILED = "Couldn't update your vote — try again"
    }
}
