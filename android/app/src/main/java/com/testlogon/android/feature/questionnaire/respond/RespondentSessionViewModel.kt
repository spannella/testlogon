package com.testlogon.android.feature.questionnaire.respond

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.feature.questionnaire.respond.data.RespondentSessionRepository
import com.testlogon.android.feature.questionnaire.respond.data.SessionStartOutcome
import com.testlogon.android.feature.questionnaire.respond.data.SessionValidation
import com.testlogon.android.feature.questionnaire.respond.data.SubmitOutcome
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

/**
 * AND-348 - presentation logic for the respondent session lifecycle (epic E45). SUBMIT + PDF are OUT OF
 * SCOPE (AND-349); this VM hands off [RespondentSessionUiState.Active.canSubmit].
 *
 * Autosave: [onAnswerChanged] updates the in-memory answers, calls the repo's [saveLocal] IMMEDIATELY
 * (FR-5, never blocks on network), then DEBOUNCES a single [syncSave] via a cancellable [Job] that
 * delay()s [debounceMillis] before flushing (the prior job is cancelled). No poll loop. The delay runs
 * on [viewModelScope] (Dispatchers.Main -> the test TestDispatcher under MainDispatcherRule), so tests
 * drive it with the test scheduler (runCurrent / advanceTimeBy), never advanceUntilIdle.
 *
 * Offline (FR-5): a failed sync leaves the draft dirty and shows SYNC_ERROR; the buffered edit shows
 * SYNC_PENDING until the debounce fires. Schema-version safety (FR-6) surfaces [SchemaChanged].
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
@HiltViewModel
class RespondentSessionViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val repository: RespondentSessionRepository,
) : ViewModel() {

    val slug: String = savedState.get<String>(ARG_SLUG).orEmpty()

    /** Autosave debounce window (ms). NOT a ctor param (Hilt cannot inject a bare Long); tests set it. */
    internal var debounceMillis: Long = DEFAULT_DEBOUNCE_MILLIS

    private val _uiState = MutableStateFlow<RespondentSessionUiState>(RespondentSessionUiState.Loading)
    val uiState: StateFlow<RespondentSessionUiState> = _uiState.asStateFlow()

    /**
     * AND-349 - one-shot effects (the PDF [OpenPdf] hand-off the screen relays to OpenWithLauncher). A
     * BUFFERED Channel consumed exactly once; never replayed on recomposition.
     */
    private val _effects = Channel<RespondEffect>(Channel.BUFFERED)
    val effects: Flow<RespondEffect> = _effects.receiveAsFlow()

    /**
     * AND-349 - schema question order (set by the screen once the schema is known) used to compute the
     * first-errored field for scroll-to-first on a rejected submit. Empty -> the first error key wins.
     */
    var fieldOrder: List<String> = emptyList()

    private var syncJob: Job? = null

    /** AND-349 - guards against a double-tap on Submit while one is in flight. */
    private var submitting = false

    init {
        if (slug.isBlank()) {
            _uiState.value = RespondentSessionUiState.Error(ApiError(ApiError.STATUS_PARSE, MISSING_SLUG))
        } else {
            // AND-349 FR-7: a session already submitted on this device opens directly in the terminal
            // confirmation (re-submit guard) rather than re-editing; otherwise start/resume as normal.
            viewModelScope.launch {
                if (repository.isAlreadySubmitted(slug)) {
                    loadAlreadySubmitted()
                } else {
                    loadStartOrResume()
                }
            }
        }
    }

    private fun loadStartOrResume() = load { repository.startOrResume(slug) }

    /** Re-runs start/resume (e.g. retry after a load error). */
    fun onReload() {
        if (slug.isBlank()) return
        loadStartOrResume()
    }

    /**
     * FR-1/2 - drives a start/resume-shaped outcome into the UI state. SchemaChanged surfaces the
     * prompt; Failed becomes Error; Ready becomes Active (preserving any field errors / canSubmit is
     * reset because the answers are now the server-fresh set).
     */
    private fun load(block: suspend () -> SessionStartOutcome) {
        _uiState.value = RespondentSessionUiState.Loading
        viewModelScope.launch {
            when (val outcome = block()) {
                is SessionStartOutcome.Ready -> _uiState.value = active(outcome.session)
                is SessionStartOutcome.SchemaChanged ->
                    _uiState.value = RespondentSessionUiState.SchemaChanged(outcome.slug)
                is SessionStartOutcome.Failed ->
                    _uiState.value = RespondentSessionUiState.Error(errorOf(outcome.error))
            }
        }
    }

    /**
     * FR-5 - the user changed an answer: update in-memory immediately, persist the dirty draft
     * immediately (never blocking on network), mark SYNC_PENDING, and (re)arm the debounced sync.
     */
    fun onAnswerChanged(questionId: String, value: AnswerValue) {
        val current = _uiState.value as? RespondentSessionUiState.Active ?: return
        val newAnswers = current.answers + (questionId to value)
        // Clear any stale field error for this question now that it has been edited.
        val newErrors = current.fieldErrors - questionId
        _uiState.value = current.copy(
            answers = newAnswers,
            fieldErrors = newErrors,
            syncState = SyncState.SYNC_PENDING,
        )
        viewModelScope.launch {
            repository.saveLocal(current.session, newAnswers)
        }
        scheduleSync()
    }

    /** FR-3 - explicit save: cancel the debounce and flush immediately. */
    fun onSaveNow() {
        if (_uiState.value !is RespondentSessionUiState.Active) return
        syncJob?.cancel()
        runSync()
    }

    /**
     * FR-4/8 - save-and-continue / advance: flush any pending edit, then validate and map the field
     * errors + canSubmit. Used by the screen's "Continue" / section-advance affordance.
     */
    fun onSaveAndContinue() {
        if (_uiState.value !is RespondentSessionUiState.Active) return
        syncJob?.cancel()
        viewModelScope.launch {
            // Flush the latest edits first so validate sees the saved answers (best-effort).
            flushOnce()
            applyValidation(repository.validate(slug, finalSubmit = false))
        }
    }

    /** FR-4 - alias for an explicit section advance; same validate-then-map behaviour. */
    fun onAdvanceSection() = onSaveAndContinue()

    /** FR-7 - discard the local draft and start a brand-new session. */
    fun onStartOver() {
        if (slug.isBlank()) return
        syncJob?.cancel()
        load { repository.startOver(slug) }
    }

    /** FR-6 - the user accepted the schema change: adopt the new schema (start over) and reload. */
    fun onReloadSchema() {
        if (slug.isBlank()) return
        syncJob?.cancel()
        load { repository.startOver(slug) }
    }

    // ---- AND-349 submit + PDF ----

    /**
     * AND-349 FR-2/3/4 - the terminal action. Disables the form + blocks a double-tap while in flight,
     * flushes-then-submits via the repository (NO auto-retry). On Submitted -> the terminal confirmation
     * (form non-editable). On a 200 with can_submit==false -> the field errors are merged back into Active
     * and [Active.firstErrorQuestionId] drives scroll-to-first (NOT a success). On a transport/HTTP
     * failure -> a retryable inline error WITHOUT losing the draft (the Active answers are untouched).
     */
    fun onSubmit() {
        if (submitting) return
        val current = _uiState.value as? RespondentSessionUiState.Active ?: return
        // FR-1 gate: submit is only meaningful with a verdict + a real session.
        if (!current.canSubmit || current.session.sessionId.isBlank()) return
        submitting = true
        syncJob?.cancel()
        _uiState.value = current.copy(submitting = true)
        viewModelScope.launch {
            try {
                when (val outcome = repository.submit(slug, fieldOrder)) {
                    is SubmitOutcome.Submitted -> _uiState.value = RespondentSessionUiState.Submitted(
                        sessionId = outcome.sessionId,
                        sessionStatus = outcome.sessionStatus,
                    )
                    is SubmitOutcome.ValidationFailed -> {
                        val active = _uiState.value as? RespondentSessionUiState.Active ?: return@launch
                        _uiState.value = active.copy(
                            submitting = false,
                            canSubmit = outcome.validation.canSubmit,
                            fieldErrors = outcome.validation.fieldErrors,
                            firstErrorQuestionId = outcome.validation.firstErrorQuestionId,
                        )
                    }
                    is SubmitOutcome.Failed -> {
                        // FR-8: keep the draft; surface a retryable error inline (stay editable).
                        val active = _uiState.value as? RespondentSessionUiState.Active ?: return@launch
                        _uiState.value = active.copy(submitting = false, syncState = SyncState.SYNC_ERROR)
                        _effects.send(RespondEffect.ShowError(errorMessageOf(outcome)))
                    }
                }
            } finally {
                submitting = false
            }
        }
    }

    /**
     * AND-349 - clears the scroll-to-first marker after the screen has consumed it (so a recomposition or
     * a manual edit does not re-trigger the scroll).
     */
    fun onFirstErrorConsumed() {
        val current = _uiState.value as? RespondentSessionUiState.Active ?: return
        if (current.firstErrorQuestionId != null) {
            _uiState.value = current.copy(firstErrorQuestionId = null)
        }
    }

    /**
     * AND-349 FR-5 - generates + downloads the response PDF to cache, then emits a one-shot [OpenPdf]
     * effect the screen hands to OpenWithLauncher (system chooser). Only valid in the terminal Submitted
     * state. A failure surfaces a retryable [PdfState.Error]; no auto-retry.
     */
    fun onDownloadPdf() {
        val current = _uiState.value as? RespondentSessionUiState.Submitted ?: return
        if (current.pdfState is PdfState.Downloading) return
        _uiState.value = current.copy(pdfState = PdfState.Downloading)
        viewModelScope.launch {
            when (val result = repository.downloadSubmissionPdf(slug)) {
                is ApiResult.Success -> {
                    setPdfState(PdfState.Idle)
                    _effects.send(RespondEffect.OpenPdf(result.data))
                }
                is ApiResult.Failure -> setPdfState(PdfState.Error(result.error.message))
                is ApiResult.NetworkError -> setPdfState(PdfState.Error(OFFLINE))
            }
        }
    }

    /** AND-349 - loads the terminal Submitted state for an already-submitted session (FR-7, cold start). */
    private fun loadAlreadySubmitted() {
        viewModelScope.launch {
            when (val outcome = repository.startOrResume(slug)) {
                is SessionStartOutcome.Ready -> _uiState.value = RespondentSessionUiState.Submitted(
                    sessionId = outcome.session.sessionId,
                    sessionStatus = outcome.session.status,
                )
                is SessionStartOutcome.SchemaChanged ->
                    _uiState.value = RespondentSessionUiState.SchemaChanged(outcome.slug)
                is SessionStartOutcome.Failed ->
                    _uiState.value = RespondentSessionUiState.Error(errorOf(outcome.error))
            }
        }
    }

    private fun setPdfState(state: PdfState) {
        _uiState.update { s ->
            if (s is RespondentSessionUiState.Submitted) s.copy(pdfState = state) else s
        }
    }

    private fun errorMessageOf(failed: SubmitOutcome.Failed): String =
        failed.error.message.ifBlank { OFFLINE }

    // ---- sync internals ----

    /** Arms a single debounced sync, cancelling any prior pending one (NO poll loop). */
    private fun scheduleSync() {
        syncJob?.cancel()
        syncJob = viewModelScope.launch {
            delay(debounceMillis)
            runSync()
        }
    }

    /** Performs one sync, updating [SyncState] (SAVING -> SYNCED / SYNC_ERROR). */
    private fun runSync() {
        viewModelScope.launch {
            setSync(SyncState.SAVING)
            when (val result = repository.syncSave(slug)) {
                is ApiResult.Success -> setSync(SyncState.SYNCED)
                is ApiResult.Failure -> setSync(SyncState.SYNC_ERROR)
                is ApiResult.NetworkError -> setSync(SyncState.SYNC_ERROR)
            }
        }
    }

    /** Flushes one sync inline (for save-and-continue); ignores the outcome's sync indicator nuance. */
    private suspend fun flushOnce() {
        setSync(SyncState.SAVING)
        when (repository.syncSave(slug)) {
            is ApiResult.Success -> setSync(SyncState.SYNCED)
            else -> setSync(SyncState.SYNC_ERROR)
        }
    }

    private fun applyValidation(result: ApiResult<SessionValidation>) {
        val current = _uiState.value as? RespondentSessionUiState.Active ?: return
        when (result) {
            is ApiResult.Success -> _uiState.value = current.copy(
                fieldErrors = result.data.fieldErrors,
                canSubmit = result.data.canSubmit,
            )
            // A failed validate does not clobber the working answers; the sync indicator already
            // reflects any save failure. canSubmit is conservatively cleared.
            is ApiResult.Failure, is ApiResult.NetworkError ->
                _uiState.value = current.copy(canSubmit = false)
        }
    }

    private fun setSync(state: SyncState) {
        _uiState.update { s ->
            if (s is RespondentSessionUiState.Active) s.copy(syncState = state) else s
        }
    }

    private fun active(session: RespondentSession): RespondentSessionUiState.Active =
        RespondentSessionUiState.Active(
            session = session,
            answers = session.answers,
            syncState = SyncState.SYNCED,
        )

    private fun errorOf(failure: ApiResult<Nothing>): ApiError = when (failure) {
        is ApiResult.Failure -> failure.error
        is ApiResult.NetworkError -> ApiError(ApiError.STATUS_NETWORK, OFFLINE)
        is ApiResult.Success -> ApiError(ApiError.STATUS_PARSE, MISSING_SLUG)
    }

    override fun onCleared() {
        syncJob?.cancel()
    }

    companion object {
        /** Nav arg carrying the published-questionnaire slug. */
        const val ARG_SLUG = "slug"

        /** Default autosave debounce window (ms). Override via [debounceMillis] in tests. */
        const val DEFAULT_DEBOUNCE_MILLIS = 800L

        private const val MISSING_SLUG = "No questionnaire was specified."
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}

/**
 * AND-349 - one-shot effects emitted by [RespondentSessionViewModel] for the screen to act on exactly
 * once (NOT replayed on recomposition). [OpenPdf] hands a downloaded PDF [File] to OpenWithLauncher (the
 * system chooser); [ShowError] surfaces a transient submit error.
 */
sealed interface RespondEffect {
    /** Open the downloaded response PDF [file] via the system chooser (OpenWithLauncher). */
    data class OpenPdf(val file: File) : RespondEffect

    /** Show a transient error [message] (e.g. a retryable submit failure). */
    data class ShowError(val message: String) : RespondEffect
}
