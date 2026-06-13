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
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
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

    private var syncJob: Job? = null

    init {
        if (slug.isBlank()) {
            _uiState.value = RespondentSessionUiState.Error(ApiError(ApiError.STATUS_PARSE, MISSING_SLUG))
        } else {
            load { repository.startOrResume(slug) }
        }
    }

    /** Re-runs start/resume (e.g. retry after a load error). */
    fun onReload() {
        if (slug.isBlank()) return
        load { repository.startOrResume(slug) }
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
