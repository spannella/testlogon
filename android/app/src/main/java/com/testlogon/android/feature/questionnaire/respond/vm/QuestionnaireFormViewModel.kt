package com.testlogon.android.feature.questionnaire.respond.vm

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireDto
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.feature.questionnaire.respond.state.DefaultFieldValidator
import com.testlogon.android.feature.questionnaire.respond.state.DefaultVisibilityEvaluator
import com.testlogon.android.feature.questionnaire.respond.state.FieldAnswer
import com.testlogon.android.feature.questionnaire.respond.state.FieldValidator
import com.testlogon.android.feature.questionnaire.respond.state.FormVisibilityEvaluator
import com.testlogon.android.feature.questionnaire.respond.state.NoOpSubmitGateway
import com.testlogon.android.feature.questionnaire.respond.state.QuestionnaireFormReducer
import com.testlogon.android.feature.questionnaire.respond.state.QuestionnaireUiState
import com.testlogon.android.feature.questionnaire.respond.state.RespondentAnswers
import com.testlogon.android.feature.questionnaire.respond.state.SubmitGateway
import com.testlogon.android.feature.questionnaire.respond.state.SubmitPhase
import com.testlogon.android.feature.questionnaire.respond.state.SubmitResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-351 - the @HiltViewModel that owns the questionnaire FORM state machine (epic E45). It is a thin
 * shell over the PURE [QuestionnaireFormReducer]: it holds the single [StateFlow], performs the one side
 * effect (the [SubmitGateway] call) and otherwise delegates every transition to the reducer.
 *
 * ANTI-DUPLICATION: this is ADDITIVE to AND-348's RespondentSessionViewModel (the network/session VM is
 * UNTOUCHED). The validation + visibility rule logic is AND-350's (wrapped behind the
 * [FieldValidator] / [FormVisibilityEvaluator] seams, defaulting to
 * [DefaultFieldValidator] / [DefaultVisibilityEvaluator]). Submit is AND-349's, behind the
 * [SubmitGateway] seam (the default is a no-op stub so the form runs in isolation).
 *
 * SCHEMA HANDOFF (documented choice): a published schema is NOT a nav primitive and CANNOT be a bare Hilt
 * ctor param, so the VM is Hilt-constructed with only the (injectable) seams + SavedStateHandle, and the
 * schema is delivered via [hydrate] once the owner (the session VM / screen) has it. The optional resumed
 * session (AND-348) is passed through the same call. No network is performed here.
 *
 * Intents are public funs (the project idiom - see RespondentSessionViewModel) backed by a sealed
 * [QuestionnaireFormIntent] for callers that prefer dispatch. Single [StateFlow]; no poll loop; the only
 * suspending work is the gateway submit on [viewModelScope].
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
@HiltViewModel
class QuestionnaireFormViewModel @Inject constructor(
    private val validator: FieldValidator,
    private val visibility: FormVisibilityEvaluator,
    private val submitGateway: SubmitGateway,
    @Suppress("unused") private val savedState: SavedStateHandle,
) : ViewModel() {

    private val reducer = QuestionnaireFormReducer(validator, visibility)

    private val _uiState = MutableStateFlow<QuestionnaireUiState>(QuestionnaireUiState.Loading)
    val uiState: StateFlow<QuestionnaireUiState> = _uiState.asStateFlow()

    /**
     * AND-351 FR-9 - the schema + resumed session of the last [hydrate], retained so a [retry] after a
     * hydration [QuestionnaireUiState.Error] can re-run hydration WHILE preserving any answers the user
     * had already entered.
     */
    private var lastSchema: QuestionnaireDto? = null
    private var lastResumed: RespondentSession? = null

    /**
     * AND-351 FR-9 - answers stashed when hydration fails, so [retry] can restore them after the state has
     * already been replaced by [QuestionnaireUiState.Error] (which carries no answers).
     */
    private var preservedOnError: Map<String, FieldAnswer> = emptyMap()

    /** Guards against re-entrant submits while one gateway call is in flight. */
    private var submitInFlight = false

    /** Dispatches a [QuestionnaireFormIntent] to the matching handler (exhaustive when). */
    fun dispatch(intent: QuestionnaireFormIntent) {
        when (intent) {
            is QuestionnaireFormIntent.Hydrate -> hydrate(intent.schema, intent.resumed)
            is QuestionnaireFormIntent.FieldChanged -> onFieldChanged(intent.fieldId, intent.value)
            is QuestionnaireFormIntent.FieldBlurred -> onFieldBlurred(intent.fieldId)
            QuestionnaireFormIntent.Next -> onNext()
            QuestionnaireFormIntent.Previous -> onPrevious()
            is QuestionnaireFormIntent.GoToPage -> onGoToPage(intent.pageIndex)
            QuestionnaireFormIntent.Submit -> onSubmit()
            QuestionnaireFormIntent.Retry -> retry()
        }
    }

    /**
     * AND-351 FR-1 - hydrate the form from [schema] (+ optional [resumed] session seeds). Emits Ready.
     * Idempotent on the same inputs apart from re-seeding; preserves nothing from a prior Ready (use
     * [retry] for answer-preserving reload after an error).
     */
    fun hydrate(schema: QuestionnaireDto, resumed: RespondentSession? = null) {
        lastSchema = schema
        lastResumed = resumed
        _uiState.value = reducer.hydrate(schema, resumed)
    }

    /**
     * AND-351 - marks hydration failed (e.g. the owner could not fetch the schema). [retry] re-runs
     * hydration preserving any entered answers. Exposed so the owner can surface a load error through this
     * VM's single state stream.
     */
    fun onHydrationError(message: String, retryable: Boolean = true) {
        (_uiState.value as? QuestionnaireUiState.Ready)?.let { preservedOnError = it.answers }
        _uiState.value = QuestionnaireUiState.Error(message, retryable)
    }

    /** AND-351 FR-2 - the user changed [fieldId]'s answer. */
    fun onFieldChanged(fieldId: String, value: AnswerValue) {
        updateReady { reducer.onFieldChanged(it, fieldId, value) }
    }

    /** AND-351 FR-3 - the user left [fieldId] (blur). */
    fun onFieldBlurred(fieldId: String) {
        updateReady { reducer.onFieldBlurred(it, fieldId) }
    }

    /** AND-351 FR-6 - advance a page (blocked on an invalid current page). */
    fun onNext() = updateReady { reducer.onNext(it) }

    /** AND-351 FR-6 - go back a page. */
    fun onPrevious() = updateReady { reducer.onPrevious(it) }

    /** AND-351 FR-6 - jump to [pageIndex]. */
    fun onGoToPage(pageIndex: Int) = updateReady { reducer.onGoToPage(it, pageIndex) }

    /**
     * AND-351 FR-7 - submit. Validates first; if invalid, surfaces every error (submitAttempted) and does
     * NOT call the gateway. If valid, transitions to Submitting and calls the [SubmitGateway] on
     * [viewModelScope]; a Success -> Submitted(receipt), a Failure (or thrown error) -> Failed + the
     * message. Re-entrant calls while in flight are ignored.
     */
    fun onSubmit() {
        if (submitInFlight) return
        val ready = _uiState.value as? QuestionnaireUiState.Ready ?: return
        when (val start = reducer.beginSubmit(ready)) {
            is QuestionnaireFormReducer.SubmitStart.Blocked -> {
                _uiState.value = start.state
            }
            is QuestionnaireFormReducer.SubmitStart.Proceed -> {
                _uiState.value = start.state
                submitInFlight = true
                viewModelScope.launch {
                    val result: SubmitResult = try {
                        submitGateway.submit(start.snapshot)
                    } catch (e: Exception) {
                        SubmitResult.Failure(e.message ?: SUBMIT_FAILED)
                    }
                    finishSubmit(result)
                    submitInFlight = false
                }
            }
        }
    }

    private fun finishSubmit(result: SubmitResult) {
        val current = _uiState.value as? QuestionnaireUiState.Ready ?: return
        _uiState.value = when (result) {
            is SubmitResult.Success -> reducer.onSubmitSucceeded(current, result.receipt)
            is SubmitResult.Failure -> reducer.onSubmitFailed(current, result.message)
        }
    }

    /**
     * AND-351 FR-9 - retry after a hydration error: re-run hydration with the last schema, PRESERVING any
     * answers already entered into a prior Ready state (their dirty/touched flags survive). A no-op when
     * there is no schema to re-hydrate from.
     */
    fun retry() {
        val schema = lastSchema ?: return
        val preserved: Map<String, FieldAnswer> =
            (_uiState.value as? QuestionnaireUiState.Ready)?.answers ?: preservedOnError
        _uiState.value = reducer.hydrate(schema, lastResumed, preserved)
    }

    /** AND-351 FR-8 - the current answers snapshot (for AND-348 save/resume). */
    fun currentAnswersSnapshot(): RespondentAnswers {
        val ready = _uiState.value as? QuestionnaireUiState.Ready
            ?: return RespondentAnswers(emptyMap())
        return reducer.currentAnswersSnapshot(ready)
    }

    private inline fun updateReady(block: (QuestionnaireUiState.Ready) -> QuestionnaireUiState.Ready) {
        val ready = _uiState.value as? QuestionnaireUiState.Ready ?: return
        _uiState.value = block(ready)
    }

    companion object {
        private const val SUBMIT_FAILED = "Submission failed. Try again."
    }
}

/**
 * AND-351 - the form intents, exposed for callers that prefer a single [QuestionnaireFormViewModel.dispatch]
 * entry over the public funs. Sealed + exhaustive.
 */
sealed interface QuestionnaireFormIntent {
    /** FR-1 - hydrate from [schema] (+ optional [resumed] session). */
    data class Hydrate(val schema: QuestionnaireDto, val resumed: RespondentSession? = null) :
        QuestionnaireFormIntent

    /** FR-2 - [fieldId] answer changed to [value]. */
    data class FieldChanged(val fieldId: String, val value: AnswerValue) : QuestionnaireFormIntent

    /** FR-3 - [fieldId] blurred. */
    data class FieldBlurred(val fieldId: String) : QuestionnaireFormIntent

    /** FR-6 - next page. */
    data object Next : QuestionnaireFormIntent

    /** FR-6 - previous page. */
    data object Previous : QuestionnaireFormIntent

    /** FR-6 - go to [pageIndex]. */
    data class GoToPage(val pageIndex: Int) : QuestionnaireFormIntent

    /** FR-7 - submit. */
    data object Submit : QuestionnaireFormIntent

    /** FR-9 - retry hydration (preserving answers). */
    data object Retry : QuestionnaireFormIntent
}
