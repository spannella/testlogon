package com.testlogon.android.feature.questionnaire.respond.state

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField

/**
 * AND-351 - the PURE, Android-free presentation STATE for the respondent questionnaire FORM state
 * machine (epic E45). This is the transient form layer that AND-347's renderer binds to and whose seams
 * AND-348 (session network), AND-349 (submit) and AND-350 (validation + visibility) plug into.
 *
 * ANTI-DUPLICATION: this does NOT own the network session ([com.testlogon.android.feature.questionnaire
 * .respond.RespondentSessionViewModel] does, AND-348), nor the inline rule logic (AND-350's
 * ClientValidator + VisibilityEvaluator do, wrapped behind this package's seams), nor submit/PDF wire
 * calls (AND-349 does, behind the SubmitGateway seam). Its UNIQUE additive value is the normalized
 * per-field answer map with dirty/touched tracking, touched-gated error display, paged/section
 * navigation, and the submit lifecycle expressed as explicit phases.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */

/**
 * AND-351 - one field's transient answer cell. [value] is the normalized answer; [dirty] flips true the
 * first time the user edits it (FR-2); [touched] flips true on blur (FR-3) and gates inline error
 * display together with submitAttempted.
 */
data class FieldAnswer(
    val value: AnswerValue,
    val dirty: Boolean = false,
    val touched: Boolean = false,
)

/**
 * AND-351 - the validation verdict for a single field: an ordered list of human messages. [isValid] is
 * the derived "no errors" view. These come from the [FieldValidator] seam (default delegates to AND-350
 * ClientValidator); hidden fields are never validated (FR-5).
 */
data class FieldValidation(
    val errors: List<String> = emptyList(),
) {
    val isValid: Boolean get() = errors.isEmpty()
}

/**
 * AND-351 FR-7 - the submit lifecycle as explicit, exhaustive phases:
 * Idle -> Validating -> Submitting -> Submitted(receipt) on success, or -> Failed on a gateway error.
 * Validation MUST pass before Submitting (the VM never transitions Validating -> Submitting on invalid).
 */
sealed interface SubmitPhase {
    /** No submit in flight. */
    data object Idle : SubmitPhase

    /** Pre-submit validation pass running (synchronous in practice, but a distinct observable phase). */
    data object Validating : SubmitPhase

    /** The SubmitGateway call is in flight. */
    data object Submitting : SubmitPhase

    /** The gateway accepted the submission. [receipt] is the optional server handle (may be null). */
    data class Submitted(val receipt: String?) : SubmitPhase

    /** The gateway rejected/failed the submission; see [QuestionnaireUiState.Ready.submitError]. */
    data object Failed : SubmitPhase
}

/**
 * AND-351 - the immutable UI state of the questionnaire form. Sealed + exhaustive: Loading while the
 * schema is being hydrated, Error on a hydration failure (retryable preserves entered answers, FR-9),
 * and Ready carrying the full form snapshot the renderer binds to.
 */
sealed interface QuestionnaireUiState {

    /** Hydration in progress (no schema yet). */
    data object Loading : QuestionnaireUiState

    /** Hydration failed. [retryable] drives a Retry affordance (FR-9). */
    data class Error(val message: String, val retryable: Boolean = true) : QuestionnaireUiState

    /**
     * The form is hydrated and editable.
     *
     * @property orderedFields ALL fields in schema/section declaration order (FR-1) - the renderer
     *   filters to [visibleFieldIds].
     * @property visibleFieldIds the currently-visible field ids (FR-5) from the VisibilityEvaluator seam.
     * @property answers normalized per-field cells keyed by questionId (dirty/touched, FR-2/3).
     * @property validation per-field verdicts (visible fields only contribute to [isValid]).
     * @property isValid aggregate over VISIBLE fields ONLY - hidden fields are excluded (FR-5).
     * @property currentPageIndex the active page (a "page" == a section; FR-6).
     * @property pageCount total pages (1 when unsectioned, FR-6).
     * @property submitAttempted set by a blocked Next or a blocked Submit; un-gates error display (FR-3).
     * @property submit the submit lifecycle phase (FR-7).
     * @property submitError the last gateway failure message (null unless [submit] is Failed).
     */
    data class Ready(
        val orderedFields: List<QuestionnaireField>,
        val visibleFieldIds: Set<String>,
        val answers: Map<String, FieldAnswer>,
        val validation: Map<String, FieldValidation>,
        val isValid: Boolean,
        val currentPageIndex: Int,
        val pageCount: Int,
        val submitAttempted: Boolean = false,
        val submit: SubmitPhase = SubmitPhase.Idle,
        val submitError: String? = null,
    ) : QuestionnaireUiState {

        /**
         * AND-351 FR-3 - the per-field errors the renderer should DISPLAY right now: a field's errors are
         * surfaced only once it is touched OR a submit/next has been attempted. Fields gated off are
         * absent from the map (not present with an empty list).
         */
        val displayedErrors: Map<String, List<String>>
            get() = buildMap {
                for ((id, v) in validation) {
                    if (v.errors.isEmpty()) continue
                    val touched = answers[id]?.touched == true
                    if (touched || submitAttempted) put(id, v.errors)
                }
            }
    }
}
