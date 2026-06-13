package com.testlogon.android.feature.questionnaire.respond.state

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireDto
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.core.model.questionnaire.RespondentSession

/**
 * AND-351 - the PURE (Android-free, no coroutines, no network) reducer that owns every form state
 * transition: hydration, field change, blur, recompute of visibility + validation + aggregate validity,
 * paged navigation, and the submit-phase folds. The [QuestionnaireFormViewModel] is a thin Hilt shell
 * that owns the StateFlow + the one side effect (the SubmitGateway call) and delegates ALL logic here, so
 * the logic is unit-testable in complete isolation.
 *
 * The reducer takes the two PURE seams ([FieldValidator] + [FormVisibilityEvaluator]) as constructor deps
 * (the SubmitGateway is a suspend side effect and stays in the VM). Reducer functions return a fresh
 * immutable [QuestionnaireUiState]; they never mutate.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
class QuestionnaireFormReducer(
    private val validator: FieldValidator,
    private val visibility: FormVisibilityEvaluator,
) {

    /**
     * AND-351 FR-1 - builds the ordered field list from [schema] sections (declaration order preserved),
     * seeds answers from [resumed] session values (or [AnswerValue.Empty] when absent), computes the page
     * layout (one page per section, min one), then computes visibility + validation + aggregate validity
     * and returns [QuestionnaireUiState.Ready]. Seeded answers are NOT dirty/touched.
     *
     * [preservedAnswers] (FR-9) lets a Retry re-hydrate while keeping the user's already-entered values:
     * a preserved cell wins over the resumed/default seed and retains its dirty/touched flags.
     */
    fun hydrate(
        schema: QuestionnaireDto,
        resumed: RespondentSession? = null,
        preservedAnswers: Map<String, FieldAnswer> = emptyMap(),
    ): QuestionnaireUiState.Ready {
        val orderedFields = orderedFieldsOf(schema)
        val sectionIds = schema.sections.map { it.section_id }
        val pageCount = maxOf(1, sectionIds.size)

        val seeded = LinkedHashMap<String, FieldAnswer>()
        for (field in orderedFields) {
            val id = field.questionId
            val preserved = preservedAnswers[id]
            if (preserved != null) {
                seeded[id] = preserved
                continue
            }
            val resumedValue = resumed?.answers?.get(id)
            seeded[id] = FieldAnswer(value = resumedValue ?: AnswerValue.Empty)
        }

        val base = QuestionnaireUiState.Ready(
            orderedFields = orderedFields,
            visibleFieldIds = emptySet(),
            answers = seeded,
            validation = emptyMap(),
            isValid = false,
            currentPageIndex = 0,
            pageCount = pageCount,
        )
        return recompute(base)
    }

    /**
     * AND-351 FR-2 - applies a single field edit: replaces ONLY that [fieldId]'s cell (value updated,
     * dirty=true; touched preserved), then recomputes visibility + that field's validation + the
     * aggregate. No other field's identity changes. A no-op (returns [state] unchanged) when the field is
     * unknown.
     */
    fun onFieldChanged(
        state: QuestionnaireUiState.Ready,
        fieldId: String,
        value: AnswerValue,
    ): QuestionnaireUiState.Ready {
        val existing = state.answers[fieldId] ?: return state
        val updated = existing.copy(value = value, dirty = true)
        val answers = state.answers.toMutableMap().apply { put(fieldId, updated) }
        return recompute(state.copy(answers = answers))
    }

    /**
     * AND-351 FR-3 - marks [fieldId] touched (un-gating its inline errors). No validity change. No-op for
     * an unknown field.
     */
    fun onFieldBlurred(
        state: QuestionnaireUiState.Ready,
        fieldId: String,
    ): QuestionnaireUiState.Ready {
        val existing = state.answers[fieldId] ?: return state
        if (existing.touched) return state
        val answers = state.answers.toMutableMap().apply { put(fieldId, existing.copy(touched = true)) }
        return state.copy(answers = answers)
    }

    /**
     * AND-351 FR-6 - advance to the next page. BLOCKED when the current page has invalid VISIBLE fields:
     * in that case it sets submitAttempted=true (so the page's errors surface) and stays put. Otherwise it
     * advances (clamped to the last page).
     */
    fun onNext(state: QuestionnaireUiState.Ready): QuestionnaireUiState.Ready {
        if (!currentPageValid(state)) {
            return state.copy(submitAttempted = true)
        }
        val next = (state.currentPageIndex + 1).coerceAtMost(state.pageCount - 1)
        return state.copy(currentPageIndex = next)
    }

    /** AND-351 FR-6 - go to the previous page (clamped to 0). Never blocked. */
    fun onPrevious(state: QuestionnaireUiState.Ready): QuestionnaireUiState.Ready {
        val prev = (state.currentPageIndex - 1).coerceAtLeast(0)
        return state.copy(currentPageIndex = prev)
    }

    /** AND-351 FR-6 - jump to [pageIndex] (clamped to a valid page). Never blocked. */
    fun onGoToPage(state: QuestionnaireUiState.Ready, pageIndex: Int): QuestionnaireUiState.Ready {
        val clamped = pageIndex.coerceIn(0, state.pageCount - 1)
        return state.copy(currentPageIndex = clamped)
    }

    /**
     * AND-351 FR-7 - begin a submit. Validates first (over ALL visible fields). When invalid: set
     * submitAttempted (so every error surfaces) and return [SubmitStart.Blocked] WITHOUT changing the
     * phase - the VM does not call the gateway. When valid: move to [SubmitPhase.Validating] then
     * [SubmitPhase.Submitting] and return [SubmitStart.Proceed] carrying the snapshot the VM submits.
     */
    fun beginSubmit(state: QuestionnaireUiState.Ready): SubmitStart {
        val recomputed = recompute(state)
        if (!recomputed.isValid) {
            return SubmitStart.Blocked(
                recomputed.copy(submitAttempted = true, submit = SubmitPhase.Idle),
            )
        }
        val submitting = recomputed.copy(
            submitAttempted = true,
            submit = SubmitPhase.Submitting,
            submitError = null,
        )
        return SubmitStart.Proceed(submitting, currentAnswersSnapshot(recomputed))
    }

    /** AND-351 FR-7 - fold a successful gateway result into [SubmitPhase.Submitted]. */
    fun onSubmitSucceeded(
        state: QuestionnaireUiState.Ready,
        receipt: String?,
    ): QuestionnaireUiState.Ready =
        state.copy(submit = SubmitPhase.Submitted(receipt), submitError = null)

    /** AND-351 FR-7 - fold a gateway failure into [SubmitPhase.Failed] + the error message. */
    fun onSubmitFailed(
        state: QuestionnaireUiState.Ready,
        message: String,
    ): QuestionnaireUiState.Ready =
        state.copy(submit = SubmitPhase.Failed, submitError = message)

    /** AND-351 FR-8 - the immutable answer snapshot for AND-348 save/resume and the gateway. */
    fun currentAnswersSnapshot(state: QuestionnaireUiState.Ready): RespondentAnswers =
        RespondentAnswers(values = state.answers.mapValues { it.value.value })

    // ---- internals ----

    /**
     * Recomputes visibility (seam), per-field validation (seam, VISIBLE fields only) and the aggregate
     * [QuestionnaireUiState.Ready.isValid] (over VISIBLE fields only - hidden fields are EXCLUDED, FR-5).
     * Validation entries for hidden fields are dropped so stale errors never linger.
     */
    fun recompute(state: QuestionnaireUiState.Ready): QuestionnaireUiState.Ready {
        val rawAnswers = state.answers.mapValues { it.value.value }
        val visibleIds = visibility.visibleFieldIds(state.orderedFields, rawAnswers)

        val validation = LinkedHashMap<String, FieldValidation>()
        var allValid = true
        for (field in state.orderedFields) {
            val id = field.questionId
            if (id !in visibleIds) continue
            val value = rawAnswers[id] ?: AnswerValue.Empty
            val errors = validator.validate(field, value, rawAnswers)
            validation[id] = FieldValidation(errors)
            if (errors.isNotEmpty()) allValid = false
        }
        return state.copy(
            visibleFieldIds = visibleIds,
            validation = validation,
            isValid = allValid,
        )
    }

    /** True when every VISIBLE field on the CURRENT page is valid (FR-6 Next gate). */
    private fun currentPageValid(state: QuestionnaireUiState.Ready): Boolean {
        val pageSectionId = sectionIdForPage(state)
        for (field in state.orderedFields) {
            if (field.questionId !in state.visibleFieldIds) continue
            if (pageSectionId != null && field.sectionId != pageSectionId) continue
            val v = state.validation[field.questionId]
            if (v != null && !v.isValid) return false
        }
        return true
    }

    /**
     * The section id backing the current page, or null when the schema is unsectioned (single page over
     * all fields). Derived from the orderedFields' distinct section ids in first-seen order.
     */
    private fun sectionIdForPage(state: QuestionnaireUiState.Ready): String? {
        val sectionIds = state.orderedFields.map { it.sectionId }.distinct()
        if (sectionIds.size <= 1) return null
        return sectionIds.getOrNull(state.currentPageIndex)
    }

    private fun orderedFieldsOf(schema: QuestionnaireDto): List<QuestionnaireField> =
        schema.sections.flatMap { it.questions }

    /** AND-351 FR-7 - the outcome of [beginSubmit]: either blocked (invalid) or proceed (with snapshot). */
    sealed interface SubmitStart {
        /** Validation failed; [state] has submitAttempted set and phase Idle. Do NOT call the gateway. */
        data class Blocked(val state: QuestionnaireUiState.Ready) : SubmitStart

        /** Valid; [state] is in [SubmitPhase.Submitting] and [snapshot] is what to submit. */
        data class Proceed(
            val state: QuestionnaireUiState.Ready,
            val snapshot: RespondentAnswers,
        ) : SubmitStart
    }
}
