package com.testlogon.android.feature.questionnaire.respond.state

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireDto
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.core.model.questionnaire.QuestionnaireSection
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-351 - PURE tests for [QuestionnaireFormReducer] (no coroutines, no Android). Two layers:
 * (1) reducer transitions against simple stub seams, and
 * (2) the DEFAULT seams ([DefaultFieldValidator] / [DefaultVisibilityEvaluator]) really delegating to the
 *     AND-350 evaluators - proving the REUSE wiring (a required constraint actually fires, an all-visible
 *     default holds with no rules).
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
class QuestionnaireFormReducerTest {

    private val allVisible = FormVisibilityEvaluator { fields, _ -> fields.map { it.questionId }.toSet() }
    private val noErrors = FieldValidator { _, _, _ -> emptyList() }

    private fun textField(id: String, sectionId: String, required: Boolean = false) =
        QuestionnaireField.Text(
            questionId = id,
            sectionId = sectionId,
            label = id,
            required = required,
        )

    private fun schema() = QuestionnaireDto(
        questionnaire_id = "q",
        sections = listOf(
            QuestionnaireSection(section_id = "s1", questions = listOf(textField("a", "s1"))),
            QuestionnaireSection(section_id = "s2", questions = listOf(textField("b", "s2"))),
        ),
    )

    @Test
    fun `hydrate computes page count per section`() {
        val reducer = QuestionnaireFormReducer(noErrors, allVisible)
        val state = reducer.hydrate(schema())
        assertEquals(2, state.pageCount)
        assertEquals(listOf("a", "b"), state.orderedFields.map { it.questionId })
    }

    @Test
    fun `field change recompute keeps other field identity`() {
        val reducer = QuestionnaireFormReducer(noErrors, allVisible)
        val state = reducer.hydrate(schema())
        val before = state.answers["b"]
        val after = reducer.onFieldChanged(state, "a", AnswerValue.Text("x"))
        // b's cell is the same instance (no churn).
        assertTrue(before === after.answers["b"])
    }

    @Test
    fun `beginSubmit blocked when invalid`() {
        val reducer = QuestionnaireFormReducer(
            FieldValidator { _, _, _ -> listOf("bad") },
            allVisible,
        )
        val state = reducer.hydrate(schema())
        val start = reducer.beginSubmit(state)
        assertTrue(start is QuestionnaireFormReducer.SubmitStart.Blocked)
    }

    @Test
    fun `beginSubmit proceeds when valid and carries snapshot`() {
        val reducer = QuestionnaireFormReducer(noErrors, allVisible)
        var state = reducer.hydrate(schema())
        state = reducer.onFieldChanged(state, "a", AnswerValue.Num(3.5))
        val start = reducer.beginSubmit(state)
        assertTrue(start is QuestionnaireFormReducer.SubmitStart.Proceed)
        val proceed = start as QuestionnaireFormReducer.SubmitStart.Proceed
        val num = proceed.snapshot.values["a"] as AnswerValue.Num
        assertEquals(3.5, num.value, 0.0001)
    }

    // ---- AND-350 reuse proof ----

    @Test
    fun `default validator delegates to AND-350 required constraint`() {
        val reducer = QuestionnaireFormReducer(DefaultFieldValidator, DefaultVisibilityEvaluator)
        val requiredSchema = QuestionnaireDto(
            questionnaire_id = "q",
            sections = listOf(
                QuestionnaireSection(
                    section_id = "s1",
                    questions = listOf(textField("a", "s1", required = true)),
                ),
            ),
        )
        val state = reducer.hydrate(requiredSchema)
        // Required + empty -> AND-350 ClientValidator produces a required error -> aggregate invalid.
        assertFalse(state.isValid)
        assertTrue(state.validation["a"]!!.errors.isNotEmpty())
    }

    @Test
    fun `default visibility is all-visible when no rules`() {
        val reducer = QuestionnaireFormReducer(DefaultFieldValidator, DefaultVisibilityEvaluator)
        val state = reducer.hydrate(schema())
        assertEquals(setOf("a", "b"), state.visibleFieldIds)
    }
}
