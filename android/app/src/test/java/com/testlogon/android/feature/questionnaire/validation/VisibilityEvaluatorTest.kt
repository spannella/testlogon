package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-350 - JVM tests for the PURE [VisibilityEvaluator]: simple show/hide, transitive cascade (hiding a
 * controller hides its dependents), terminating cycle detection (fail open), and order preservation.
 */
class VisibilityEvaluatorTest {

    private fun field(id: String, visibleWhen: Map<String, Any?>? = null): QuestionnaireField =
        QuestionnaireField.Text(
            questionId = id,
            sectionId = "s",
            label = id,
            required = false,
            configJson = if (visibleWhen != null) mapOf("visible_when" to visibleWhen) else emptyMap(),
        )

    private fun showWhenEq(q: String, value: String): Map<String, Any?> =
        mapOf("question_id" to q, "op" to "eq", "value" to value)

    @Test
    fun noRules_allVisible_orderPreserved() {
        val fields = listOf(field("a"), field("b"), field("c"))
        val result = VisibilityEvaluator.evaluate(fields, emptyMap())
        assertEquals(listOf("a", "b", "c"), result.visibleQuestionIds)
    }

    @Test
    fun simpleShowHide() {
        val fields = listOf(field("ctrl"), field("dep", showWhenEq("ctrl", "yes")))
        // Controller not "yes" -> dependent hidden.
        val hidden = VisibilityEvaluator.evaluate(fields, mapOf("ctrl" to AnswerValue.Text("no")))
        assertEquals(listOf("ctrl"), hidden.visibleQuestionIds)
        // Controller "yes" -> dependent shown.
        val shown = VisibilityEvaluator.evaluate(fields, mapOf("ctrl" to AnswerValue.Text("yes")))
        assertEquals(listOf("ctrl", "dep"), shown.visibleQuestionIds)
    }

    @Test
    fun transitiveCascade_hidingControllerHidesDependents() {
        // a controls b; b controls c. Hide a -> b hides -> c cascade-hides (b reads as empty).
        val fields = listOf(
            field("a"),
            field("b", showWhenEq("a", "yes")),
            field("c", showWhenEq("b", "yes")),
        )
        // a is "no": b hidden; even though c's controller b would be "yes" only if answered, b is hidden
        // so its answer is masked -> c also hidden.
        val answers = mapOf(
            "a" to AnswerValue.Text("no"),
            "b" to AnswerValue.Text("yes"),
            "c" to AnswerValue.Text("anything"),
        )
        val result = VisibilityEvaluator.evaluate(fields, answers)
        assertEquals(listOf("a"), result.visibleQuestionIds)
    }

    @Test
    fun cascade_restoresWhenControllerShown() {
        val fields = listOf(
            field("a"),
            field("b", showWhenEq("a", "yes")),
            field("c", showWhenEq("b", "yes")),
        )
        val answers = mapOf(
            "a" to AnswerValue.Text("yes"),
            "b" to AnswerValue.Text("yes"),
            "c" to AnswerValue.Text("x"),
        )
        val result = VisibilityEvaluator.evaluate(fields, answers)
        assertEquals(listOf("a", "b", "c"), result.visibleQuestionIds)
    }

    @Test
    fun cycle_terminates_andFailsOpen() {
        // a shows-when b==yes; b shows-when a==yes (mutual). With both answered "yes" the fixpoint is
        // stable (both visible). The point is it TERMINATES and does not infinite-loop.
        val fields = listOf(
            field("a", showWhenEq("b", "yes")),
            field("b", showWhenEq("a", "yes")),
        )
        val both = VisibilityEvaluator.evaluate(
            fields,
            mapOf("a" to AnswerValue.Text("yes"), "b" to AnswerValue.Text("yes")),
        )
        // Mutually-satisfied -> both visible; terminates.
        assertEquals(listOf("a", "b"), both.visibleQuestionIds)

        // With neither satisfied the cascade resolves to neither (still terminates, no loop).
        val neither = VisibilityEvaluator.evaluate(fields, emptyMap())
        assertEquals(emptyList<String>(), neither.visibleQuestionIds)
    }

    @Test
    fun unparseableRule_staysVisible_failOpen() {
        val fields = listOf(field("a", mapOf("op" to "garbage")))
        val result = VisibilityEvaluator.evaluate(fields, emptyMap())
        assertEquals(listOf("a"), result.visibleQuestionIds)
    }
}
