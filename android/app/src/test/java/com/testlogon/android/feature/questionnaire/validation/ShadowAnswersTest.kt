package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.AnswerValue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * AND-350 - JVM tests for the PURE [ShadowAnswers]: hidden questions are excluded from the submit body,
 * yet their values are retained and restored on re-show (FR-2).
 */
class ShadowAnswersTest {

    @Test
    fun visibleAnswers_excludesHidden() {
        val all = mapOf(
            "a" to AnswerValue.Text("1"),
            "b" to AnswerValue.Text("2"),
            "c" to AnswerValue.Text("3"),
        )
        val visible = ShadowAnswers.visibleAnswers(all, setOf("a", "c"))
        assertEquals(setOf("a", "c"), visible.keys)
        assertFalse(visible.containsKey("b"))
    }

    @Test
    fun mergeOnReshow_restoresRetainedValue() {
        // The full shadow retains b's value; current pruned it. Re-showing b restores it.
        val shadow = mapOf("a" to AnswerValue.Text("1"), "b" to AnswerValue.Text("kept"))
        val current = mapOf("a" to AnswerValue.Text("1"))
        val merged = ShadowAnswers.mergeOnReshow(shadow, current, visibleIds = setOf("a", "b"))
        assertEquals(AnswerValue.Text("kept"), merged["b"])
    }

    @Test
    fun mergeOnReshow_currentValueWins() {
        val shadow = mapOf("b" to AnswerValue.Text("stale"))
        val current = mapOf("b" to AnswerValue.Text("fresh"))
        val merged = ShadowAnswers.mergeOnReshow(shadow, current, visibleIds = setOf("b"))
        assertEquals(AnswerValue.Text("fresh"), merged["b"])
    }
}
