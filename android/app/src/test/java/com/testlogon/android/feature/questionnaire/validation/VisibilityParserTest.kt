package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.Condition
import com.testlogon.android.core.model.questionnaire.Op
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-350 - JVM tests for the PURE, LENIENT [VisibilityParser]. Verifies a valid `visible_when` builds a
 * [Condition], and that any unknown op / shape / key (or a null config) FAILS OPEN to [Condition.Always].
 */
class VisibilityParserTest {

    private fun config(visibleWhen: Any?): Map<String, Any?> =
        mapOf("visible_when" to visibleWhen)

    @Test
    fun nullConfig_isAlways() {
        assertEquals(Condition.Always, VisibilityParser.parse(null))
    }

    @Test
    fun absentSlice_isAlways() {
        assertEquals(Condition.Always, VisibilityParser.parse(mapOf("other" to 1)))
    }

    @Test
    fun simpleCompare_eq() {
        val c = VisibilityParser.parse(
            config(mapOf("question_id" to "q1", "op" to "eq", "value" to "yes")),
        )
        assertTrue(c is Condition.Compare)
        c as Condition.Compare
        assertEquals("q1", c.questionId)
        assertEquals(Op.EQ, c.op)
        assertEquals(AnswerValue.Text("yes"), c.value)
    }

    @Test
    fun opSynonyms_andSeparators() {
        fun op(token: String): Op? =
            (VisibilityParser.parse(config(mapOf("question_id" to "q", "op" to token))) as? Condition.Compare)?.op
        assertEquals(Op.GTE, op("gte"))
        assertEquals(Op.GTE, op("ge"))
        assertEquals(Op.NOT_IN, op("not-in"))
        assertEquals(Op.NEQ, op("ne"))
    }

    @Test
    fun presenceShorthand_isAnswered() {
        val c = VisibilityParser.parse(config(mapOf("question_id" to "q1")))
        assertTrue(c is Condition.Compare)
        assertEquals(Op.IS_ANSWERED, (c as Condition.Compare).op)
    }

    @Test
    fun combinators_allAnyNot() {
        val all = VisibilityParser.parse(
            config(
                mapOf(
                    "all" to listOf(
                        mapOf("question_id" to "q1", "op" to "eq", "value" to "a"),
                        mapOf("question_id" to "q2", "op" to "is_answered"),
                    ),
                ),
            ),
        )
        assertTrue(all is Condition.All)
        assertEquals(2, (all as Condition.All).of.size)

        val not = VisibilityParser.parse(
            config(mapOf("not" to mapOf("question_id" to "q1", "op" to "eq", "value" to "a"))),
        )
        assertTrue(not is Condition.Not)
    }

    @Test
    fun valueCoercion_numberBooleanList() {
        fun value(v: Any?): AnswerValue? =
            (VisibilityParser.parse(config(mapOf("question_id" to "q", "op" to "eq", "value" to v))) as? Condition.Compare)?.value
        assertEquals(AnswerValue.Num(3.0), value(3))
        assertEquals(AnswerValue.Bool(true), value(true))
        assertEquals(AnswerValue.Choices(listOf("a", "b")), value(listOf("a", "b")))
    }

    @Test
    fun unknownOp_failsOpenToAlways() {
        val c = VisibilityParser.parse(
            config(mapOf("question_id" to "q1", "op" to "wat", "value" to "x")),
        )
        assertEquals(Condition.Always, c)
    }

    @Test
    fun unknownShape_failsOpenToAlways() {
        assertEquals(Condition.Always, VisibilityParser.parse(config("just a string")))
        assertEquals(Condition.Always, VisibilityParser.parse(config(42)))
        assertEquals(Condition.Always, VisibilityParser.parse(config(mapOf("no" to "id"))))
    }

    @Test
    fun notWithUnparseableChild_failsOpenToAlways() {
        // A "not" wrapping an unknown predicate must not flip visible to hidden - fail open.
        val c = VisibilityParser.parse(config(mapOf("not" to "garbage")))
        assertEquals(Condition.Always, c)
    }
}
