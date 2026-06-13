package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.Condition
import com.testlogon.android.core.model.questionnaire.Op
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-350 - JVM tests for the PURE [ConditionEvaluator]. Covers every [Op], the All/Any/Not/Always
 * combinators, a missing answer, and type mismatches (false, never a throw).
 */
class ConditionEvaluatorTest {

    private fun answers(vararg pairs: Pair<String, AnswerValue>) = pairs.toMap()

    private fun cmp(q: String, op: Op, v: AnswerValue) = Condition.Compare(q, op, v)

    @Test
    fun always_isTrue() {
        assertTrue(ConditionEvaluator.eval(Condition.Always, emptyMap()))
    }

    @Test
    fun eq_and_neq_scalar() {
        val a = answers("q" to AnswerValue.Text("yes"))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.EQ, AnswerValue.Text("yes")), a))
        assertFalse(ConditionEvaluator.eval(cmp("q", Op.EQ, AnswerValue.Text("no")), a))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.NEQ, AnswerValue.Text("no")), a))
    }

    @Test
    fun eq_numeric_crossEncoding() {
        val a = answers("q" to AnswerValue.Num(5.0))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.EQ, AnswerValue.Text("5")), a))
    }

    @Test
    fun in_and_notIn_overChoices() {
        val a = answers("q" to AnswerValue.Choices(listOf("b")))
        val operand = AnswerValue.Choices(listOf("a", "b", "c"))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.IN, operand), a))
        assertFalse(ConditionEvaluator.eval(cmp("q", Op.NOT_IN, operand), a))
        val a2 = answers("q" to AnswerValue.Text("z"))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.NOT_IN, operand), a2))
    }

    @Test
    fun numeric_ordering() {
        val a = answers("q" to AnswerValue.Num(10.0))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.GT, AnswerValue.Num(5.0)), a))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.GTE, AnswerValue.Num(10.0)), a))
        assertFalse(ConditionEvaluator.eval(cmp("q", Op.LT, AnswerValue.Num(10.0)), a))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.LTE, AnswerValue.Num(10.0)), a))
    }

    @Test
    fun contains_choicesAndText() {
        val choices = answers("q" to AnswerValue.Choices(listOf("x", "y")))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.CONTAINS, AnswerValue.Text("y")), choices))
        val text = answers("q" to AnswerValue.Text("hello world"))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.CONTAINS, AnswerValue.Text("world")), text))
        assertFalse(ConditionEvaluator.eval(cmp("q", Op.CONTAINS, AnswerValue.Text("nope")), text))
    }

    @Test
    fun isAnswered_isEmpty() {
        val present = answers("q" to AnswerValue.Text("v"))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.IS_ANSWERED, AnswerValue.Empty), present))
        assertFalse(ConditionEvaluator.eval(cmp("q", Op.IS_EMPTY, AnswerValue.Empty), present))

        val blank = answers("q" to AnswerValue.Text("   "))
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.IS_EMPTY, AnswerValue.Empty), blank))
    }

    @Test
    fun missingAnswer_treatedAsEmpty() {
        assertTrue(ConditionEvaluator.eval(cmp("q", Op.IS_EMPTY, AnswerValue.Empty), emptyMap()))
        assertFalse(ConditionEvaluator.eval(cmp("q", Op.EQ, AnswerValue.Text("v")), emptyMap()))
    }

    @Test
    fun typeMismatch_isFalse_neverThrows() {
        val a = answers("q" to AnswerValue.Text("not-a-number"))
        // Ordering against a non-numeric Text yields false rather than throwing.
        assertFalse(ConditionEvaluator.eval(cmp("q", Op.GT, AnswerValue.Num(1.0)), a))
    }

    @Test
    fun combinators_allAnyNot() {
        val a = answers("q" to AnswerValue.Text("yes"))
        val isYes = cmp("q", Op.EQ, AnswerValue.Text("yes"))
        val isNo = cmp("q", Op.EQ, AnswerValue.Text("no"))
        assertTrue(ConditionEvaluator.eval(Condition.All(listOf(isYes, Condition.Always)), a))
        assertFalse(ConditionEvaluator.eval(Condition.All(listOf(isYes, isNo)), a))
        assertTrue(ConditionEvaluator.eval(Condition.Any(listOf(isNo, isYes)), a))
        assertTrue(ConditionEvaluator.eval(Condition.Not(isNo), a))
        // Empty combinators: All vacuously true, Any vacuously false.
        assertTrue(ConditionEvaluator.eval(Condition.All(emptyList()), a))
        assertFalse(ConditionEvaluator.eval(Condition.Any(emptyList()), a))
    }
}
