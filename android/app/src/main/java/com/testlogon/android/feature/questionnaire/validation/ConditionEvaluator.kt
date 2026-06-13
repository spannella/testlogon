package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.Condition
import com.testlogon.android.core.model.questionnaire.Op

/**
 * AND-350 - PURE (Android-free) evaluator for a [Condition] against the current answer map. JVM-testable
 * (no Compose / network / Room). TOTAL over the sealed [Condition] hierarchy AND every [Op]; tolerant
 * by construction - a missing answer is treated as empty, a type mismatch yields false, and nothing
 * EVER throws (the schema + the `visible_when` shape are both opaque / unverified, AND-346 + AND-350).
 *
 * The client mirrors server rule semantics here only for fast inline UX; the SERVER remains
 * authoritative. This evaluator is the shared core of both the visibility cascade (VisibilityEvaluator)
 * and any inline predicate check.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object ConditionEvaluator {

    /**
     * Evaluates [condition] against [answers] (questionId -> [AnswerValue]). Returns true/false; never
     * throws. An absent key in [answers] is read as [AnswerValue.Empty].
     */
    fun eval(condition: Condition, answers: Map<String, AnswerValue>): Boolean = when (condition) {
        is Condition.Always -> true
        is Condition.Not -> !eval(condition.of, answers)
        is Condition.All -> condition.of.all { eval(it, answers) }
        is Condition.Any -> condition.of.any { eval(it, answers) }
        is Condition.Compare -> evalCompare(condition, answers)
    }

    private fun evalCompare(c: Condition.Compare, answers: Map<String, AnswerValue>): Boolean {
        val actual = answers[c.questionId] ?: AnswerValue.Empty
        return when (c.op) {
            Op.IS_ANSWERED -> !isEmpty(actual)
            Op.IS_EMPTY -> isEmpty(actual)
            Op.EQ -> scalarEquals(actual, c.value)
            Op.NEQ -> !scalarEquals(actual, c.value)
            Op.IN -> membership(actual, c.value)
            Op.NOT_IN -> !membership(actual, c.value)
            Op.GT -> compareNumeric(actual, c.value)?.let { it > 0 } ?: false
            Op.GTE -> compareNumeric(actual, c.value)?.let { it >= 0 } ?: false
            Op.LT -> compareNumeric(actual, c.value)?.let { it < 0 } ?: false
            Op.LTE -> compareNumeric(actual, c.value)?.let { it <= 0 } ?: false
            Op.CONTAINS -> containment(actual, c.value)
        }
    }

    /** An answer is empty when it is [AnswerValue.Empty], a blank Text, or an empty Choices list. */
    fun isEmpty(value: AnswerValue): Boolean = when (value) {
        is AnswerValue.Empty -> true
        is AnswerValue.Text -> value.value.isBlank()
        is AnswerValue.Choices -> value.values.isEmpty()
        is AnswerValue.Num -> false
        is AnswerValue.Bool -> false
    }

    /**
     * Scalar equality across the union, tolerant of cross-encoding. Num/Text compare numerically when
     * both look numeric, else by string form; Bool compares to Bool or a "true"/"false" Text; a single
     * element Choices compares to its only value. A type mismatch is false (never throws).
     */
    private fun scalarEquals(actual: AnswerValue, operand: AnswerValue): Boolean {
        // Numeric comparison first (tolerates Num-vs-Text "5" == 5.0).
        val an = asNumber(actual)
        val on = asNumber(operand)
        if (an != null && on != null) return an == on

        val ab = asBool(actual)
        val ob = asBool(operand)
        if (ab != null && ob != null) return ab == ob

        val asStr = asScalarString(actual)
        val osStr = asScalarString(operand)
        if (asStr != null && osStr != null) return asStr == osStr
        return false
    }

    /**
     * Membership: true when the operand's value(s) include the actual scalar, OR (when the actual is a
     * Choices list) when the lists intersect. Tolerant of either side being a scalar or a list.
     */
    private fun membership(actual: AnswerValue, operand: AnswerValue): Boolean {
        val operandSet = asStringList(operand)
        if (operandSet.isEmpty()) return false
        val actualValues = asStringList(actual)
        if (actualValues.isEmpty()) return false
        return actualValues.any { it in operandSet }
    }

    /**
     * CONTAINS: for a Choices actual, true when it contains any operand value; for a Text actual, true
     * when the text contains the operand scalar as a substring. Tolerant; false on a mismatch.
     */
    private fun containment(actual: AnswerValue, operand: AnswerValue): Boolean = when (actual) {
        is AnswerValue.Choices -> {
            val ops = asStringList(operand)
            ops.isNotEmpty() && ops.any { it in actual.values }
        }
        is AnswerValue.Text -> {
            val needle = asScalarString(operand)
            needle != null && actual.value.contains(needle)
        }
        else -> false
    }

    /**
     * Numeric three-way compare of [actual] against [operand]: negative/zero/positive, or null when
     * either side is not numeric (the caller then yields false for the ordering op).
     */
    private fun compareNumeric(actual: AnswerValue, operand: AnswerValue): Int? {
        val a = asNumber(actual) ?: return null
        val o = asNumber(operand) ?: return null
        return a.compareTo(o)
    }

    // ---- tolerant coercions over the AnswerValue union (never throw) ----

    private fun asNumber(value: AnswerValue): Double? = when (value) {
        is AnswerValue.Num -> value.value
        is AnswerValue.Text -> value.value.trim().toDoubleOrNull()
        else -> null
    }

    private fun asBool(value: AnswerValue): Boolean? = when (value) {
        is AnswerValue.Bool -> value.value
        is AnswerValue.Text -> when (value.value.trim().lowercase()) {
            "true" -> true
            "false" -> false
            else -> null
        }
        else -> null
    }

    /** The scalar string form of a Text / Num / Bool / single-element Choices answer; null otherwise. */
    private fun asScalarString(value: AnswerValue): String? = when (value) {
        is AnswerValue.Text -> value.value
        is AnswerValue.Num -> formatNumber(value.value)
        is AnswerValue.Bool -> value.value.toString()
        is AnswerValue.Choices -> value.values.singleOrNull()
        is AnswerValue.Empty -> null
    }

    /** A list view of an answer/operand: Choices as-is; a scalar as a one-element list; Empty as empty. */
    private fun asStringList(value: AnswerValue): List<String> = when (value) {
        is AnswerValue.Choices -> value.values
        is AnswerValue.Text -> if (value.value.isBlank()) emptyList() else listOf(value.value)
        is AnswerValue.Num -> listOf(formatNumber(value.value))
        is AnswerValue.Bool -> listOf(value.value.toString())
        is AnswerValue.Empty -> emptyList()
    }

    /** Integral doubles render without a trailing ".0" so "5" matches Num(5.0). Mirrors the renderer. */
    private fun formatNumber(value: Double): String =
        if (value == Math.floor(value) && !value.isInfinite()) value.toLong().toString()
        else value.toString()
}
