package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.Condition
import com.testlogon.android.core.model.questionnaire.QuestionnaireField

/**
 * AND-350 - PURE (Android-free) evaluator that, given the ordered fields + the current answers, computes
 * the VISIBLE field set for the dynamic form renderer (AND-347 filters to this set).
 *
 * FR-3 transitive cascade: a field whose controlling question is HIDDEN cascade-hides. This is achieved
 * by a bounded fixpoint: a [Condition.Compare] that references a currently-hidden question's answer is
 * evaluated as if that question were EMPTY / ABSENT (its captured value is masked out of the answer map
 * used for evaluation), so its dependents fall away too.
 *
 * TD-4 cycle safety: the fixpoint is BOUNDED (at most one pass per field) and converges by only ever
 * REMOVING fields (monotone). If the bound is hit without convergence (e.g. a pathological cyclic
 * predicate), any still-unresolved field is left VISIBLE - FAIL OPEN, consistent with the lenient
 * parser. It NEVER infinite-loops.
 *
 * REVIEW CORRECTION (obey): `visible_when` is unverified + Android-only; the SERVER is authoritative, so
 * being too lenient here only ever shows MORE content (which the server then validates), never less.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object VisibilityEvaluator {

    /** The result of a visibility pass: the ordered visible fields + their ids (a convenience view). */
    data class Result(
        val visibleFields: List<QuestionnaireField>,
        val visibleQuestionIds: List<String>,
    ) {
        /** Set view for fast membership tests (e.g. ShadowAnswers / ClientValidator). */
        val visibleIdSet: Set<String> get() = visibleQuestionIds.toSet()
    }

    /**
     * Computes the visible subset of [fields] (declaration order preserved) given [answers].
     *
     * Algorithm: start with ALL fields visible; repeatedly hide any field whose parsed `visible_when`
     * predicate evaluates to false against the answers MASKED to the currently-visible questions (so a
     * hidden controller reads as empty and its dependents cascade-hide). Repeat until stable or the
     * iteration bound is hit (cycle guard). Parsing is lenient (Always -> visible) so unparseable rules
     * never hide.
     */
    fun evaluate(
        fields: List<QuestionnaireField>,
        answers: Map<String, AnswerValue>,
    ): Result {
        if (fields.isEmpty()) return Result(emptyList(), emptyList())

        // Pre-parse each field's predicate once (pure + lenient).
        val conditions: Map<String, Condition> =
            fields.associate { it.questionId to VisibilityParser.parse(it.configJson) }

        // Visibility flags keyed by questionId; everything starts visible (fail open).
        val visible = LinkedHashMap<String, Boolean>()
        fields.forEach { visible[it.questionId] = true }

        // Bounded fixpoint: at most fields.size passes guarantees convergence for any acyclic graph and
        // bounds any cyclic one. Monotone (only flips true -> false), so it terminates.
        val maxPasses = fields.size
        var pass = 0
        while (pass < maxPasses) {
            pass++
            var changed = false
            // The answer map masked to the CURRENTLY-visible questions: a hidden question reads as absent
            // so its dependents cascade-hide on the next pass.
            val maskedAnswers = maskAnswers(answers, visible)
            for (field in fields) {
                val id = field.questionId
                if (visible[id] != true) continue
                val condition = conditions[id] ?: Condition.Always
                val shouldShow = ConditionEvaluator.eval(condition, maskedAnswers)
                if (!shouldShow) {
                    visible[id] = false
                    changed = true
                }
            }
            if (!changed) break
        }

        val visibleFields = fields.filter { visible[it.questionId] == true }
        return Result(
            visibleFields = visibleFields,
            visibleQuestionIds = visibleFields.map { it.questionId },
        )
    }

    /** Returns [answers] with every currently-hidden question's entry removed (read as absent). */
    private fun maskAnswers(
        answers: Map<String, AnswerValue>,
        visible: Map<String, Boolean>,
    ): Map<String, AnswerValue> =
        answers.filterKeys { visible[it] != false }
}
