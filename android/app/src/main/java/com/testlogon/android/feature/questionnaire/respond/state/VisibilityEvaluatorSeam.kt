package com.testlogon.android.feature.questionnaire.respond.state

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.feature.questionnaire.validation.VisibilityEvaluator as RuleVisibilityEvaluator

/**
 * AND-351 - the VISIBILITY seam (FR-5). The form state machine depends only on this interface; the
 * production binding [DefaultVisibilityEvaluator] DELEGATES to AND-350's
 * [com.testlogon.android.feature.questionnaire.validation.VisibilityEvaluator] (the transitive
 * cascade + fail-open behaviour). Defaults to all-visible when there are no rules. Hidden fields are
 * EXCLUDED from the validity aggregation by the VM.
 *
 * Named [FormVisibilityEvaluator] (not VisibilityEvaluator) to avoid colliding with the AND-350 object of
 * that name; the alias [RuleVisibilityEvaluator] points at the AND-350 evaluator it wraps.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
fun interface FormVisibilityEvaluator {
    /** Returns the ids of the currently-visible fields given [fields] (all) and the [answers] snapshot. */
    fun visibleFieldIds(
        fields: List<QuestionnaireField>,
        answers: Map<String, AnswerValue>,
    ): Set<String>
}

/**
 * AND-351 - the DEFAULT [FormVisibilityEvaluator]: delegates to AND-350's evaluator, which starts
 * all-visible and only ever hides (fail open when there are no parseable rules). No new rule logic here.
 */
object DefaultVisibilityEvaluator : FormVisibilityEvaluator {
    override fun visibleFieldIds(
        fields: List<QuestionnaireField>,
        answers: Map<String, AnswerValue>,
    ): Set<String> = RuleVisibilityEvaluator.evaluate(fields, answers).visibleIdSet
}
