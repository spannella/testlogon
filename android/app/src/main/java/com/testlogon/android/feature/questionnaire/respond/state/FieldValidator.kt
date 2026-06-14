package com.testlogon.android.feature.questionnaire.respond.state

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.feature.questionnaire.validation.ClientValidator

/**
 * AND-351 - the per-field VALIDATION seam (FR-4). The form state machine depends only on this interface;
 * the production binding [DefaultFieldValidator] DELEGATES to AND-350's [ClientValidator] (the full
 * constraint impl: required / min-max length / numeric range / pattern / choice membership / date
 * bounds). Tests substitute a fake. This seam is INTENTIONALLY thin so AND-351 adds no rule logic.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
fun interface FieldValidator {
    /**
     * Returns the ordered error messages for [field] given its [value] and the full [answers] snapshot
     * (cross-field constraints may read other answers). An empty list means the field is valid. Never
     * throws.
     */
    fun validate(
        field: QuestionnaireField,
        value: AnswerValue,
        answers: Map<String, AnswerValue>,
    ): List<String>
}

/**
 * AND-351 - the DEFAULT [FieldValidator]: a thin adapter over AND-350 [ClientValidator]. It validates the
 * single [field] (ClientValidator is given a one-field list so cross-field config still reads the full
 * [answers] map) and flattens the resulting [ClientValidator.LocalIssue]s to their messages. No new rule
 * logic lives here - the constraint catalog is entirely AND-350's.
 */
object DefaultFieldValidator : FieldValidator {
    override fun validate(
        field: QuestionnaireField,
        value: AnswerValue,
        answers: Map<String, AnswerValue>,
    ): List<String> {
        val effective = answers + (field.questionId to value)
        val issues = ClientValidator.validate(listOf(field), effective)
        return issues[field.questionId]?.map { it.message } ?: emptyList()
    }
}
