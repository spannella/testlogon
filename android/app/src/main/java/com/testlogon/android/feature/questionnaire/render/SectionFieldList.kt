package com.testlogon.android.feature.questionnaire.render

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.core.model.questionnaire.QuestionnaireSection

/**
 * AND-347 - renders one section's [fields] IN ORDER in a plain [Column]. STATELESS: the per-question
 * current value comes from [answers] (keyed by questionId) and per-question inline error from [errors];
 * every edit calls [onAnswerChanged]. The renderer does NOT own scroll / paging / LazyColumn - the
 * caller hosts the scroll container (AND-351). No networking / session / validation / visibility here.
 */
@Composable
fun SectionFieldList(
    fields: List<QuestionnaireField>,
    answers: Map<String, AnswerValue>,
    enabled: Boolean,
    errors: Map<String, String>,
    onAnswerChanged: (questionId: String, value: AnswerValue) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        fields.forEach { field ->
            QuestionField(
                field = field,
                answer = answers[field.questionId],
                enabled = enabled,
                error = errors[field.questionId],
                onAnswerChanged = onAnswerChanged,
            )
        }
    }
}

/** Convenience overload taking a [QuestionnaireSection] (renders its ordered `questions`). */
@Composable
fun SectionFieldList(
    section: QuestionnaireSection,
    answers: Map<String, AnswerValue>,
    enabled: Boolean,
    errors: Map<String, String>,
    onAnswerChanged: (questionId: String, value: AnswerValue) -> Unit,
    modifier: Modifier = Modifier,
) {
    SectionFieldList(
        fields = section.questions,
        answers = answers,
        enabled = enabled,
        errors = errors,
        onAnswerChanged = onAnswerChanged,
        modifier = modifier,
    )
}
