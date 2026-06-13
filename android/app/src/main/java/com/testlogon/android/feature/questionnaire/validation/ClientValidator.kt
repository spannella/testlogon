package com.testlogon.android.feature.questionnaire.validation

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField

/**
 * AND-350 - PURE (Android-free) CLIENT-SIDE constraint checker (FR-4): fast INLINE feedback only.
 *
 * REVIEW CORRECTION (obey): this is fast inline UX ONLY; the SERVER is AUTHORITATIVE. The ViewModel
 * NEVER enables submit on the strength of this validator - submit is gated solely on the server's
 * can_submit. These local issues are surfaced inline (merged with server errors by IssueReconciler) so
 * the user sees obvious problems immediately without a round-trip; the server's verdict still governs.
 *
 * It mirrors the per-field constraints expressed in the field config (typed views + opaque config_json),
 * tolerating both snake_case and camelCase keys (the schema is opaque - AND-346):
 *   - required: an empty answer on a required field
 *   - text length: min_length / max_length (a.k.a. minLength / maxLength)
 *   - numeric range: min / max (slider + numeric)
 *   - pattern: a regex the Text answer must fully match
 *   - choice membership: a select/radio/multiselect value must be one of options()
 *   - date range: min_date / max_date (a.k.a. minDate / maxDate), yyyy-MM-dd lexical compare
 *
 * It validates ONLY the VISIBLE fields (hidden fields are never validated - FR-2) and only the answered
 * ones plus required-but-empty ones (an unanswered OPTIONAL field is skipped). Never throws.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object ClientValidator {

    /** A single local (client-derived) issue. [code] de-dups against server codes; [message] is shown. */
    data class LocalIssue(val code: String, val message: String)

    /** Stable issue codes (mirror common server codes so the reconciler can de-dup by code). */
    object Codes {
        const val REQUIRED = "required"
        const val MIN_LENGTH = "min_length"
        const val MAX_LENGTH = "max_length"
        const val MIN = "min"
        const val MAX = "max"
        const val PATTERN = "pattern"
        const val CHOICE = "invalid_choice"
        const val MIN_DATE = "min_date"
        const val MAX_DATE = "max_date"
    }

    /**
     * Validates the [visibleFields] against [answers]. Returns questionId -> ordered list of issues; a
     * field with no issues is absent from the map. Only visible fields are considered (the caller passes
     * the visible subset). An unanswered optional field contributes nothing.
     */
    fun validate(
        visibleFields: List<QuestionnaireField>,
        answers: Map<String, AnswerValue>,
    ): Map<String, List<LocalIssue>> {
        val result = LinkedHashMap<String, List<LocalIssue>>()
        for (field in visibleFields) {
            val issues = validateField(field, answers[field.questionId] ?: AnswerValue.Empty)
            if (issues.isNotEmpty()) result[field.questionId] = issues
        }
        return result
    }

    private fun validateField(field: QuestionnaireField, answer: AnswerValue): List<LocalIssue> {
        val empty = ConditionEvaluator.isEmpty(answer)
        // Required-but-empty is the only check on an empty answer; an empty OPTIONAL field is skipped.
        if (empty) {
            return if (field.required) {
                listOf(LocalIssue(Codes.REQUIRED, MSG_REQUIRED))
            } else {
                emptyList()
            }
        }

        val issues = mutableListOf<LocalIssue>()
        val config = field.configJson

        // Text length + pattern (apply to a Text answer; tolerate other shapes by reading scalar text).
        val text = textOf(answer)
        if (text != null) {
            readInt(config, "min_length", "minLength")?.let { min ->
                if (text.length < min) issues.add(LocalIssue(Codes.MIN_LENGTH, msgMinLength(min)))
            }
            readInt(config, "max_length", "maxLength")?.let { max ->
                if (text.length > max) issues.add(LocalIssue(Codes.MAX_LENGTH, msgMaxLength(max)))
            }
            readString(config, "pattern")?.let { pattern ->
                if (!matchesPattern(text, pattern)) issues.add(LocalIssue(Codes.PATTERN, MSG_PATTERN))
            }
        }

        // Numeric range (slider + any numeric answer).
        val number = numberOf(answer)
        if (number != null) {
            readNumber(config, "min")?.let { min ->
                if (number < min) issues.add(LocalIssue(Codes.MIN, msgMin(min)))
            }
            readNumber(config, "max")?.let { max ->
                if (number > max) issues.add(LocalIssue(Codes.MAX, msgMax(max)))
            }
        }

        // Choice membership (select / radio / multiselect).
        val options = optionValues(field)
        if (options.isNotEmpty()) {
            val chosen = chosenValues(answer)
            val invalid = chosen.any { it !in options }
            if (invalid) issues.add(LocalIssue(Codes.CHOICE, MSG_CHOICE))
        }

        // Date range (yyyy-MM-dd lexical compare - ISO dates sort correctly lexically).
        if (text != null && looksLikeIsoDate(text)) {
            readString(config, "min_date", "minDate")?.takeIf { looksLikeIsoDate(it) }?.let { minDate ->
                if (text < minDate) issues.add(LocalIssue(Codes.MIN_DATE, msgMinDate(minDate)))
            }
            readString(config, "max_date", "maxDate")?.takeIf { looksLikeIsoDate(it) }?.let { maxDate ->
                if (text > maxDate) issues.add(LocalIssue(Codes.MAX_DATE, msgMaxDate(maxDate)))
            }
        }

        return issues
    }

    // ---- option / answer readers (tolerant) ----

    private fun optionValues(field: QuestionnaireField): Set<String> = when (field) {
        is QuestionnaireField.Select -> field.options().map { it.value }.toSet()
        is QuestionnaireField.Radio -> field.options().map { it.value }.toSet()
        is QuestionnaireField.Multiselect -> field.options().map { it.value }.toSet()
        else -> emptySet()
    }

    private fun chosenValues(answer: AnswerValue): List<String> = when (answer) {
        is AnswerValue.Choices -> answer.values
        is AnswerValue.Text -> if (answer.value.isBlank()) emptyList() else listOf(answer.value)
        else -> emptyList()
    }

    private fun textOf(answer: AnswerValue): String? = when (answer) {
        is AnswerValue.Text -> answer.value
        else -> null
    }

    private fun numberOf(answer: AnswerValue): Double? = when (answer) {
        is AnswerValue.Num -> answer.value
        is AnswerValue.Text -> answer.value.trim().toDoubleOrNull()
        else -> null
    }

    private fun matchesPattern(text: String, pattern: String): Boolean = try {
        Regex(pattern).matches(text)
    } catch (e: Exception) {
        // A malformed regex in the opaque config must not crash; treat as a non-constraint (pass).
        true
    }

    private fun looksLikeIsoDate(s: String): Boolean =
        s.length == 10 && s[4] == '-' && s[7] == '-' &&
            s.take(4).all { it.isDigit() } &&
            s.substring(5, 7).all { it.isDigit() } &&
            s.substring(8, 10).all { it.isDigit() }

    // ---- tolerant config readers (snake_case or camelCase) ----

    private fun readInt(config: Map<String, Any?>, vararg keys: String): Int? =
        keys.firstNotNullOfOrNull { key ->
            when (val v = config[key]) {
                is Number -> v.toInt()
                is String -> v.trim().toDoubleOrNull()?.toInt()
                else -> null
            }
        }

    private fun readNumber(config: Map<String, Any?>, vararg keys: String): Double? =
        keys.firstNotNullOfOrNull { key ->
            when (val v = config[key]) {
                is Number -> v.toDouble()
                is String -> v.trim().toDoubleOrNull()
                else -> null
            }
        }

    private fun readString(config: Map<String, Any?>, vararg keys: String): String? =
        keys.firstNotNullOfOrNull { config[it] as? String }

    // ---- default messages (fallbacks shown when there is no server message; server wins on display) ----

    private const val MSG_REQUIRED = "This field is required."
    private const val MSG_PATTERN = "This value is not in the expected format."
    private const val MSG_CHOICE = "Choose a valid option."
    private fun msgMinLength(min: Int) = "Enter at least $min characters."
    private fun msgMaxLength(max: Int) = "Enter at most $max characters."
    private fun msgMin(min: Double) = "Value must be at least ${trim(min)}."
    private fun msgMax(max: Double) = "Value must be at most ${trim(max)}."
    private fun msgMinDate(min: String) = "Choose a date on or after $min."
    private fun msgMaxDate(max: String) = "Choose a date on or before $max."

    private fun trim(value: Double): String =
        if (value == Math.floor(value) && !value.isInfinite()) value.toLong().toString()
        else value.toString()
}
