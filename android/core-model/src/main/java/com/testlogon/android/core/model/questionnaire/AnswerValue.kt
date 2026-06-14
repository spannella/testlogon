package com.testlogon.android.core.model.questionnaire

/**
 * AND-346 - the respondent ANSWER union (the value side of `answers_by_question_id`). The wire is an
 * opaque map whose values are heterogeneous: a string, a number, a boolean, a list of strings, or a
 * date-string. Modeled as a typed sealed hierarchy so callers get a typed value rather than `Any?`; a
 * custom dependency-free core-network AnswerValueAdapter (@FromJson/@ToJson) round-trips it. Malformed
 * values decode to [Empty] rather than crashing (FR / error-handling - never throws).
 *
 * RECONCILIATION NOTE: core-model has no Moshi dependency, so the adapter itself lives in core-network
 * (where Moshi is on the classpath); this file declares only the immutable value types.
 *
 * NOTE ON [Choices] vs scalar single-select (R4): the backend `answers_by_question_id` is opaque and it
 * is not pinned whether single-select answers are scalar or single-element arrays. The union tolerates
 * both - a JSON array decodes to [Choices]; a scalar string decodes to [Text].
 */
sealed interface AnswerValue {

    /** A plain string answer (also covers date/time/timezone string answers). */
    data class Text(val value: String) : AnswerValue

    /** A numeric answer (slider, etc.). Held as Double to tolerate int/float wire encodings. */
    data class Num(val value: Double) : AnswerValue

    /** A boolean answer. */
    data class Bool(val value: Boolean) : AnswerValue

    /** A list-of-strings answer (multiselect; or single-select encoded as a one-element array). */
    data class Choices(val values: List<String>) : AnswerValue

    /** Absent / null / unrecognized answer shape. The non-throwing fallback. */
    data object Empty : AnswerValue
}
