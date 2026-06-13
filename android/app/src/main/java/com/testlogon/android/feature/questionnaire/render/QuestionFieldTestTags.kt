package com.testlogon.android.feature.questionnaire.render

/**
 * AND-347 - stable Compose testTags for the dynamic form renderer (used by the androidTest suite). The
 * per-question control carries `qfield_<questionId>`; the inline error carries `qfield_error_<questionId>`;
 * an Unknown field carries `qfield_unsupported_<rawType>`; a choice option carries
 * `qopt_<questionId>_<index>`.
 */
object QuestionFieldTestTags {

    /** The primary input control for a question. */
    fun field(questionId: String): String = "qfield_$questionId"

    /** The inline error text for a question. */
    fun error(questionId: String): String = "qfield_error_$questionId"

    /** The non-crashing placeholder card for an unsupported (Unknown) field, keyed by raw type. */
    fun unsupported(rawType: String): String = "qfield_unsupported_$rawType"

    /** A single choice option (checkbox / radio / dropdown item) by question + option index. */
    fun option(questionId: String, index: Int): String = "qopt_${questionId}_$index"

    /** An address sub-field control, keyed by question + sub-field id. */
    fun addressPart(questionId: String, part: String): String = "qfield_${questionId}_$part"

    /** The confirm action inside a date / time picker dialog. */
    fun pickerConfirm(questionId: String): String = "qfield_${questionId}_confirm"

    /** The clear action on a date / time / picker control. */
    fun clear(questionId: String): String = "qfield_${questionId}_clear"
}
