package com.testlogon.android.feature.questionnaire.builder.data

/**
 * Framework-free domain models for the questionnaire BUILDER (creator-authoring) surface.
 *
 * Kept in feature/data (NOT core-model) because core-model cannot depend on core-network; mirrors the
 * apikeys ApiKeyDomain pattern. Times are the backend's epoch-second STRINGS, passed through verbatim
 * (the UI formats / ignores them). `configJson` is the opaque per-type config object (the typed shaping
 * lives in the builder UI's per-type editor).
 */

/** The nine question types the backend accepts (app/routers/questionnaires.py `_ALLOWED_TYPES`). */
enum class QnrQuestionType(val wire: String) {
    TEXT("text"),
    SELECT("select"),
    MULTISELECT("multiselect"),
    RADIO("radio"),
    SLIDER("slider"),
    DATE("date"),
    TIME("time"),
    TIMEZONE("timezone"),
    ADDRESS("address");

    companion object {
        fun fromWire(value: String): QnrQuestionType =
            entries.firstOrNull { it.wire == value } ?: TEXT

        /**
         * The default config_json for a freshly-created/retyped question (mirrors the web
         * `defaultConfigForType`). Empty for types whose config the backend tolerates as {}.
         */
        fun defaultConfig(type: QnrQuestionType): Map<String, Any?> = when (type) {
            // The backend requires text minLength/maxLength to be INTEGERS (not floats) - use Int so Moshi
            // serializes them without a decimal point (0, 200 - not 0.0, 200.0).
            TEXT -> mapOf("minLength" to 0, "maxLength" to 200)
            SELECT, RADIO -> mapOf("options" to listOf("Option 1", "Option 2"))
            MULTISELECT -> mapOf("options" to listOf("Option 1", "Option 2"))
            SLIDER -> mapOf("min" to 0, "max" to 10, "step" to 1)
            DATE -> mapOf("minDate" to "", "maxDate" to "")
            TIME -> mapOf("minTime" to "", "maxTime" to "")
            TIMEZONE -> mapOf("allowedTimezones" to emptyList<String>())
            ADDRESS -> mapOf("requiredFields" to listOf("line1", "city", "country"))
        }
    }
}

/** One questionnaire draft row (the list / overview). */
data class QnrDraft(
    val questionnaireId: String,
    val title: String,
    val description: String,
    val status: String,
    val visibility: String,
    val publishedVersionId: String?,
    val updatedAt: String?,
) {
    val isPublished: Boolean get() = publishedVersionId != null
    val isArchived: Boolean get() = status == "archived"
}

/** One section in the builder. */
data class QnrSection(
    val sectionId: String,
    val title: String,
    val description: String,
    val position: Int,
)

/** One question in the builder. */
data class QnrQuestion(
    val questionId: String,
    val sectionId: String,
    val type: QnrQuestionType,
    val label: String,
    val required: Boolean,
    val hint: String,
    val configJson: Map<String, Any?>,
    val position: Int,
)

/** A published version (returned by publish). */
data class QnrPublishedVersion(
    val versionId: String,
    val publishedSlug: String?,
    val publishedAt: String?,
)
