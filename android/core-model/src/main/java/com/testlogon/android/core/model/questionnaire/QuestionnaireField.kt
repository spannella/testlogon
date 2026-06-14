package com.testlogon.android.core.model.questionnaire

/**
 * AND-346 - polymorphic questionnaire FIELD schema (the QUESTIONNAIRES domain, epic E45).
 *
 * RECONCILIATION NOTE (core-model has no Moshi): core-model's build.gradle.kts applies only
 * android.library + kotlin.android and has NO moshi / moshi-codegen dependency (mirrors the AND-319
 * KYC DTO precedent). So these types carry NO `@Json` / `@JsonClass` annotations. The production Moshi
 * (core-network NetworkModule.provideMoshi) decodes the common keys via the reflective
 * KotlinJsonAdapterFactory (property names ARE the snake_case wire keys: question_id, section_id, ...),
 * while the polymorphic dispatch + config_json capture is performed by the CUSTOM dependency-free
 * QuestionnaireFieldAdapter in core-network. This split is why the polymorphic round-trip tests live in
 * core-network (the adapter is core-network scoped) - see the test reconciliation in that module.
 *
 * Wire shape (frontend src/api/types.ts QuestionnaireQuestion):
 *   { question_id, section_id, type, label, required, hint?, config_json, position? }
 * COMMON required keys on EVERY question (FR-6 fail-fast if absent): type, question_id, section_id,
 * label, required. Per-type configuration is OPAQUE: every question carries config_json
 * (Map<String, Any?>, read-only). Each subtype MAY expose a typed VIEW of its slice of config_json
 * (e.g. Select.options(), Slider.min()/max()) but MUST tolerate the opaque map (never throws).
 *
 * The nine real question types (FR-3, corrected catalog) are exactly:
 *   text, select, multiselect, radio, slider, date, time, timezone, address
 * plus Unknown(rawType) for any unrecognized/future type (FR-5 - never throws on an unknown type).
 */

/**
 * Discriminator catalog for [QuestionnaireField]. Wire token is the lowercase [token]; an unrecognized
 * token decodes to [UNKNOWN] (lenient, never throws) via the core-network QuestionTypeAdapter.
 */
enum class QuestionType(val token: String) {
    TEXT("text"),
    SELECT("select"),
    MULTISELECT("multiselect"),
    RADIO("radio"),
    SLIDER("slider"),
    DATE("date"),
    TIME("time"),
    TIMEZONE("timezone"),
    ADDRESS("address"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** Lenient: an unrecognized token maps to [UNKNOWN] rather than throwing. */
        fun fromToken(t: String?): QuestionType = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** A single selectable option surfaced from a SELECT / MULTISELECT / RADIO question's config_json. */
data class FieldOption(
    val value: String,
    val label: String? = null,
)

/**
 * AND-346 - a single questionnaire question/field. Sealed hierarchy keyed on the `type` discriminator;
 * decoded by the custom core-network QuestionnaireFieldAdapter which reads the COMMON keys, captures the
 * remaining object into [configJson], and dispatches to the correct subtype. [Unknown] is the
 * forward-compatibility fallback for any unrecognized type (never throws).
 *
 * COMMON keys (required structural keys per FR-6): type / questionId / sectionId / label / required.
 * `hint` and `position` are optional. configJson is the opaque per-type config map (read-only).
 */
sealed class QuestionnaireField {

    /** Discriminator type for this field (UNKNOWN for unrecognized wire tokens). */
    abstract val type: QuestionType

    /** Stable question id (wire `question_id`). */
    abstract val questionId: String

    /** Owning section id (wire `section_id`). */
    abstract val sectionId: String

    /** Display label (server-localized, passed through verbatim). */
    abstract val label: String

    /** Whether an answer is required. */
    abstract val required: Boolean

    /** Optional helper text (wire `hint`). */
    abstract val hint: String?

    /** Optional ordering hint within the section (wire `position`). */
    abstract val position: Int?

    /**
     * Opaque per-type configuration. Holds the contents of the wire `config_json` object (plus any
     * unrecognized extra top-level keys, merged in for forward-compatibility). Read-only; tolerates any
     * keys. The typed accessors below read their slice of this map and NEVER throw on a
     * missing/malformed entry.
     */
    abstract val configJson: Map<String, Any?>

    /** Free-text question. */
    data class Text(
        override val questionId: String,
        override val sectionId: String,
        override val label: String,
        override val required: Boolean,
        override val hint: String? = null,
        override val position: Int? = null,
        override val configJson: Map<String, Any?> = emptyMap(),
    ) : QuestionnaireField() {
        override val type: QuestionType get() = QuestionType.TEXT

        /** Optional placeholder hint read from config_json (tolerant). */
        fun placeholder(): String? = configJson["placeholder"] as? String
    }

    /** Single-select (dropdown) question. */
    data class Select(
        override val questionId: String,
        override val sectionId: String,
        override val label: String,
        override val required: Boolean,
        override val hint: String? = null,
        override val position: Int? = null,
        override val configJson: Map<String, Any?> = emptyMap(),
    ) : QuestionnaireField() {
        override val type: QuestionType get() = QuestionType.SELECT

        /** Typed view of the options slice of config_json (tolerant; empty if absent/malformed). */
        fun options(): List<FieldOption> = readOptions(configJson)
    }

    /** Multi-select question. */
    data class Multiselect(
        override val questionId: String,
        override val sectionId: String,
        override val label: String,
        override val required: Boolean,
        override val hint: String? = null,
        override val position: Int? = null,
        override val configJson: Map<String, Any?> = emptyMap(),
    ) : QuestionnaireField() {
        override val type: QuestionType get() = QuestionType.MULTISELECT

        /** Typed view of the options slice of config_json (tolerant; empty if absent/malformed). */
        fun options(): List<FieldOption> = readOptions(configJson)
    }

    /** Radio-group (single-choice) question. */
    data class Radio(
        override val questionId: String,
        override val sectionId: String,
        override val label: String,
        override val required: Boolean,
        override val hint: String? = null,
        override val position: Int? = null,
        override val configJson: Map<String, Any?> = emptyMap(),
    ) : QuestionnaireField() {
        override val type: QuestionType get() = QuestionType.RADIO

        /** Typed view of the options slice of config_json (tolerant; empty if absent/malformed). */
        fun options(): List<FieldOption> = readOptions(configJson)
    }

    /** Numeric slider question. */
    data class Slider(
        override val questionId: String,
        override val sectionId: String,
        override val label: String,
        override val required: Boolean,
        override val hint: String? = null,
        override val position: Int? = null,
        override val configJson: Map<String, Any?> = emptyMap(),
    ) : QuestionnaireField() {
        override val type: QuestionType get() = QuestionType.SLIDER

        /** Lower bound from config_json `min` (tolerant; null if absent/non-numeric). */
        fun min(): Double? = readNumber(configJson["min"])

        /** Upper bound from config_json `max` (tolerant; null if absent/non-numeric). */
        fun max(): Double? = readNumber(configJson["max"])

        /** Step from config_json `step` (tolerant; null if absent/non-numeric). */
        fun step(): Double? = readNumber(configJson["step"])
    }

    /** Date-picker question. */
    data class DateField(
        override val questionId: String,
        override val sectionId: String,
        override val label: String,
        override val required: Boolean,
        override val hint: String? = null,
        override val position: Int? = null,
        override val configJson: Map<String, Any?> = emptyMap(),
    ) : QuestionnaireField() {
        override val type: QuestionType get() = QuestionType.DATE
    }

    /** Time-picker question. */
    data class TimeField(
        override val questionId: String,
        override val sectionId: String,
        override val label: String,
        override val required: Boolean,
        override val hint: String? = null,
        override val position: Int? = null,
        override val configJson: Map<String, Any?> = emptyMap(),
    ) : QuestionnaireField() {
        override val type: QuestionType get() = QuestionType.TIME
    }

    /** Timezone-picker question. */
    data class Timezone(
        override val questionId: String,
        override val sectionId: String,
        override val label: String,
        override val required: Boolean,
        override val hint: String? = null,
        override val position: Int? = null,
        override val configJson: Map<String, Any?> = emptyMap(),
    ) : QuestionnaireField() {
        override val type: QuestionType get() = QuestionType.TIMEZONE
    }

    /** Structured address question. */
    data class Address(
        override val questionId: String,
        override val sectionId: String,
        override val label: String,
        override val required: Boolean,
        override val hint: String? = null,
        override val position: Int? = null,
        override val configJson: Map<String, Any?> = emptyMap(),
    ) : QuestionnaireField() {
        override val type: QuestionType get() = QuestionType.ADDRESS
    }

    /**
     * Forward-compatibility fallback for an unrecognized/future `type` token (FR-5). Preserves the
     * [rawType] string and the full opaque body so the renderer (AND-347) can show a placeholder and
     * nothing is lost. NEVER produced by throwing - this is the non-throwing default of the adapter.
     */
    data class Unknown(
        val rawType: String,
        override val questionId: String,
        override val sectionId: String,
        override val label: String,
        override val required: Boolean,
        override val hint: String? = null,
        override val position: Int? = null,
        override val configJson: Map<String, Any?> = emptyMap(),
    ) : QuestionnaireField() {
        override val type: QuestionType get() = QuestionType.UNKNOWN
    }

    companion object {
        /**
         * Tolerant reader of the `options` slice of a config_json map. Accepts a list of
         * {value,label} maps (or bare string values) and ignores anything malformed. Never throws.
         */
        private fun readOptions(config: Map<String, Any?>): List<FieldOption> {
            val raw = config["options"] as? List<*> ?: return emptyList()
            return raw.mapNotNull { entry ->
                when (entry) {
                    is Map<*, *> -> {
                        val value = entry["value"]?.toString() ?: return@mapNotNull null
                        FieldOption(value = value, label = entry["label"]?.toString())
                    }
                    is String -> FieldOption(value = entry)
                    else -> null
                }
            }
        }

        /** Tolerant numeric reader (Number or numeric String) - null on absent/non-numeric. */
        private fun readNumber(value: Any?): Double? = when (value) {
            is Number -> value.toDouble()
            is String -> value.toDoubleOrNull()
            else -> null
        }
    }
}
