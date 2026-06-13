package com.testlogon.android.feature.questionnaire.render

import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import java.time.ZoneId

/**
 * AND-347 - PURE (android-free) helpers backing the stateless dynamic form renderer. Kept in a separate
 * file from the Composables so they are unit-testable on the JVM (app src test) without a Compose rule.
 *
 * Everything here is tolerant: malformed or missing config_json slices fall back to a sensible default
 * and NEVER throw (the schema is opaque - AND-346 reconciliation). No networking / session / validation
 * / visibility logic lives here (those are AND-346 / 348 / 350 / 351).
 */
object QuestionRenderSupport {

    // ---- config_json typed reads (the AND-346 field subtypes expose only a few typed views; the rest
    // ---- are read here directly from the opaque configJson map with safe casts) ----

    /** Tolerant Int read from config_json (Number or numeric String); null on absent/non-numeric. */
    fun readInt(config: Map<String, Any?>, key: String): Int? = when (val v = config[key]) {
        is Number -> v.toInt()
        is String -> v.toDoubleOrNull()?.toInt()
        else -> null
    }

    /** Tolerant String read from config_json; null on absent/non-string. */
    fun readString(config: Map<String, Any?>, key: String): String? = config[key] as? String

    /** Tolerant String-list read from config_json; empty on absent/malformed. */
    fun readStringList(config: Map<String, Any?>, key: String): List<String> {
        val raw = config[key] as? List<*> ?: return emptyList()
        return raw.mapNotNull { it?.toString() }
    }

    // ---- Text ----

    /**
     * Soft-trims a text edit to the field's config_json `maxLength` (if any). The `pattern` / `minLength`
     * constraints are display-only here (validation is AND-350) so they do NOT alter the value.
     */
    fun coerceText(field: QuestionnaireField, raw: String): String {
        val max = readInt(field.configJson, "maxLength")
        return if (max != null && max >= 0 && raw.length > max) raw.take(max) else raw
    }

    /** Builds the AnswerValue for a text edit: blank -> [AnswerValue.Empty], else [AnswerValue.Text]. */
    fun textAnswer(value: String): AnswerValue =
        if (value.isBlank()) AnswerValue.Empty else AnswerValue.Text(value)

    /** Reads the current text from an incoming answer (rehydration). Empty/other -> "". */
    fun textOf(answer: AnswerValue?): String = when (answer) {
        is AnswerValue.Text -> answer.value
        is AnswerValue.Num -> formatNumber(answer.value)
        is AnswerValue.Choices -> answer.values.firstOrNull().orEmpty()
        else -> ""
    }

    // ---- Single-select (select / radio) ----
    //
    // ASSUMPTION (AND-346 R4): single-select answers are stored as a scalar string -> [AnswerValue.Text].
    // The backend tolerates a one-element array too, so [selectedOption] also reads [Choices].

    /** AnswerValue for a single-choice pick: null/blank -> Empty, else Text(value). */
    fun singleChoiceAnswer(value: String?): AnswerValue =
        if (value.isNullOrBlank()) AnswerValue.Empty else AnswerValue.Text(value)

    /** The currently-selected option value for a single-select control (rehydration). */
    fun selectedOption(answer: AnswerValue?): String? = when (answer) {
        is AnswerValue.Text -> answer.value.ifBlank { null }
        is AnswerValue.Choices -> answer.values.firstOrNull()
        else -> null
    }

    // ---- Multiselect ----

    /** The currently-selected option values for a multiselect control (rehydration). */
    fun selectedOptions(answer: AnswerValue?): List<String> = when (answer) {
        is AnswerValue.Choices -> answer.values
        is AnswerValue.Text -> if (answer.value.isBlank()) emptyList() else listOf(answer.value)
        else -> emptyList()
    }

    /**
     * Toggles [option] in [current] and returns the new selection IN [optionOrder] (stable, the option
     * declaration order). Empty selection -> [AnswerValue.Empty]; else [AnswerValue.Choices].
     */
    fun toggleMultiselect(
        current: List<String>,
        option: String,
        checked: Boolean,
        optionOrder: List<String>,
    ): AnswerValue {
        val set = current.toMutableSet()
        if (checked) set.add(option) else set.remove(option)
        val ordered = optionOrder.filter { it in set }
        return if (ordered.isEmpty()) AnswerValue.Empty else AnswerValue.Choices(ordered)
    }

    // ---- Slider ----

    /** Effective slider lower bound (config min, default 0.0). */
    fun sliderMin(field: QuestionnaireField.Slider): Float = (field.min() ?: 0.0).toFloat()

    /** Effective slider upper bound (config max, default 100.0; never below min). */
    fun sliderMax(field: QuestionnaireField.Slider): Float {
        val min = sliderMin(field)
        val max = (field.max() ?: 100.0).toFloat()
        return if (max < min) min else max
    }

    /**
     * Discrete step count for a Material3 Slider = number of INTERNAL stops between endpoints. Derived
     * from config `step`; 0 (continuous) when step is absent/non-positive or does not evenly divide.
     */
    fun sliderSteps(field: QuestionnaireField.Slider): Int {
        val step = field.step() ?: return 0
        if (step <= 0.0) return 0
        val span = (sliderMax(field) - sliderMin(field)).toDouble()
        if (span <= 0.0) return 0
        val divisions = Math.round(span / step).toInt()
        // Material3 `steps` excludes the two endpoints.
        return (divisions - 1).coerceAtLeast(0)
    }

    /** Coerces a raw slider value into [min, max] (defends against stale rehydrated answers). */
    fun coerceSliderValue(field: QuestionnaireField.Slider, raw: Float): Float =
        raw.coerceIn(sliderMin(field), sliderMax(field))

    /** Initial slider position from an incoming answer (rehydration); falls back to the min. */
    fun sliderValueOf(field: QuestionnaireField.Slider, answer: AnswerValue?): Float {
        val raw = when (answer) {
            is AnswerValue.Num -> answer.value.toFloat()
            is AnswerValue.Text -> answer.value.toFloatOrNull() ?: sliderMin(field)
            else -> sliderMin(field)
        }
        return coerceSliderValue(field, raw)
    }

    /** AnswerValue for a slider position. Emits [AnswerValue.Num] (the numeric variant). */
    fun sliderAnswer(value: Float): AnswerValue = AnswerValue.Num(value.toDouble())

    /** Formats a slider/number for display: integral doubles show without a trailing ".0". */
    fun formatNumber(value: Double): String =
        if (value == Math.floor(value) && !value.isInfinite()) value.toLong().toString()
        else value.toString()

    // ---- Timezone ----

    /**
     * The timezone choices for a [QuestionnaireField.Timezone]: the field's allowed list (config
     * `allowedTimezones`/`timezones`) when present, otherwise ALL available zone ids, sorted.
     */
    fun timezoneOptions(field: QuestionnaireField.Timezone): List<String> {
        val allowed = readStringList(field.configJson, "allowedTimezones")
            .ifEmpty { readStringList(field.configJson, "timezones") }
        return if (allowed.isNotEmpty()) allowed else allZoneIds()
    }

    /** All java.time zone ids, sorted (extracted for testability). */
    fun allZoneIds(): List<String> = ZoneId.getAvailableZoneIds().sorted()

    // ---- Address ----
    //
    // ENCODING (so AND-349 submit can read it back): the structured address is encoded as a COMPACT JSON
    // object string wrapped in [AnswerValue.Text] (AnswerValue has no map variant). Keys are the stable
    // sub-field ids below. Empty -> [AnswerValue.Empty]. [decodeAddress] round-trips it.

    /** Stable, ordered address sub-field ids (also the JSON keys for the encoded value). */
    val ADDRESS_FIELDS: List<String> =
        listOf("line1", "line2", "city", "state", "postalCode", "country")

    /** The sub-fields the schema marks required (config `requiredFields`); empty when unspecified. */
    fun addressRequiredFields(field: QuestionnaireField.Address): Set<String> =
        readStringList(field.configJson, "requiredFields").toSet()

    /**
     * Encodes the address sub-field map into an [AnswerValue]. All-blank -> [AnswerValue.Empty]; else a
     * compact JSON object string (key order = [ADDRESS_FIELDS]) in [AnswerValue.Text].
     */
    fun encodeAddress(parts: Map<String, String>): AnswerValue {
        val nonBlank = ADDRESS_FIELDS.filter { parts[it]?.isNotBlank() == true }
        if (nonBlank.isEmpty()) return AnswerValue.Empty
        val json = buildString {
            append('{')
            nonBlank.forEachIndexed { i, key ->
                if (i > 0) append(',')
                append(jsonString(key))
                append(':')
                append(jsonString(parts[key].orEmpty()))
            }
            append('}')
        }
        return AnswerValue.Text(json)
    }

    /**
     * Decodes an address [AnswerValue] back into a sub-field map (rehydration + AND-349 read). Tolerant:
     * a non-JSON / non-Text answer yields an empty map. Hand-rolled (no JSON dependency added).
     */
    fun decodeAddress(answer: AnswerValue?): Map<String, String> {
        val raw = (answer as? AnswerValue.Text)?.value?.trim() ?: return emptyMap()
        if (!raw.startsWith("{") || !raw.endsWith("}")) return emptyMap()
        return parseFlatJsonObject(raw)
    }

    // ---- tiny dependency-free JSON object helpers (flat string->string only) ----

    /** Encodes a string as a JSON string literal (escapes quote, backslash, and the control chars). */
    private fun jsonString(s: String): String {
        val sb = StringBuilder(s.length + 2)
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> sb.append(c)
            }
        }
        sb.append('"')
        return sb.toString()
    }

    /** Parses a FLAT JSON object of string->string pairs. Tolerant; unparsable input -> empty map. */
    private fun parseFlatJsonObject(raw: String): Map<String, String> {
        val body = raw.substring(1, raw.length - 1)
        val result = LinkedHashMap<String, String>()
        var i = 0
        while (i < body.length) {
            while (i < body.length && (body[i] == ',' || body[i].isWhitespace())) i++
            if (i >= body.length) break
            if (body[i] != '"') return result
            val keyEnd = readJsonString(body, i) ?: return result
            val key = unescape(body.substring(i + 1, keyEnd.first))
            i = keyEnd.second
            while (i < body.length && body[i].isWhitespace()) i++
            if (i >= body.length || body[i] != ':') return result
            i++
            while (i < body.length && body[i].isWhitespace()) i++
            if (i >= body.length || body[i] != '"') return result
            val valEnd = readJsonString(body, i) ?: return result
            val value = unescape(body.substring(i + 1, valEnd.first))
            i = valEnd.second
            result[key] = value
        }
        return result
    }

    /**
     * Scans a JSON string literal starting at the opening quote [start]. Returns (indexOfClosingQuote,
     * indexAfterClosingQuote) or null if unterminated.
     */
    private fun readJsonString(s: String, start: Int): Pair<Int, Int>? {
        var i = start + 1
        while (i < s.length) {
            when (s[i]) {
                '\\' -> i += 2
                '"' -> return i to (i + 1)
                else -> i++
            }
        }
        return null
    }

    /** Reverses [jsonString] escaping for the flat parser. */
    private fun unescape(s: String): String {
        if ('\\' !in s) return s
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '\\' && i + 1 < s.length) {
                when (s[i + 1]) {
                    '"' -> sb.append('"')
                    '\\' -> sb.append('\\')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    else -> sb.append(s[i + 1])
                }
                i += 2
            } else {
                sb.append(c)
                i++
            }
        }
        return sb.toString()
    }
}
