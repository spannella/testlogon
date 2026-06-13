package com.testlogon.android.core.network.questionnaire

import com.squareup.moshi.FromJson
import com.squareup.moshi.JsonAdapter
import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonReader
import com.squareup.moshi.JsonWriter
import com.squareup.moshi.Moshi
import com.squareup.moshi.ToJson
import com.squareup.moshi.Types
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionType
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import java.lang.reflect.Type

/**
 * AND-346 - the CUSTOM, dependency-free Moshi adapters for the QUESTIONNAIRES transport (epic E45).
 *
 * RECONCILIATION (no moshi-adapters): this ticket forbids adding any dependency, so there is NO
 * PolymorphicJsonAdapterFactory and NO EnumJsonAdapter.withUnknownFallback (both live in the
 * moshi-adapters artifact, which is not on the classpath). We reproduce the same semantics by hand,
 * mirroring the AND-339 signing enum-adapter precedent (custom @FromJson/@ToJson with an UNKNOWN
 * fallback) and adding a hand-rolled polymorphic factory for the sealed [QuestionnaireField].
 *
 * THREE adapters are defined here and ALL are registered on NetworkModule.provideMoshi BEFORE the
 * reflective KotlinJsonAdapterFactory (so they win for their types):
 *   1. [QuestionTypeAdapter]        - QuestionType enum token <-> enum, unknown token -> UNKNOWN.
 *   2. [AnswerValueAdapter]         - the answer union (string/number/boolean/list/date-string).
 *   3. [QuestionnaireFieldFactory]  - the polymorphic field schema (type discriminator -> sealed
 *                                     subtype + config_json capture; unknown type -> Unknown, never
 *                                     throws per FR-5).
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */

/**
 * AND-346 - Moshi adapter for [QuestionType]. Wire value is the lowercase token; an unrecognized token
 * decodes to [QuestionType.UNKNOWN] (never throws) and serializes back to its token. Dependency-free
 * stand-in for EnumJsonAdapter.withUnknownFallback (mirrors the AND-339 signing enum adapters).
 */
object QuestionTypeAdapter {
    @FromJson fun fromJson(token: String?): QuestionType = QuestionType.fromToken(token)
    @ToJson fun toJson(value: QuestionType): String = value.token
}

/**
 * AND-346 - Moshi adapter for the [AnswerValue] union. fromJson peeks the next JSON token and dispatches:
 * STRING -> Text, NUMBER -> Num, BOOLEAN -> Bool, BEGIN_ARRAY -> Choices (list of strings), NULL/other
 * -> Empty (never throws - malformed values fall back to Empty per the error-handling contract). toJson
 * writes the underlying scalar/array back so it ROUND-TRIPS.
 */
object AnswerValueAdapter {

    @FromJson
    fun fromJson(reader: JsonReader): AnswerValue = when (reader.peek()) {
        JsonReader.Token.STRING -> AnswerValue.Text(reader.nextString())
        JsonReader.Token.NUMBER -> AnswerValue.Num(reader.nextDouble())
        JsonReader.Token.BOOLEAN -> AnswerValue.Bool(reader.nextBoolean())
        JsonReader.Token.NULL -> {
            reader.nextNull<Unit>()
            AnswerValue.Empty
        }
        JsonReader.Token.BEGIN_ARRAY -> {
            val values = mutableListOf<String>()
            reader.beginArray()
            while (reader.hasNext()) {
                if (reader.peek() == JsonReader.Token.NULL) {
                    reader.nextNull<Unit>()
                } else {
                    // Coerce scalars to their string form; tolerate non-string array entries.
                    values.add(reader.readJsonValue()?.toString() ?: "")
                }
            }
            reader.endArray()
            AnswerValue.Choices(values)
        }
        else -> {
            // Object or any other shape we do not model as a typed answer -> Empty (never throws).
            reader.skipValue()
            AnswerValue.Empty
        }
    }

    @ToJson
    fun toJson(writer: JsonWriter, value: AnswerValue?) {
        when (value) {
            is AnswerValue.Text -> writer.value(value.value)
            is AnswerValue.Num -> writer.value(value.value)
            is AnswerValue.Bool -> writer.value(value.value)
            is AnswerValue.Choices -> {
                writer.beginArray()
                value.values.forEach { writer.value(it) }
                writer.endArray()
            }
            AnswerValue.Empty, null -> writer.nullValue()
        }
    }
}

/**
 * AND-346 - the hand-rolled polymorphic [JsonAdapter.Factory] for the sealed [QuestionnaireField].
 *
 * Mechanism (dependency-free): read the whole field object generically into a Map via a Moshi
 * Map<String, Any?> adapter (preserving key order), pull the COMMON required keys (type / question_id /
 * section_id / label / required) off the map - throwing a [JsonDataException] if any is absent (FR-6
 * fail-fast) - and treat the REMAINING keys as the opaque config_json. The `type` token selects the
 * sealed subtype; an unrecognized/missing-but-present type yields [QuestionnaireField.Unknown]
 * (NEVER throws on unknown type per FR-5). toJson writes type + common keys + config_json back so the
 * field ROUND-TRIPS.
 *
 * The Map adapter is resolved with `moshi.nextAdapter` (NOT `moshi.adapter`) so this factory is not
 * re-entrant for the Map type and the built-in map support is used for the generic body.
 */
object QuestionnaireFieldFactory : JsonAdapter.Factory {

    private val COMMON_KEYS =
        setOf("type", "question_id", "section_id", "label", "required", "hint", "position", "config_json")

    override fun create(type: Type, annotations: Set<Annotation>, moshi: Moshi): JsonAdapter<*>? {
        if (Types.getRawType(type) != QuestionnaireField::class.java) return null

        val mapType = Types.newParameterizedType(
            Map::class.java,
            String::class.java,
            Any::class.java,
        )
        val mapAdapter: JsonAdapter<Map<String, Any?>> = moshi.adapter(mapType)

        return object : JsonAdapter<QuestionnaireField>() {

            override fun fromJson(reader: JsonReader): QuestionnaireField? {
                if (reader.peek() == JsonReader.Token.NULL) {
                    return reader.nextNull()
                }
                val obj = mapAdapter.fromJson(reader) ?: return null

                val typeToken = requireString(obj, "type")
                val questionId = requireString(obj, "question_id")
                val sectionId = requireString(obj, "section_id")
                val label = requireString(obj, "label")
                val required = requireBoolean(obj, "required")
                val hint = obj["hint"] as? String
                val position = (obj["position"] as? Number)?.toInt()

                // The opaque per-type config is the nested config_json object. Any OTHER unrecognized
                // top-level keys (forward-compat extras like server_time) are merged in so nothing is
                // lost and unknown keys are tolerated (FR-5). Order is preserved (nested config first).
                val config = LinkedHashMap<String, Any?>()
                @Suppress("UNCHECKED_CAST")
                (obj["config_json"] as? Map<String, Any?>)?.let { config.putAll(it) }
                obj.forEach { (k, v) -> if (k !in COMMON_KEYS) config[k] = v }

                return when (QuestionType.fromToken(typeToken)) {
                    QuestionType.TEXT -> QuestionnaireField.Text(
                        questionId, sectionId, label, required, hint, position, config,
                    )
                    QuestionType.SELECT -> QuestionnaireField.Select(
                        questionId, sectionId, label, required, hint, position, config,
                    )
                    QuestionType.MULTISELECT -> QuestionnaireField.Multiselect(
                        questionId, sectionId, label, required, hint, position, config,
                    )
                    QuestionType.RADIO -> QuestionnaireField.Radio(
                        questionId, sectionId, label, required, hint, position, config,
                    )
                    QuestionType.SLIDER -> QuestionnaireField.Slider(
                        questionId, sectionId, label, required, hint, position, config,
                    )
                    QuestionType.DATE -> QuestionnaireField.DateField(
                        questionId, sectionId, label, required, hint, position, config,
                    )
                    QuestionType.TIME -> QuestionnaireField.TimeField(
                        questionId, sectionId, label, required, hint, position, config,
                    )
                    QuestionType.TIMEZONE -> QuestionnaireField.Timezone(
                        questionId, sectionId, label, required, hint, position, config,
                    )
                    QuestionType.ADDRESS -> QuestionnaireField.Address(
                        questionId, sectionId, label, required, hint, position, config,
                    )
                    // Unknown / unrecognized type token -> Unknown fallback, NEVER throws (FR-5).
                    QuestionType.UNKNOWN -> QuestionnaireField.Unknown(
                        rawType = typeToken,
                        questionId = questionId,
                        sectionId = sectionId,
                        label = label,
                        required = required,
                        hint = hint,
                        position = position,
                        configJson = config,
                    )
                }
            }

            override fun toJson(writer: JsonWriter, value: QuestionnaireField?) {
                if (value == null) {
                    writer.nullValue()
                    return
                }
                // Reassemble the wire object: type + common keys + the opaque config_json (nested).
                val typeToken = if (value is QuestionnaireField.Unknown) value.rawType else value.type.token
                val out = LinkedHashMap<String, Any?>()
                out["type"] = typeToken
                out["question_id"] = value.questionId
                out["section_id"] = value.sectionId
                out["label"] = value.label
                out["required"] = value.required
                value.hint?.let { out["hint"] = it }
                value.position?.let { out["position"] = it }
                out["config_json"] = value.configJson
                mapAdapter.toJson(writer, out)
            }

            private fun requireString(obj: Map<String, Any?>, key: String): String {
                val v = obj[key]
                    ?: throw JsonDataException("Required field '$key' missing in QuestionnaireField")
                return v as? String
                    ?: throw JsonDataException("Field '$key' must be a string in QuestionnaireField")
            }

            private fun requireBoolean(obj: Map<String, Any?>, key: String): Boolean {
                val v = obj[key]
                    ?: throw JsonDataException("Required field '$key' missing in QuestionnaireField")
                return v as? Boolean
                    ?: throw JsonDataException("Field '$key' must be a boolean in QuestionnaireField")
            }
        }
    }
}
