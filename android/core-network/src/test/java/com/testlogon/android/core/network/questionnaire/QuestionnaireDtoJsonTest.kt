package com.testlogon.android.core.network.questionnaire

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.PublishedQuestionnaireEnvelope
import com.testlogon.android.core.model.questionnaire.QuestionType
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.core.network.json.BigDecimalAdapter
import com.testlogon.android.core.network.signing.PacketRoleAdapter
import com.testlogon.android.core.network.signing.PacketStatusAdapter
import com.testlogon.android.core.network.signing.SignatureFieldTypeAdapter
import com.testlogon.android.core.network.signing.SignatureInputModeAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-346 - DTO-level Moshi tests for the QUESTIONNAIRES transport (epic E45), focused on the
 * polymorphic field schema + the AnswerValue union.
 *
 * RECONCILIATION (test placement): the spec sketch put these round-trips in core-model test resources,
 * but the CUSTOM polymorphic field / answer adapters live in core-NETWORK (per the spec's own module
 * placement, §2). A polymorphic round-trip is meaningless without those adapters, so the round-trip
 * tests that need them live HERE in core-network test (core-model alone has no Moshi). The Moshi is
 * built EXACTLY like NetworkModule.provideMoshi (the custom questionnaire adapters BEFORE the reflective
 * KotlinJsonAdapterFactory, same order) so decoding reflects production. JSON is inline (core-network
 * has no :core-testing test dependency). KDoc avoids the comment-terminator character pair.
 */
class QuestionnaireDtoJsonTest {

    // Built exactly like NetworkModule.provideMoshi (custom questionnaire adapters before the factory).
    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(PacketStatusAdapter)
        .add(SignatureFieldTypeAdapter)
        .add(PacketRoleAdapter)
        .add(SignatureInputModeAdapter)
        .add(QuestionnaireFieldFactory)
        .add(QuestionTypeAdapter)
        .add(AnswerValueAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private val fieldAdapter = moshi.adapter(QuestionnaireField::class.java)
    private val envelopeAdapter = moshi.adapter(PublishedQuestionnaireEnvelope::class.java)
    private val answerAdapter = moshi.adapter(AnswerValue::class.java)

    // ---- One of every field type decodes to the correct sealed subtype ----

    @Test
    fun publishedSchema_decodesOneOfEveryFieldType_toCorrectSubtype() {
        val envelope = requireNotNull(envelopeAdapter.fromJson(ALL_FIELD_TYPES_ENVELOPE))
        val fields = envelope.version.schema_json.sections.flatMap { it.questions }

        // Nine documented types, in order, each to its sealed subtype.
        assertEquals(9, fields.size)
        assertTrue(fields[0] is QuestionnaireField.Text)
        assertTrue(fields[1] is QuestionnaireField.Select)
        assertTrue(fields[2] is QuestionnaireField.Multiselect)
        assertTrue(fields[3] is QuestionnaireField.Radio)
        assertTrue(fields[4] is QuestionnaireField.Slider)
        assertTrue(fields[5] is QuestionnaireField.DateField)
        assertTrue(fields[6] is QuestionnaireField.TimeField)
        assertTrue(fields[7] is QuestionnaireField.Timezone)
        assertTrue(fields[8] is QuestionnaireField.Address)

        // Common required keys decoded.
        assertEquals("q_name", fields[0].questionId)
        assertEquals("s1", fields[0].sectionId)
        assertEquals("Full name", fields[0].label)
        assertTrue(fields[0].required)

        // Envelope + version required keys decoded.
        assertEquals("intake-2026", envelope.version.published_slug)
        assertEquals("qn_01", envelope.version.questionnaire_id)
        assertEquals("v1", envelope.version.version_id)
        assertEquals("qn_01", envelope.version.schema_json.questionnaire_id)
    }

    // ---- config_json preserved + typed views ----

    @Test
    fun selectOptions_andSliderBounds_readFromConfigJson() {
        val envelope = requireNotNull(envelopeAdapter.fromJson(ALL_FIELD_TYPES_ENVELOPE))
        val fields = envelope.version.schema_json.sections.flatMap { it.questions }

        val select = fields[1] as QuestionnaireField.Select
        val options = select.options()
        assertEquals(2, options.size)
        assertEquals("r", options[0].value)
        assertEquals("Red", options[0].label)
        // The opaque config_json is preserved verbatim.
        assertNotNull(select.configJson["options"])

        val slider = fields[4] as QuestionnaireField.Slider
        assertEquals(0.0, slider.min())
        assertEquals(10.0, slider.max())
        assertEquals(1.0, slider.step())
    }

    // ---- Unknown type never throws ----

    @Test
    fun unknownFieldType_decodesToUnknown_neverThrows() {
        val json = """
            {"type":"signature","question_id":"q_sig","section_id":"s1",
             "label":"Sign here","required":true,"config_json":{"pad":"large"}}
        """.trimIndent()
        val field = requireNotNull(fieldAdapter.fromJson(json))
        assertTrue(field is QuestionnaireField.Unknown)
        field as QuestionnaireField.Unknown
        assertEquals("signature", field.rawType)
        assertEquals(QuestionType.UNKNOWN, field.type)
        assertEquals("q_sig", field.questionId)
        // The opaque config_json is preserved on Unknown.
        assertEquals("large", field.configJson["pad"])
    }

    // ---- Field round-trips (re-serialize -> re-parse equal) ----

    @Test
    fun field_roundTrips_preservingTypeCommonKeysAndConfig() {
        val original = QuestionnaireField.Slider(
            questionId = "q_nps",
            sectionId = "s1",
            label = "Rate us",
            required = false,
            hint = "0 to 10",
            position = 5,
            configJson = mapOf("min" to 0.0, "max" to 10.0),
        )
        val json = fieldAdapter.toJson(original)
        val decoded = requireNotNull(fieldAdapter.fromJson(json))
        assertTrue(decoded is QuestionnaireField.Slider)
        decoded as QuestionnaireField.Slider
        assertEquals("q_nps", decoded.questionId)
        assertEquals("s1", decoded.sectionId)
        assertEquals("Rate us", decoded.label)
        assertFalse(decoded.required)
        assertEquals("0 to 10", decoded.hint)
        assertEquals(5, decoded.position)
        assertEquals(0.0, decoded.min())
        assertEquals(10.0, decoded.max())
    }

    @Test
    fun unknownField_roundTripsBackToItsRawType() {
        val original = QuestionnaireField.Unknown(
            rawType = "hologram",
            questionId = "q_x",
            sectionId = "s1",
            label = "Future",
            required = true,
            configJson = mapOf("foo" to "bar"),
        )
        val json = fieldAdapter.toJson(original)
        assertTrue(json.contains("\"hologram\""))
        val decoded = requireNotNull(fieldAdapter.fromJson(json))
        assertTrue(decoded is QuestionnaireField.Unknown)
        assertEquals("hologram", (decoded as QuestionnaireField.Unknown).rawType)
    }

    // ---- Missing required structural key -> JsonDataException ----

    @Test
    fun missingQuestionId_throwsJsonDataException() {
        val json = """{"type":"text","section_id":"s1","label":"X","required":true}"""
        assertThrows(JsonDataException::class.java) { fieldAdapter.fromJson(json) }
    }

    @Test
    fun missingType_throwsJsonDataException() {
        val json = """{"question_id":"q1","section_id":"s1","label":"X","required":true}"""
        assertThrows(JsonDataException::class.java) { fieldAdapter.fromJson(json) }
    }

    @Test
    fun missingLabel_throwsJsonDataException() {
        val json = """{"type":"text","question_id":"q1","section_id":"s1","required":true}"""
        assertThrows(JsonDataException::class.java) { fieldAdapter.fromJson(json) }
    }

    // ---- Extra unknown top-level keys tolerated ----

    @Test
    fun extraUnknownKeys_tolerated_andLandInConfigJson() {
        val json = """
            {"type":"text","question_id":"q1","section_id":"s1","label":"X","required":false,
             "server_time":"2026-06-01","future_flag":true}
        """.trimIndent()
        val field = requireNotNull(fieldAdapter.fromJson(json))
        assertTrue(field is QuestionnaireField.Text)
        // Non-common keys are captured into the opaque config_json (nothing throws).
        assertEquals("2026-06-01", field.configJson["server_time"])
        assertEquals(true, field.configJson["future_flag"])
    }

    @Test
    fun unknownEnvelopeKeys_tolerated() {
        val json = """
            {"version":{"published_slug":"s","questionnaire_id":"q","version_id":"v",
             "schema_json":{"questionnaire_id":"q","sections":[]},"server_time":"now"},
             "trace_id":"abc"}
        """.trimIndent()
        val envelope = requireNotNull(envelopeAdapter.fromJson(json))
        assertEquals("s", envelope.version.published_slug)
    }

    // ---- AnswerValue union round-trips all variants ----

    @Test
    fun answerValue_allVariantsRoundTrip() {
        assertEquals(AnswerValue.Text("Ada"), answerAdapter.fromJson("\"Ada\""))
        assertEquals(AnswerValue.Num(9.0), answerAdapter.fromJson("9"))
        assertEquals(AnswerValue.Bool(true), answerAdapter.fromJson("true"))
        assertEquals(AnswerValue.Choices(listOf("b", "g")), answerAdapter.fromJson("""["b","g"]"""))
        assertEquals(AnswerValue.Empty, answerAdapter.fromJson("null"))
        // A date-string decodes to Text.
        assertEquals(AnswerValue.Text("2026-05-02"), answerAdapter.fromJson("\"2026-05-02\""))

        // Re-serialize each back to its scalar/array form.
        assertEquals("\"Ada\"", answerAdapter.toJson(AnswerValue.Text("Ada")))
        assertEquals("9.0", answerAdapter.toJson(AnswerValue.Num(9.0)))
        assertEquals("true", answerAdapter.toJson(AnswerValue.Bool(true)))
        assertEquals("""["b","g"]""", answerAdapter.toJson(AnswerValue.Choices(listOf("b", "g"))))
        assertEquals("null", answerAdapter.toJson(AnswerValue.Empty))
    }

    @Test
    fun answerValue_objectShape_fallsBackToEmpty_neverThrows() {
        assertEquals(AnswerValue.Empty, answerAdapter.fromJson("""{"unexpected":1}"""))
    }

    private companion object {

        // A published envelope with ONE OF EVERY documented field type (the nine real types), each with
        // a representative config_json. Synthetic answers only (no PII).
        val ALL_FIELD_TYPES_ENVELOPE = """
            {
              "version": {
                "published_slug": "intake-2026",
                "questionnaire_id": "qn_01",
                "version_id": "v1",
                "version_number": 1,
                "visibility": "public",
                "allow_anonymous": true,
                "published_at": "2026-06-01T10:00:00Z",
                "schema_json": {
                  "questionnaire_id": "qn_01",
                  "title": "Intake",
                  "sections": [
                    {
                      "section_id": "s1",
                      "title": "About you",
                      "position": 0,
                      "questions": [
                        {"type":"text","question_id":"q_name","section_id":"s1",
                         "label":"Full name","required":true,"position":0,
                         "config_json":{"placeholder":"Jane Doe","max_length":120}},
                        {"type":"select","question_id":"q_color","section_id":"s1",
                         "label":"Favorite color","required":false,"position":1,
                         "config_json":{"options":[{"value":"r","label":"Red"},{"value":"b","label":"Blue"}]}},
                        {"type":"multiselect","question_id":"q_tags","section_id":"s1",
                         "label":"Tags","required":false,"position":2,
                         "config_json":{"options":[{"value":"a","label":"A"},{"value":"b","label":"B"}]}},
                        {"type":"radio","question_id":"q_yn","section_id":"s1",
                         "label":"Yes or no","required":true,"position":3,
                         "config_json":{"options":[{"value":"y","label":"Yes"},{"value":"n","label":"No"}]}},
                        {"type":"slider","question_id":"q_nps","section_id":"s1",
                         "label":"Rate us","required":false,"position":4,
                         "config_json":{"min":0,"max":10,"step":1}},
                        {"type":"date","question_id":"q_dob","section_id":"s1",
                         "label":"Date of birth","required":false,"position":5,"config_json":{}},
                        {"type":"time","question_id":"q_time","section_id":"s1",
                         "label":"Preferred time","required":false,"position":6,"config_json":{}},
                        {"type":"timezone","question_id":"q_tz","section_id":"s1",
                         "label":"Timezone","required":false,"position":7,"config_json":{}},
                        {"type":"address","question_id":"q_addr","section_id":"s1",
                         "label":"Address","required":false,"position":8,"config_json":{}}
                      ]
                    }
                  ]
                }
              }
            }
        """.trimIndent()
    }
}
