package com.testlogon.android.core.network.questionnaire

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationRequest
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationResponse
import com.testlogon.android.core.model.questionnaire.ResponseSessionEnvelope
import com.testlogon.android.core.model.questionnaire.SessionSaveReq
import com.testlogon.android.core.model.questionnaire.SessionStateEnvelope
import com.testlogon.android.core.model.questionnaire.SessionSubmitEnvelope
import com.testlogon.android.core.network.json.BigDecimalAdapter
import com.testlogon.android.core.network.signing.PacketRoleAdapter
import com.testlogon.android.core.network.signing.PacketStatusAdapter
import com.testlogon.android.core.network.signing.SignatureFieldTypeAdapter
import com.testlogon.android.core.network.signing.SignatureInputModeAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-346 - round-trip + shape tests for the respondent SESSION + validation DTOs (epic E45). These
 * exercise the corrected contract: enveloped responses, the PUT save body shape, the validation request
 * defaults, the map-shaped validation errors, and the toString() PII redaction.
 *
 * Built like NetworkModule.provideMoshi (custom questionnaire adapters before the reflective factory).
 * The session DTOs need the AnswerValueAdapter (answers_by_question_id values), so these tests live in
 * core-network. JSON is inline (no :core-testing test dependency). KDoc avoids the comment terminator.
 */
class QuestionnaireSessionJsonTest {

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

    // ---- Start session envelope ----

    @Test
    fun responseSessionEnvelope_decodesOpaqueSession() {
        val json = """{"session":{"response_session_id":"sess_abc","questionnaire_id":"qn_01",
            "version_id":"v1","status":"in_progress"}}""".trimIndent()
        val decoded = requireNotNull(moshi.adapter(ResponseSessionEnvelope::class.java).fromJson(json))
        assertEquals("sess_abc", decoded.session["response_session_id"])
        assertEquals("in_progress", decoded.session["status"])
    }

    // ---- Session state envelope (answers map + typed session) ----

    @Test
    fun sessionStateEnvelope_decodesSessionAndAnswersMap() {
        val json = """
            {"session":{"response_session_id":"sess_abc","questionnaire_id":"qn_01",
              "version_id":"v1","status":"in_progress","current_section_index":0},
             "answers_by_question_id":{"q_name":"Ada","q_nps":9,"q_color":["b"]}}
        """.trimIndent()
        val decoded = requireNotNull(moshi.adapter(SessionStateEnvelope::class.java).fromJson(json))
        assertEquals("sess_abc", decoded.session.response_session_id)
        assertEquals("qn_01", decoded.session.questionnaire_id)
        assertEquals("v1", decoded.session.version_id)
        assertEquals("in_progress", decoded.session.status)
        assertEquals(0, decoded.session.current_section_index)
        assertEquals(AnswerValue.Text("Ada"), decoded.answers_by_question_id["q_name"])
        assertEquals(AnswerValue.Num(9.0), decoded.answers_by_question_id["q_nps"])
        assertEquals(AnswerValue.Choices(listOf("b")), decoded.answers_by_question_id["q_color"])
    }

    @Test
    fun sessionState_missingResponseSessionId_throwsJsonDataException() {
        val json = """
            {"session":{"questionnaire_id":"qn_01","version_id":"v1","status":"in_progress"},
             "answers_by_question_id":{}}
        """.trimIndent()
        assertThrows(JsonDataException::class.java) {
            moshi.adapter(SessionStateEnvelope::class.java).fromJson(json)
        }
    }

    // ---- Save request (PUT body shape) ----

    @Test
    fun sessionSaveReq_roundTrips_withCursorFields() {
        val req = SessionSaveReq(
            answers_by_question_id = mapOf(
                "q_name" to AnswerValue.Text("Ada"),
                "q_color" to AnswerValue.Choices(listOf("b")),
            ),
            current_section_index = 0,
            current_question_id = "q_color",
        )
        val adapter = moshi.adapter(SessionSaveReq::class.java)
        val json = adapter.toJson(req)
        assertTrue(json.contains("answers_by_question_id"))
        assertTrue(json.contains("current_section_index"))
        assertTrue(json.contains("current_question_id"))
        val decoded = requireNotNull(adapter.fromJson(json))
        assertEquals(0, decoded.current_section_index)
        assertEquals("q_color", decoded.current_question_id)
        assertEquals(AnswerValue.Text("Ada"), decoded.answers_by_question_id["q_name"])
    }

    @Test
    fun sessionSaveReq_toString_redactsAnswers() {
        val req = SessionSaveReq(
            answers_by_question_id = mapOf("q_secret" to AnswerValue.Text("SSN-123-45-6789")),
        )
        val s = req.toString()
        assertFalse(s.contains("SSN-123-45-6789"))
        assertTrue(s.contains("redacted"))
    }

    // ---- Validation request defaults ----

    @Test
    fun validationRequest_appliesDefaults() {
        val req = QuestionnaireValidationRequest(
            answers_by_question_id = mapOf("q_name" to AnswerValue.Text("Ada")),
        )
        assertEquals("2026-03-validation-v1", req.contract_version)
        assertFalse(req.final_submit)
        assertTrue(req.form_rules.isEmpty())
        assertTrue(req.group_rules.isEmpty())

        val adapter = moshi.adapter(QuestionnaireValidationRequest::class.java)
        val json = adapter.toJson(req)
        assertTrue(json.contains("\"contract_version\":\"2026-03-validation-v1\""))
        assertTrue(json.contains("\"final_submit\":false"))
        val decoded = requireNotNull(adapter.fromJson(json))
        assertEquals("2026-03-validation-v1", decoded.contract_version)
    }

    @Test
    fun validationRequest_toString_redactsAnswers() {
        val req = QuestionnaireValidationRequest(
            answers_by_question_id = mapOf("q" to AnswerValue.Text("private-answer")),
        )
        assertFalse(req.toString().contains("private-answer"))
    }

    // ---- Validation response (errors map of issues) ----

    @Test
    fun validationResponse_decodesErrorsMap() {
        val json = """
            {"is_valid":false,"can_submit":false,"has_blocking_form_error":true,
             "errors":{"q_doc":[{"code":"required","message":"Required","blocking":true,"rule_id":null}]},
             "contract_version":"2026-03-validation-v1"}
        """.trimIndent()
        val decoded = requireNotNull(
            moshi.adapter(QuestionnaireValidationResponse::class.java).fromJson(json),
        )
        assertFalse(decoded.is_valid)
        assertFalse(decoded.can_submit)
        assertTrue(decoded.has_blocking_form_error)
        val issues = decoded.errors["q_doc"]!!
        assertEquals(1, issues.size)
        assertEquals("required", issues[0].code)
        assertEquals("Required", issues[0].message)
        assertEquals(true, issues[0].blocking)
    }

    @Test
    fun validationResponse_missingIsValid_throwsJsonDataException() {
        val json = """{"can_submit":true,"has_blocking_form_error":false,"errors":{}}"""
        assertThrows(JsonDataException::class.java) {
            moshi.adapter(QuestionnaireValidationResponse::class.java).fromJson(json)
        }
    }

    // ---- Submit envelope ----

    @Test
    fun submitEnvelope_decodesSessionAndResult() {
        val json = """
            {"session":{"response_session_id":"sess_abc","status":"submitted"},
             "result":{"is_valid":true,"can_submit":true,"has_blocking_form_error":false,
               "errors":{},"contract_version":"2026-03-validation-v1"}}
        """.trimIndent()
        val decoded = requireNotNull(moshi.adapter(SessionSubmitEnvelope::class.java).fromJson(json))
        assertEquals("submitted", decoded.session["status"])
        assertTrue(decoded.result.is_valid)
        assertTrue(decoded.result.errors.isEmpty())
    }
}
