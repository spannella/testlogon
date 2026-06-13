package com.testlogon.android.core.network.questionnaire

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireValidationRequest
import com.testlogon.android.core.model.questionnaire.ResponseSessionStartReq
import com.testlogon.android.core.model.questionnaire.SessionSaveReq
import com.testlogon.android.core.network.json.BigDecimalAdapter
import com.testlogon.android.core.network.signing.PacketRoleAdapter
import com.testlogon.android.core.network.signing.PacketStatusAdapter
import com.testlogon.android.core.network.signing.SignatureFieldTypeAdapter
import com.testlogon.android.core.network.signing.SignatureInputModeAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-346 - hermetic contract tests for [QuestionnaireApi] against MockWebServer (epic E45, FR-8).
 *
 * For each endpoint this asserts the HTTP VERB, the resolved PATH (proving the {published_slug} /
 * {response_session_id} tokens are substituted), the request BODY (for the body verbs), and that the
 * enveloped response DECODES. The 422 FastAPI-detail path is asserted to surface as an HttpException
 * (the error -> ApiResult mapping is the downstream repo's job). Everything is hermetic: MockWebServer
 * only, the production-style shared Moshi (built like NetworkModule.provideMoshi), runTest. There is NO
 * nested runTest (the 422 case uses a single runBlocking). KDoc avoids the comment terminator.
 */
class QuestionnaireApiTest {

    private lateinit var server: MockWebServer

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

    private val bodyMapAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    private fun questionnaireApi(): QuestionnaireApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(QuestionnaireApi::class.java)

    /** Decode a recorded request body to a loosely-typed map (read the body source ONCE). */
    private fun RecordedRequest.bodyAsMap(): Map<String, Any?> {
        val raw = body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        return bodyMapAdapter.fromJson(raw) ?: emptyMap()
    }

    private fun jsonResponse(body: String, code: Int = 200) =
        MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)

    @Before
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    // ---- getPublished: GET + path + envelope decode ----

    @Test
    fun getPublished_getsBySlug_decodesEnvelope() = runTest {
        server.enqueue(jsonResponse(PUBLISHED_ENVELOPE))

        val envelope = questionnaireApi().getPublished("intake-2026")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/questionnaires/published/intake-2026", recorded.requestUrl?.encodedPath)
        assertEquals("intake-2026", envelope.version.published_slug)
        assertEquals("qn_01", envelope.version.schema_json.questionnaire_id)
        assertEquals(1, envelope.version.schema_json.sections.size)
    }

    // ---- startSession: POST + path + body ----

    @Test
    fun startSession_postsToSessionsPath_withStartBody() = runTest {
        server.enqueue(jsonResponse("""{"session":{"response_session_id":"sess_abc","status":"in_progress"}}"""))

        val envelope = questionnaireApi().startSession("intake-2026", ResponseSessionStartReq())

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals(
            "/questionnaires/published/intake-2026/sessions",
            recorded.requestUrl?.encodedPath,
        )
        assertEquals("sess_abc", envelope.session["response_session_id"])
    }

    // ---- getSession: GET + both path tokens substituted ----

    @Test
    fun getSession_substitutesBothPathTokens() = runTest {
        server.enqueue(
            jsonResponse(
                """{"session":{"response_session_id":"sess_abc","questionnaire_id":"qn_01",
                   "version_id":"v1","status":"in_progress"},"answers_by_question_id":{"q_name":"Ada"}}""",
            ),
        )

        val envelope = questionnaireApi().getSession("intake-2026", "sess_abc")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals(
            "/questionnaires/published/intake-2026/sessions/sess_abc",
            recorded.requestUrl?.encodedPath,
        )
        assertEquals("sess_abc", envelope.session.response_session_id)
        assertEquals(AnswerValue.Text("Ada"), envelope.answers_by_question_id["q_name"])
    }

    // ---- saveAnswers: PUT (not PATCH) + body shape ----

    @Test
    fun saveAnswers_usesPut_withAnswersByQuestionIdBody() = runTest {
        server.enqueue(
            jsonResponse(
                """{"session":{"response_session_id":"sess_abc","questionnaire_id":"qn_01",
                   "version_id":"v1","status":"in_progress","current_section_index":0},
                   "answers_by_question_id":{"q_name":"Ada"}}""",
            ),
        )

        questionnaireApi().saveAnswers(
            "intake-2026",
            "sess_abc",
            SessionSaveReq(
                answers_by_question_id = mapOf("q_name" to AnswerValue.Text("Ada")),
                current_section_index = 0,
                current_question_id = "q_name",
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("PUT", recorded.method)
        assertEquals(
            "/questionnaires/published/intake-2026/sessions/sess_abc",
            recorded.requestUrl?.encodedPath,
        )
        val body = recorded.bodyAsMap()
        assertTrue(body.containsKey("answers_by_question_id"))
        assertEquals(0.0, (body["current_section_index"] as Number).toDouble(), 0.0)
        assertEquals("q_name", body["current_question_id"])
    }

    // ---- validate: POST QuestionnaireValidationRequest -> map-shaped errors ----

    @Test
    fun validate_postsValidationRequest_decodesErrorsMap() = runTest {
        server.enqueue(
            jsonResponse(
                """{"is_valid":false,"can_submit":false,"has_blocking_form_error":true,
                   "errors":{"q_doc":[{"code":"required","message":"Required","blocking":true}]},
                   "contract_version":"2026-03-validation-v1"}""",
            ),
        )

        val resp = questionnaireApi().validate(
            "intake-2026",
            "sess_abc",
            QuestionnaireValidationRequest(
                answers_by_question_id = mapOf("q_name" to AnswerValue.Text("Ada")),
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals(
            "/questionnaires/published/intake-2026/sessions/sess_abc/validate",
            recorded.requestUrl?.encodedPath,
        )
        val body = recorded.bodyAsMap()
        assertEquals("2026-03-validation-v1", body["contract_version"])
        assertEquals(false, body["final_submit"])
        assertEquals(1, resp.errors["q_doc"]?.size)
    }

    // ---- submit: POST QuestionnaireValidationRequest -> submit envelope ----

    @Test
    fun submit_postsValidationRequest_decodesSubmitEnvelope() = runTest {
        server.enqueue(
            jsonResponse(
                """{"session":{"response_session_id":"sess_abc","status":"submitted"},
                   "result":{"is_valid":true,"can_submit":true,"has_blocking_form_error":false,
                     "errors":{},"contract_version":"2026-03-validation-v1"}}""",
            ),
        )

        val envelope = questionnaireApi().submit(
            "intake-2026",
            "sess_abc",
            QuestionnaireValidationRequest(
                answers_by_question_id = mapOf("q_name" to AnswerValue.Text("Ada")),
                final_submit = true,
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals(
            "/questionnaires/published/intake-2026/sessions/sess_abc/submit",
            recorded.requestUrl?.encodedPath,
        )
        val body = recorded.bodyAsMap()
        assertEquals(true, body["final_submit"])
        assertEquals("submitted", envelope.session["status"])
        assertTrue(envelope.result.is_valid)
    }

    // ---- error path: 422 FastAPI detail -> HttpException ----

    @Test
    fun saveAnswers_422DetailBody_throwsHttpException() {
        // No runTest wrapper: assertThrows needs a synchronous throw, bridged with a single runBlocking
        // (NOT nested inside runTest).
        server.enqueue(
            jsonResponse(
                """{"detail":[{"loc":["body","answers_by_question_id"],"msg":"field required",
                   "type":"value_error.missing"}]}""",
                code = 422,
            ),
        )

        val thrown = assertThrows(HttpException::class.java) {
            kotlinx.coroutines.runBlocking {
                questionnaireApi().saveAnswers(
                    "intake-2026",
                    "sess_abc",
                    SessionSaveReq(answers_by_question_id = emptyMap()),
                )
            }
        }
        assertEquals(422, thrown.code())
        assertTrue(thrown.response()?.errorBody()?.string()?.contains("field required") == true)
    }

    private companion object {

        val PUBLISHED_ENVELOPE = """
            {
              "version": {
                "published_slug": "intake-2026",
                "questionnaire_id": "qn_01",
                "version_id": "v1",
                "schema_json": {
                  "questionnaire_id": "qn_01",
                  "title": "Intake",
                  "sections": [
                    {"section_id":"s1","title":"About you","questions":[
                      {"type":"text","question_id":"q_name","section_id":"s1",
                       "label":"Full name","required":true,"config_json":{"max_length":120}}
                    ]}
                  ]
                }
              }
            }
        """.trimIndent()
    }
}
