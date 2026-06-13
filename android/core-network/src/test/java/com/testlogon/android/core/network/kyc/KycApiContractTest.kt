package com.testlogon.android.core.network.kyc

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.kyc.KycCaseCreateRequest
import com.testlogon.android.core.model.kyc.KycCaseDraftPatchRequest
import com.testlogon.android.core.model.kyc.KycCaseEnvelope
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.core.model.kyc.KycFileAttachmentRequest
import com.testlogon.android.core.model.kyc.KycFileType
import com.testlogon.android.core.model.kyc.KycSubmitCaseRequest
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-319 - contract tests for [KycApi] against MockWebServer with the production-style shared Moshi
 * (BigDecimalAdapter + the two KYC enum adapters + KotlinJsonAdapterFactory, mirroring
 * NetworkModule.provideMoshi). Mirrors the existing core-network MockWebServer idiom
 * (RetryInterceptorTest): a manually started server, retrofit.create against it, asserting recorded
 * method/path/body and decoding responses. Stays within core-network's existing test deps (no
 * core-testing dependency added).
 */
class KycApiContractTest {

    private lateinit var server: MockWebServer

    // Built exactly like the production NetworkModule.provideMoshi so adapter resolution matches prod.
    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KycCaseStatusAdapter)
        .add(KycFileTypeAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private val mapAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    private fun api(): KycApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(KycApi::class.java)

    /** Decode a recorded request body to a loosely-typed map (read the body source ONCE). */
    private fun RecordedRequest.bodyJson(): Map<String, Any?> {
        val raw = body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        return mapAdapter.fromJson(raw) ?: emptyMap()
    }

    private fun okBody(body: String, code: Int = 200) =
        MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)

    @Before
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    // ---- Tier endpoints (ResponseBody, verb + path only) ----

    @Test
    fun tierMe_verb_path_returnsBody() = runTest {
        server.enqueue(okBody("""{"tier":"basic"}"""))
        val resp = api().tierMe()
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/tiers/me", recorded.requestUrl?.encodedPath)
        assertEquals("""{"tier":"basic"}""", resp.string())
    }

    @Test
    fun evaluateTier_verb_path_noBody() = runTest {
        server.enqueue(okBody("""{"evaluated":true}"""))
        val resp = api().evaluateTier()
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/kyc/tiers/me/evaluate", recorded.requestUrl?.encodedPath)
        assertEquals(0L, recorded.bodySize)
        assertEquals("""{"evaluated":true}""", resp.string())
    }

    @Test
    fun tierRequirements_pathInterpolation_returnsBody() = runTest {
        server.enqueue(okBody("""{"requirements":[]}"""))
        val resp = api().tierRequirements("verified")
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/tiers/me/requirements/verified", recorded.requestUrl?.encodedPath)
        assertEquals("""{"requirements":[]}""", resp.string())
    }

    // ---- Cases ----

    @Test
    fun createCase_verb_path_body_decode() = runTest {
        server.enqueue(okBody(CASE_ENVELOPE))
        val env = api().createCase(KycCaseCreateRequest(intake_profile = "individual"))
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/kyc/cases", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("individual", body["intake_profile"])
        // 200 (not 201) decodes the case envelope.
        assertEquals("case_1", env.case.kyc_case_id)
        assertEquals(KycCaseStatus.DRAFT, env.case.status)
    }

    @Test
    fun listCases_verb_path_decode() = runTest {
        server.enqueue(okBody(LIST_ENVELOPE))
        val env = api().listCases()
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/cases", recorded.requestUrl?.encodedPath)
        assertEquals(1, env.items.size)
        assertEquals("case_1", env.items[0].kyc_case_id)
        assertEquals("cursor_2", env.next_cursor)
    }

    @Test
    fun estimatedWait_verb_path_decode_notShadowedByCaseId() = runTest {
        server.enqueue(okBody(WAIT_ENVELOPE))
        val env = api().estimatedWait()
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/cases/estimated-wait", recorded.requestUrl?.encodedPath)
        assertEquals(4.5, env.estimated_wait.estimated_hours, 0.0)
        assertEquals(7, env.estimated_wait.queue_position)
        assertEquals("About 4-5 hours", env.estimated_wait.message)
    }

    @Test
    fun getCase_pathInterpolation_decode() = runTest {
        server.enqueue(okBody(CASE_ENVELOPE))
        val env = api().getCase("abc")
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/cases/abc", recorded.requestUrl?.encodedPath)
        assertEquals("case_1", env.case.kyc_case_id)
    }

    @Test
    fun patchDraft_verb_path_body() = runTest {
        server.enqueue(okBody(CASE_ENVELOPE))
        api().patchDraft("abc", KycCaseDraftPatchRequest(expected_version = 3, intake_profile = "business"))
        val recorded = server.takeRequest()
        assertEquals("PATCH", recorded.method)
        assertEquals("/v1/kyc/cases/abc", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        // numbers decode as Double via the loosely-typed map.
        assertEquals(3.0, body["expected_version"])
        assertEquals("business", body["intake_profile"])
    }

    @Test
    fun attachFile_verb_path_body_enumToken() = runTest {
        server.enqueue(okBody(CASE_ENVELOPE))
        api().attachFile(
            "abc",
            KycFileAttachmentRequest(expected_version = 2, path = "uploads/x.jpg", file_type = KycFileType.ID_FRONT),
        )
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/kyc/cases/abc/files", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals(2.0, body["expected_version"])
        assertEquals("uploads/x.jpg", body["path"])
        // KycFileType serializes to its wire token via KycFileTypeAdapter.
        assertEquals("id_front", body["file_type"])
    }

    @Test
    fun readiness_pathInterpolation_decode() = runTest {
        server.enqueue(okBody(READINESS_ENVELOPE))
        val env = api().readiness("abc")
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/cases/abc/readiness", recorded.requestUrl?.encodedPath)
        assertEquals(true, env.readiness.ready_to_submit)
        assertEquals(KycCaseStatus.SUBMITTED, env.readiness.status)
        assertEquals(true, env.readiness.checks["has_id"])
        assertEquals(listOf("selfie"), env.readiness.missing_requirements)
    }

    @Test
    fun submitCase_verb_path_body() = runTest {
        server.enqueue(okBody(CASE_ENVELOPE))
        api().submitCase("abc", KycSubmitCaseRequest(expected_version = 5))
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/kyc/cases/abc/submit", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals(5.0, body["expected_version"])
    }

    // ---- Decode semantics ----

    @Test
    fun caseDecode_enumMapping_epochLongs_and_nestedRefs() = runTest {
        server.enqueue(okBody(CASE_ENVELOPE_RICH))
        val case = api().getCase("rich").case
        server.takeRequest()
        // "under_review" -> UNDER_REVIEW.
        assertEquals(KycCaseStatus.UNDER_REVIEW, case.status)
        assertEquals(1_780_000_000L, case.created_at)
        assertEquals(1_780_000_100L, case.updated_at)
        assertEquals(4, case.version)
        // file_type unknown token -> UNKNOWN is on the typed enum surface only; KycCaseFile.type is a
        // raw string passthrough (per contract), so the raw token is preserved here.
        assertEquals("mystery_doc", case.files[0].type)
        assertEquals(1_780_000_050L, case.files[0].uploaded_at)
        assertEquals("ticket_9", case.review?.ticket_id)
        assertEquals(listOf("blurry_id"), case.review?.reason_codes)
        assertEquals("ok", case.submission["state"])
    }

    @Test
    fun caseDecode_unrecognizedStatusToken_mapsToUnknown() = runTest {
        server.enqueue(okBody(CASE_ENVELOPE.replace("\"draft\"", "\"martian\"")))
        val case = api().getCase("u").case
        server.takeRequest()
        assertEquals(KycCaseStatus.UNKNOWN, case.status)
    }

    @Test
    fun fileTypeAdapter_unknownToken_mapsToUnknown() {
        assertEquals(KycFileType.UNKNOWN, KycFileType.fromToken("not_a_real_type"))
        assertEquals(KycFileType.SELFIE, KycFileType.fromToken("selfie"))
    }

    @Test
    fun caseDecode_missingCreatedAt_throwsJsonDataException() {
        val adapter = moshi.adapter(KycCaseEnvelope::class.java)
        // created_at absent -> required field with no default -> JsonDataException.
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(CASE_ENVELOPE_MISSING_CREATED_AT)
        }
    }

    @Test
    fun caseDecode_missingVersion_throwsJsonDataException() {
        val adapter = moshi.adapter(KycCaseEnvelope::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(CASE_ENVELOPE_MISSING_VERSION)
        }
    }

    // ---- Request DTO round-trip fidelity ----

    @Test
    fun requestDtos_roundTrip() {
        val create = KycCaseCreateRequest(intake_profile = "individual")
        val createAdapter = moshi.adapter(KycCaseCreateRequest::class.java)
        assertEquals(create, createAdapter.fromJson(createAdapter.toJson(create)))

        val patch = KycCaseDraftPatchRequest(expected_version = 3, intake_profile = "business")
        val patchAdapter = moshi.adapter(KycCaseDraftPatchRequest::class.java)
        assertEquals(patch, patchAdapter.fromJson(patchAdapter.toJson(patch)))

        val attach = KycFileAttachmentRequest(expected_version = 2, path = "p", file_type = KycFileType.SELFIE)
        val attachAdapter = moshi.adapter(KycFileAttachmentRequest::class.java)
        val attachJson = attachAdapter.toJson(attach)
        assertTrue(attachJson.contains("\"selfie\""))
        assertEquals(attach, attachAdapter.fromJson(attachJson))

        val submit = KycSubmitCaseRequest(expected_version = 5)
        val submitAdapter = moshi.adapter(KycSubmitCaseRequest::class.java)
        assertEquals(submit, submitAdapter.fromJson(submitAdapter.toJson(submit)))
    }

    @Test
    fun createRequest_omittedIntakeProfile_serializesNull() {
        val adapter = moshi.adapter(KycCaseCreateRequest::class.java)
        val parsed = mapAdapter.fromJson(adapter.toJson(KycCaseCreateRequest()))
        assertNull(parsed?.get("intake_profile"))
    }

    private companion object {
        val CASE_ENVELOPE = """
            {
              "case": {
                "contract_version": "2026-03-kyc-v1",
                "kyc_case_id": "case_1",
                "user_sub": "user_1",
                "status": "draft",
                "created_at": 1780000000,
                "updated_at": 1780000010,
                "version": 1
              }
            }
        """.trimIndent()

        val CASE_ENVELOPE_RICH = """
            {
              "case": {
                "kyc_case_id": "rich",
                "user_sub": "user_2",
                "status": "under_review",
                "intake_profile": "individual",
                "files": [
                  { "type": "mystery_doc", "path": "u/1.jpg", "uploaded_at": 1780000050, "size": 1234 }
                ],
                "submission": { "state": "ok" },
                "review": { "ticket_id": "ticket_9", "reason_codes": ["blurry_id"] },
                "created_at": 1780000000,
                "updated_at": 1780000100,
                "version": 4,
                "missing_requirements": []
              }
            }
        """.trimIndent()

        val LIST_ENVELOPE = """
            {
              "items": [
                {
                  "kyc_case_id": "case_1", "user_sub": "user_1", "status": "submitted",
                  "created_at": 1780000000, "updated_at": 1780000010, "version": 2
                }
              ],
              "next_cursor": "cursor_2"
            }
        """.trimIndent()

        val WAIT_ENVELOPE = """
            {
              "estimated_wait": {
                "contract_version": "2026-03-kyc-v1",
                "estimated_hours": 4.5,
                "queue_position": 7,
                "message": "About 4-5 hours"
              }
            }
        """.trimIndent()

        val READINESS_ENVELOPE = """
            {
              "readiness": {
                "contract_version": "2026-03-kyc-v1",
                "kyc_case_id": "abc",
                "status": "submitted",
                "ready_to_submit": true,
                "missing_requirements": ["selfie"],
                "missing_hints": ["Upload a selfie"],
                "checks": { "has_id": true, "has_selfie": false },
                "requirements": [ { "key": "id", "satisfied": true } ]
              }
            }
        """.trimIndent()

        val CASE_ENVELOPE_MISSING_CREATED_AT = """
            {
              "case": {
                "kyc_case_id": "case_1", "user_sub": "user_1", "status": "draft",
                "updated_at": 1780000010, "version": 1
              }
            }
        """.trimIndent()

        val CASE_ENVELOPE_MISSING_VERSION = """
            {
              "case": {
                "kyc_case_id": "case_1", "user_sub": "user_1", "status": "draft",
                "created_at": 1780000000, "updated_at": 1780000010
              }
            }
        """.trimIndent()
    }
}
