package com.testlogon.android.core.network.kyc

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.kyc.StartEidVerificationInDto
import com.testlogon.android.core.model.kyc.StartEidVerificationOutDto
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
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-325 - contract tests for [KycEidvApi] against MockWebServer with the production-style shared Moshi
 * (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring NetworkModule.provideMoshi
 * and the AND-321/322/323/324 contract tests). Asserts the schemes GET (with + without the country query),
 * the start POST (verb / path `/v1/kyc/cases/kyc_1/eid/start` / body {scheme:"eidas"}) and its 200 decode
 * (session_id, redirect_url, epoch expires_at), the status GET with eid_verification present (assertion_id,
 * discrepancy severity) AND a null eid_verification case, 422 mapping (try/catch, NO nested runTest), and a
 * required-field-absent (session_id) decode failure. The recorded request body is read ONCE.
 */
class KycEidvApiContractTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KycCaseStatusAdapter)
        .add(KycFileTypeAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private val mapAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    private fun api(): KycEidvApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(KycEidvApi::class.java)

    /** Decode a recorded request body to a loosely-typed map (read the body source ONCE). */
    private fun RecordedRequest.bodyJson(): Map<String, Any?> {
        val raw = body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        return mapAdapter.fromJson(raw) ?: emptyMap()
    }

    private fun jsonResponse(body: String, code: Int) =
        MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)

    @Before
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun listSchemes_withCountry_query_path_and_decode() = runTest {
        server.enqueue(jsonResponse(SCHEMES_OUT, code = 200))

        val out = api().listSchemes(country = "NL")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/eid/schemes", recorded.requestUrl?.encodedPath)
        assertEquals("NL", recorded.requestUrl?.queryParameter("country"))

        assertEquals(2, out.schemes.size)
        assertEquals("eidas", out.schemes[0].scheme)
        assertEquals("substantial", out.schemes[0].assurance_level)
        assertEquals("browser_redirect", out.schemes[0].auth_flow)
        assertEquals(listOf("NL", "DE"), out.schemes[0].countries)
        assertEquals("digid", out.schemes[1].scheme)
    }

    @Test
    fun listSchemes_withoutCountry_omitsQuery() = runTest {
        server.enqueue(jsonResponse(SCHEMES_OUT, code = 200))

        api().listSchemes(country = null)

        val recorded = server.takeRequest()
        assertEquals("/v1/kyc/eid/schemes", recorded.requestUrl?.encodedPath)
        assertNull(recorded.requestUrl?.queryParameter("country"))
    }

    @Test
    fun listSchemes_absentWrapper_decodesEmpty() = runTest {
        server.enqueue(jsonResponse("""{}""", code = 200))
        val out = api().listSchemes(country = null)
        server.takeRequest()
        assertTrue(out.schemes.isEmpty())
    }

    @Test
    fun startEid_verb_path_body_and_200_decode() = runTest {
        server.enqueue(jsonResponse(START_OUT, code = 200))

        val out = api().startEid(caseId = "kyc_1", body = StartEidVerificationInDto(scheme = "eidas"))

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/kyc/cases/kyc_1/eid/start", recorded.requestUrl?.encodedPath)

        val body = recorded.bodyJson()
        assertEquals("eidas", body["scheme"])

        assertEquals("sess_1", out.session_id)
        assertEquals("https://eid.example/redirect/abc", out.redirect_url)
        assertEquals(1_780_000_000L, out.expires_at)
    }

    @Test
    fun eidStatus_pathInterpolation_withVerification_decode() = runTest {
        server.enqueue(jsonResponse(STATUS_VERIFIED, code = 200))

        val out = api().eidStatus(caseId = "kyc_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/kyc/cases/kyc_1/eid/status", recorded.requestUrl?.encodedPath)

        val verification = out.eid_verification
        assertEquals("assertion_1", verification?.assertion_id)
        assertEquals("high", verification?.assurance_level)
        assertEquals(1, verification?.discrepancies?.size)
        assertEquals("date_of_birth", verification?.discrepancies?.get(0)?.field)
        assertEquals("critical", verification?.discrepancies?.get(0)?.severity)
        assertEquals(true, out.auto_tier_upgrade)
    }

    @Test
    fun eidStatus_nullVerification_decodesNull() = runTest {
        server.enqueue(jsonResponse("""{ "eid_verification": null }""", code = 200))
        val out = api().eidStatus("kyc_1")
        server.takeRequest()
        assertNull(out.eid_verification)
    }

    @Test
    fun startEid_422_validation_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        // assertThrows takes a non-suspend lambda, so catch the suspend call directly (no nested runTest).
        val ex = try {
            api().startEid(caseId = "kyc_1", body = StartEidVerificationInDto(scheme = "nope"))
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
        val raw = ex?.response()?.errorBody()?.string()
        assertEquals(true, raw?.contains("scheme"))
    }

    @Test
    fun startDecode_missingSessionId_throwsJsonDataException() {
        val adapter = moshi.adapter(StartEidVerificationOutDto::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(START_OUT_MISSING_SESSION_ID)
        }
    }

    private companion object {
        val SCHEMES_OUT = """
            {
              "schemes": [
                {
                  "scheme": "eidas",
                  "name": "eIDAS",
                  "assurance_level": "substantial",
                  "auth_flow": "browser_redirect",
                  "countries": ["NL", "DE"],
                  "description": "EU cross-border eID"
                },
                {
                  "scheme": "digid",
                  "name": "DigiD",
                  "assurance_level": "high",
                  "auth_flow": "mobile_app_qr",
                  "countries": ["NL"]
                }
              ]
            }
        """.trimIndent()

        val START_OUT = """
            {
              "session_id": "sess_1",
              "redirect_url": "https://eid.example/redirect/abc",
              "expires_at": 1780000000
            }
        """.trimIndent()

        val STATUS_VERIFIED = """
            {
              "eid_verification": {
                "assertion_id": "assertion_1",
                "assurance_level": "high",
                "verified_at": 1779990000,
                "verified_fields": { "given_name": "Alex", "minor": false },
                "discrepancies": [
                  {
                    "field": "date_of_birth",
                    "profile_value": "1990-01-01",
                    "eid_value": "1990-02-01",
                    "severity": "critical"
                  }
                ]
              },
              "auto_tier_upgrade": true
            }
        """.trimIndent()

        val START_OUT_MISSING_SESSION_ID = """
            {
              "redirect_url": "https://eid.example/redirect/abc",
              "expires_at": 1780000000
            }
        """.trimIndent()

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["body", "scheme"], "msg": "string does not match regex", "type": "value_error.str.regex" }
              ]
            }
        """.trimIndent()
    }
}
