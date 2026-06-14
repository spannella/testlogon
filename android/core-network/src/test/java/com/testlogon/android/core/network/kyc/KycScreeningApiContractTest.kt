package com.testlogon.android.core.network.kyc

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.kyc.KycScreeningResultOut
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-328 - contract tests for [KycScreeningApi] against MockWebServer with the production-style shared Moshi
 * (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring NetworkModule.provideMoshi
 * and the AND-326/327 contract tests). Asserts:
 *   - screening GET decode of the {results:[...]} envelope (result enum token, screen_type, epoch screened_at,
 *     match_count, loosely-typed details),
 *   - empty {results:[]} decodes to an empty list,
 *   - 422 via try/catch (NO nested runTest),
 *   - a required-field-absent (result) decode failure (JsonDataException).
 * The endpoint is READ-ONLY (a single GET); the recorded request body is not read.
 */
class KycScreeningApiContractTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KycCaseStatusAdapter)
        .add(KycFileTypeAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun api(): KycScreeningApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(KycScreeningApi::class.java)

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
    fun screening_path_and_decode() = runTest {
        server.enqueue(jsonResponse(RESULTS_OUT, code = 200))

        val out = api().screening(caseId = "case_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/kyc/screening/cases/case_1", recorded.requestUrl?.encodedPath)

        assertEquals(3, out.results.size)
        val ofac = out.results[0]
        assertEquals("confirmed_match", ofac.result)
        assertEquals("sanctions_ofac", ofac.screen_type)
        assertEquals(1_780_000_000L, ofac.screened_at)
        assertEquals(2, ofac.match_count)
        assertEquals("OFAC SDN", ofac.details?.get("source"))

        assertEquals("potential_match", out.results[1].result)
        assertEquals("pep_check", out.results[1].screen_type)
        assertEquals("clear", out.results[2].result)
        assertEquals("adverse_media", out.results[2].screen_type)
    }

    @Test
    fun screening_emptyResults_decodesEmptyList() = runTest {
        server.enqueue(jsonResponse(EMPTY_OUT, code = 200))

        val out = api().screening(caseId = "case_1")

        assertEquals("GET", server.takeRequest().method)
        assertEquals(0, out.results.size)
    }

    @Test
    fun screening_422_validation_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        // assertThrows takes a non-suspend lambda, so catch the suspend call directly (no nested runTest).
        val ex = try {
            api().screening(caseId = "case_1")
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
        val raw = ex?.response()?.errorBody()?.string()
        assertEquals(true, raw?.contains("case_id"))
    }

    @Test
    fun resultDecode_missingResult_throwsJsonDataException() {
        val adapter = moshi.adapter(KycScreeningResultOut::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(RESULT_OUT_MISSING_RESULT)
        }
    }

    private companion object {
        val RESULTS_OUT = """
            {
              "results": [
                {
                  "result": "confirmed_match",
                  "screen_type": "sanctions_ofac",
                  "screened_at": 1780000000,
                  "match_count": 2,
                  "details": { "source": "OFAC SDN" }
                },
                {
                  "result": "potential_match",
                  "screen_type": "pep_check",
                  "screened_at": 1780000050,
                  "match_count": 1
                },
                {
                  "result": "clear",
                  "screen_type": "adverse_media",
                  "screened_at": 1780000100
                }
              ]
            }
        """.trimIndent()

        val EMPTY_OUT = """
            {
              "results": []
            }
        """.trimIndent()

        val RESULT_OUT_MISSING_RESULT = """
            {
              "screen_type": "sanctions_ofac",
              "screened_at": 1780000000
            }
        """.trimIndent()

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["path", "case_id"], "msg": "invalid case id", "type": "value_error" }
              ]
            }
        """.trimIndent()
    }
}
