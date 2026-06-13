package com.testlogon.android.core.network.kyc

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.kyc.KycIdScannerScanOutDto
import com.testlogon.android.core.model.kyc.KycIdScannerScanRequestDto
import com.testlogon.android.core.model.kyc.KycIdScannerValidateRequestDto
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
 * AND-322 - contract tests for [KycIdScannerApi] against MockWebServer with the production-style shared Moshi
 * (BigDecimalAdapter + the KYC enum adapters + KotlinJsonAdapterFactory, mirroring NetworkModule.provideMoshi
 * and the AND-321 KycDocumentsApiContractTest). Asserts the verb/path/body of the validate + scan POSTs and
 * the decode of the validation + scan responses (including the nested extraction / expiry_check /
 * cross_reference and the mrz_valid flag), plus 422 / 403 error mapping and a required-field-absent decode
 * failure. The recorded request body is read ONCE. No nested runTest.
 */
class KycIdScannerApiContractTest {

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

    private fun api(): KycIdScannerApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(KycIdScannerApi::class.java)

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
    fun validateDocument_verb_path_body_and_200_decode() = runTest {
        server.enqueue(jsonResponse(VALIDATION_OUT, code = 200))

        val out = api().validateDocument(
            caseId = "kyc_1",
            body = KycIdScannerValidateRequestDto(document_type = "passport"),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/kyc/id-scanner/cases/kyc_1/validate-document", recorded.requestUrl?.encodedPath)
        assertEquals("passport", recorded.bodyJson()["document_type"])

        assertEquals("passport", out.document_type)
        assertEquals(listOf("id_front"), out.sides_required)
        assertEquals(true, out.has_mrz)
        assertEquals("TD3", out.mrz_format)
        assertEquals(false, out.all_sides_present)
    }

    @Test
    fun scanDocument_verb_path_body_and_201_decode() = runTest {
        server.enqueue(jsonResponse(SCAN_OUT, code = 201))

        val out = api().scanDocument(
            caseId = "kyc_1",
            body = KycIdScannerScanRequestDto(
                document_type = "passport",
                file_type = "id_front",
                mrz_lines = null,
                image_ref = "doc_7",
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/kyc/id-scanner/cases/kyc_1/scan-document", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("passport", body["document_type"])
        assertEquals("id_front", body["file_type"])
        assertEquals("doc_7", body["image_ref"])
        // mrz_lines was null -> omitted from the serialized body.
        assertNull(body["mrz_lines"])

        // Required scalar fields + the status enum string + mrz_valid.
        assertEquals("scan_1", out.scan_id)
        assertEquals("kyc_1", out.case_id)
        assertEquals("matched", out.status)
        assertEquals(true, out.mrz_valid)
        // Nested extraction.
        assertEquals("X1234567", out.extraction.document_number)
        assertEquals("DOE", out.extraction.surname)
        assertEquals(true, out.extraction.checksums["document_number"])
        // Nested expiry_check.
        assertEquals("valid", out.expiry_check.status)
        assertEquals(365, out.expiry_check.days_until_expiry)
        // Nested cross_reference (optional, present here).
        assertEquals(0.98, out.cross_reference?.match_score)
        assertTrue(out.cross_reference?.mismatches?.isEmpty() == true)
        assertEquals("https://cdn.example/scan_1.jpg", out.image_url)
    }

    @Test
    fun scanDocument_withMrzLines_serializesArray() = runTest {
        server.enqueue(jsonResponse(SCAN_OUT, code = 201))
        api().scanDocument(
            caseId = "kyc_1",
            body = KycIdScannerScanRequestDto(
                document_type = "national_id_card",
                file_type = "id_back",
                mrz_lines = listOf("LINE1", "LINE2"),
                image_ref = "doc_8",
            ),
        )
        val body = server.takeRequest().bodyJson()
        assertEquals("id_back", body["file_type"])
        @Suppress("UNCHECKED_CAST")
        assertEquals(listOf("LINE1", "LINE2"), body["mrz_lines"] as? List<String>)
    }

    @Test
    fun validateDocument_422_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(VALIDATION_DETAIL, code = 422))
        val ex = try {
            api().validateDocument("kyc_1", KycIdScannerValidateRequestDto("passport"))
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(422, ex?.code())
    }

    @Test
    fun scanDocument_403_csrf_throwsHttpException() = runTest {
        server.enqueue(jsonResponse(FORBIDDEN_DETAIL, code = 403))
        val ex = try {
            api().scanDocument("kyc_1", KycIdScannerScanRequestDto("passport"))
            null
        } catch (e: HttpException) {
            e
        }
        assertEquals(403, ex?.code())
    }

    @Test
    fun scanDecode_missingScanId_throwsJsonDataException() {
        val adapter = moshi.adapter(KycIdScannerScanOutDto::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(SCAN_OUT_MISSING_SCAN_ID)
        }
    }

    private companion object {
        val VALIDATION_OUT = """
            {
              "document_type": "passport",
              "sides_required": ["id_front"],
              "sides_present": [],
              "has_mrz": true,
              "mrz_format": "TD3",
              "all_sides_present": false
            }
        """.trimIndent()

        val SCAN_OUT = """
            {
              "scan_id": "scan_1",
              "case_id": "kyc_1",
              "document_type": "passport",
              "file_type": "id_front",
              "status": "matched",
              "mrz_valid": true,
              "extraction": {
                "document_number": "X1234567",
                "expiry_date": "2030-01-01",
                "given_names": "JOHN",
                "surname": "DOE",
                "nationality": "GBR",
                "date_of_birth": "1990-01-01",
                "sex": "M",
                "issuing_state": "GBR",
                "checksums": { "document_number": true, "composite": true }
              },
              "expiry_check": {
                "status": "valid",
                "message": "Document is valid.",
                "expiry_date": "2030-01-01",
                "days_until_expiry": 365
              },
              "cross_reference": {
                "match_score": 0.98,
                "total_fields_checked": 5,
                "fields_matched": 5,
                "matches": { "surname": "DOE" },
                "mismatches": {}
              },
              "review_decision": null,
              "review_note": null,
              "image_url": "https://cdn.example/scan_1.jpg"
            }
        """.trimIndent()

        val SCAN_OUT_MISSING_SCAN_ID = """
            {
              "case_id": "kyc_1",
              "document_type": "passport",
              "file_type": "id_front",
              "status": "matched",
              "mrz_valid": true,
              "extraction": { "checksums": {} },
              "expiry_check": { "status": "valid", "message": "ok" }
            }
        """.trimIndent()

        val VALIDATION_DETAIL = """
            {
              "detail": [
                { "loc": ["body", "document_type"], "msg": "field required", "type": "value_error.missing" }
              ]
            }
        """.trimIndent()

        val FORBIDDEN_DETAIL = """{ "detail": "CSRF token missing or invalid" }"""
    }
}
