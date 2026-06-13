package com.testlogon.android.core.network.signing

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-345 - hermetic request-shape / streaming / error tests for the AND-339 [SigningApi] (FR-2/5).
 *
 * This EXTENDS SigningApiContractTest (which already covers verb/path/body decoding for every
 * endpoint). The additions here are the gaps: a deterministic 2-page-PDF STREAMING round-trip through
 * @Streaming, an explicit RecordedRequest assertion of the fill / mark-done / acknowledge request
 * SHAPE (method + path + whether a body is present), and the ERROR path - a 422 with a FastAPI detail
 * body surfaces as an HttpException from the API (the error -> ApiResult mapping is the repository's
 * job, so the API itself is asserted to throw).
 *
 * Everything is hermetic: MockWebServer only, the production-style Moshi (built like
 * NetworkModule.provideMoshi), and runTest. No real dev host. core-network has no test dependency on
 * :core-testing, so the bodies + the PDF bytes are built inline. KDoc avoids the comment-terminator
 * character pair.
 */
class SigningApiTest {

    private lateinit var server: MockWebServer

    // Built exactly like NetworkModule.provideMoshi (same factory + registered signing enum adapters).
    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(PacketStatusAdapter)
        .add(SignatureFieldTypeAdapter)
        .add(PacketRoleAdapter)
        .add(SignatureInputModeAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private val mapAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    private fun api(): SigningApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(SigningApi::class.java)

    /** Decode a recorded request body to a loosely-typed map (read the body source ONCE). */
    private fun RecordedRequest.bodyMap(): Map<String, Any?> {
        val raw = body.readUtf8()
        if (raw.isBlank()) return emptyMap()
        return mapAdapter.fromJson(raw) ?: emptyMap()
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

    // ---- getPacket decodes the full fixture detail ----

    @Test
    fun getPacket_decodesSignersFieldsAndLegalNotice() = runTest {
        server.enqueue(jsonResponse(PACKET_DETAIL))

        val detail = api().getPacket("pkt_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/signature-packets/pkt_1", recorded.requestUrl?.encodedPath)
        assertEquals(PacketStatus.SENT, detail.status)
        assertEquals(PacketRole.SIGNER, detail.role)
        assertEquals(2, detail.signers.size)
        assertEquals(3, detail.fields.size)
        assertEquals(SignatureFieldType.SIGNATURE, detail.fields[0].fieldType)
        assertEquals(true, detail.capabilities["can_fill_fields"])
        assertEquals("v2", detail.legalNotice?.version)
    }

    // ---- fillField request shape ----

    @Test
    fun fillField_postsToFillPath_withTypedBody() = runTest {
        server.enqueue(jsonResponse("""{"ok":true}"""))

        api().fillField(
            "pkt_1",
            "fld_date",
            SignaturePacketFieldFillRequest(
                value = "2026-05-02",
                captureMode = SignatureInputMode.TYPED,
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals(
            "/v1/signature-packets/pkt_1/fields/fld_date/fill",
            recorded.requestUrl?.encodedPath,
        )
        assertEquals("application/json", recorded.getHeader("Content-Type"))
        val body = recorded.bodyMap()
        assertEquals("2026-05-02", body["value"])
        assertEquals("typed", body["capture_mode"])
    }

    // ---- empty-body POSTs: mark-done + acknowledge ----

    @Test
    fun markDone_postsEmptyBody_toMarkDonePath() = runTest {
        server.enqueue(jsonResponse("""{"ok":true,"status":"completed"}"""))

        val resp = api().markDone("pkt_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/signature-packets/pkt_1/mark-done", recorded.requestUrl?.encodedPath)
        assertEquals(0L, recorded.bodySize)
        assertEquals(PacketStatus.COMPLETED, resp.status)
    }

    @Test
    fun acknowledgeLegalNotice_postsEmptyBody_toAckPath() = runTest {
        server.enqueue(jsonResponse("""{"ok":true,"accepted":true}"""))

        val resp = api().acknowledgeLegalNotice("pkt_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals(
            "/v1/signature-packets/pkt_1/acknowledge-legal-notice",
            recorded.requestUrl?.encodedPath,
        )
        assertEquals(0L, recorded.bodySize)
        assertEquals(true, resp.accepted)
    }

    // ---- downloadFinalPdf streams the 2-page PDF bytes ----

    @Test
    fun downloadFinalPdf_streamsRawPdfBytes_startingWithMagic() = runTest {
        val pdf = twoPagePdfBytes()
        // ISO-8859-1 maps each byte to one char and back, so the opaque PDF bytes round-trip verbatim
        // through MockResponse.setBody(String) without needing an okio Buffer.
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/pdf")
                .setBody(String(pdf, Charsets.ISO_8859_1)),
        )

        val response = api().downloadFinalPdf("pkt_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/signature-packets/pkt_1/final-pdf", recorded.requestUrl?.encodedPath)
        val received = response.body()?.bytes()
        assertArrayEquals(pdf, received)
        // The fixture begins with the 5-byte PDF signature that AND-341's PdfSource verifies.
        assertArrayEquals(
            byteArrayOf(0x25, 0x50, 0x44, 0x46, 0x2D),
            received?.copyOfRange(0, 5),
        )
    }

    // ---- error path: 422 + FastAPI detail -> HttpException ----

    @Test
    fun fillField_422DetailBody_throwsHttpException_withCodeAndBody() {
        // No runTest wrapper here: assertThrows needs a synchronous throw, so the suspend call is
        // bridged with a single runBlocking (NOT nested inside runTest).
        server.enqueue(
            jsonResponse(
                """{"detail":[{"loc":["body","value"],"msg":"field required","type":"value_error.missing"}]}""",
                code = 422,
            ),
        )

        val thrown = assertThrows(HttpException::class.java) {
            kotlinx.coroutines.runBlocking {
                api().fillField("pkt_1", "fld_date", SignaturePacketFieldFillRequest(value = "x"))
            }
        }
        assertEquals(422, thrown.code())
        // The error body is available for the repo's ApiErrorParser (mapping is the repo's job).
        assertTrue(thrown.response()?.errorBody()?.string()?.contains("field required") == true)
    }

    private companion object {

        /**
         * A tiny, well-formed 2-page PDF-1.4 document, terminated by the end-of-file marker and
         * starting with the 5-byte PDF signature. Built inline (core-network has no :core-testing test
         * dependency). Encoded ISO-8859-1 so each char maps to one literal byte.
         */
        fun twoPagePdfBytes(): ByteArray {
            val eof = "%" + "%EOF"
            val pdf = buildString {
                append("%PDF-1.4\n")
                append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
                append("2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj\n")
                append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n")
                append("4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n")
                append("5 0 obj\n<< /Length 8 >>\nstream\nBT ET\nendstream\nendobj\n")
                append("trailer\n<< /Root 1 0 R /Size 6 >>\n")
                append(eof)
                append("\n")
            }
            return pdf.toByteArray(Charsets.ISO_8859_1)
        }

        val PACKET_DETAIL = """
            {
              "packet_id": "pkt_1",
              "status": "sent",
              "owner_user_id": "usr_owner",
              "source_path": "/docs/contract.pdf",
              "role": "signer",
              "signer_status": "pending",
              "created_at": "2026-05-01T10:00:00Z",
              "sent_at": "2026-05-02T10:00:00Z",
              "signers": [
                { "signer_id": "sgn_1", "status": "pending" },
                { "signer_id": "sgn_2", "status": "completed" }
              ],
              "fields": [
                {
                  "field_id": "fld_sig", "field_type": "signature", "page": 1,
                  "x": 0.1, "y": 0.2, "width": 0.3, "height": 0.1,
                  "is_assigned_to_viewer": true, "capture_mode": "drawn"
                },
                {
                  "field_id": "fld_init", "field_type": "initials", "page": 1,
                  "x": 0.5, "y": 0.2, "width": 0.1, "height": 0.05, "is_assigned_to_viewer": true
                },
                {
                  "field_id": "fld_date", "field_type": "date", "page": 1,
                  "x": 0.1, "y": 0.4, "width": 0.2, "height": 0.05, "capture_mode": "typed"
                }
              ],
              "capabilities": { "can_fill_fields": true },
              "legal_notice": { "required": true, "accepted": false, "version": "v2", "text": "Notice" }
            }
        """.trimIndent()
    }
}
