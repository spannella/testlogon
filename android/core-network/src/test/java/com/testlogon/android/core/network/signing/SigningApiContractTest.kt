package com.testlogon.android.core.network.signing

import com.squareup.moshi.JsonDataException
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
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-339 - contract tests for [SigningApi] against MockWebServer with the production-style shared
 * Moshi (BigDecimalAdapter + the four signing enum adapters + KotlinJsonAdapterFactory, built exactly
 * like NetworkModule.provideMoshi and mirroring the AND-319 KycApiContractTest idiom). For each
 * endpoint this asserts the verb, the resolved path (incl. @Path interpolation), the request body (for
 * the body POSTs), and that the response decodes. The recorded request body is read ONCE per request.
 * There is NO nested runTest.
 */
class SigningApiContractTest {

    private lateinit var server: MockWebServer

    // Built exactly like the production NetworkModule.provideMoshi so adapter resolution matches prod.
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
    private fun RecordedRequest.bodyJson(): Map<String, Any?> {
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

    // ---- Packets ----

    @Test
    fun createPacket_verb_path_body_decode() = runTest {
        server.enqueue(jsonResponse("""{"packet_id":"pkt_1","status":"draft"}"""))

        val resp = api().createPacket(
            CreateSignaturePacketRequest(
                sourcePath = "/docs/a.pdf",
                originChannel = "share",
                originRef = "lnk_9",
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/signature-packets", recorded.requestUrl?.encodedPath)
        assertEquals("application/json", recorded.getHeader("Content-Type"))
        val body = recorded.bodyJson()
        assertEquals("/docs/a.pdf", body["source_path"])
        assertEquals("share", body["origin_channel"])
        assertEquals("lnk_9", body["origin_ref"])
        assertEquals("pkt_1", resp.packetId)
        assertEquals(PacketStatus.DRAFT, resp.status)
    }

    @Test
    fun createPacket_omitsOriginRef_whenNull() = runTest {
        server.enqueue(jsonResponse("""{"packet_id":"pkt_1","status":"draft"}"""))
        api().createPacket(CreateSignaturePacketRequest(sourcePath = "/a", originChannel = "message"))
        val recorded = server.takeRequest()
        assertNull(recorded.bodyJson()["origin_ref"])
    }

    @Test
    fun getPacket_pathInterpolation_decode_enums_map_legalNotice() = runTest {
        server.enqueue(jsonResponse(PACKET_DETAIL))

        val detail = api().getPacket("pkt_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/signature-packets/pkt_1", recorded.requestUrl?.encodedPath)
        assertEquals("pkt_1", detail.packetId)
        assertEquals(PacketStatus.SENT, detail.status)
        assertEquals(PacketRole.SIGNER, detail.role)
        assertEquals("2026-05-01T10:00:00Z", detail.createdAt)
        // signers + fields decode.
        assertEquals(1, detail.signers.size)
        assertEquals("sgn_1", detail.signers[0].signerId)
        assertEquals(2, detail.fields.size)
        assertEquals(SignatureFieldType.SIGNATURE, detail.fields[0].fieldType)
        assertEquals(SignatureInputMode.DRAWN, detail.fields[0].captureMode)
        assertEquals(1, detail.fields[0].page)
        // render_payload is a loosely-typed map.
        assertEquals("blue", detail.fields[0].renderPayload?.get("color"))
        // second field has the typed capture mode + default required true.
        assertEquals(SignatureFieldType.DATE, detail.fields[1].fieldType)
        assertEquals(SignatureInputMode.TYPED, detail.fields[1].captureMode)
        assertTrue(detail.fields[1].required)
        // capabilities map of booleans.
        assertEquals(true, detail.capabilities["can_send"])
        assertEquals(false, detail.capabilities["can_void"])
        // legal_notice nested object.
        assertEquals(true, detail.legalNotice?.required)
        assertEquals("v2", detail.legalNotice?.version)
    }

    @Test
    fun getPacket_unknownStatusToken_mapsToUnknown_noCrash() = runTest {
        server.enqueue(jsonResponse(PACKET_DETAIL.replace("\"sent\"", "\"martian\"")))
        val detail = api().getPacket("pkt_x")
        server.takeRequest()
        assertEquals(PacketStatus.UNKNOWN, detail.status)
    }

    @Test
    fun getPacket_missingPacketId_throwsJsonDataException() {
        val adapter = moshi.adapter(SignaturePacketDetailDto::class.java)
        // packet_id absent -> required field with no default -> JsonDataException.
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(PACKET_DETAIL_MISSING_PACKET_ID)
        }
    }

    @Test
    fun mutateField_verb_path_body_decode() = runTest {
        server.enqueue(jsonResponse("""{"ok":true}"""))

        val resp = api().mutateField(
            "pkt_1",
            SignaturePacketFieldMutationRequest(
                action = "create",
                fieldType = SignatureFieldType.SIGNATURE,
                page = 1,
                x = 10.5f,
                y = 20f,
                width = 100f,
                height = 40f,
                required = true,
                assignedSignerId = "sgn_1",
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/signature-packets/pkt_1/fields", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("create", body["action"])
        // enum serializes to its wire token.
        assertEquals("signature", body["field_type"])
        assertEquals(1.0, body["page"])
        assertEquals("sgn_1", body["assigned_signer_id"])
        assertEquals(true, resp.ok)
    }

    @Test
    fun fillField_path_with_fieldId_and_body() = runTest {
        server.enqueue(jsonResponse("""{"ok":true,"field":{"field_id":"f1","field_type":"signature","page":1,"x":0,"y":0,"width":1,"height":1}}"""))

        val resp = api().fillField(
            "pkt_1",
            "f1",
            SignaturePacketFieldFillRequest(
                value = "John Doe",
                captureMode = SignatureInputMode.TYPED,
                renderPayload = mapOf("font" to "cursive"),
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/signature-packets/pkt_1/fields/f1/fill", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("John Doe", body["value"])
        assertEquals("typed", body["capture_mode"])
        @Suppress("UNCHECKED_CAST")
        val payload = body["render_payload"] as Map<String, Any?>
        assertEquals("cursive", payload["font"])
        assertEquals(true, resp.ok)
        assertEquals("f1", resp.field?.fieldId)
    }

    @Test
    fun sendPacket_emptyBodyPost_lenientDecode() = runTest {
        server.enqueue(jsonResponse("""{"ok":true,"status":"sent"}"""))

        val resp = api().sendPacket("pkt_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/signature-packets/pkt_1/send", recorded.requestUrl?.encodedPath)
        assertEquals(0L, recorded.bodySize)
        assertEquals(true, resp.ok)
        assertEquals(PacketStatus.SENT, resp.status)
    }

    @Test
    fun markDone_emptyBodyPost_lenientDecode() = runTest {
        server.enqueue(jsonResponse("""{"ok":true}"""))

        val resp = api().markDone("pkt_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/signature-packets/pkt_1/mark-done", recorded.requestUrl?.encodedPath)
        assertEquals(0L, recorded.bodySize)
        assertEquals(true, resp.ok)
        // status absent -> lenient null.
        assertNull(resp.status)
    }

    @Test
    fun acknowledgeLegalNotice_emptyBodyPost_lenientDecode() = runTest {
        server.enqueue(jsonResponse("""{"ok":true,"accepted":true}"""))

        val resp = api().acknowledgeLegalNotice("pkt_1")

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals(
            "/v1/signature-packets/pkt_1/acknowledge-legal-notice",
            recorded.requestUrl?.encodedPath,
        )
        assertEquals(0L, recorded.bodySize)
        assertEquals(true, resp.ok)
        assertEquals(true, resp.accepted)
    }

    @Test
    fun getEvents_pathInterpolation_decode() = runTest {
        server.enqueue(jsonResponse(EVENTS_BODY))

        val events = api().getEvents("pkt_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/signature-packets/pkt_1/events", recorded.requestUrl?.encodedPath)
        assertEquals("pkt_1", events.packetId)
        assertEquals(1, events.events.size)
        assertEquals("evt_1", events.events[0].eventId)
        assertEquals("packet.sent", events.events[0].eventType)
        assertEquals("2026-05-01T10:00:00Z", events.events[0].createdAt)
        assertEquals("sgn_1", events.events[0].eventPayload["signer_id"])
    }

    @Test
    fun downloadFinalPdf_streaming_rawBytes() = runTest {
        // The body is opaque PDF bytes; a deterministic ASCII payload keeps the byte assertion simple.
        val pdf = "%PDF-fake".toByteArray(Charsets.UTF_8)
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/pdf")
                .setBody(String(pdf, Charsets.UTF_8)),
        )

        val response = api().downloadFinalPdf("pkt_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/signature-packets/pkt_1/final-pdf", recorded.requestUrl?.encodedPath)
        // The body is opaque PDF bytes (read ONCE).
        assertArrayEquals(pdf, response.body()?.bytes())
    }

    // ---- Templates ----

    @Test
    fun listTemplates_verb_path_decode_epochCreatedAt() = runTest {
        server.enqueue(jsonResponse(TEMPLATE_LIST))

        val list = api().listTemplates()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/signing/templates", recorded.requestUrl?.encodedPath)
        assertEquals(1, list.templates.size)
        val tpl = list.templates[0]
        assertEquals("nda", tpl.templateKey)
        assertEquals(2, tpl.version)
        // created_at is an epoch-SECOND Long on the template version.
        assertEquals(1_780_000_000L, tpl.createdAt)
        assertEquals(1, tpl.fields.size)
        assertEquals(SignatureFieldType.SIGNATURE, tpl.fields[0].type)
    }

    @Test
    fun createTemplateVersion_verb_path_body_decode() = runTest {
        server.enqueue(jsonResponse(TEMPLATE_VERSION))

        val version = api().createTemplateVersion(
            CreateSignatureTemplateVersionRequest(
                templateKey = "nda",
                displayName = "NDA",
                description = "Mutual NDA",
                fields = listOf(
                    CreateSignatureTemplateFieldRequest(
                        id = "sig",
                        type = SignatureFieldType.SIGNATURE,
                        label = "Sign here",
                        required = true,
                    ),
                ),
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/signing/templates", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("nda", body["template_key"])
        assertEquals("NDA", body["display_name"])
        @Suppress("UNCHECKED_CAST")
        val fields = body["fields"] as List<Map<String, Any?>>
        assertEquals("sig", fields[0]["id"])
        assertEquals("signature", fields[0]["type"])
        assertEquals("nda", version.templateKey)
        assertEquals(2, version.version)
    }

    @Test
    fun getTemplateVersions_pathInterpolation_decode() = runTest {
        server.enqueue(jsonResponse(TEMPLATE_VERSIONS))

        val versions = api().getTemplateVersions("nda")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/signing/templates/nda/versions", recorded.requestUrl?.encodedPath)
        assertEquals("nda", versions.templateKey)
        assertEquals(2, versions.versions.size)
    }

    @Test
    fun getTemplateVersion_intVersionPath_decode() = runTest {
        server.enqueue(jsonResponse(TEMPLATE_VERSION))

        val version = api().getTemplateVersion("nda", 2)

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/signing/templates/nda/versions/2", recorded.requestUrl?.encodedPath)
        assertEquals(2, version.version)
        assertEquals(1_780_000_000L, version.createdAt)
    }

    @Test
    fun migrationCheck_verb_path_body_lenientDecode() = runTest {
        server.enqueue(jsonResponse("""{"migrations":[{"field_id":"sig","change":"moved"}]}"""))

        val result = api().migrationCheck(
            SignatureTemplateMigrationCheckRequest(
                templateKey = "nda",
                fromVersion = 1,
                toVersion = 2,
            ),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/signing/templates/migration-check", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("nda", body["template_key"])
        assertEquals(1.0, body["from_version"])
        assertEquals(2.0, body["to_version"])
        assertEquals(1, result.migrations.size)
        assertEquals("moved", result.migrations[0]["change"])
    }

    private companion object {
        val PACKET_DETAIL = """
            {
              "packet_id": "pkt_1",
              "status": "sent",
              "owner_user_id": "user_1",
              "source_path": "/docs/a.pdf",
              "role": "signer",
              "origin_channel": "share",
              "created_at": "2026-05-01T10:00:00Z",
              "signers": [ { "signer_id": "sgn_1", "status": "pending" } ],
              "fields": [
                {
                  "field_id": "f1", "field_type": "signature", "page": 1,
                  "x": 10.0, "y": 20.0, "width": 100.0, "height": 40.0,
                  "capture_mode": "drawn", "render_payload": { "color": "blue" }
                },
                {
                  "field_id": "f2", "field_type": "date", "page": 1,
                  "x": 5.0, "y": 5.0, "width": 50.0, "height": 20.0,
                  "capture_mode": "typed"
                }
              ],
              "capabilities": { "can_send": true, "can_void": false },
              "legal_notice": { "required": true, "accepted": false, "version": "v2", "text": "Notice" }
            }
        """.trimIndent()

        val PACKET_DETAIL_MISSING_PACKET_ID = """
            {
              "status": "sent",
              "owner_user_id": "user_1",
              "source_path": "/docs/a.pdf",
              "role": "signer"
            }
        """.trimIndent()

        val EVENTS_BODY = """
            {
              "packet_id": "pkt_1",
              "events": [
                {
                  "event_id": "evt_1",
                  "packet_id": "pkt_1",
                  "actor_user_id": "user_1",
                  "event_type": "packet.sent",
                  "event_payload": { "signer_id": "sgn_1" },
                  "created_at": "2026-05-01T10:00:00Z"
                }
              ]
            }
        """.trimIndent()

        val TEMPLATE_VERSION = """
            {
              "template_key": "nda",
              "version": 2,
              "display_name": "NDA",
              "description": "Mutual NDA",
              "fields": [ { "id": "sig", "type": "signature", "label": "Sign", "required": true } ],
              "created_at": 1780000000,
              "created_by": "admin",
              "is_active": true
            }
        """.trimIndent()

        val TEMPLATE_LIST = """
            {
              "templates": [
                {
                  "template_key": "nda",
                  "version": 2,
                  "display_name": "NDA",
                  "fields": [ { "id": "sig", "type": "signature", "label": "Sign", "required": true } ],
                  "created_at": 1780000000
                }
              ]
            }
        """.trimIndent()

        val TEMPLATE_VERSIONS = """
            {
              "template_key": "nda",
              "versions": [
                { "template_key": "nda", "version": 1, "display_name": "NDA", "created_at": 1779000000 },
                { "template_key": "nda", "version": 2, "display_name": "NDA", "created_at": 1780000000 }
              ]
            }
        """.trimIndent()
    }
}
