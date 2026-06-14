package com.testlogon.android.core.network.signing

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-345 - DTO-level Moshi tests for the AND-339 signing transport (FR-1).
 *
 * This EXTENDS (does not duplicate) SigningApiContractTest, which already asserts per-endpoint
 * decoding through MockWebServer. Here the focus is the adapter behaviour the contract test does not
 * exercise: full serialize -> deserialize ROUND-TRIPS, SPARSE bodies decoding via the DTO defaults, and
 * UNKNOWN fallback across ALL FOUR signing enums (field_type / status / capture_mode / role).
 *
 * The Moshi is built EXACTLY like the production NetworkModule.provideMoshi (BigDecimalAdapter + the
 * four signing enum adapters + the reflective KotlinJsonAdapterFactory, in the same order) so decoding
 * reflects production. core-network has no test dependency on :core-testing, so the JSON is inline.
 * KDoc avoids the comment-terminator character pair.
 */
class SigningDtoJsonTest {

    // Built exactly like NetworkModule.provideMoshi (same factory + registered signing enum adapters).
    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(PacketStatusAdapter)
        .add(SignatureFieldTypeAdapter)
        .add(PacketRoleAdapter)
        .add(SignatureInputModeAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private inline fun <reified T> roundTrip(value: T): T {
        val adapter = moshi.adapter(T::class.java)
        val json = adapter.toJson(value)
        return requireNotNull(adapter.fromJson(json)) { "round-trip produced null for $json" }
    }

    // ---- Round-trips ----

    @Test
    fun packetDetail_roundTrips_preservingEnumsSignersFieldsLegalNotice() {
        val original = SignaturePacketDetailDto(
            packetId = "pkt_1",
            status = PacketStatus.SENT,
            ownerUserId = "usr_owner",
            sourcePath = "/docs/a.pdf",
            role = PacketRole.SIGNER,
            signerStatus = "pending",
            createdAt = "2026-05-01T10:00:00Z",
            sentAt = "2026-05-02T10:00:00Z",
            signers = listOf(SignaturePacketSignerDto(signerId = "sgn_1", status = "pending")),
            fields = listOf(
                SignatureFieldDto(
                    fieldId = "fld_sig",
                    fieldType = SignatureFieldType.SIGNATURE,
                    page = 1,
                    x = 0.1f,
                    y = 0.2f,
                    width = 0.3f,
                    height = 0.1f,
                    captureMode = SignatureInputMode.DRAWN,
                    renderPayload = mapOf("color" to "blue"),
                ),
            ),
            capabilities = mapOf("can_fill_fields" to true),
            legalNotice = LegalNoticeDto(
                required = true,
                accepted = false,
                version = "v2",
                text = "Notice",
            ),
        )

        val decoded = roundTrip(original)

        assertEquals("pkt_1", decoded.packetId)
        assertEquals(PacketStatus.SENT, decoded.status)
        assertEquals(PacketRole.SIGNER, decoded.role)
        assertEquals(1, decoded.signers.size)
        assertEquals("sgn_1", decoded.signers[0].signerId)
        assertEquals(1, decoded.fields.size)
        assertEquals(SignatureFieldType.SIGNATURE, decoded.fields[0].fieldType)
        assertEquals(SignatureInputMode.DRAWN, decoded.fields[0].captureMode)
        assertEquals("blue", decoded.fields[0].renderPayload?.get("color"))
        assertEquals(true, decoded.capabilities["can_fill_fields"])
        assertEquals("v2", decoded.legalNotice?.version)
        assertEquals(true, decoded.legalNotice?.required)
    }

    @Test
    fun signatureField_roundTrips() {
        val original = SignatureFieldDto(
            fieldId = "fld_date",
            fieldType = SignatureFieldType.DATE,
            page = 2,
            x = 0.5f,
            y = 0.6f,
            width = 0.2f,
            height = 0.05f,
            required = false,
            assignedSignerId = "sgn_2",
            isAssignedToViewer = true,
            captureMode = SignatureInputMode.TYPED,
        )

        val decoded = roundTrip(original)

        assertEquals("fld_date", decoded.fieldId)
        assertEquals(SignatureFieldType.DATE, decoded.fieldType)
        assertEquals(2, decoded.page)
        assertEquals(false, decoded.required)
        assertEquals("sgn_2", decoded.assignedSignerId)
        assertEquals(true, decoded.isAssignedToViewer)
        assertEquals(SignatureInputMode.TYPED, decoded.captureMode)
    }

    @Test
    fun legalNotice_roundTrips() {
        val decoded = roundTrip(
            LegalNoticeDto(required = true, accepted = true, version = "v7", text = "Sign here"),
        )
        assertEquals(true, decoded.required)
        assertEquals(true, decoded.accepted)
        assertEquals("v7", decoded.version)
        assertEquals("Sign here", decoded.text)
    }

    @Test
    fun fillResponse_roundTrips_withNestedField() {
        val decoded = roundTrip(
            SignaturePacketFieldFillResponse(
                ok = true,
                field = SignatureFieldDto(
                    fieldId = "fld_sig",
                    fieldType = SignatureFieldType.SIGNATURE,
                    page = 1,
                    x = 0f,
                    y = 0f,
                    width = 1f,
                    height = 1f,
                ),
            ),
        )
        assertEquals(true, decoded.ok)
        assertEquals("fld_sig", decoded.field?.fieldId)
    }

    @Test
    fun markDoneAndAckResponses_roundTrip() {
        val markDone = roundTrip(SignaturePacketMarkDoneResponse(ok = true, status = PacketStatus.COMPLETED))
        assertEquals(true, markDone.ok)
        assertEquals(PacketStatus.COMPLETED, markDone.status)

        val ack = roundTrip(SignaturePacketLegalNoticeAckResponse(ok = true, accepted = true))
        assertEquals(true, ack.ok)
        assertEquals(true, ack.accepted)
    }

    // ---- Sparse / optional decoding (defaults kick in) ----

    @Test
    fun sparsePacketBody_decodesViaDefaults() {
        val adapter = moshi.adapter(SignaturePacketDetailDto::class.java)
        // Only the required, no-default fields present; everything else absent.
        val decoded = requireNotNull(
            adapter.fromJson(
                """
                {
                  "packet_id": "pkt_sparse",
                  "status": "draft",
                  "owner_user_id": "usr_owner",
                  "source_path": "/docs/x.pdf",
                  "role": "sender"
                }
                """.trimIndent(),
            ),
        )

        assertEquals("pkt_sparse", decoded.packetId)
        assertEquals(PacketStatus.DRAFT, decoded.status)
        // Optional fields default: lists empty, maps empty, nullable nulls.
        assertTrue(decoded.signers.isEmpty())
        assertTrue(decoded.fields.isEmpty())
        assertTrue(decoded.capabilities.isEmpty())
        assertNull(decoded.signerStatus)
        assertNull(decoded.createdAt)
        assertNull(decoded.legalNotice)
    }

    @Test
    fun sparseLegalNotice_decodesAllDefaults() {
        val adapter = moshi.adapter(LegalNoticeDto::class.java)
        val decoded = requireNotNull(adapter.fromJson("{}"))
        assertEquals(false, decoded.required)
        assertEquals(false, decoded.accepted)
        assertEquals("", decoded.version)
        assertEquals("", decoded.text)
    }

    @Test
    fun sparseField_decodesRequiredDefaultTrue_andNullOptionals() {
        val adapter = moshi.adapter(SignatureFieldDto::class.java)
        val decoded = requireNotNull(
            adapter.fromJson(
                """{"field_id":"f1","field_type":"text","page":1,"x":0,"y":0,"width":1,"height":1}""",
            ),
        )
        assertEquals(SignatureFieldType.TEXT, decoded.fieldType)
        // required has a default of true.
        assertTrue(decoded.required)
        assertNull(decoded.captureMode)
        assertNull(decoded.value)
        assertNull(decoded.renderPayload)
    }

    @Test
    fun missingRequiredPacketId_throwsJsonDataException() {
        val adapter = moshi.adapter(SignaturePacketDetailDto::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(
                """{"status":"sent","owner_user_id":"u","source_path":"/a","role":"signer"}""",
            )
        }
    }

    // ---- UNKNOWN fallback across all four enums ----

    @Test
    fun unknownFieldType_decodesToUnknown() {
        val adapter = moshi.adapter(SignatureFieldDto::class.java)
        val decoded = requireNotNull(
            adapter.fromJson(
                """{"field_id":"f1","field_type":"hologram","page":1,"x":0,"y":0,"width":1,"height":1}""",
            ),
        )
        assertEquals(SignatureFieldType.UNKNOWN, decoded.fieldType)
    }

    @Test
    fun unknownStatus_decodesToUnknown() {
        val adapter = moshi.adapter(SignaturePacketDetailDto::class.java)
        val decoded = requireNotNull(
            adapter.fromJson(
                """{"packet_id":"p","status":"vaporized","owner_user_id":"u","source_path":"/a","role":"signer"}""",
            ),
        )
        assertEquals(PacketStatus.UNKNOWN, decoded.status)
    }

    @Test
    fun unknownRole_decodesToUnknown() {
        val adapter = moshi.adapter(SignaturePacketDetailDto::class.java)
        val decoded = requireNotNull(
            adapter.fromJson(
                """{"packet_id":"p","status":"sent","owner_user_id":"u","source_path":"/a","role":"observer"}""",
            ),
        )
        assertEquals(PacketRole.UNKNOWN, decoded.role)
    }

    @Test
    fun unknownCaptureMode_decodesToUnknown() {
        val adapter = moshi.adapter(SignatureFieldDto::class.java)
        val decoded = requireNotNull(
            adapter.fromJson(
                """{"field_id":"f1","field_type":"signature","page":1,"x":0,"y":0,"width":1,"height":1,"capture_mode":"telepathy"}""",
            ),
        )
        assertEquals(SignatureInputMode.UNKNOWN, decoded.captureMode)
    }

    @Test
    fun enumAdapters_serializeBackToWireToken() {
        // The adapter toJson writes the lowercase wire token (not the Kotlin member name).
        assertEquals("\"completed\"", moshi.adapter(PacketStatus::class.java).toJson(PacketStatus.COMPLETED))
        assertEquals(
            "\"notary_stamp\"",
            moshi.adapter(SignatureFieldType::class.java).toJson(SignatureFieldType.NOTARY_STAMP),
        )
        assertEquals("\"signer\"", moshi.adapter(PacketRole::class.java).toJson(PacketRole.SIGNER))
        assertEquals(
            "\"drawn\"",
            moshi.adapter(SignatureInputMode::class.java).toJson(SignatureInputMode.DRAWN),
        )
    }
}
