package com.testlogon.android.feature.signing.submit

import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SignatureInputMode
import com.testlogon.android.core.network.signing.SignaturePacketMarkDoneResponse
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.NormalizedRect
import com.testlogon.android.feature.signing.model.SignaturePacket
import com.testlogon.android.feature.signing.submit.model.AssetBytesReader
import com.testlogon.android.feature.signing.submit.model.buildFillRequest
import com.testlogon.android.feature.signing.submit.model.toMarkDoneResult
import com.testlogon.android.core.network.signing.PacketRole
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import java.util.Base64

/**
 * AND-343 - PURE JVM tests for the terminal e-sign request-builder + MarkDoneResult mapping.
 *
 * Covers: typed/date placement -> value + capture_mode TYPED; drawn placement -> capture_mode DRAWN +
 * a base64 render_payload sourced from a FAKE [AssetBytesReader] (no android.* on the classpath); the
 * mark-done response fold (status + completed_at enrichment from a reload). Distinct fake-helper names.
 */
class SubmitSignDomainTest {

    private val rect = NormalizedRect(left = 0.1f, top = 0.2f, right = 0.5f, bottom = 0.6f)

    private class StubBytes(private val bytes: ByteArray?) : AssetBytesReader {
        override fun read(path: String): ByteArray? = bytes
    }

    @Test
    fun typedPlacement_mapsToValueAndTypedMode() {
        val placement = FieldPlacement(
            fieldId = "fld_text",
            page = 0,
            rect = rect,
            textValue = "Ada Lovelace",
            satisfied = true,
        )
        val req = buildFillRequest(placement, StubBytes(null))

        assertEquals("Ada Lovelace", req.value)
        assertEquals(SignatureInputMode.TYPED, req.captureMode)
        assertNull(req.renderPayload)
    }

    @Test
    fun datePlacement_mapsToYyyyMmDdValue_typedMode() {
        val placement = FieldPlacement(
            fieldId = "fld_date",
            page = 2,
            rect = rect,
            textValue = "2026-06-13",
            satisfied = true,
        )
        val req = buildFillRequest(placement, StubBytes(null))

        assertEquals("2026-06-13", req.value)
        assertEquals(SignatureInputMode.TYPED, req.captureMode)
    }

    @Test
    fun drawnPlacement_mapsToDrawnMode_withBase64RenderPayload() {
        val raw = byteArrayOf(1, 2, 3, 4, 5)
        val placement = FieldPlacement(
            fieldId = "fld_sig",
            page = 1,
            rect = rect,
            assetPath = "/cache/sig.png",
            satisfied = true,
        )
        val req = buildFillRequest(placement, StubBytes(raw))

        assertNull(req.value)
        assertEquals(SignatureInputMode.DRAWN, req.captureMode)
        val payload = req.renderPayload!!
        assertEquals(Base64.getEncoder().encodeToString(raw), payload["image_png_base64"])
        assertEquals(1, payload["page"])
        @Suppress("UNCHECKED_CAST")
        val r = payload["rect"] as Map<String, Any?>
        assertEquals(0.1f, r["x"] as Float, 1e-4f)
        assertEquals(0.2f, r["y"] as Float, 1e-4f)
        assertEquals(0.4f, r["width"] as Float, 1e-4f)
        assertEquals(0.4f, r["height"] as Float, 1e-4f)
    }

    @Test
    fun drawnPlacement_missingBytes_omitsImageButKeepsDrawnMode() {
        val placement = FieldPlacement(
            fieldId = "fld_sig",
            page = 0,
            rect = rect,
            assetPath = "/cache/missing.png",
            satisfied = true,
        )
        val req = buildFillRequest(placement, StubBytes(null))

        assertEquals(SignatureInputMode.DRAWN, req.captureMode)
        assertNull(req.renderPayload!!["image_png_base64"])
    }

    @Test
    fun markDoneResult_usesResponseStatus_andReloadCompletedAt() {
        val response = SignaturePacketMarkDoneResponse(ok = true, status = PacketStatus.COMPLETED)
        val reloaded = samplePacket(
            status = PacketStatus.COMPLETED,
            completedAt = Instant.parse("2026-06-13T12:00:00Z"),
            signerStatus = "signed",
        )
        val result = response.toMarkDoneResult(reloaded)

        assertEquals(PacketStatus.COMPLETED, result.packetStatus)
        assertEquals(Instant.parse("2026-06-13T12:00:00Z"), result.completedAt)
        assertEquals("signed", result.signerStatus)
        assertTrue(result.isCompleted)
    }

    @Test
    fun markDoneResult_fallsBackToReloadStatus_whenResponseSparse() {
        val response = SignaturePacketMarkDoneResponse(ok = true, status = null)
        val reloaded = samplePacket(status = PacketStatus.COMPLETED)
        val result = response.toMarkDoneResult(reloaded)

        assertEquals(PacketStatus.COMPLETED, result.packetStatus)
    }

    @Test
    fun markDoneResult_unknown_whenNoStatusAnywhere() {
        val result = SignaturePacketMarkDoneResponse().toMarkDoneResult(null)
        assertEquals(PacketStatus.UNKNOWN, result.packetStatus)
        assertNull(result.completedAt)
    }

    private fun samplePacket(
        status: PacketStatus,
        completedAt: Instant? = null,
        signerStatus: String? = null,
    ) = SignaturePacket(
        packetId = "pkt_1",
        status = status,
        ownerUserId = "usr",
        sourcePath = "files/doc.pdf",
        role = PacketRole.SIGNER,
        signerStatus = signerStatus,
        completedAt = completedAt,
    )
}
