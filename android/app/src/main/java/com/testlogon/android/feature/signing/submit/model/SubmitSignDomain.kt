package com.testlogon.android.feature.signing.submit.model

import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SignaturePacketFieldFillRequest
import com.testlogon.android.core.network.signing.SignaturePacketMarkDoneResponse
import com.testlogon.android.core.network.signing.SignatureInputMode
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.model.SignaturePacket
import java.time.Instant
import java.util.Base64

/**
 * AND-343 - PURE (JVM-testable) domain for the TERMINAL e-sign step.
 *
 * SCOPE: maps an AND-342 [FieldPlacement] to the AND-339 per-field
 * [SignaturePacketFieldFillRequest], and folds the lenient AND-339 mark-done response (plus a
 * follow-up packet reload) to a [MarkDoneResult]. There is NO bulk submit, NO license-agreements
 * endpoint and NO `signed` status: the terminal action is POST mark-done (EMPTY body) and the
 * terminal status is [PacketStatus.COMPLETED].
 *
 * This file holds NO android.* types (Base64 is java.util.Base64; the PNG bytes arrive via the
 * injectable [AssetBytesReader] seam) so every mapping is exercised by plain JVM unit tests.
 */

/**
 * Reads the raw bytes of a captured signature/initials asset (an on-disk PNG path). Behind an
 * interface so the JVM request-builder test injects a fake; the production impl reads from the file
 * system. android.util.Base64 / Bitmap are intentionally NOT used here - the bytes are base64-encoded
 * with java.util.Base64 so the builder stays JVM-testable.
 */
fun interface AssetBytesReader {
    /** Returns the bytes at [path], or null when the path is blank / missing / unreadable. */
    fun read(path: String): ByteArray?
}

/**
 * The outcome of the terminal mark-done call. [packetStatus] is the AND-339 [PacketStatus] (terminal
 * is [PacketStatus.COMPLETED]); [completedAt] is populated from a follow-up packet reload because the
 * mark-done response is lenient (only {ok,status}). [signerStatus] mirrors the packet's signer_status.
 */
data class MarkDoneResult(
    val packetStatus: PacketStatus,
    val completedAt: Instant? = null,
    val signerStatus: String? = null,
) {
    /** True once the packet reached the terminal completed status. */
    val isCompleted: Boolean get() = packetStatus == PacketStatus.COMPLETED
}

/**
 * Folds the lenient AND-339 [SignaturePacketMarkDoneResponse] to a [MarkDoneResult], enriched with the
 * [reloaded] packet detail (the source of completed_at / signer_status, since mark-done is sparse). The
 * response status wins when present; otherwise the reloaded packet status is used; UNKNOWN is the last
 * resort. NEVER throws.
 */
fun SignaturePacketMarkDoneResponse.toMarkDoneResult(
    reloaded: SignaturePacket?,
): MarkDoneResult {
    val resolvedStatus = status ?: reloaded?.status ?: PacketStatus.UNKNOWN
    return MarkDoneResult(
        packetStatus = resolvedStatus,
        completedAt = reloaded?.completedAt,
        signerStatus = reloaded?.signerStatus,
    )
}

/**
 * Builds the per-field fill request for a single [placement].
 *
 *   - a [textValue]-bearing placement (date YYYY-MM-DD, or a typed signature / text) -> value =
 *     textValue with capture_mode = TYPED,
 *   - an [assetPath]-bearing placement (a DRAWN/stamped signature or initials PNG) -> capture_mode =
 *     DRAWN with a dependency-free base64 render_payload carrying the rendered PNG (read via
 *     [bytesReader]) plus the page + normalized rect,
 *   - an empty placement -> a bare request (value/capture_mode null), letting the backend reject it.
 *
 * KDOC-FLAG: the exact DRAWN wire shape (raw strokes vs a rendered image) is BACKEND-UNCERTAIN. We
 * send a dependency-free base64 PNG under render_payload[image_png_base64]; this is trivially swapped
 * to a strokes payload later without touching the call sites. NO SDK is used.
 *
 * The [page] is taken from the placement; [forceTextMode] lets a date field pin TYPED even though it
 * has a text value (the default already does, this is documentation of intent).
 */
fun buildFillRequest(
    placement: FieldPlacement,
    bytesReader: AssetBytesReader,
): SignaturePacketFieldFillRequest {
    val text = placement.textValue
    val assetPath = placement.assetPath
    return when {
        // Typed signature / date (YYYY-MM-DD) / text: a plain value captured as TYPED.
        text != null -> SignaturePacketFieldFillRequest(
            value = text,
            captureMode = SignatureInputMode.TYPED,
            renderPayload = null,
        )
        // Drawn / stamped signature or initials: a base64 PNG render payload captured as DRAWN.
        !assetPath.isNullOrBlank() -> {
            val bytes = bytesReader.read(assetPath)
            val payload = mutableMapOf<String, Any?>(
                KEY_PAGE to placement.page,
                KEY_RECT to mapOf(
                    KEY_X to placement.rect.x,
                    KEY_Y to placement.rect.y,
                    KEY_WIDTH to placement.rect.width,
                    KEY_HEIGHT to placement.rect.height,
                ),
            )
            if (bytes != null) {
                payload[KEY_IMAGE] = Base64.getEncoder().encodeToString(bytes)
            }
            SignaturePacketFieldFillRequest(
                value = null,
                captureMode = SignatureInputMode.DRAWN,
                renderPayload = payload,
            )
        }
        // Nothing captured: a bare request (the backend decides whether this is acceptable).
        else -> SignaturePacketFieldFillRequest()
    }
}

/** render_payload keys (kept out of comments to avoid an inadvertent comment terminator). */
private const val KEY_IMAGE = "image_png_base64"
private const val KEY_PAGE = "page"
private const val KEY_RECT = "rect"
private const val KEY_X = "x"
private const val KEY_Y = "y"
private const val KEY_WIDTH = "width"
private const val KEY_HEIGHT = "height"
