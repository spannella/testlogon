package com.testlogon.android.feature.signing.capture.model

import androidx.compose.ui.geometry.Rect
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.feature.signing.model.PacketField
import java.time.LocalDate
import java.time.format.DateTimeFormatter

/**
 * AND-342 - PURE (JVM-testable) domain for in-app signature CAPTURE + PLACEMENT.
 *
 * REUSE: the field geometry originates from AND-340's [PacketField] (normalized x,y,width,height in
 * 0..1, top-left origin, 1-based page) and is projected onto AND-341's per-page on-screen
 * [com.testlogon.android.feature.signing.document.model.PageOnScreen.contentRect] each frame so the
 * overlay stays aligned across scroll, zoom and rotation - the PDF is NOT re-rendered here.
 *
 * SCOPE: this ticket is capture + placement + a validated in-memory [SignedPacketDraft] only. There is
 * NO network submit (that is AND-343) and NO Room persistence. Only signature / initials / date fields
 * are auto-fillable in v1; text / notary_stamp are out of scope.
 *
 * This file contains NO android.graphics types (the rasterizer lives behind an interface) so all of the
 * geometry + draft math is exercised by plain JVM unit tests.
 */

/** The field kinds this capture surface understands (wire token is lowercase, mirrors AND-339). */
enum class FieldType(val token: String) {
    SIGNATURE("signature"),
    INITIALS("initials"),
    DATE("date"),
    TEXT("text"),
    NOTARY_STAMP("notary_stamp"),
    ;

    /** True when the field can be auto-satisfied in v1 (signature / initials stamp, or date auto-fill). */
    val isAutoFillable: Boolean
        get() = this == SIGNATURE || this == INITIALS || this == DATE

    companion object {
        /** Maps an AND-339 [SignatureFieldType] to this feature enum (UNKNOWN degrades to [TEXT]). */
        fun from(wire: SignatureFieldType): FieldType = when (wire) {
            SignatureFieldType.SIGNATURE -> SIGNATURE
            SignatureFieldType.INITIALS -> INITIALS
            SignatureFieldType.DATE -> DATE
            SignatureFieldType.TEXT -> TEXT
            SignatureFieldType.NOTARY_STAMP -> NOTARY_STAMP
            SignatureFieldType.UNKNOWN -> TEXT
        }
    }
}

/**
 * A normalized rectangle in 0..1 page space with a top-left origin. [project] maps it onto a page's
 * on-screen [displayRect] (the AND-341 contentRect) in device pixels - this is the single piece of
 * geometry math that keeps the overlay aligned every frame.
 */
data class NormalizedRect(
    val left: Float,
    val top: Float,
    val right: Float,
    val bottom: Float,
) {
    val x: Float get() = left
    val y: Float get() = top
    val width: Float get() = right - left
    val height: Float get() = bottom - top

    /**
     * Projects this normalized rect onto [displayRect] (a page's on-screen bounds). Pure math: the
     * normalized fractions are scaled by the display width/height and offset by the display origin.
     */
    fun project(displayRect: Rect): Rect = Rect(
        left = displayRect.left + left * displayRect.width,
        top = displayRect.top + top * displayRect.height,
        right = displayRect.left + right * displayRect.width,
        bottom = displayRect.top + bottom * displayRect.height,
    )

    companion object {
        /** Builds a rect from AND-340 x,y,width,height (clamped to a sane 0..1 box, left<=right). */
        fun fromXywh(x: Float, y: Float, width: Float, height: Float): NormalizedRect {
            val l = x.coerceIn(0f, 1f)
            val t = y.coerceIn(0f, 1f)
            val r = (x + width).coerceIn(l, 1f)
            val b = (y + height).coerceIn(t, 1f)
            return NormalizedRect(left = l, top = t, right = r, bottom = b)
        }
    }
}

/** One field the viewer can act on, projected from an AND-340 [PacketField]. */
data class SignatureField(
    val id: String,
    val page: Int,
    val type: FieldType,
    val rect: NormalizedRect,
    val required: Boolean,
    val assignedSignerId: String? = null,
    val isAssignedToViewer: Boolean = false,
)

/** How the captured signature asset was produced. */
enum class SignatureSource {
    DRAWN,
    TYPED,
    SAVED,
}

/**
 * A captured signature asset: a transparent PNG for the full signature plus one for the initials, with
 * the [source] + intrinsic pixel size. Paths point at files in the app cache (written by the rasterizer).
 */
data class SignatureAsset(
    val signaturePngPath: String,
    val initialsPngPath: String,
    val source: SignatureSource,
    val widthPx: Int,
    val heightPx: Int,
)

/**
 * A single placed field. For signature / initials [assetPath] is the stamped PNG; for date [textValue]
 * carries the YYYY-MM-DD string. [satisfied] is true once the field carries a value.
 */
data class FieldPlacement(
    val fieldId: String,
    val page: Int,
    val rect: NormalizedRect,
    val assetPath: String? = null,
    val textValue: String? = null,
    val satisfied: Boolean = false,
)

/**
 * The validated in-memory draft handed to AND-343. Holds the captured [asset] plus every [placements]
 * the viewer made. [unsatisfiedRequired] + [isComplete] are PURE validators over the field manifest.
 */
data class SignedPacketDraft(
    val packetId: String,
    val documentId: String,
    val asset: SignatureAsset? = null,
    val placements: List<FieldPlacement> = emptyList(),
) {
    /** The ids of required [fields] that have no satisfied placement (the blockers to completion). */
    fun unsatisfiedRequired(fields: List<SignatureField>): List<String> {
        val satisfiedIds = placements.filter { it.satisfied }.map { it.fieldId }.toSet()
        return fields
            .filter { it.required && it.id !in satisfiedIds }
            .map { it.id }
    }

    /** True when every required field in [fields] has a satisfied placement. */
    fun isComplete(fields: List<SignatureField>): Boolean = unsatisfiedRequired(fields).isEmpty()
}

/** Maps an AND-340 [PacketField] to a capture [SignatureField] (normalized rect + viewer flag). */
fun PacketField.toSignatureField(): SignatureField = SignatureField(
    id = fieldId,
    page = page,
    type = FieldType.from(fieldType),
    rect = NormalizedRect.fromXywh(x = x, y = y, width = width, height = height),
    required = required,
    assignedSignerId = assignedSignerId,
    isAssignedToViewer = isAssignedToViewer == true,
)

/** The canonical submit date format (YYYY-MM-DD), matching the AND-339 wire contract. */
private val DATE_FORMAT: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")

/** Formats [date] as YYYY-MM-DD for a date-field auto-fill. */
fun formatSubmitDate(date: LocalDate): String = date.format(DATE_FORMAT)
