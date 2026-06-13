package com.testlogon.android.feature.signing.capture

import androidx.compose.ui.geometry.Rect
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.FieldType
import com.testlogon.android.feature.signing.capture.model.NormalizedRect
import com.testlogon.android.feature.signing.capture.model.SignatureField
import com.testlogon.android.feature.signing.capture.model.SignedPacketDraft
import com.testlogon.android.feature.signing.capture.model.formatSubmitDate
import com.testlogon.android.feature.signing.capture.model.toSignatureField
import com.testlogon.android.feature.signing.model.PacketField
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDate

/**
 * AND-342 - PURE (JVM) tests for the capture domain: NormalizedRect.fromXywh + project math, the
 * PacketField -> SignatureField mapping, the YYYY-MM-DD date format, and SignedPacketDraft validation
 * (unsatisfiedRequired / isComplete). No android.graphics here (the rasterizer is faked elsewhere).
 */
class SignatureCaptureDomainTest {

    @Test
    fun fromXywh_buildsRect_andExposesAccessors() {
        val rect = NormalizedRect.fromXywh(x = 0.1f, y = 0.2f, width = 0.3f, height = 0.4f)
        assertEquals(0.1f, rect.left, EPS)
        assertEquals(0.2f, rect.top, EPS)
        assertEquals(0.4f, rect.right, EPS)
        assertEquals(0.6f, rect.bottom, EPS)
        assertEquals(0.3f, rect.width, EPS)
        assertEquals(0.4f, rect.height, EPS)
        assertEquals(0.1f, rect.x, EPS)
        assertEquals(0.2f, rect.y, EPS)
    }

    @Test
    fun fromXywh_clampsOutOfRange() {
        val rect = NormalizedRect.fromXywh(x = -0.5f, y = 0.9f, width = 2f, height = 2f)
        assertEquals(0f, rect.left, EPS)
        assertEquals(0.9f, rect.top, EPS)
        assertEquals(1f, rect.right, EPS)
        assertEquals(1f, rect.bottom, EPS)
    }

    @Test
    fun project_mapsNormalizedRectOntoDisplayRect() {
        val rect = NormalizedRect.fromXywh(x = 0.25f, y = 0.5f, width = 0.5f, height = 0.25f)
        // A page displayed at (100, 200) sized 400 x 800.
        val display = Rect(left = 100f, top = 200f, right = 500f, bottom = 1000f)
        val projected = rect.project(display)
        assertEquals(100f + 0.25f * 400f, projected.left, EPS) // 200
        assertEquals(200f + 0.5f * 800f, projected.top, EPS) // 600
        assertEquals(100f + 0.75f * 400f, projected.right, EPS) // 400
        assertEquals(200f + 0.75f * 800f, projected.bottom, EPS) // 800
    }

    @Test
    fun packetField_mapsToSignatureField_withViewerFlag() {
        val pf = PacketField(
            fieldId = "f1",
            fieldType = SignatureFieldType.SIGNATURE,
            page = 2,
            x = 0.1f,
            y = 0.1f,
            width = 0.2f,
            height = 0.05f,
            required = true,
            assignedSignerId = "s1",
            isAssignedToViewer = true,
        )
        val field = pf.toSignatureField()
        assertEquals("f1", field.id)
        assertEquals(2, field.page)
        assertEquals(FieldType.SIGNATURE, field.type)
        assertTrue(field.required)
        assertTrue(field.isAssignedToViewer)
        assertEquals("s1", field.assignedSignerId)
        assertEquals(0.1f, field.rect.left, EPS)
        assertEquals(0.3f, field.rect.right, EPS)
    }

    @Test
    fun fieldType_mapsUnknownToText_andDateIsAutoFillable() {
        assertEquals(FieldType.TEXT, FieldType.from(SignatureFieldType.UNKNOWN))
        assertEquals(FieldType.DATE, FieldType.from(SignatureFieldType.DATE))
        assertTrue(FieldType.SIGNATURE.isAutoFillable)
        assertTrue(FieldType.INITIALS.isAutoFillable)
        assertTrue(FieldType.DATE.isAutoFillable)
        assertFalse(FieldType.TEXT.isAutoFillable)
        assertFalse(FieldType.NOTARY_STAMP.isAutoFillable)
    }

    @Test
    fun formatSubmitDate_isYyyyMmDd() {
        val out = formatSubmitDate(LocalDate.of(2026, 6, 9))
        assertEquals("2026-06-09", out)
        assertTrue(out.matches(Regex("^\\d{4}-\\d{2}-\\d{2}$")))
    }

    @Test
    fun unsatisfiedRequired_listsOnlyRequiredUnsatisfied() {
        val fields = listOf(
            requiredField("a"),
            requiredField("b"),
            optionalField("c"),
        )
        val draft = SignedPacketDraft(
            packetId = "p",
            documentId = "d",
            placements = listOf(
                FieldPlacement(fieldId = "a", page = 1, rect = boxRect(), satisfied = true),
            ),
        )
        assertEquals(listOf("b"), draft.unsatisfiedRequired(fields))
        assertFalse(draft.isComplete(fields))
    }

    @Test
    fun isComplete_trueWhenAllRequiredSatisfied() {
        val fields = listOf(requiredField("a"), optionalField("b"))
        val draft = SignedPacketDraft(
            packetId = "p",
            documentId = "d",
            placements = listOf(
                FieldPlacement(fieldId = "a", page = 1, rect = boxRect(), satisfied = true),
            ),
        )
        assertTrue(draft.unsatisfiedRequired(fields).isEmpty())
        assertTrue(draft.isComplete(fields))
    }

    @Test
    fun unsatisfiedPlacement_doesNotCount() {
        val fields = listOf(requiredField("a"))
        val draft = SignedPacketDraft(
            packetId = "p",
            documentId = "d",
            placements = listOf(
                FieldPlacement(fieldId = "a", page = 1, rect = boxRect(), satisfied = false),
            ),
        )
        assertEquals(listOf("a"), draft.unsatisfiedRequired(fields))
    }

    private fun boxRect() = NormalizedRect.fromXywh(0.1f, 0.1f, 0.2f, 0.1f)

    private fun requiredField(id: String) = SignatureField(
        id = id,
        page = 1,
        type = FieldType.SIGNATURE,
        rect = boxRect(),
        required = true,
        isAssignedToViewer = true,
    )

    private fun optionalField(id: String) = SignatureField(
        id = id,
        page = 1,
        type = FieldType.TEXT,
        rect = boxRect(),
        required = false,
        isAssignedToViewer = true,
    )

    private companion object {
        const val EPS = 0.0001f
    }
}
