package com.testlogon.android.feature.signing.model

import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.FieldType
import com.testlogon.android.feature.signing.capture.model.NormalizedRect
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * AND-344 - tests for the [PlacedField] read-model mappers (from AND-342 [FieldPlacement] / AND-340
 * [PacketField]) and the pure [isComplete] gate.
 */
class PlacedFieldTest {

    private val rect = NormalizedRect(0.1f, 0.1f, 0.4f, 0.2f)

    private fun packetField(
        id: String,
        required: Boolean = true,
        assignedToViewer: Boolean = true,
        filledAt: Instant? = null,
        value: String? = null,
    ) = PacketField(
        fieldId = id,
        fieldType = SignatureFieldType.SIGNATURE,
        page = 2,
        x = 0.1f,
        y = 0.1f,
        width = 0.3f,
        height = 0.1f,
        required = required,
        isAssignedToViewer = assignedToViewer,
        filledAt = filledAt,
        value = value,
    )

    @Test
    fun fieldPlacement_toPlacedField_hasContentWhenSatisfied() {
        val placement = FieldPlacement(
            fieldId = "a",
            page = 3,
            rect = rect,
            assetPath = "/cache/a.png",
            satisfied = true,
        )
        val placed = placement.toPlacedField(FieldType.SIGNATURE)
        assertEquals("a", placed.fieldId)
        assertEquals(3, placed.page)
        assertEquals(rect, placed.rect)
        assertEquals(FieldType.SIGNATURE, placed.type)
        assertTrue(placed.hasContent)
    }

    @Test
    fun fieldPlacement_toPlacedField_unsatisfiedHasNoContent() {
        val placement = FieldPlacement(fieldId = "a", page = 1, rect = rect, satisfied = false)
        assertFalse(placement.toPlacedField(FieldType.DATE).hasContent)
    }

    @Test
    fun packetField_toPlacedField_mapsTypeAndRect() {
        val placed = packetField("f").toPlacedField()
        assertEquals("f", placed.fieldId)
        assertEquals(2, placed.page)
        assertEquals(FieldType.SIGNATURE, placed.type)
        // Rect built from x,y,width,height via NormalizedRect.fromXywh.
        assertEquals(0.1f, placed.rect.left, 0.0001f)
        assertEquals(0.4f, placed.rect.right, 0.0001f)
        assertFalse(placed.hasContent)
    }

    @Test
    fun packetField_toPlacedField_hasContentWhenFilled() {
        assertTrue(packetField("f", filledAt = Instant.EPOCH).toPlacedField().hasContent)
        assertTrue(packetField("f", value = "x").toPlacedField().hasContent)
    }

    @Test
    fun isComplete_trueOnlyWhenAllRequiredAssignedSatisfied() {
        val required = listOf(
            packetField("a", required = true, assignedToViewer = true),
            packetField("b", required = true, assignedToViewer = true),
        )
        val placedOne = listOf(PlacedField("a", 1, rect, FieldType.SIGNATURE, hasContent = true))
        assertFalse(isComplete(required, placedOne))

        val placedBoth = placedOne + PlacedField("b", 1, rect, FieldType.SIGNATURE, hasContent = true)
        assertTrue(isComplete(required, placedBoth))
    }

    @Test
    fun isComplete_ignoresNonRequiredAndOtherSignerFields() {
        val required = listOf(
            packetField("a", required = true, assignedToViewer = true),
            packetField("optional", required = false, assignedToViewer = true),
            packetField("other", required = true, assignedToViewer = false),
        )
        val placed = listOf(PlacedField("a", 1, rect, FieldType.SIGNATURE, hasContent = true))
        // Only "a" is a required+viewer blocker; it is satisfied, so complete.
        assertTrue(isComplete(required, placed))
    }

    @Test
    fun isComplete_placedWithoutContentDoesNotSatisfy() {
        val required = listOf(packetField("a", required = true, assignedToViewer = true))
        val placed = listOf(PlacedField("a", 1, rect, FieldType.SIGNATURE, hasContent = false))
        assertFalse(isComplete(required, placed))
    }
}
