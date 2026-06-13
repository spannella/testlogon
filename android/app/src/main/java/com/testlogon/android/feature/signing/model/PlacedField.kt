package com.testlogon.android.feature.signing.model

import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.FieldType
import com.testlogon.android.feature.signing.capture.model.NormalizedRect

/**
 * AND-344 - the PRESENTATION read-model for one field inside the editor state machine
 * (SigningEditorState). It is a flat, immutable projection the editor renders + reasons over, derived
 * from EITHER:
 *   - an AND-342 [FieldPlacement] (a field the viewer has already placed / satisfied), OR
 *   - an AND-340 [PacketField] (a field from the manifest the viewer still has to satisfy).
 *
 * REUSE (NO redefinition): the geometry type is AND-342's [NormalizedRect] and the kind is AND-342's
 * [FieldType]; this file does NOT define a parallel rect / type. [FieldPlacement] remains the capture
 * write-model - [PlacedField] is purely the editor read-model layered on top.
 *
 * This file is Android-free and PURE (no android.* imports) so the editor reducer + its mappers are
 * exercised by plain JVM unit tests.
 */
data class PlacedField(
    val fieldId: String,
    val page: Int,
    val rect: NormalizedRect,
    val type: FieldType,
    val hasContent: Boolean,
)

/**
 * Maps an AND-342 [FieldPlacement] to a [PlacedField]. A placement is read-model "has content" exactly
 * when it is [FieldPlacement.satisfied]. [type] is supplied by the caller because the placement itself
 * does not carry the field kind (the manifest does).
 */
fun FieldPlacement.toPlacedField(type: FieldType): PlacedField = PlacedField(
    fieldId = fieldId,
    page = page,
    rect = rect,
    type = type,
    hasContent = satisfied,
)

/**
 * Maps an AND-340 [PacketField] to a [PlacedField] for the editor read-model. The kind is mapped via
 * AND-342 [FieldType.from]; the normalized rect is built via AND-342 [NormalizedRect.fromXywh].
 * [hasContent] is true when the manifest field already carries a filled value (filled_at present); an
 * unfilled manifest field starts empty.
 */
fun PacketField.toPlacedField(): PlacedField = PlacedField(
    fieldId = fieldId,
    page = page,
    rect = NormalizedRect.fromXywh(x = x, y = y, width = width, height = height),
    type = FieldType.from(fieldType),
    hasContent = filledAt != null || value != null,
)

/**
 * PURE completeness check for the editor: every REQUIRED field that is ASSIGNED TO THE VIEWER must have
 * a corresponding [PlacedField] with content. A required field that is NOT assigned to the viewer (e.g.
 * another signer's field) is NOT a blocker for this viewer and is ignored. Fields that are not required
 * are also ignored.
 *
 * @param required the AND-340 manifest fields (the source of required + viewer-assignment truth).
 * @param placed   the current editor read-model fields (the source of has-content truth).
 */
fun isComplete(required: List<PacketField>, placed: List<PlacedField>): Boolean {
    val contentIds = placed.filter { it.hasContent }.map { it.fieldId }.toSet()
    return required
        .filter { it.required && it.isAssignedToViewer == true }
        .all { it.fieldId in contentIds }
}
