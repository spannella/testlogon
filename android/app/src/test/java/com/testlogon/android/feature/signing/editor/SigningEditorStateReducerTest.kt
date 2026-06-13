package com.testlogon.android.feature.signing.editor

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.feature.signing.capture.model.FieldType
import com.testlogon.android.feature.signing.capture.model.NormalizedRect
import com.testlogon.android.feature.signing.capture.model.SignatureAsset
import com.testlogon.android.feature.signing.capture.model.SignatureSource
import com.testlogon.android.feature.signing.model.PacketField
import com.testlogon.android.feature.signing.model.PlacedField
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-344 - exhaustive transition tests for the PURE [SigningEditorReducer] / [SigningEditorState]
 * machine: every LEGAL edge, that every ILLEGAL transition is a no-op (returns the SAME instance),
 * isComplete recomputation on place/move/remove, and that onContinue is gated by isComplete.
 */
class SigningEditorStateReducerTest {

    private val asset = SignatureAsset(
        signaturePngPath = "/cache/sig.png",
        initialsPngPath = "/cache/ini.png",
        source = SignatureSource.DRAWN,
        widthPx = 600,
        heightPx = 200,
    )

    private val rect = NormalizedRect(0.1f, 0.1f, 0.4f, 0.15f)

    private fun requiredField(id: String, assignedToViewer: Boolean = true) = PacketField(
        fieldId = id,
        fieldType = SignatureFieldType.SIGNATURE,
        page = 1,
        x = 0.1f,
        y = 0.1f,
        width = 0.3f,
        height = 0.05f,
        required = true,
        isAssignedToViewer = assignedToViewer,
    )

    private fun placed(id: String, hasContent: Boolean) = PlacedField(
        fieldId = id,
        page = 1,
        rect = rect,
        type = FieldType.SIGNATURE,
        hasContent = hasContent,
    )

    // ---- Legal edges ----

    @Test
    fun loading_loadOk_goesToCapturing_drawWhenNoSaved() {
        val next = SigningEditorReducer.loadOk(SigningEditorState.Loading)
        val capturing = next as SigningEditorState.Capturing
        assertEquals(CaptureMode.DRAW, capturing.mode)
        assertEquals(null, capturing.savedSignature)
    }

    @Test
    fun loading_loadOk_goesToCapturing_adoptSavedWhenSaved() {
        val next = SigningEditorReducer.loadOk(SigningEditorState.Loading, asset)
        val capturing = next as SigningEditorState.Capturing
        assertEquals(CaptureMode.ADOPT_SAVED, capturing.mode)
        assertEquals(asset, capturing.savedSignature)
    }

    @Test
    fun loading_loadErr_goesToError() {
        val error = ApiError(500, "boom")
        val next = SigningEditorReducer.loadErr(SigningEditorState.Loading, error)
        assertEquals(SigningEditorState.Error(error), next)
    }

    @Test
    fun capturing_onSignatureCaptured_goesToPlacing_recomputesIsComplete() {
        val start = SigningEditorState.Capturing(CaptureMode.DRAW)
        val required = listOf(requiredField("a"))
        // No content yet -> not complete.
        val placing = SigningEditorReducer.onSignatureCaptured(
            state = start,
            signature = asset,
            placed = emptyList(),
            required = required,
        ) as SigningEditorState.Placing
        assertEquals(asset, placing.signature)
        assertFalse(placing.isComplete)
        assertEquals(null, placing.activeFieldId)
    }

    @Test
    fun placing_onFieldPlaced_addsField_recomputesComplete() {
        val required = listOf(requiredField("a"))
        val start = SigningEditorState.Placing(asset, emptyList(), isComplete = false)
        val next = SigningEditorReducer.onFieldPlaced(
            state = start,
            field = placed("a", hasContent = true),
            required = required,
        ) as SigningEditorState.Placing
        assertEquals(1, next.placed.size)
        assertEquals("a", next.activeFieldId)
        assertTrue(next.isComplete)
    }

    @Test
    fun placing_onFieldPlaced_replacesById() {
        val required = listOf(requiredField("a"))
        val start = SigningEditorState.Placing(
            asset,
            listOf(placed("a", hasContent = false)),
            isComplete = false,
        )
        val next = SigningEditorReducer.onFieldPlaced(
            state = start,
            field = placed("a", hasContent = true),
            required = required,
        ) as SigningEditorState.Placing
        assertEquals(1, next.placed.size)
        assertTrue(next.placed.first().hasContent)
        assertTrue(next.isComplete)
    }

    @Test
    fun placing_onFieldMoved_updatesRect_recomputesComplete() {
        val required = listOf(requiredField("a"))
        val start = SigningEditorState.Placing(
            asset,
            listOf(placed("a", hasContent = true)),
            isComplete = true,
        )
        val moved = NormalizedRect(0.5f, 0.5f, 0.7f, 0.6f)
        val next = SigningEditorReducer.onFieldMoved(
            state = start,
            fieldId = "a",
            rect = moved,
            required = required,
        ) as SigningEditorState.Placing
        assertEquals(moved, next.placed.first().rect)
        assertEquals("a", next.activeFieldId)
        assertTrue(next.isComplete)
    }

    @Test
    fun placing_onFieldMoved_unknownField_isNoOp() {
        val start = SigningEditorState.Placing(
            asset,
            listOf(placed("a", hasContent = true)),
            isComplete = true,
        )
        val next = SigningEditorReducer.onFieldMoved(start, "zzz", rect, emptyList())
        assertSame(start, next)
    }

    @Test
    fun placing_onFieldRemoved_dropsField_recomputesComplete() {
        val required = listOf(requiredField("a"))
        val start = SigningEditorState.Placing(
            asset,
            listOf(placed("a", hasContent = true)),
            activeFieldId = "a",
            isComplete = true,
        )
        val next = SigningEditorReducer.onFieldRemoved(start, "a", required) as SigningEditorState.Placing
        assertTrue(next.placed.isEmpty())
        assertEquals(null, next.activeFieldId)
        assertFalse(next.isComplete)
    }

    @Test
    fun placing_onFieldRemoved_unknownField_isNoOp() {
        val start = SigningEditorState.Placing(
            asset,
            listOf(placed("a", hasContent = true)),
            isComplete = true,
        )
        val next = SigningEditorReducer.onFieldRemoved(start, "zzz", emptyList())
        assertSame(start, next)
    }

    @Test
    fun placing_onContinue_goesToReadyToSubmit_whenComplete() {
        val start = SigningEditorState.Placing(
            asset,
            listOf(placed("a", hasContent = true)),
            isComplete = true,
        )
        val next = SigningEditorReducer.onContinue(start) as SigningEditorState.ReadyToSubmit
        assertEquals(asset, next.signature)
        assertEquals(1, next.placed.size)
    }

    @Test
    fun placing_onContinue_isNoOp_whenIncomplete() {
        val start = SigningEditorState.Placing(asset, emptyList(), isComplete = false)
        val next = SigningEditorReducer.onContinue(start)
        assertSame(start, next)
    }

    @Test
    fun readyToSubmit_onBack_goesToPlacing() {
        val start = SigningEditorState.ReadyToSubmit(
            asset,
            listOf(placed("a", hasContent = true)),
        )
        val required = listOf(requiredField("a"))
        val next = SigningEditorReducer.onBack(start, required) as SigningEditorState.Placing
        assertEquals(asset, next.signature)
        assertTrue(next.isComplete)
    }

    // ---- Illegal transitions are no-ops (same instance returned) ----

    @Test
    fun loadOk_fromNonLoading_isNoOp() {
        val capturing = SigningEditorState.Capturing(CaptureMode.DRAW)
        assertSame(capturing, SigningEditorReducer.loadOk(capturing))
    }

    @Test
    fun loadErr_fromNonLoading_isNoOp() {
        val capturing = SigningEditorState.Capturing(CaptureMode.DRAW)
        assertSame(capturing, SigningEditorReducer.loadErr(capturing, ApiError(500, "x")))
    }

    @Test
    fun onSignatureCaptured_fromNonCapturing_isNoOp() {
        val loading = SigningEditorState.Loading
        assertSame(loading, SigningEditorReducer.onSignatureCaptured(loading, asset))
    }

    @Test
    fun onFieldPlaced_fromNonPlacing_isNoOp() {
        val loading = SigningEditorState.Loading
        assertSame(
            loading,
            SigningEditorReducer.onFieldPlaced(loading, placed("a", true), emptyList()),
        )
    }

    @Test
    fun onContinue_fromNonPlacing_isNoOp() {
        val loading = SigningEditorState.Loading
        assertSame(loading, SigningEditorReducer.onContinue(loading))
    }

    @Test
    fun onBack_fromNonReadyToSubmit_isNoOp() {
        val placing = SigningEditorState.Placing(asset, emptyList(), isComplete = false)
        assertSame(placing, SigningEditorReducer.onBack(placing))
    }

    @Test
    fun requiredButNotAssignedToViewer_doesNotBlockCompleteness() {
        // A required field NOT assigned to the viewer must not block completion.
        val required = listOf(
            requiredField("a", assignedToViewer = true),
            requiredField("b", assignedToViewer = false),
        )
        val start = SigningEditorState.Placing(asset, emptyList(), isComplete = false)
        val next = SigningEditorReducer.onFieldPlaced(
            state = start,
            field = placed("a", hasContent = true),
            required = required,
        ) as SigningEditorState.Placing
        assertTrue(next.isComplete)
    }
}
