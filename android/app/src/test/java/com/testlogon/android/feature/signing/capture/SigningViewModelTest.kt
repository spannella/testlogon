package com.testlogon.android.feature.signing.capture

import androidx.compose.ui.geometry.Offset
import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.signing.capture.model.SignatureAsset
import com.testlogon.android.feature.signing.capture.model.SignatureSource
import com.testlogon.android.feature.signing.data.SignatureRepository
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.PacketField
import com.testlogon.android.feature.signing.model.SignaturePacket
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.File
import java.time.LocalDate

/**
 * AND-342 - unit tests for [SigningViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop (capture is event-driven). Tests use runCurrent() and
 * NEVER advanceUntilIdle; one-shot events are collected via backgroundScope.launch. packetId/documentId
 * come from the SavedStateHandle nav arg.
 *
 * RASTERIZER SEAM: the real [AndroidSignatureRasterizer] uses android.graphics (Bitmap/Canvas/Paint/
 * Typeface), which is android-only and NOT on the JVM classpath, so this test injects a FAKE
 * [SignatureRasterizer] that returns a stub File - the pure geometry/draft math is JVM-tested separately
 * in [SignatureCaptureDomainTest]. The asset store is a simple in-memory fake. Fake-helper names are
 * distinct from the production seams.
 */
class SigningViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class StubSigningRepo(
        var packetResult: ApiResult<SignaturePacket>,
    ) : SignatureRepository {
        override suspend fun getPacket(packetId: String): ApiResult<SignaturePacket> = packetResult
        override suspend fun getEvents(packetId: String): ApiResult<List<PacketEvent>> =
            ApiResult.Success(emptyList())
        override suspend fun createDraft(
            sourcePath: String,
            originChannel: String,
            originRef: String?,
        ): ApiResult<String> = throw UnsupportedOperationException("not used in capture tests")
        override suspend fun send(packetId: String): ApiResult<Unit> =
            throw UnsupportedOperationException("not used in capture tests")

        // AND-343 additions (unused by the capture tests; defaulted to keep AND-342 tests passing).
        override suspend fun fillField(
            packetId: String,
            placement: com.testlogon.android.feature.signing.capture.model.FieldPlacement,
        ): ApiResult<Unit> = throw UnsupportedOperationException("not used in capture tests")

        override suspend fun flushDraft(
            draft: com.testlogon.android.feature.signing.capture.model.SignedPacketDraft,
        ): ApiResult<Unit> = throw UnsupportedOperationException("not used in capture tests")

        override suspend fun acknowledgeLegalNotice(packetId: String): ApiResult<Unit> =
            throw UnsupportedOperationException("not used in capture tests")

        override suspend fun markDone(
            packetId: String,
        ): ApiResult<com.testlogon.android.feature.signing.submit.model.MarkDoneResult> =
            throw UnsupportedOperationException("not used in capture tests")
    }

    private class FakeRasterizer : SignatureRasterizer {
        var strokeCalls = 0
        var typedCalls = 0
        override suspend fun rasterizeStrokes(
            strokes: List<List<Offset>>,
            widthPx: Int,
            heightPx: Int,
        ): File {
            strokeCalls++
            return File("build/tmp/sig-$strokeCalls.png")
        }

        override suspend fun rasterizeTyped(
            text: String,
            fontStyleIndex: Int,
            widthPx: Int,
            heightPx: Int,
        ): File {
            typedCalls++
            return File("build/tmp/typed-$typedCalls.png")
        }
    }

    private class InMemoryAssetStore(private var stored: SignatureAsset? = null) : SignatureAssetStore {
        var saveCount = 0
        override suspend fun save(asset: SignatureAsset) {
            saveCount++
            stored = asset
        }
        override suspend fun load(): SignatureAsset? = stored
        override suspend fun clear() {
            stored = null
        }
    }

    private fun signatureField(id: String, required: Boolean = true) = PacketField(
        fieldId = id,
        fieldType = SignatureFieldType.SIGNATURE,
        page = 1,
        x = 0.1f,
        y = 0.1f,
        width = 0.3f,
        height = 0.05f,
        required = required,
        isAssignedToViewer = true,
    )

    private fun dateField(id: String, required: Boolean = true) = PacketField(
        fieldId = id,
        fieldType = SignatureFieldType.DATE,
        page = 1,
        x = 0.5f,
        y = 0.5f,
        width = 0.2f,
        height = 0.04f,
        required = required,
        isAssignedToViewer = true,
    )

    private fun otherUserField(id: String) = PacketField(
        fieldId = id,
        fieldType = SignatureFieldType.SIGNATURE,
        page = 1,
        x = 0.1f,
        y = 0.6f,
        width = 0.3f,
        height = 0.05f,
        required = true,
        isAssignedToViewer = false,
    )

    private fun packetWith(fields: List<PacketField>) = SignaturePacket(
        packetId = "pkt_1",
        status = PacketStatus.SENT,
        ownerUserId = "owner",
        sourcePath = "/docs/x.pdf",
        role = PacketRole.SIGNER,
        fields = fields,
    )

    private fun buildVm(
        repo: StubSigningRepo,
        store: SignatureAssetStore = InMemoryAssetStore(),
        rasterizer: SignatureRasterizer = FakeRasterizer(),
        packetId: String? = "pkt_1",
        documentId: String? = "doc_1",
    ): SigningViewModel {
        val handle = SavedStateHandle().apply {
            if (packetId != null) set(SigningViewModel.ARG_PACKET_ID, packetId)
            if (documentId != null) set(SigningViewModel.ARG_DOCUMENT_ID, documentId)
        }
        return SigningViewModel(repo, store, rasterizer, handle).apply {
            today = { LocalDate.of(2026, 6, 9) }
        }
    }

    @Test
    fun load_mapsOnlyViewerFields() = runTest {
        val repo = StubSigningRepo(
            ApiResult.Success(
                packetWith(listOf(signatureField("a"), otherUserField("b"))),
            ),
        )
        val vm = buildVm(repo)
        runCurrent()

        val state = vm.uiState.value as SigningUiState.Editing
        assertEquals(1, state.fields.size)
        assertEquals("a", state.fields.first().id)
        assertEquals(1, state.requiredTotal)
        assertEquals(0, state.requiredDone)
    }

    @Test
    fun load_failure_landsOnRetryableError() = runTest {
        val repo = StubSigningRepo(ApiResult.Failure(ApiError(500, "boom")))
        val vm = buildVm(repo)
        runCurrent()

        val state = vm.uiState.value as SigningUiState.Error
        assertTrue(state.retryable)
    }

    @Test
    fun captureStrokes_setsAsset_andPersists() = runTest {
        val store = InMemoryAssetStore()
        val raster = FakeRasterizer()
        val repo = StubSigningRepo(ApiResult.Success(packetWith(listOf(signatureField("a")))))
        val vm = buildVm(repo, store, raster)
        runCurrent()

        vm.onStrokesConfirmed(listOf(listOf(Offset(0f, 0f), Offset(10f, 10f))))
        runCurrent()

        val state = vm.uiState.value as SigningUiState.Editing
        assertNotNull(state.asset)
        assertEquals(SignatureSource.DRAWN, state.asset?.source)
        // One stroke call for the signature PNG + one for the initials PNG.
        assertEquals(2, raster.strokeCalls)
        assertEquals(1, store.saveCount)
    }

    @Test
    fun placeSignatureField_stamps_andIncrementsProgress() = runTest {
        val repo = StubSigningRepo(ApiResult.Success(packetWith(listOf(signatureField("a")))))
        val vm = buildVm(repo)
        runCurrent()
        vm.onStrokesConfirmed(listOf(listOf(Offset(0f, 0f), Offset(5f, 5f))))
        runCurrent()

        vm.placeField("a")
        runCurrent()

        val state = vm.uiState.value as SigningUiState.Editing
        assertEquals(1, state.requiredDone)
        assertTrue(state.isComplete)
        assertNotNull(state.placements["a"]?.assetPath)
        assertTrue(state.placements["a"]?.satisfied == true)
    }

    @Test
    fun placeSignatureField_withoutAsset_isNoOp() = runTest {
        val repo = StubSigningRepo(ApiResult.Success(packetWith(listOf(signatureField("a")))))
        val vm = buildVm(repo)
        runCurrent()

        vm.placeField("a")
        runCurrent()

        val state = vm.uiState.value as SigningUiState.Editing
        assertNull(state.placements["a"])
        assertEquals(0, state.requiredDone)
    }

    @Test
    fun placeDateField_autoFillsTodayAsYyyyMmDd() = runTest {
        val repo = StubSigningRepo(ApiResult.Success(packetWith(listOf(dateField("d")))))
        val vm = buildVm(repo)
        runCurrent()

        vm.placeField("d")
        runCurrent()

        val state = vm.uiState.value as SigningUiState.Editing
        assertEquals("2026-06-09", state.placements["d"]?.textValue)
        assertTrue(state.placements["d"]?.satisfied == true)
        assertTrue(state.isComplete)
    }

    @Test
    fun clearField_unsatisfies_andDecrementsProgress() = runTest {
        val repo = StubSigningRepo(ApiResult.Success(packetWith(listOf(dateField("d")))))
        val vm = buildVm(repo)
        runCurrent()
        vm.placeField("d")
        runCurrent()

        vm.clearField("d")
        runCurrent()

        val state = vm.uiState.value as SigningUiState.Editing
        assertNull(state.placements["d"])
        assertEquals(0, state.requiredDone)
        assertFalse(state.isComplete)
    }

    @Test
    fun useSaved_adoptsSavedAsset() = runTest {
        val saved = SignatureAsset(
            signaturePngPath = "/cache/sig.png",
            initialsPngPath = "/cache/ini.png",
            source = SignatureSource.SAVED,
            widthPx = 600,
            heightPx = 200,
        )
        val repo = StubSigningRepo(ApiResult.Success(packetWith(listOf(signatureField("a")))))
        val vm = buildVm(repo, store = InMemoryAssetStore(saved))
        runCurrent()

        vm.onUseSaved()
        runCurrent()

        val state = vm.uiState.value as SigningUiState.Editing
        assertEquals(SignatureSource.SAVED, state.asset?.source)
        assertEquals("/cache/sig.png", state.asset?.signaturePngPath)
    }

    @Test
    fun continue_emitsDraft_whenComplete() = runTest {
        val repo = StubSigningRepo(ApiResult.Success(packetWith(listOf(dateField("d")))))
        val vm = buildVm(repo)
        runCurrent()

        var emitted: SigningEvent.ContinueToSubmit? = null
        backgroundScope.launch {
            vm.events.collect { if (it is SigningEvent.ContinueToSubmit) emitted = it }
        }

        vm.placeField("d")
        runCurrent()
        vm.onContinue()
        runCurrent()

        assertNotNull(emitted)
        val draft = emitted!!.draft
        assertEquals("pkt_1", draft.packetId)
        assertEquals("doc_1", draft.documentId)
        assertTrue(draft.isComplete(listOf()))
        assertEquals(1, draft.placements.size)
    }

    @Test
    fun continue_doesNotEmit_whenIncomplete() = runTest {
        val repo = StubSigningRepo(ApiResult.Success(packetWith(listOf(signatureField("a")))))
        val vm = buildVm(repo)
        runCurrent()

        var emitted = false
        backgroundScope.launch {
            vm.events.collect { emitted = true }
        }

        vm.onContinue()
        runCurrent()

        assertFalse(emitted)
    }

    @Test
    fun buildDraft_carriesAllSatisfiedPlacements() = runTest {
        val repo = StubSigningRepo(
            ApiResult.Success(packetWith(listOf(signatureField("a"), dateField("d")))),
        )
        val vm = buildVm(repo)
        runCurrent()
        vm.onStrokesConfirmed(listOf(listOf(Offset(0f, 0f), Offset(1f, 1f))))
        runCurrent()
        vm.placeField("a")
        vm.placeField("d")
        runCurrent()

        val draft = vm.buildDraft()
        assertEquals(2, draft.placements.size)
        assertTrue(draft.placements.all { it.satisfied })
        assertNotNull(draft.asset)
    }
}
