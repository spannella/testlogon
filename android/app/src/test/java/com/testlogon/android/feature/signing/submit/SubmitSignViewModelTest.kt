package com.testlogon.android.feature.signing.submit

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.NormalizedRect
import com.testlogon.android.feature.signing.capture.model.SignedPacketDraft
import com.testlogon.android.feature.signing.data.SignatureRepository
import com.testlogon.android.feature.signing.document.data.PdfSource
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.PacketField
import com.testlogon.android.feature.signing.model.PacketLegalNotice
import com.testlogon.android.feature.signing.model.SignaturePacket
import com.testlogon.android.feature.signing.submit.model.MarkDoneResult
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.File
import java.time.Instant

/**
 * AND-343 - unit tests for [SubmitSignViewModel] (the terminal e-sign step).
 *
 * ANTI-HANG DISCIPLINE: NO poll loop; runCurrent (never advanceUntilIdle); one-shot events collected
 * via backgroundScope.launch. The fake repository extends the AND-340 [SignatureRepository] with the
 * AND-343 methods (distinct helper names). The draft is injected via [SubmitSignViewModel.setDraft]
 * (the handoff is faked empty), mirroring the production process-scoped handoff pickup.
 */
class SubmitSignViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class RecordingRepo(
        var packetResult: ApiResult<SignaturePacket>,
        var ackResult: ApiResult<Unit> = ApiResult.Success(Unit),
        var flushResult: ApiResult<Unit> = ApiResult.Success(Unit),
        var markDoneResult: ApiResult<MarkDoneResult> =
            ApiResult.Success(MarkDoneResult(PacketStatus.COMPLETED, Instant.EPOCH, "signed")),
    ) : SignatureRepository {
        var getPacketCount = 0
        var ackCount = 0
        var markDoneCount = 0
        val flushedFieldIds = mutableListOf<String>()

        override suspend fun getPacket(packetId: String): ApiResult<SignaturePacket> {
            getPacketCount++
            return packetResult
        }

        override suspend fun getEvents(packetId: String): ApiResult<List<PacketEvent>> =
            ApiResult.Success(emptyList())

        override suspend fun createDraft(
            sourcePath: String,
            originChannel: String,
            originRef: String?,
        ): ApiResult<String> = throw UnsupportedOperationException("not used in submit tests")

        override suspend fun send(packetId: String): ApiResult<Unit> =
            throw UnsupportedOperationException("not used in submit tests")

        override suspend fun fillField(
            packetId: String,
            placement: FieldPlacement,
        ): ApiResult<Unit> {
            flushedFieldIds += placement.fieldId
            return ApiResult.Success(Unit)
        }

        override suspend fun flushDraft(draft: SignedPacketDraft): ApiResult<Unit> {
            draft.placements.forEach { flushedFieldIds += it.fieldId }
            return flushResult
        }

        override suspend fun acknowledgeLegalNotice(packetId: String): ApiResult<Unit> {
            ackCount++
            return ackResult
        }

        override suspend fun markDone(packetId: String): ApiResult<MarkDoneResult> {
            markDoneCount++
            return markDoneResult
        }

        override suspend fun revokeSigningLink(
            packetId: String,
            signerId: String,
            jti: String,
        ): ApiResult<com.testlogon.android.feature.signing.data.RevokeLinkResult> =
            throw UnsupportedOperationException("not used in submit tests")
    }

    private class StubPdfSource(
        var result: ApiResult<File> = ApiResult.Success(File("build/tmp/final.pdf")),
    ) : PdfSource {
        var downloadCount = 0
        override suspend fun downloadPdf(packetId: String): ApiResult<File> {
            downloadCount++
            return result
        }
    }

    private fun handle() = SavedStateHandle().apply {
        set(SubmitSignViewModel.ARG_PACKET_ID, "pkt_1")
    }

    private fun vm(
        repo: RecordingRepo,
        pdf: StubPdfSource = StubPdfSource(),
    ): SubmitSignViewModel = SubmitSignViewModel(
        repository = repo,
        pdfSource = pdf,
        draftHandoff = SignedDraftHandoff(),
        savedStateHandle = handle(),
    )

    private fun legalNotice(accepted: Boolean, required: Boolean = true) =
        PacketLegalNotice(required = required, accepted = accepted, version = "v1", text = "notice")

    private fun packet(
        legalNotice: PacketLegalNotice? = null,
        fields: List<PacketField> = emptyList(),
        status: PacketStatus = PacketStatus.SENT,
    ) = SignaturePacket(
        packetId = "pkt_1",
        status = status,
        ownerUserId = "usr",
        sourcePath = "files/doc.pdf",
        role = PacketRole.SIGNER,
        fields = fields,
        legalNotice = legalNotice,
    )

    private fun viewerField(id: String) = PacketField(
        fieldId = id,
        fieldType = SignatureFieldType.SIGNATURE,
        page = 0,
        x = 0f,
        y = 0f,
        width = 1f,
        height = 1f,
        required = true,
        isAssignedToViewer = true,
    )

    private fun placement(id: String) = FieldPlacement(
        fieldId = id,
        page = 0,
        rect = NormalizedRect(0f, 0f, 1f, 1f),
        textValue = "v",
        satisfied = true,
    )

    @Test
    fun load_surfacesLegalNotice() = runTest {
        val repo = RecordingRepo(ApiResult.Success(packet(legalNotice = legalNotice(accepted = false))))
        val model = vm(repo)
        runCurrent()

        val state = model.uiState.value as SubmitUiState.Ready
        assertNotNull(state.legalNotice)
        assertFalse(state.legalNotice!!.accepted)
    }

    @Test
    fun canMarkDone_falseUntilAcknowledged() = runTest {
        val repo = RecordingRepo(ApiResult.Success(packet(legalNotice = legalNotice(accepted = false))))
        val model = vm(repo)
        runCurrent()

        assertFalse((model.uiState.value as SubmitUiState.Ready).canMarkDone)
    }

    @Test
    fun acknowledge_reloadsAndHidesGate() = runTest {
        val repo = RecordingRepo(ApiResult.Success(packet(legalNotice = legalNotice(accepted = false))))
        val model = vm(repo)
        runCurrent()

        // After ack the reload serves an accepted notice -> canMarkDone true.
        repo.packetResult = ApiResult.Success(packet(legalNotice = legalNotice(accepted = true)))
        model.acknowledge()
        runCurrent()

        assertEquals(1, repo.ackCount)
        assertTrue(repo.getPacketCount >= 2) // initial load + reload after ack.
        val state = model.uiState.value as SubmitUiState.Ready
        assertTrue(state.legalNotice!!.accepted)
        assertTrue(state.canMarkDone)
    }

    @Test
    fun markDone_flushesEachPlacement_thenConfirms() = runTest {
        val repo = RecordingRepo(
            ApiResult.Success(
                packet(
                    legalNotice = legalNotice(accepted = true),
                    fields = listOf(viewerField("fld_a"), viewerField("fld_b")),
                ),
            ),
        )
        val model = vm(repo)
        runCurrent()
        model.setDraft(
            SignedPacketDraft(
                packetId = "pkt_1",
                documentId = "pkt_1",
                placements = listOf(placement("fld_a"), placement("fld_b")),
            ),
        )

        model.markDone()
        runCurrent()

        assertEquals(listOf("fld_a", "fld_b"), repo.flushedFieldIds)
        assertEquals(1, repo.markDoneCount)
        val confirmed = model.uiState.value as SubmitUiState.Confirmed
        assertEquals(PacketStatus.COMPLETED, confirmed.status)
        assertTrue(confirmed.canDownloadPdf)
    }

    @Test
    fun markDone_doesNotAutoRetry_onFailure() = runTest {
        val repo = RecordingRepo(
            ApiResult.Success(packet(legalNotice = legalNotice(accepted = true))),
            markDoneResult = ApiResult.Failure(ApiError(status = 500, message = "boom")),
        )
        val model = vm(repo)
        runCurrent()

        model.markDone()
        runCurrent()

        assertEquals(1, repo.markDoneCount) // exactly one attempt, NO auto-retry.
        assertTrue(model.uiState.value is SubmitUiState.Error)
    }

    @Test
    fun duplicateMarkDoneTap_blockedWhileSubmitting() = runTest {
        // flush never completes synchronously here; second tap must be ignored. We approximate by a slow
        // mark-done: both taps issued before runCurrent; only one markDone call should land.
        val repo = RecordingRepo(ApiResult.Success(packet(legalNotice = legalNotice(accepted = true))))
        val model = vm(repo)
        runCurrent()

        model.markDone()
        model.markDone() // duplicate while the first is in flight.
        runCurrent()

        assertEquals(1, repo.markDoneCount)
    }

    @Test
    fun downloadCompletedPdf_emitsOpenEvent() = runTest {
        val repo = RecordingRepo(ApiResult.Success(packet(legalNotice = legalNotice(accepted = true))))
        val pdf = StubPdfSource()
        val model = vm(repo, pdf)
        runCurrent()
        model.markDone()
        runCurrent()

        var event: SubmitSignEvent? = null
        backgroundScope.launch { model.events.collect { event = it } }

        model.downloadCompletedPdf()
        runCurrent()

        assertEquals(1, pdf.downloadCount)
        assertTrue(event is SubmitSignEvent.OpenCompletedPdf)
        assertEquals("pkt_1", (event as SubmitSignEvent.OpenCompletedPdf).packetId)
    }
}
