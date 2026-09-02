package com.testlogon.android.feature.signing

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.signing.data.SignatureRepository
import com.testlogon.android.feature.signing.model.PacketAction
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.PacketField
import com.testlogon.android.feature.signing.model.PacketSigner
import com.testlogon.android.feature.signing.model.SignaturePacket
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-340 - unit tests for [PacketDetailViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop (manual refresh only). Tests use runCurrent() and NEVER
 * advanceUntilIdle. packetId is sourced from the SavedStateHandle nav arg. One-shot events are collected
 * via backgroundScope.launch. The fake repo's test-data builder ([packet]) does NOT share a name with the
 * repo overrides (no shadowing). No nested runTest.
 */
class PacketDetailViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private class StubRepo(
        var packetResult: ApiResult<SignaturePacket>,
        var eventsResult: ApiResult<List<PacketEvent>> = ApiResult.Success(emptyList()),
        var sendResult: ApiResult<Unit> = ApiResult.Success(Unit),
    ) : SignatureRepository {
        var sendCount = 0

        override suspend fun getPacket(packetId: String): ApiResult<SignaturePacket> = packetResult
        override suspend fun getEvents(packetId: String): ApiResult<List<PacketEvent>> = eventsResult
        override suspend fun createDraft(
            sourcePath: String,
            originChannel: String,
            originRef: String?,
        ): ApiResult<String> = throw UnsupportedOperationException("not used in detail tests")

        override suspend fun send(packetId: String): ApiResult<Unit> {
            sendCount++
            return sendResult
        }

        // AND-343 additions (unused by the detail tests; defaulted to keep AND-340 tests passing).
        override suspend fun fillField(
            packetId: String,
            placement: com.testlogon.android.feature.signing.capture.model.FieldPlacement,
        ): ApiResult<Unit> = throw UnsupportedOperationException("not used in detail tests")

        override suspend fun flushDraft(
            draft: com.testlogon.android.feature.signing.capture.model.SignedPacketDraft,
        ): ApiResult<Unit> = throw UnsupportedOperationException("not used in detail tests")

        override suspend fun acknowledgeLegalNotice(packetId: String): ApiResult<Unit> =
            throw UnsupportedOperationException("not used in detail tests")

        override suspend fun markDone(
            packetId: String,
        ): ApiResult<com.testlogon.android.feature.signing.submit.model.MarkDoneResult> =
            throw UnsupportedOperationException("not used in detail tests")

        override suspend fun revokeSigningLink(
            packetId: String,
            signerId: String,
            jti: String,
        ): ApiResult<com.testlogon.android.feature.signing.data.RevokeLinkResult> =
            throw UnsupportedOperationException("not used in detail tests")
    }

    private fun vm(repo: StubRepo, packetId: String? = "pkt_1"): PacketDetailViewModel {
        val handle = SavedStateHandle().apply {
            if (packetId != null) set(PacketDetailViewModel.ARG_PACKET_ID, packetId)
        }
        return PacketDetailViewModel(repo, handle)
    }

    @Test
    fun load_landsOnContent_withPacketAndEvents() = runTest {
        val repo = StubRepo(
            packetResult = ApiResult.Success(packet()),
            eventsResult = ApiResult.Success(listOf(event("ev_1"))),
        )
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as PacketDetailUiState.Content
        assertEquals("pkt_1", state.packet.packetId)
        assertEquals(1, state.events.size)
        assertFalse(state.isStale)
    }

    @Test
    fun blankPacketId_landsOnNonRetryableError() = runTest {
        val repo = StubRepo(packetResult = ApiResult.Success(packet()))
        val viewModel = vm(repo, packetId = null)
        runCurrent()

        val state = viewModel.uiState.value as PacketDetailUiState.Error
        assertFalse(state.retryable)
    }

    @Test
    fun loadFailure_withNoPriorContent_landsOnError() = runTest {
        val repo = StubRepo(packetResult = ApiResult.Failure(ApiError(404, "missing")))
        val viewModel = vm(repo)
        runCurrent()

        assertTrue(viewModel.uiState.value is PacketDetailUiState.Error)
    }

    @Test
    fun refreshFailure_withPriorContent_keepsContentStale() = runTest {
        val repo = StubRepo(packetResult = ApiResult.Success(packet()))
        val viewModel = vm(repo)
        runCurrent()
        assertTrue(viewModel.uiState.value is PacketDetailUiState.Content)

        repo.packetResult = ApiResult.Failure(ApiError(422, "bad"))
        viewModel.refresh()
        runCurrent()

        val state = viewModel.uiState.value as PacketDetailUiState.Content
        assertTrue(state.isStale)
        assertEquals("pkt_1", state.packet.packetId)
    }

    @Test
    fun primaryAction_draftSender_callsSend_andEmitsPacketSent() = runTest {
        val repo = StubRepo(
            packetResult = ApiResult.Success(
                packet(status = PacketStatus.DRAFT, role = PacketRole.SENDER),
            ),
        )
        val viewModel = vm(repo)
        runCurrent()

        val events = mutableListOf<PacketDetailEvent>()
        backgroundScope.launch { viewModel.events.collect { events += it } }

        viewModel.onPrimaryAction()
        runCurrent()

        assertEquals(1, repo.sendCount)
        assertTrue(events.any { it is PacketDetailEvent.PacketSent })
    }

    @Test
    fun primaryAction_assignedSigner_emitsNavigateToSign_withoutSend() = runTest {
        val repo = StubRepo(
            packetResult = ApiResult.Success(
                packet(
                    status = PacketStatus.SENT,
                    role = PacketRole.SIGNER,
                    fields = listOf(field(isAssignedToViewer = true)),
                ),
            ),
        )
        val viewModel = vm(repo)
        runCurrent()

        val events = mutableListOf<PacketDetailEvent>()
        backgroundScope.launch { viewModel.events.collect { events += it } }

        viewModel.onPrimaryAction()
        runCurrent()

        assertEquals(0, repo.sendCount)
        assertEquals(
            PacketDetailEvent.NavigateToSign("pkt_1"),
            events.single(),
        )
    }

    @Test
    fun sendFailure_emitsActionFailed_andClearsInFlight() = runTest {
        val repo = StubRepo(
            packetResult = ApiResult.Success(
                packet(status = PacketStatus.DRAFT, role = PacketRole.SENDER),
            ),
            sendResult = ApiResult.Failure(ApiError(500, "nope")),
        )
        val viewModel = vm(repo)
        runCurrent()

        val events = mutableListOf<PacketDetailEvent>()
        backgroundScope.launch { viewModel.events.collect { events += it } }

        viewModel.onPrimaryAction()
        runCurrent()

        assertTrue(events.any { it is PacketDetailEvent.ActionFailed })
        val state = viewModel.uiState.value as PacketDetailUiState.Content
        assertFalse(state.actionInFlight)
    }

    @Test
    fun action_isNone_forTerminalCompletedPacket() = runTest {
        val repo = StubRepo(
            packetResult = ApiResult.Success(
                packet(status = PacketStatus.COMPLETED, role = PacketRole.SENDER),
            ),
        )
        val viewModel = vm(repo)
        runCurrent()

        val state = viewModel.uiState.value as PacketDetailUiState.Content
        assertEquals(PacketAction.NONE, state.action)
    }

    // ---- fake test-data builders (distinct names; never shadow a repo override) ----

    private companion object {
        fun packet(
            status: PacketStatus = PacketStatus.SENT,
            role: PacketRole = PacketRole.SENDER,
            signers: List<PacketSigner> = listOf(PacketSigner("sgn_1", "pending")),
            fields: List<PacketField> = emptyList(),
        ) = SignaturePacket(
            packetId = "pkt_1",
            status = status,
            ownerUserId = "usr_owner",
            sourcePath = "files/doc.pdf",
            role = role,
            signers = signers,
            fields = fields,
        )

        fun field(isAssignedToViewer: Boolean) = PacketField(
            fieldId = "fld_1",
            fieldType = SignatureFieldType.SIGNATURE,
            page = 0,
            x = 1f,
            y = 2f,
            width = 3f,
            height = 4f,
            required = true,
            isAssignedToViewer = isAssignedToViewer,
        )

        fun event(id: String) = PacketEvent(
            eventId = id,
            eventType = "created",
            actorUserId = "usr_1",
            createdAt = Instant.parse("2026-06-01T10:00:00Z"),
        )
    }
}
