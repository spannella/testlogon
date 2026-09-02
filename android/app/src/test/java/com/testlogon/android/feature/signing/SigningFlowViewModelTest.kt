package com.testlogon.android.feature.signing

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.NormalizedRect
import com.testlogon.android.feature.signing.capture.model.SignatureAsset
import com.testlogon.android.feature.signing.capture.model.SignatureSource
import com.testlogon.android.feature.signing.capture.model.SignedPacketDraft
import com.testlogon.android.feature.signing.data.SignatureRepository
import com.testlogon.android.feature.signing.editor.SigningEditorState
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.PlacedField
import com.testlogon.android.feature.signing.model.SignaturePacket
import com.testlogon.android.feature.signing.model.SigningEffect
import com.testlogon.android.feature.signing.submit.model.MarkDoneResult
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-344 - unit tests for the orchestrator [SigningFlowViewModel].
 *
 * ANTI-HANG DISCIPLINE: the VM has NO poll loop. Tests use runCurrent() and NEVER advanceUntilIdle;
 * one-shot effects are collected via backgroundScope.launch. The recording fake repo
 * ([RecordingFlowRepo]) has a DISTINCT name from the AND-342 capture fake and records the call BEFORE
 * any throw.
 */
class SigningFlowViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private val asset = SignatureAsset(
        signaturePngPath = "/cache/sig.png",
        initialsPngPath = "/cache/ini.png",
        source = SignatureSource.DRAWN,
        widthPx = 600,
        heightPx = 200,
    )

    private val rect = NormalizedRect(0.1f, 0.1f, 0.4f, 0.2f)

    /** Recording fake (distinct name): records getPacket calls before returning the canned result. */
    private class RecordingFlowRepo(
        var packetResult: ApiResult<SignaturePacket>,
    ) : SignatureRepository {
        val getPacketCalls = mutableListOf<String>()

        override suspend fun getPacket(packetId: String): ApiResult<SignaturePacket> {
            getPacketCalls += packetId
            return packetResult
        }
        override suspend fun getEvents(packetId: String): ApiResult<List<PacketEvent>> =
            ApiResult.Success(emptyList())
        override suspend fun createDraft(
            sourcePath: String,
            originChannel: String,
            originRef: String?,
        ): ApiResult<String> = throw UnsupportedOperationException("not used in flow tests")
        override suspend fun send(packetId: String): ApiResult<Unit> =
            throw UnsupportedOperationException("not used in flow tests")
        override suspend fun fillField(
            packetId: String,
            placement: FieldPlacement,
        ): ApiResult<Unit> = throw UnsupportedOperationException("not used in flow tests")
        override suspend fun flushDraft(draft: SignedPacketDraft): ApiResult<Unit> =
            throw UnsupportedOperationException("not used in flow tests")
        override suspend fun acknowledgeLegalNotice(packetId: String): ApiResult<Unit> =
            throw UnsupportedOperationException("not used in flow tests")
        override suspend fun markDone(packetId: String): ApiResult<MarkDoneResult> =
            throw UnsupportedOperationException("not used in flow tests")

        override suspend fun revokeSigningLink(
            packetId: String,
            signerId: String,
            jti: String,
        ): ApiResult<com.testlogon.android.feature.signing.data.RevokeLinkResult> =
            throw UnsupportedOperationException("not used in flow tests")
    }

    private fun packet(
        role: PacketRole = PacketRole.SIGNER,
        status: PacketStatus = PacketStatus.SENT,
        canFillFields: Boolean = true,
    ) = SignaturePacket(
        packetId = "pkt_1",
        status = status,
        ownerUserId = "owner",
        sourcePath = "/docs/x.pdf",
        role = role,
        capabilities = mapOf(SigningFlowViewModel.CAP_CAN_FILL_FIELDS to canFillFields),
    )

    private fun buildVm(
        repo: RecordingFlowRepo,
        packetId: String? = "pkt_1",
    ): SigningFlowViewModel {
        val handle = SavedStateHandle().apply {
            if (packetId != null) set(SigningFlowViewModel.ARG_PACKET_ID, packetId)
        }
        return SigningFlowViewModel(repo, handle)
    }

    @Test
    fun load_ok_landsOnDocument_derivesCanSignTrue_emitsNavigateToDocument() = runTest {
        val repo = RecordingFlowRepo(ApiResult.Success(packet()))
        val effects = mutableListOf<SigningEffect>()
        val vm = buildVm(repo)
        backgroundScope.launch { vm.effects.collect { effects += it } }
        runCurrent()

        val state = vm.uiState.value
        assertEquals(SigningStep.DOCUMENT, state.step)
        assertTrue(state.canSign)
        assertEquals(null, state.error)
        assertEquals(listOf("pkt_1"), repo.getPacketCalls)
        assertTrue(effects.any { it is SigningEffect.NavigateToDocument })
    }

    @Test
    fun canSign_false_whenNonSigner() = runTest {
        val repo = RecordingFlowRepo(ApiResult.Success(packet(role = PacketRole.SENDER)))
        val vm = buildVm(repo)
        runCurrent()
        assertFalse(vm.uiState.value.canSign)
    }

    @Test
    fun canSign_false_whenTerminal() = runTest {
        val repo = RecordingFlowRepo(
            ApiResult.Success(packet(status = PacketStatus.COMPLETED)),
        )
        val vm = buildVm(repo)
        runCurrent()
        assertFalse(vm.uiState.value.canSign)
    }

    @Test
    fun canSign_false_whenCannotFillFields() = runTest {
        val repo = RecordingFlowRepo(ApiResult.Success(packet(canFillFields = false)))
        val vm = buildVm(repo)
        runCurrent()
        assertFalse(vm.uiState.value.canSign)
    }

    @Test
    fun load_error_landsOnError_emitsShowError() = runTest {
        val error = ApiError(500, "boom")
        val repo = RecordingFlowRepo(ApiResult.Failure(error))
        val effects = mutableListOf<SigningEffect>()
        val vm = buildVm(repo)
        backgroundScope.launch { vm.effects.collect { effects += it } }
        runCurrent()

        val state = vm.uiState.value
        assertEquals(SigningStep.ERROR, state.step)
        assertEquals(error, state.error)
        assertTrue(state.editor is SigningEditorState.Error)
        assertTrue(effects.any { it is SigningEffect.ShowError && it.error == error })
    }

    @Test
    fun continue_whenComplete_emitsNavigateToSubmit_andMovesStep() = runTest {
        val repo = RecordingFlowRepo(ApiResult.Success(packet()))
        val effects = mutableListOf<SigningEffect>()
        val vm = buildVm(repo)
        backgroundScope.launch { vm.effects.collect { effects += it } }
        runCurrent()

        // Drive the editor: begin -> capture -> place a field -> continue.
        vm.beginEditing()
        runCurrent()
        vm.onSignatureCaptured(asset)
        runCurrent()
        vm.onFieldPlaced(
            PlacedField(
                fieldId = "a",
                page = 1,
                rect = rect,
                type = com.testlogon.android.feature.signing.capture.model.FieldType.SIGNATURE,
                hasContent = true,
            ),
        )
        runCurrent()
        // No required-viewer fields in the manifest -> isComplete is true; Continue proceeds.
        vm.onContinue()
        runCurrent()

        assertEquals(SigningStep.SUBMIT, vm.uiState.value.step)
        assertTrue(vm.uiState.value.editor is SigningEditorState.ReadyToSubmit)
        assertTrue(effects.any { it is SigningEffect.NavigateToSubmit })
    }

    @Test
    fun continue_doesNotEmit_whenNotInPlacing() = runTest {
        val repo = RecordingFlowRepo(ApiResult.Success(packet()))
        val effects = mutableListOf<SigningEffect>()
        val vm = buildVm(repo)
        backgroundScope.launch { vm.effects.collect { effects += it } }
        runCurrent()

        // Still on DOCUMENT step (editor Loading) -> onContinue is a no-op.
        vm.onContinue()
        runCurrent()

        assertEquals(SigningStep.DOCUMENT, vm.uiState.value.step)
        assertFalse(effects.any { it is SigningEffect.NavigateToSubmit })
    }

    @Test
    fun missingPacketId_landsOnError() = runTest {
        val repo = RecordingFlowRepo(ApiResult.Success(packet()))
        val vm = buildVm(repo, packetId = null)
        runCurrent()
        assertEquals(SigningStep.ERROR, vm.uiState.value.step)
        assertTrue(repo.getPacketCalls.isEmpty())
    }
}
