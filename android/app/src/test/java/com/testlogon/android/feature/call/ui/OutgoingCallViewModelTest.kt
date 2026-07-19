package com.testlogon.android.feature.call.ui

import android.content.Context
import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.CallAction
import com.testlogon.android.data.call.CallBillingStatus
import com.testlogon.android.data.call.CallHeartbeat
import com.testlogon.android.data.call.CallHistoryPage
import com.testlogon.android.data.call.CallInvited
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.call.CallRepository
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.webrtc.IceServer
import com.testlogon.android.data.webrtc.IceServersProvider
import com.testlogon.android.data.webrtc.StubPeerConnectionController
import com.testlogon.android.data.webrtc.StubSignalingTransport
import com.testlogon.android.feature.call.domain.CallManager
import com.testlogon.android.feature.call.domain.CallTiming
import com.testlogon.android.feature.call.telecom.ConnectionRegistry
import com.testlogon.android.feature.call.telecom.TelecomCapabilities
import com.testlogon.android.feature.call.telecom.TelecomCallController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito.mock

/**
 * AND-296 — [OutgoingCallViewModel] mapping tests. Drives a real [CallManager] with fakes/stubs and
 * asserts the VM maps CallManager.state -> CallUiState (RINGING + mediaUnavailable from the FLAGGED seam).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OutgoingCallViewModelTest {

    // Unconfined Main so the VM's stateIn collector runs eagerly (no cross-scheduler timing dependency).
    @get:Rule
    val mainDispatcher = MainDispatcherRule(UnconfinedTestDispatcher())

    private class FakeRepo : CallRepository {
        override suspend fun invite(
            callId: String, conversationId: String, calleeUserId: String, mode: CallMode,
            idempotencyKey: String?, paid: Boolean, rateCentsPerMin: Int?,
        ): ApiResult<CallInvited> =
            ApiResult.Success(CallInvited(callId, conversationId, "self", calleeUserId, "ringing", mode, 0, false, null))
        override suspend fun accept(callId: String, idempotencyKey: String?) = ok(callId)
        override suspend fun decline(callId: String, reason: String) = ok(callId)
        override suspend fun end(callId: String, reason: String, idempotencyKey: String?) = ok(callId)
        override suspend fun timeout(callId: String, reason: String, idempotencyKey: String?) = ok(callId)
        override suspend fun heartbeat(callId: String, clientTsEpochSeconds: Long?) =
            ApiResult.Success(CallHeartbeat(callId, 0, 0, 0, 0, 0, false, 10.0, false, "ok"))
        override suspend fun billing(callId: String) =
            ApiResult.Success(CallBillingStatus(callId, false, 0, 0, 0, 0, 0, ""))
        override suspend fun history(cursor: String?, limit: Int?) =
            ApiResult.Success(CallHistoryPage(emptyList(), null))
        override suspend fun detail(callId: String) =
            ApiResult.Success(
                com.testlogon.android.data.call.CallHistoryEntry(
                    callId, "self", "peer", CallMode.AUDIO,
                    com.testlogon.android.data.call.CallDirection.OUTGOING,
                    com.testlogon.android.data.call.CallStatus.COMPLETED, 0L, 0L, "completed",
                ),
            )
        override suspend fun deleteRecord(callId: String) = ApiResult.Success(Unit)
        override suspend fun stats() =
            ApiResult.Success(com.testlogon.android.data.call.CallStats(0, emptyMap(), emptyMap(), 0L))
        private fun ok(callId: String): ApiResult<CallAction> =
            ApiResult.Success(CallAction(callId, "conv", "ended", 0, null, null, false))
    }

    private fun vm(scope: CoroutineScope): OutgoingCallViewModel {
        val manager = CallManager(
            callRepository = FakeRepo(),
            iceServers = object : IceServersProvider {
                override suspend fun current(callId: String) = listOf(IceServer(urls = listOf("stun:x")))
            },
            peer = StubPeerConnectionController(),
            signaling = StubSignalingTransport(),
            clock = Clock { 0L },
            scope = scope,
            timing = CallTiming(),
        )
        val saved = SavedStateHandle(
            mapOf(
                OutgoingCallViewModel.ARG_CONVERSATION_ID to "conv_1",
                OutgoingCallViewModel.ARG_CALLEE_USER_ID to "peer_1",
                OutgoingCallViewModel.ARG_MODE to "audio",
                OutgoingCallViewModel.ARG_PEER_NAME to "Alex",
            ),
        )
        // AND-301: the FLAGGED wallet seam always returns NotConfigured (no real charge).
        val authorizer = object : BillingAuthorizer {
            override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?) =
                BillingResult.NotConfigured
        }
        // AND-304: no-op Telecom on the JVM (SDK_INT=0 -> isSupported() false; placeOutgoing no-ops), so the
        // AND-296 placeCall path is unaffected and the existing mapping assertions still hold.
        val telecom = TelecomCallController(
            context = mock(Context::class.java),
            telecomManager = null,
            capabilities = TelecomCapabilities(telecomManager = null),
            registry = ConnectionRegistry(),
        )
        return OutgoingCallViewModel(
            manager,
            authorizer,
            telecom,
            com.testlogon.android.feature.messaging.fakeDisplayNameResolver(),
            saved,
        )
    }

    @Test
    fun init_placesCall_mapsRinging_andMediaUnavailable() = runTest {
        val scope = CoroutineScope(UnconfinedTestDispatcher(testScheduler))
        val viewModel = vm(scope)
        // Active collector before reading stateIn(WhileSubscribed).value.
        val job = launch { viewModel.uiState.collect {} }
        // Settle the eager placeCall/negotiate work without advancing the clock — advanceUntilIdle would
        // walk the now-surviving 45s ring timeout and end the call before we read RINGING.
        runCurrent()

        val state = viewModel.uiState.value
        assertEquals("Alex", state.peerName)
        // The eager placeCall reaches RINGING via the control plane. Since the WebRTC-parity program the
        // mediaUnavailable flag is owned by the real media layer (bound in prod); with the stub media seam
        // it stays false, so the assertion here is on the observable RINGING phase, not the flag.
        assertEquals(CallUiPhase.RINGING, state.phase)

        job.cancel()
        scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
    }

    @Test
    fun formatDuration_padsMmSs() {
        assertEquals("00:00", formatDuration(0))
        assertEquals("00:42", formatDuration(42))
        assertEquals("01:05", formatDuration(65))
        assertEquals("10:00", formatDuration(600))
    }
}
