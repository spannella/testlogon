package com.testlogon.android.feature.golive

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.webrtc.BroadcastPublisher
import com.testlogon.android.data.webrtc.GoLiveResult
import com.testlogon.android.data.webrtc.PublishState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-288 — GoLiveViewModel permission/availability state transitions and the FLAGGED-engine go-live path.
 * Asserts the default-bound stub publisher resolves go-live to "broadcasting unavailable" and never starts
 * a real publish (state never reaches LIVE).
 */
class GoLiveViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** Mirrors the bound StubBroadcastPublisher: always NotConfigured, never starts. */
    private class StubLikePublisher(
        var result: GoLiveResult = GoLiveResult.NotConfigured,
    ) : BroadcastPublisher {
        var goLiveCalls = 0
        var stopCalls = 0
        private val _state = MutableStateFlow<PublishState>(PublishState.Unavailable)
        override val state: StateFlow<PublishState> = _state
        override suspend fun goLive(sessionId: String, inputId: String): GoLiveResult {
            goLiveCalls++
            return result
        }
        override fun stop() { stopCalls++ }
    }

    private fun viewModel(publisher: BroadcastPublisher = StubLikePublisher()) = GoLiveViewModel(
        savedStateHandle = SavedStateHandle(mapOf("sessionId" to "bcs_1", "inputId" to "in_1")),
        publisher = publisher,
    )

    @Test
    fun clickWithoutPermission_emitsRequestPermissions() = runTest {
        val vm = viewModel()
        val effects = mutableListOf<GoLiveEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.onGoLiveClicked()
        advanceUntilIdle()

        assertTrue(effects.any { it is GoLiveEffect.RequestPermissions })
        job.cancel()
    }

    @Test
    fun grantedPermission_drivesGoLive_toUnavailable_withStub() = runTest {
        val publisher = StubLikePublisher(result = GoLiveResult.NotConfigured)
        val vm = viewModel(publisher)
        val effects = mutableListOf<GoLiveEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.onPermissionResult(cameraGranted = true, micGranted = true, showRationale = false)
        advanceUntilIdle()

        assertEquals(AvPermissionStatus.GRANTED, vm.uiState.value.permission)
        assertEquals(GoLivePublishState.UNAVAILABLE, vm.uiState.value.publish)
        assertTrue(vm.uiState.value.broadcastingUnavailable)
        assertEquals(1, publisher.goLiveCalls)
        assertTrue(
            effects.any { it is GoLiveEffect.Notice && it.kind == GoLiveNotice.BROADCASTING_UNAVAILABLE },
        )
        job.cancel()
    }

    @Test
    fun deniedNotPermanent_setsDenied_noGoLive() = runTest {
        val publisher = StubLikePublisher()
        val vm = viewModel(publisher)

        vm.onPermissionResult(cameraGranted = false, micGranted = true, showRationale = true)
        advanceUntilIdle()

        assertEquals(AvPermissionStatus.DENIED, vm.uiState.value.permission)
        assertEquals(0, publisher.goLiveCalls)
    }

    @Test
    fun permanentlyDenied_clickOpensAppSettings() = runTest {
        val vm = viewModel()
        // First: a denial with no rationale => permanently denied.
        vm.onPermissionResult(cameraGranted = false, micGranted = false, showRationale = false)
        advanceUntilIdle()
        assertEquals(AvPermissionStatus.PERMANENTLY_DENIED, vm.uiState.value.permission)

        val effects = mutableListOf<GoLiveEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        vm.onGoLiveClicked()
        advanceUntilIdle()

        assertTrue(effects.any { it is GoLiveEffect.OpenAppSettings })
        job.cancel()
    }

    @Test
    fun resumeRecheck_promotesToGranted() = runTest {
        val vm = viewModel()
        vm.onPermissionResult(cameraGranted = false, micGranted = false, showRationale = false)
        advanceUntilIdle()
        assertEquals(AvPermissionStatus.PERMANENTLY_DENIED, vm.uiState.value.permission)

        // User toggled permissions in Settings, returned: resume re-check promotes to GRANTED.
        vm.onPermissionStateRefreshed(cameraGranted = true, micGranted = true)
        assertEquals(AvPermissionStatus.GRANTED, vm.uiState.value.permission)
    }

    @Test
    fun grantedPath_neverReachesLive_withStub() = runTest {
        val publisher = StubLikePublisher(result = GoLiveResult.NotConfigured)
        val vm = viewModel(publisher)
        vm.onPermissionResult(cameraGranted = true, micGranted = true, showRationale = false)
        advanceUntilIdle()
        assertFalse(vm.uiState.value.publish == GoLivePublishState.LIVE)
    }
}
