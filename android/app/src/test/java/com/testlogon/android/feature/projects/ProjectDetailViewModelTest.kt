package com.testlogon.android.feature.projects

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.projects.DriveConnection
import com.testlogon.android.core.model.projects.ProviderCallbackParams
import com.testlogon.android.feature.projects.provider.ProjectDriveReturnDispatcher
import com.testlogon.android.feature.projects.testing.FakeProjectsRepo
import com.testlogon.android.feature.projects.ui.detail.ProjectDetailEffect
import com.testlogon.android.feature.projects.ui.detail.ProjectDetailUiState
import com.testlogon.android.feature.projects.ui.detail.ProjectDetailViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-374 - tests for [ProjectDetailViewModel]: Loading -> Content (with Drive-connection read), retry on
 * error, connectGoogleDrive emits a one-shot LaunchAuth + stores the state, a callback with a MISMATCHED state
 * aborts WITHOUT calling completeGoogleDrive, an access_denied return shows a neutral canceled message, and a
 * matching callback flips the screen to Drive-connected. A terminal 401 emits NavigateToLogin.
 *
 * runCurrent (NOT advanceUntilIdle) drains init; effects are collected on backgroundScope so the test never
 * blocks on the channel. No nested runTest.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ProjectDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val dispatcher = ProjectDriveReturnDispatcher()

    private fun vm(
        repo: FakeProjectsRepo,
        savedState: SavedStateHandle = SavedStateHandle(mapOf("projectId" to "p1")),
    ) = ProjectDetailViewModel(repo, savedState, dispatcher)

    @Test
    fun load_success_isContent_withDriveConnectionRead() = runTest {
        val repo = FakeProjectsRepo(
            detailResult = ApiResult.Success(FakeProjectsRepo.sampleProject("p1")),
            driveConnectedResult = ApiResult.Success(DriveConnection(connected = true)),
        )
        val vm = vm(repo)
        runCurrent()

        val state = vm.state.value
        assertTrue(state is ProjectDetailUiState.Content)
        state as ProjectDetailUiState.Content
        assertEquals("p1", state.project.id)
        assertTrue(state.driveConnected)
        assertFalse(state.connecting)
        assertEquals(1, repo.isDriveConnectedCallCount)
    }

    @Test
    fun load_failure_isError_thenRetrySucceeds() = runTest {
        val repo = FakeProjectsRepo(detailResult = FakeProjectsRepo.failure(500))
        val vm = vm(repo)
        runCurrent()
        assertTrue(vm.state.value is ProjectDetailUiState.Error)

        repo.detailResult = ApiResult.Success(FakeProjectsRepo.sampleProject("p1"))
        vm.retry()
        runCurrent()
        assertTrue(vm.state.value is ProjectDetailUiState.Content)
    }

    @Test
    fun load_401_emitsNavigateToLogin() = runTest {
        val repo = FakeProjectsRepo(detailResult = FakeProjectsRepo.failure(401))
        val received = mutableListOf<ProjectDetailEffect>()
        val vm = vm(repo)
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()
        assertTrue(received.any { it is ProjectDetailEffect.NavigateToLogin })
    }

    @Test
    fun connectGoogleDrive_emitsLaunchAuth_andStoresState() = runTest {
        val saved = SavedStateHandle(mapOf("projectId" to "p1"))
        val repo = FakeProjectsRepo()
        val received = mutableListOf<ProjectDetailEffect>()
        val vm = vm(repo, saved)
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()

        vm.connectGoogleDrive()
        runCurrent()

        val launch = received.filterIsInstance<ProjectDetailEffect.LaunchAuth>().single()
        assertEquals("https://auth", launch.url)
        assertEquals("st_1", saved.get<String>("projects_drive_oauth_state"))
        assertEquals(1, repo.startCallCount)
    }

    @Test
    fun callback_stateMismatch_abortsWithoutPosting_showsUnverified() = runTest {
        val saved = SavedStateHandle(mapOf("projectId" to "p1", "projects_drive_oauth_state" to "st_A"))
        val repo = FakeProjectsRepo()
        val received = mutableListOf<ProjectDetailEffect>()
        val vm = vm(repo, saved)
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()

        vm.onProviderCallback(ProviderCallbackParams(code = "c", state = "st_B"))
        runCurrent()

        assertTrue(repo.callbackArgs.isEmpty())
        assertTrue(received.any { it is ProjectDetailEffect.ShowMessage && it.message.contains("verified") })
    }

    @Test
    fun callback_accessDenied_showsCanceled_doesNotPost() = runTest {
        val saved = SavedStateHandle(mapOf("projectId" to "p1", "projects_drive_oauth_state" to "st_A"))
        val repo = FakeProjectsRepo()
        val received = mutableListOf<ProjectDetailEffect>()
        val vm = vm(repo, saved)
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()

        vm.onProviderCallback(ProviderCallbackParams(error = "access_denied"))
        runCurrent()

        assertTrue(repo.callbackArgs.isEmpty())
        assertTrue(received.any { it is ProjectDetailEffect.ShowMessage && it.message.contains("canceled") })
    }

    @Test
    fun callback_matchingState_postsAndFlipsToConnected() = runTest {
        val saved = SavedStateHandle(mapOf("projectId" to "p1", "projects_drive_oauth_state" to "st_1"))
        val repo = FakeProjectsRepo(
            detailResult = ApiResult.Success(FakeProjectsRepo.sampleProject("p1")),
            driveConnectedResult = ApiResult.Success(DriveConnection(connected = false)),
            callbackResult = ApiResult.Success(DriveConnection(connected = true)),
        )
        val vm = vm(repo, saved)
        runCurrent()
        // start as not-connected Content
        assertTrue((vm.state.value as ProjectDetailUiState.Content).driveConnected.not())

        vm.onProviderCallback(ProviderCallbackParams(code = "c", state = "st_1"))
        runCurrent()

        val params = repo.callbackArgs.single()
        assertEquals("c", params.code)
        assertEquals("st_1", params.state)
        val state = vm.state.value as ProjectDetailUiState.Content
        assertTrue(state.driveConnected)
        assertFalse(state.connecting)
    }

    @Test
    fun callback_viaDispatcher_forMatchingProjectId_isHandled() = runTest {
        val saved = SavedStateHandle(mapOf("projectId" to "p1", "projects_drive_oauth_state" to "st_1"))
        val repo = FakeProjectsRepo(callbackResult = ApiResult.Success(DriveConnection(connected = true)))
        val vm = vm(repo, saved)
        runCurrent()

        dispatcher.emit(
            com.testlogon.android.feature.projects.provider.ProjectDriveReturn(
                projectId = "p1", code = "c", state = "st_1", error = null, cancelled = false,
            ),
        )
        runCurrent()

        assertEquals(1, repo.callbackArgs.size)
    }
}
