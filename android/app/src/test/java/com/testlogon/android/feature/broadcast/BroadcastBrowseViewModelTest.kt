package com.testlogon.android.feature.broadcast

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.BroadcastInput
import com.testlogon.android.data.broadcast.BroadcastPlaybackUrl
import com.testlogon.android.data.broadcast.BroadcastReminderRepository
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.broadcast.BroadcastScheduledPage
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionPage
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import com.testlogon.android.data.broadcast.BroadcastViewerCountApi
import com.testlogon.android.data.broadcast.BroadcastViewerCountRepository
import com.testlogon.android.data.broadcast.ReminderRegistration
import com.testlogon.android.data.broadcast.ViewerCountDto
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

class BroadcastBrowseViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private val now = Instant.parse("2026-06-09T12:00:00Z")
    private val fixedClock = Clock { now.toEpochMilli() }

    private fun upcomingSession(id: String) = BroadcastSession(
        id = id,
        profileId = "p",
        name = "Show $id",
        description = null,
        status = BroadcastSessionStatus.SCHEDULED,
        createdBy = "host",
        scheduledAt = now.plusSeconds(3600),
        scheduleStatus = "scheduled",
        startedAt = null,
        stoppedAt = null,
        cancelledAt = null,
        playbackUrl = null,
        thumbnailUrl = null,
        tipTotalCents = null,
        tipCount = null,
        createdAt = Instant.EPOCH,
        updatedAt = Instant.EPOCH,
    )

    private class FakeBroadcastRepository(
        var result: ApiResult<BroadcastSessionPage>,
    ) : BroadcastRepository {
        override suspend fun sessions(status: String?, limit: Int?) = result
        override suspend fun scheduledSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
            ApiResult.Success(BroadcastScheduledPage(emptyList(), 0))
        override suspend fun upcomingSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
            ApiResult.Success(BroadcastScheduledPage(emptyList(), 0))
        override suspend fun session(sessionId: String): ApiResult<BroadcastSession> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun mintPlaybackUrl(sessionId: String): ApiResult<BroadcastPlaybackUrl> =
            ApiResult.Failure(ApiError(404, "nope"))
        // AND-307 host mutations — unused by browse; stubbed.
        override suspend fun create(profileId: String): ApiResult<BroadcastSession> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun schedule(
            sessionId: String,
            scheduledAtEpochSeconds: Long,
            name: String?,
            description: String?,
        ): ApiResult<BroadcastSession> = ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun cancelSchedule(sessionId: String): ApiResult<BroadcastSession> =
            ApiResult.Failure(ApiError(404, "nope"))
        // AND-308 inputs control plane — unused by browse; stubbed.
        override suspend fun createInput(
            sessionId: String,
            inputType: String,
            label: String?,
        ): ApiResult<BroadcastInput> = ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun activateInput(sessionId: String, inputId: String): ApiResult<Unit> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun deactivateInput(sessionId: String, inputId: String): ApiResult<Unit> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun removeInput(sessionId: String, inputId: String): ApiResult<Unit> =
            ApiResult.Failure(ApiError(404, "nope"))
    }

    private class FakeReminderRepository(
        var setResult: ApiResult<ReminderRegistration> = ApiResult.Success(ReminderRegistration(true, null)),
        var clearResult: ApiResult<Unit> = ApiResult.Success(Unit),
    ) : BroadcastReminderRepository {
        var setCalls = 0
        var clearCalls = 0
        override suspend fun setReminder(sessionId: String): ApiResult<ReminderRegistration> {
            setCalls++
            return setResult
        }
        override suspend fun clearReminder(sessionId: String): ApiResult<Unit> {
            clearCalls++
            return clearResult
        }
    }

    private fun viewerCountRepo() = BroadcastViewerCountRepository(
        api = object : BroadcastViewerCountApi {
            override suspend fun viewerCount(sessionId: String) = ViewerCountDto(sessionId, 0)
        },
        errorParser = com.testlogon.android.core.network.error.ApiErrorParser(com.squareup.moshi.Moshi.Builder().build()),
    )

    private fun viewModel(
        repo: BroadcastRepository,
        reminderRepo: BroadcastReminderRepository = FakeReminderRepository(),
    ) = BroadcastBrowseViewModel(
        repo = repo,
        reminderRepo = reminderRepo,
        viewerCountRepo = viewerCountRepo(),
        savedState = SavedStateHandle(),
        clock = fixedClock,
    )

    @Test
    fun loadsContent_andBucketsUpcoming() = runTest {
        val repo = FakeBroadcastRepository(
            ApiResult.Success(BroadcastSessionPage(listOf(upcomingSession("a")), hasMore = false)),
        )
        val vm = viewModel(repo)
        advanceUntilIdle()

        val state = vm.uiState.value
        assertTrue(state is BroadcastUiState.Content)
        assertEquals(1, (state as BroadcastUiState.Content).upcoming.size)
    }

    @Test
    fun toggleReminder_optimisticThenSuccess_callsOnce() = runTest {
        val repo = FakeBroadcastRepository(
            ApiResult.Success(BroadcastSessionPage(listOf(upcomingSession("a")), hasMore = false)),
        )
        val reminderRepo = FakeReminderRepository()
        val vm = viewModel(repo, reminderRepo)
        advanceUntilIdle()

        vm.toggleReminder("a", enable = true)
        advanceUntilIdle()

        val item = (vm.uiState.value as BroadcastUiState.Content).upcoming.single()
        assertTrue(item.reminderSet)
        assertFalse(item.reminderPending)
        assertEquals(1, reminderRepo.setCalls)
    }

    @Test
    fun toggleReminder_failure_rollsBack_noAutoRetry() = runTest {
        val repo = FakeBroadcastRepository(
            ApiResult.Success(BroadcastSessionPage(listOf(upcomingSession("a")), hasMore = false)),
        )
        val reminderRepo = FakeReminderRepository(setResult = ApiResult.Failure(ApiError(422, "bad")))
        val vm = viewModel(repo, reminderRepo)
        advanceUntilIdle()

        vm.toggleReminder("a", enable = true)
        advanceUntilIdle()

        val item = (vm.uiState.value as BroadcastUiState.Content).upcoming.single()
        assertFalse(item.reminderSet)
        assertFalse(item.reminderPending)
        assertEquals(1, reminderRepo.setCalls) // exactly once; no auto-retry
    }

    @Test
    fun networkError_publishesError() = runTest {
        val repo = FakeBroadcastRepository(ApiResult.NetworkError(java.io.IOException("offline")))
        val vm = viewModel(repo)
        advanceUntilIdle()

        val state = vm.uiState.value
        assertTrue(state is BroadcastUiState.Error)
        assertTrue((state as BroadcastUiState.Error).cause is BroadcastError.Network)
    }
}
