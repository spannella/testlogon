package com.testlogon.android.feature.broadcast.host

import androidx.lifecycle.SavedStateHandle
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.BroadcastPlaybackUrl
import com.testlogon.android.data.broadcast.BroadcastRepository
import com.testlogon.android.data.broadcast.BroadcastScheduledPage
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionPage
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/** AND-307 — unit tests for [CreateBroadcastViewModel] (create + schedule + cancel + 422 mapping). */
class CreateBroadcastViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    private fun session(
        id: String = "bcs_1",
        status: BroadcastSessionStatus = BroadcastSessionStatus.DRAFT,
        scheduleStatus: String? = null,
        scheduledAt: Instant? = null,
    ) = BroadcastSession(
        id = id,
        profileId = "prof_9",
        name = "Show",
        description = null,
        status = status,
        createdBy = "host",
        scheduledAt = scheduledAt,
        scheduleStatus = scheduleStatus,
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

    private class FakeRepo(
        var createResult: ApiResult<BroadcastSession>,
        var scheduleResult: ApiResult<BroadcastSession>,
        var cancelResult: ApiResult<BroadcastSession>,
    ) : BroadcastRepository {
        var createCalls = 0
        var scheduleCalls = 0
        var cancelCalls = 0
        var lastScheduledAt: Long? = null
        var lastScheduleName: String? = null

        override suspend fun sessions(status: String?, limit: Int?) =
            ApiResult.Success(BroadcastSessionPage(emptyList(), false))
        override suspend fun scheduledSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
            ApiResult.Success(BroadcastScheduledPage(emptyList(), 0))
        override suspend fun upcomingSessions(limit: Int?): ApiResult<BroadcastScheduledPage> =
            ApiResult.Success(BroadcastScheduledPage(emptyList(), 0))
        override suspend fun session(sessionId: String): ApiResult<BroadcastSession> =
            ApiResult.Failure(ApiError(404, "nope"))
        override suspend fun mintPlaybackUrl(sessionId: String): ApiResult<BroadcastPlaybackUrl> =
            ApiResult.Failure(ApiError(404, "nope"))

        override suspend fun create(profileId: String): ApiResult<BroadcastSession> {
            createCalls++
            return createResult
        }
        override suspend fun schedule(
            sessionId: String,
            scheduledAtEpochSeconds: Long,
            name: String?,
            description: String?,
        ): ApiResult<BroadcastSession> {
            scheduleCalls++
            lastScheduledAt = scheduledAtEpochSeconds
            lastScheduleName = name
            return scheduleResult
        }
        override suspend fun cancelSchedule(sessionId: String): ApiResult<BroadcastSession> {
            cancelCalls++
            return cancelResult
        }
    }

    private fun vm(
        repo: BroadcastRepository,
        profileId: String? = "prof_9",
    ): CreateBroadcastViewModel {
        val saved = SavedStateHandle(
            if (profileId != null) mapOf(CreateBroadcastViewModel.ARG_PROFILE_ID to profileId) else emptyMap(),
        )
        return CreateBroadcastViewModel(repo, errorParser, saved)
    }

    @Test
    fun create_now_setsCreatedSession_noSchedule() = runTest {
        val repo = FakeRepo(
            createResult = ApiResult.Success(session(id = "bcs_1")),
            scheduleResult = ApiResult.Failure(ApiError(500, "x")),
            cancelResult = ApiResult.Failure(ApiError(500, "x")),
        )
        val vm = vm(repo)
        vm.setTitle("My show")
        vm.create()
        runCurrent()

        assertEquals(1, repo.createCalls)
        assertEquals(0, repo.scheduleCalls)
        assertEquals("bcs_1", vm.uiState.value.createdSession?.id)
        assertFalse(vm.uiState.value.isSubmitting)
    }

    @Test
    fun create_scheduleLater_createsThenSchedulesWithEpoch() = runTest {
        val repo = FakeRepo(
            createResult = ApiResult.Success(session(id = "bcs_1")),
            scheduleResult = ApiResult.Success(
                session(id = "bcs_1", status = BroadcastSessionStatus.SCHEDULED, scheduleStatus = "scheduled"),
            ),
            cancelResult = ApiResult.Failure(ApiError(500, "x")),
        )
        val vm = vm(repo)
        vm.setTitle("My show")
        vm.toggleScheduleLater(true)
        vm.setScheduledAt(1749319200L)
        vm.create()
        runCurrent()

        assertEquals(1, repo.createCalls)
        assertEquals(1, repo.scheduleCalls)
        assertEquals(1749319200L, repo.lastScheduledAt)
        assertEquals("My show", repo.lastScheduleName)
        assertTrue(vm.uiState.value.canCancelSchedule)
    }

    @Test
    fun blankTitle_gatesSubmit() = runTest {
        val repo = FakeRepo(
            createResult = ApiResult.Success(session()),
            scheduleResult = ApiResult.Success(session()),
            cancelResult = ApiResult.Success(session()),
        )
        val vm = vm(repo)
        assertFalse(vm.uiState.value.canSubmit)
        vm.create()
        runCurrent()
        assertEquals(0, repo.createCalls)
    }

    @Test
    fun schedule_422_scheduledAtLoc_mapsToFieldError() = runTest {
        val repo = FakeRepo(
            createResult = ApiResult.Success(session(id = "bcs_1")),
            scheduleResult = ApiResult.Failure(
                ApiError(
                    status = 422,
                    message = "invalid",
                    raw = """{"detail":[{"loc":["body","scheduled_at"],"msg":"past","type":"value_error"}]}""",
                ),
            ),
            cancelResult = ApiResult.Failure(ApiError(500, "x")),
        )
        val vm = vm(repo)
        vm.setTitle("My show")
        vm.toggleScheduleLater(true)
        vm.setScheduledAt(1L)
        vm.create()
        runCurrent()

        assertEquals(1, repo.scheduleCalls)
        assertTrue(vm.uiState.value.fieldErrors.containsKey(CreateBroadcastViewModel.FIELD_SCHEDULED_AT))
        assertNull(vm.uiState.value.error)
        // The draft survives so cancel/retry stays coherent.
        assertEquals("bcs_1", vm.uiState.value.createdSession?.id)
    }

    @Test
    fun cancelSchedule_callsRepo_andFinishes() = runTest {
        val scheduled = session(
            id = "bcs_1",
            status = BroadcastSessionStatus.SCHEDULED,
            scheduleStatus = "scheduled",
            scheduledAt = Instant.ofEpochSecond(1749319200L),
        )
        val repo = FakeRepo(
            createResult = ApiResult.Success(scheduled),
            scheduleResult = ApiResult.Success(scheduled),
            cancelResult = ApiResult.Success(
                session(id = "bcs_1", status = BroadcastSessionStatus.CANCELLED, scheduleStatus = "cancelled"),
            ),
        )
        val vm = vm(repo)
        // Seed a scheduled session via create + schedule-later.
        vm.setTitle("My show")
        vm.toggleScheduleLater(true)
        vm.setScheduledAt(1749319200L)
        vm.create()
        runCurrent()
        assertTrue(vm.uiState.value.canCancelSchedule)

        vm.cancelSchedule()
        runCurrent()
        assertEquals(1, repo.cancelCalls)
        assertEquals(BroadcastSessionStatus.CANCELLED, vm.uiState.value.createdSession?.status)
    }

    @Test
    fun create_noProfile_surfacesError_noCall() = runTest {
        val repo = FakeRepo(
            createResult = ApiResult.Success(session()),
            scheduleResult = ApiResult.Success(session()),
            cancelResult = ApiResult.Success(session()),
        )
        val vm = vm(repo, profileId = null)
        vm.setTitle("My show")
        vm.create()
        runCurrent()
        assertEquals(0, repo.createCalls)
        assertEquals("No broadcast profile is available.", vm.uiState.value.error)
    }
}
