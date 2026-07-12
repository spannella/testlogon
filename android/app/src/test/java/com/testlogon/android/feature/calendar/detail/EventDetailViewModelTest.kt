package com.testlogon.android.feature.calendar.detail

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.calendar.CalendarZoneProvider
import com.testlogon.android.feature.calendar.FakeCalendarRepository
import com.testlogon.android.data.calendar.ics.Rfc5545IcsSerializer
import android.content.Context
import org.mockito.Mockito.mock
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class EventDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeCalendarRepository()
    private val zone = object : CalendarZoneProvider() {
        override fun deviceZoneId(): String = "UTC"
        override fun overrideZoneId(): String? = null
    }
    private val host = object : PublicEventHostProvider {
        override fun host(): String = "app.testlogon.example.com"
    }
    // exportIcs() is not exercised here; a mock Context satisfies the (unused) file-write seam.
    private val icsExporter = IcsExporter(mock(Context::class.java))
    private val icsSerializer = Rfc5545IcsSerializer()

    private fun vm(
        calendarId: String = "cal_55",
        eventId: String = "evt_1",
        isPublic: String = "false",
    ) = EventDetailViewModel(
        repository = repo,
        zoneProvider = zone,
        shareHostProvider = host,
        icsExporter = icsExporter,
        icsSerializer = icsSerializer,
        savedStateHandle = SavedStateHandle(
            mapOf(
                EventDetailViewModel.ARG_CALENDAR_ID to calendarId,
                EventDetailViewModel.ARG_EVENT_ID to eventId,
                EventDetailViewModel.ARG_IS_PUBLIC to isPublic,
            ),
        ),
    )

    @Test
    fun loadsAuthenticatedEvent_buildsShareUrl() = runTest {
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is EventDetailUiState.Content)
        val content = state as EventDetailUiState.Content
        assertEquals("evt_1", content.event.eventId)
        assertEquals(
            "https://app.testlogon.example.com/event/cal_55/evt_1",
            content.publicShareUrl,
        )
        // AND-391 — the public iCal download URL is built eagerly on the published host.
        assertEquals(
            "https://app.testlogon.example.com/event/cal_55/evt_1/ical",
            content.publicIcalUrl,
        )
        assertEquals(1, repo.eventCalls)
    }

    @Test
    fun blankArgs_resolveUnavailable_noNetworkCall() = runTest {
        val vm = vm(calendarId = "", eventId = "")
        advanceUntilIdle()
        assertEquals(EventDetailUiState.Unavailable, vm.state.value)
        assertEquals(0, repo.eventCalls)
        assertEquals(0, repo.publicEventCalls)
    }

    @Test
    fun publicArg_usesPublicEndpoint() = runTest {
        val vm = vm(isPublic = "true")
        advanceUntilIdle()
        assertTrue(vm.state.value is EventDetailUiState.Content)
        assertEquals(1, repo.publicEventCalls)
        assertEquals(0, repo.eventCalls)
    }

    @Test
    fun authed404_fallsBackToPublic() = runTest {
        repo.eventResult = ApiResult.Failure(ApiError(status = 404, message = "x"))
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is EventDetailUiState.Content)
        assertEquals(1, repo.eventCalls)
        assertEquals(1, repo.publicEventCalls)
        assertTrue((vm.state.value as EventDetailUiState.Content).isPublic)
    }

    @Test
    fun error404_whenPublicAlsoFails_mapsToUnavailable() = runTest {
        repo.eventResult = ApiResult.Failure(ApiError(status = 404, message = "x"))
        repo.publicEventResult = ApiResult.Failure(ApiError(status = 404, message = "x"))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(EventDetailUiState.Unavailable, vm.state.value)
    }

    @Test
    fun forbidden403_mapsToForbidden() = runTest {
        repo.eventResult = ApiResult.Failure(ApiError(status = 403, message = "x"))
        repo.publicEventResult = ApiResult.Failure(ApiError(status = 403, message = "x"))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(EventDetailUiState.Forbidden, vm.state.value)
    }

    @Test
    fun validation422_mapsToUnavailableForDisplay() = runTest {
        repo.eventResult = ApiResult.Failure(ApiError(status = 422, message = "x"))
        val vm = vm()
        advanceUntilIdle()
        assertEquals(EventDetailUiState.Unavailable, vm.state.value)
    }

    @Test
    fun networkError_mapsToOfflineError_thenRetrySucceeds() = runTest {
        repo.eventResult = ApiResult.NetworkError(IOException("offline"))
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is EventDetailUiState.Error)
        assertTrue((state as EventDetailUiState.Error).offline)

        repo.eventResult = ApiResult.Success(FakeCalendarRepository.sampleEvent("evt_1"))
        vm.retry()
        advanceUntilIdle()
        assertTrue(vm.state.value is EventDetailUiState.Content)
    }

    @Test
    fun serverError_5xx_mapsToError() = runTest {
        repo.eventResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        repo.publicEventResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is EventDetailUiState.Error)
        assertEquals("boom", (state as EventDetailUiState.Error).message)
    }
}
