package com.testlogon.android.feature.calendar.integrations

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.gcal.ConnectStart
import com.testlogon.android.data.gcal.GoogleCalendarRepository
import com.testlogon.android.data.gcal.GoogleCalendarStatus
import com.testlogon.android.data.gcal.ProviderCalendar

/** AND-273 — pure-JVM fake [GoogleCalendarRepository] for ViewModel tests. */
class FakeGoogleCalendarRepository : GoogleCalendarRepository {

    var startResult: ApiResult<ConnectStart> =
        ApiResult.Success(ConnectStart("http://host/auth", "s1", "n1", ""))
    var statusResult: ApiResult<GoogleCalendarStatus> = ApiResult.Success(disconnectedStatus())
    var completeResult: ApiResult<GoogleCalendarStatus> = ApiResult.Success(connectedStatus())
    var calendarsResult: ApiResult<List<ProviderCalendar>> = ApiResult.Success(emptyList())
    var disconnectResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var mappingResult: ApiResult<ProviderCalendar> =
        ApiResult.Success(ProviderCalendar("gcal_1", "G", null, false, "cal_1"))
    var syncResult: ApiResult<Unit> = ApiResult.Success(Unit)

    var cached: GoogleCalendarStatus? = null
    var pendingState: String? = null
    var startCalls = 0
    var clearPendingCalls = 0

    override suspend fun startConnect(): ApiResult<ConnectStart> {
        startCalls++
        return startResult
    }

    override suspend fun completeConnect(code: String, state: String): ApiResult<GoogleCalendarStatus> =
        completeResult

    override suspend fun refreshStatus(): ApiResult<GoogleCalendarStatus> = statusResult

    override suspend fun cachedStatus(): GoogleCalendarStatus? = cached

    override suspend fun pendingOauthState(): String? = pendingState

    override suspend fun clearPendingOauth() { clearPendingCalls++ }

    override suspend fun listProviderCalendars(): ApiResult<List<ProviderCalendar>> = calendarsResult

    override suspend fun createMapping(
        internalCalendarId: String,
        googleCalendarId: String,
    ): ApiResult<ProviderCalendar> = mappingResult

    override suspend fun runSync(mode: String): ApiResult<Unit> = syncResult

    override suspend fun disconnect(connectionId: String?): ApiResult<Unit> = disconnectResult

    companion object {
        fun disconnectedStatus() = GoogleCalendarStatus(
            connectionActive = false, syncEnabled = false, writebackEnabled = false,
            reauthRequired = false, syncHealth = "unknown", lastSyncStatus = "never_synced",
            lastSyncAtUtc = "", rolloutMode = "off", rolloutPercent = 0, inRolloutCohort = false,
            accountEmail = null,
        )

        fun connectedStatus(email: String? = "user@example.com") = GoogleCalendarStatus(
            connectionActive = true, syncEnabled = true, writebackEnabled = false,
            reauthRequired = false, syncHealth = "healthy", lastSyncStatus = "ok",
            lastSyncAtUtc = "", rolloutMode = "all", rolloutPercent = 100, inRolloutCohort = true,
            accountEmail = email,
        )
    }
}
