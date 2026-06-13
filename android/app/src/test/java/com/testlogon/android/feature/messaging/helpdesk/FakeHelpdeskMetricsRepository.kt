package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.helpdesk.CachedMetrics
import com.testlogon.android.data.messaging.helpdesk.HelpdeskDashboardData
import com.testlogon.android.data.messaging.helpdesk.HelpdeskMetricsRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.IOException

/** AND-377 — in-memory fake for HelpdeskDashboardViewModel tests. */
class FakeHelpdeskMetricsRepository : HelpdeskMetricsRepository {

    var refreshResult: ApiResult<HelpdeskDashboardData> = ApiResult.NetworkError(IOException("default"))

    /** Backing cache the VM consults on a failed refresh (FR-6 stale fallback). */
    val cache = MutableStateFlow<CachedMetrics?>(null)

    var refreshCalls = 0

    override fun cachedMetrics(): StateFlow<CachedMetrics?> = cache

    override suspend fun refreshMetrics(): ApiResult<HelpdeskDashboardData> {
        refreshCalls++
        return refreshResult
    }
}
