package com.testlogon.android.data.push

import androidx.work.ListenableWorker
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.IOException

/**
 * AND-110 — the push worker's result mapping (pure, no Robolectric/Hilt needed):
 * success/no-op -> success, network/5xx -> retry, 4xx/unauthenticated -> failure.
 */
class PushRegistrationWorkerTest {

    @Test
    fun success_maps_to_success() {
        assertEquals(
            ListenableWorker.Result.success(),
            PushRegistrationWorker.resultFor(ApiResult.Success(Unit)),
        )
    }

    @Test
    fun network_error_maps_to_retry() {
        assertEquals(
            ListenableWorker.Result.retry(),
            PushRegistrationWorker.resultFor(ApiResult.NetworkError(IOException("x"))),
        )
    }

    @Test
    fun server_5xx_maps_to_retry() {
        assertEquals(
            ListenableWorker.Result.retry(),
            PushRegistrationWorker.resultFor(ApiResult.Failure(ApiError(503, "down"))),
        )
    }

    @Test
    fun client_4xx_maps_to_failure() {
        assertEquals(
            ListenableWorker.Result.failure(),
            PushRegistrationWorker.resultFor(ApiResult.Failure(ApiError(401, "unauth"))),
        )
    }
}
