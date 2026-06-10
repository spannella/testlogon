package com.testlogon.android.feature.tracking

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.tracking.Carrier
import com.testlogon.android.data.tracking.CarrierTracking
import com.testlogon.android.data.tracking.Shipment
import com.testlogon.android.data.tracking.ShipmentStatus
import com.testlogon.android.data.tracking.TrackingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-215 / AND-217 — [TrackingViewModel]: Loading -> Ready/NotShipped/Error transitions and the pure
 * [TrackingViewModel.reduce] reducer (404 non-retryable, network -> retryable).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TrackingViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun shipment() = Shipment(
        carrier = Carrier("ups", "UPS"),
        trackingNumber = "1Z999",
        trackingUrl = "https://ups.com",
        status = ShipmentStatus.IN_TRANSIT,
        statusDescription = null,
        estimatedDeliveryEpochMs = null,
        deliveredAtEpochMs = null,
        events = emptyList(),
    )

    private fun vm(repo: TrackingRepository) =
        TrackingViewModel(repo, SavedStateHandle(mapOf(TrackingViewModel.ARG_TXN_ID to "txn_1")))

    @Test
    fun ready_whenShipmentPresent() = runTest {
        val repo = FakeTrackingRepository(ApiResult.Success(CarrierTracking("txn_1", shipment())))
        val model = vm(repo)
        advanceUntilIdle()
        assertTrue(model.state.value is TrackingUiState.Ready)
    }

    @Test
    fun notShipped_whenShipmentNull() = runTest {
        val repo = FakeTrackingRepository(ApiResult.Success(CarrierTracking("txn_1", null)))
        val model = vm(repo)
        advanceUntilIdle()
        assertEquals(TrackingUiState.NotShipped, model.state.value)
    }

    @Test
    fun reduce_404_isNonRetryableError() {
        val state = TrackingViewModel.reduce(
            ApiResult.Failure(ApiError(status = 404, message = "x")),
        )
        assertTrue(state is TrackingUiState.Error)
        assertEquals(false, (state as TrackingUiState.Error).retryable)
    }

    @Test
    fun reduce_networkError_isRetryable() {
        val state = TrackingViewModel.reduce(ApiResult.NetworkError(RuntimeException("io")))
        assertTrue(state is TrackingUiState.Error)
        assertTrue((state as TrackingUiState.Error).retryable)
    }

    @Test
    fun blankTxnId_isNonRetryableError() = runTest {
        val repo = FakeTrackingRepository(ApiResult.Success(CarrierTracking("", null)))
        val model = TrackingViewModel(repo, SavedStateHandle())
        advanceUntilIdle()
        assertTrue(model.state.value is TrackingUiState.Error)
    }
}

private class FakeTrackingRepository(
    private val result: ApiResult<CarrierTracking>,
) : TrackingRepository {
    override suspend fun tracking(txnId: String): ApiResult<CarrierTracking> = result
}
