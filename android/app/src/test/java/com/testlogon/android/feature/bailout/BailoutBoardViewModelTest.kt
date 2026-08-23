package com.testlogon.android.feature.bailout

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bailout.BailoutAck
import com.testlogon.android.data.bailout.BailoutAuction
import com.testlogon.android.data.bailout.BailoutPrefs
import com.testlogon.android.data.bailout.BailoutRepository
import com.testlogon.android.data.bailout.BailoutStatus
import com.testlogon.android.data.bailout.DistressPosition
import com.testlogon.android.data.bailout.PositionSide
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

private fun sampleAuction(id: String) = BailoutAuction(
    auctionId = id,
    symbolId = 1,
    ownerSub = "u1",
    side = PositionSide.LONG,
    qty = 10,
    capitalNeededCents = 100_00,
    maxShareBps = 5_000,
    status = BailoutStatus.OPEN,
    liqPrice = 90_00,
    markPrice = 95_00,
)

private class FakeBailoutRepo(
    var bailoutsResult: ApiResult<List<BailoutAuction>> = ApiResult.Success(emptyList()),
) : BailoutRepository {
    override suspend fun distress(): ApiResult<List<DistressPosition>> = ApiResult.Success(emptyList())
    override suspend fun bailouts(): ApiResult<List<BailoutAuction>> = bailoutsResult
    override suspend fun positionBailout(symbolId: Int): ApiResult<BailoutAuction?> = ApiResult.Success(null)
    override suspend fun prefs(): ApiResult<BailoutPrefs> = ApiResult.Success(BailoutPrefs(false, 0))
    override suspend fun openBailout(symbolId: Int, maxShareBps: Int, closeTs: Long?) =
        ApiResult.Success(sampleAuction("a"))
    override suspend fun placeBid(auctionId: String, capitalCents: Long, shareBps: Int) =
        ApiResult.Success(BailoutAck(true))
    override suspend fun clear(auctionId: String) = ApiResult.Success(sampleAuction(auctionId))
    override suspend fun putPrefs(autoEnabled: Boolean, defaultMaxShareBps: Int) =
        ApiResult.Success(BailoutPrefs(autoEnabled, defaultMaxShareBps))
}

/**
 * ViewModel-level coverage for [BailoutBoardViewModel]: 404 -> honest empty Content (never fabricates
 * distress), happy path with a fake repo returning open auctions, and transport failure -> retryable
 * Error. Complements the pure BailoutMath tests.
 */
class BailoutBoardViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    @Test
    fun degrade_404_toEmptyContent() = runTest(mainRule.dispatcher) {
        // A 404 arrives as Failure; the VM degrades that to an empty Content board (no distress).
        val vm = BailoutBoardViewModel(
            FakeBailoutRepo(bailoutsResult = ApiResult.Failure(ApiError(status = 404, message = "not found"))),
        )
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(BailoutBoardUiState.Phase.Content, s.phase)
        assertTrue(s.auctions.isEmpty())
    }

    @Test
    fun happy_openAuctions_populated() = runTest(mainRule.dispatcher) {
        val vm = BailoutBoardViewModel(
            FakeBailoutRepo(bailoutsResult = ApiResult.Success(listOf(sampleAuction("a1"), sampleAuction("a2")))),
        )
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(BailoutBoardUiState.Phase.Content, s.phase)
        assertEquals(2, s.auctions.size)
        assertNull(s.errorMessage)
    }

    @Test
    fun transportFailure_toRetryableError() = runTest(mainRule.dispatcher) {
        val vm = BailoutBoardViewModel(
            FakeBailoutRepo(bailoutsResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)),
        )
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(BailoutBoardUiState.Phase.Error, s.phase)
        assertTrue(s.errorMessage != null)
    }
}
