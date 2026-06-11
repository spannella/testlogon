package com.testlogon.android.feature.referrals

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.referrals.ReferralCode
import com.testlogon.android.data.referrals.ReferralDashboard
import com.testlogon.android.data.referrals.ReferralStats
import com.testlogon.android.data.referrals.ReferralsRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ReferralsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun stats() = ReferralStats(12, 5, 7, 3000, 1000, 2000, 1500)

    private fun sampleReferral(code: String = "AB12CD34", active: Boolean = true) = ReferralCode(
        code = code,
        active = active,
        commissionTier = "standard",
        referralCount = 5,
        createdAt = "2026-05-01",
    )

    private fun dashboard(codes: List<ReferralCode>) = ReferralDashboard(stats = stats(), codes = codes)

    private class FakeRepo : ReferralsRepository {
        var result: ApiResult<ReferralDashboard> = ApiResult.Failure(ApiError(500, "x"))
        var createResult: ApiResult<ReferralCode> = ApiResult.Failure(ApiError(500, "x"))
        var cacheValue: ReferralDashboard? = null
        var loadCount = 0
        override suspend fun loadDashboard(): ApiResult<ReferralDashboard> {
            loadCount++
            return result
        }
        override suspend fun createCode(): ApiResult<ReferralCode> = createResult
        override fun cached(): ReferralDashboard? = cacheValue
        override fun clear() {}
    }

    @Test
    fun load_success_withCodes_movesToContent() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard(listOf(sampleReferral()))) }
        val vm = ReferralsViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(ReferralsUiState.Phase.Content, s.phase)
        assertEquals(1, s.dashboard?.codes?.size)
    }

    @Test
    fun load_emptyCodes_movesToIneligible() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Success(dashboard(emptyList())) }
        val vm = ReferralsViewModel(repo)
        advanceUntilIdle()
        assertEquals(ReferralsUiState.Phase.Ineligible, vm.uiState.value.phase)
    }

    @Test
    fun load_401_movesToSessionExpired() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.Failure(ApiError(401, "unauthorized")) }
        val vm = ReferralsViewModel(repo)
        advanceUntilIdle()
        assertEquals(ReferralsUiState.Phase.SessionExpired, vm.uiState.value.phase)
    }

    @Test
    fun load_networkError_noCache_movesToOffline() = runTest {
        val repo = FakeRepo().apply { result = ApiResult.NetworkError(java.io.IOException(), isTimeout = false) }
        val vm = ReferralsViewModel(repo)
        advanceUntilIdle()
        assertEquals(ReferralsUiState.Phase.Offline, vm.uiState.value.phase)
    }

    @Test
    fun load_failure_withCache_showsStaleContent() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Failure(ApiError(500, "boom"))
            cacheValue = dashboard(listOf(sampleReferral()))
        }
        val vm = ReferralsViewModel(repo)
        advanceUntilIdle()
        val s = vm.uiState.value
        assertEquals(ReferralsUiState.Phase.Content, s.phase)
        assertTrue(s.isStale)
    }

    @Test
    fun onCopyClicked_emitsCopyLinkEffect_withFirstActiveCodeLink() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(dashboard(listOf(sampleReferral(active = false, code = "OLD"), sampleReferral(code = "NEW"))))
        }
        val vm = ReferralsViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<ReferralsEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onCopyClicked()
        advanceUntilIdle()
        job.cancel()

        val copy = effects.filterIsInstance<ReferralsEffect.CopyLink>().single()
        assertEquals("https://app.testlogon.com/?ref=NEW", copy.link)
    }

    @Test
    fun onCreateCode_success_reloadsDashboard() = runTest {
        val repo = FakeRepo().apply {
            result = ApiResult.Success(dashboard(emptyList()))
            createResult = ApiResult.Success(sampleReferral(code = "GEN1"))
        }
        val vm = ReferralsViewModel(repo)
        advanceUntilIdle()
        val before = repo.loadCount
        vm.onCreateCode()
        advanceUntilIdle()
        assertTrue("expected a reload after create", repo.loadCount > before)
    }
}
