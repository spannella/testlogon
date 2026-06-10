package com.testlogon.android.feature.subscriptions

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.fanclub.FanClubTier
import com.testlogon.android.data.subscriptions.SubscriptionState
import com.testlogon.android.data.subscriptions.TestSubscriptionsRepository
import com.testlogon.android.data.subscriptions.sampleSubscription
import com.testlogon.android.feature.fanclub.FakeFanClubRepository
import com.testlogon.android.feature.subscriptions.entitlement.EntitlementResolver
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

/**
 * AND-241 / AND-242 — [MySubscriptionsViewModel] (the consolidated overview) transitions: load -> Content
 * with subscriptions + derived fan-club memberships; empty; full failure -> Error; fan-club read failure
 * is non-fatal; refresh failure keeps content + isStale (stale-while-revalidate); retry recovers.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class MySubscriptionsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun tier(id: String, level: Int, planId: String?) = FanClubTier(
        id = id, planId = planId, name = id, level = level, color = null, badgeEmoji = null,
        badgeImageUrl = null, description = null, memberCount = 5, sortOrder = level, active = true,
    )

    private fun vm(subs: TestSubscriptionsRepository, fan: FakeFanClubRepository) =
        MySubscriptionsViewModel(
            subscriptionsRepository = subs,
            fanClubRepository = fan,
            entitlements = EntitlementResolver(),
        )

    @Test
    fun load_success_rendersSubscriptions_andDerivedFanClubs() = runTest {
        val subs = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription(planId = "plan_basic")))
        }
        val fan = FakeFanClubRepository(
            tiersResult = ApiResult.Success(
                listOf(tier("t_gold", 2, "plan_basic"), tier("t_plat", 3, "plan_other")),
            ),
        )
        val model = vm(subs, fan)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()

        val state = model.uiState.value
        assertFalse(state.isLoading)
        assertEquals(1, state.subscriptions.size)
        // Only the tier whose plan the viewer actively holds is a "my fan club".
        assertEquals(listOf("t_gold"), state.fanClubs.map { it.tierId })
        job.cancel()
    }

    @Test
    fun load_empty_isEmptyState() = runTest {
        val subs = TestSubscriptionsRepository().apply { mySubsResult = ApiResult.Success(emptyList()) }
        val fan = FakeFanClubRepository(tiersResult = ApiResult.Success(emptyList()))
        val model = vm(subs, fan)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(model.uiState.value.isEmpty)
        job.cancel()
    }

    @Test
    fun load_subsFailure_noCache_setsError() = runTest {
        val subs = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val fan = FakeFanClubRepository()
        val model = vm(subs, fan)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertEquals("boom", model.uiState.value.error)
        assertTrue(model.uiState.value.subscriptions.isEmpty())
        job.cancel()
    }

    @Test
    fun load_fanClubFailure_isNonFatal_rendersSubscriptions() = runTest {
        val subs = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription(planId = "plan_basic")))
        }
        val fan = FakeFanClubRepository(tiersResult = FakeFanClubRepository.failure(status = 503))
        val model = vm(subs, fan)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        val state = model.uiState.value
        assertEquals(1, state.subscriptions.size)
        assertTrue(state.fanClubs.isEmpty())
        assertNull(state.error)
        job.cancel()
    }

    @Test
    fun refreshFailure_withContent_keepsContent_marksStale() = runTest {
        val subs = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription(planId = "plan_basic")))
        }
        val fan = FakeFanClubRepository(tiersResult = ApiResult.Success(emptyList()))
        val model = vm(subs, fan)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertEquals(1, model.uiState.value.subscriptions.size)

        subs.mySubsResult = ApiResult.NetworkError(IOException("offline"))
        model.refresh()
        advanceUntilIdle()

        val state = model.uiState.value
        assertTrue(state.isStale)
        assertEquals(1, state.subscriptions.size) // last-good content retained
        assertNull(state.error)
        job.cancel()
    }

    @Test
    fun retry_afterError_recovers() = runTest {
        val subs = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val fan = FakeFanClubRepository(tiersResult = ApiResult.Success(emptyList()))
        val model = vm(subs, fan)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertEquals("boom", model.uiState.value.error)

        subs.mySubsResult = ApiResult.Success(listOf(sampleSubscription(planId = "plan_basic")))
        model.retry()
        advanceUntilIdle()

        assertNull(model.uiState.value.error)
        assertEquals(1, model.uiState.value.subscriptions.size)
        job.cancel()
    }

    @Test
    fun lapsedSubscription_isShown_butNotAFanClub() = runTest {
        val subs = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(
                listOf(sampleSubscription(planId = "plan_basic", status = SubscriptionState.CANCELED)),
            )
        }
        val fan = FakeFanClubRepository(
            tiersResult = ApiResult.Success(listOf(tier("t_gold", 2, "plan_basic"))),
        )
        val model = vm(subs, fan)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        val state = model.uiState.value
        assertEquals(1, state.subscriptions.size)
        assertTrue(state.fanClubs.isEmpty()) // lapsed -> not an active membership
        job.cancel()
    }
}
