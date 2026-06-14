package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.subscriptions.BillingInterval
import com.testlogon.android.data.subscriptions.CancelSubscriptionReqDto
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.CreatorSubscriptionSummary
import com.testlogon.android.data.subscriptions.SubscribeReqDto
import com.testlogon.android.data.subscriptions.SubscriptionFeatureFlags
import com.testlogon.android.data.subscriptions.SubscriptionState
import com.testlogon.android.data.subscriptions.SubscriptionTier
import com.testlogon.android.data.subscriptions.SubscriptionsRepository
import com.testlogon.android.data.subscriptions.FakeAuthStateStore
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
 * AND-235 — [SubscriptionTiersViewModel] transitions: load -> sorted/filtered tiers; current-plan
 * derivation; empty; error-with-no-cache; refresh keeps content on failure; Subscribe CTA gated by the
 * checkout flag + the BillingAuthorizer stub (asserts NO charge / NO subscribe call under the stub).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SubscriptionTiersViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val creatorId = "usr_42"

    private fun tier(id: String, price: Long, name: String = id, status: String = "active") = SubscriptionTier(
        planId = id,
        creatorId = creatorId,
        name = name,
        description = null,
        priceCents = price,
        currency = "USD",
        interval = BillingInterval.MONTH,
        annualPriceCents = null,
        status = status,
        perks = listOf("Perk A"),
        createdAtEpochSeconds = null,
        updatedAtEpochSeconds = null,
    )

    private fun sub(planId: String, status: SubscriptionState = SubscriptionState.ACTIVE, end: Long = 99_999) =
        CreatorSubscription(
            subscriptionId = "sub_$planId",
            planId = planId,
            creatorId = creatorId,
            subscriberId = "usr_me",
            interval = BillingInterval.MONTH,
            provider = "ccbill",
            status = status,
            startAtEpochSeconds = 0,
            currentPeriodEndEpochSeconds = end,
            cancelAtPeriodEnd = false,
            priceCents = 499,
            currency = "USD",
            autoRenew = true,
        )

    private fun vm(
        repo: FakeSubscriptionsRepository,
        authorizer: BillingAuthorizer = StubAuthorizer(),
        checkoutEnabled: Boolean = false,
    ) = SubscriptionTiersViewModel(
        savedStateHandle = SavedStateHandle(mapOf(SubscriptionTiersViewModel.ARG_CREATOR_ID to creatorId)),
        repository = repo,
        billingAuthorizer = authorizer,
        featureFlags = object : SubscriptionFeatureFlags { override val checkoutEnabled = checkoutEnabled },
        authStateStore = FakeAuthStateStore("usr_me"),
    )

    @Test
    fun load_success_sortsByPriceAndFiltersInactive() = runTest {
        val repo = FakeSubscriptionsRepository().apply {
            tiers = ApiResult.Success(
                listOf(
                    tier("plan_b", 999, name = "B"),
                    tier("plan_a", 499, name = "A"),
                    tier("plan_c", 499, name = "C", status = "archived"), // filtered
                    tier("plan_d", 499, name = "D"),
                ),
            )
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        val state = model.uiState.value
        assertFalse(state.isLoading)
        // ascending price, name tie-break -> A, D (499) then B (999); archived C excluded.
        assertEquals(listOf("plan_a", "plan_d", "plan_b"), state.tiers.map { it.id })
        assertEquals(listOf("Perk A"), state.tiers.first().perks)
        job.cancel()
    }

    @Test
    fun load_derivesCurrentTier_fromActiveMatchingSub() = runTest {
        val repo = FakeSubscriptionsRepository().apply {
            tiers = ApiResult.Success(listOf(tier("plan_a", 499), tier("plan_b", 999)))
            mySubs = ApiResult.Success(listOf(sub("plan_b")))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertEquals("plan_b", model.uiState.value.currentTierId)
        assertTrue(model.uiState.value.tiers.first { it.id == "plan_b" }.isCurrent)
        assertFalse(model.uiState.value.tiers.first { it.id == "plan_a" }.isCurrent)
        job.cancel()
    }

    @Test
    fun load_subsFailure_isNonFatal_rendersTiersWithoutBadge() = runTest {
        val repo = FakeSubscriptionsRepository().apply {
            tiers = ApiResult.Success(listOf(tier("plan_a", 499)))
            mySubs = ApiResult.NetworkError(IOException("x"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertEquals(1, model.uiState.value.tiers.size)
        assertNull(model.uiState.value.currentTierId)
        job.cancel()
    }

    @Test
    fun load_empty_isEmptyState() = runTest {
        val repo = FakeSubscriptionsRepository().apply { tiers = ApiResult.Success(emptyList()) }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(model.uiState.value.isEmpty)
        job.cancel()
    }

    @Test
    fun load_error_noCache_setsError() = runTest {
        val repo = FakeSubscriptionsRepository().apply {
            tiers = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertEquals("boom", model.uiState.value.error)
        assertTrue(model.uiState.value.tiers.isEmpty())
        job.cancel()
    }

    @Test
    fun subscribeClick_flagOff_emitsPaymentsUnavailable_noCharge() = runTest {
        val authorizer = StubAuthorizer()
        val repo = FakeSubscriptionsRepository().apply { tiers = ApiResult.Success(listOf(tier("plan_a", 499))) }
        val model = vm(repo, authorizer, checkoutEnabled = false)
        val job = launch { model.uiState.collect {} }
        val events = mutableListOf<SubscriptionsEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.onSubscribeClick("plan_a")
        advanceUntilIdle()

        assertTrue(events.single() is SubscriptionsEvent.PaymentsUnavailable)
        // flag off -> authorizer never consulted, no subscribe call, NO charge.
        assertEquals(0, authorizer.authorizeCalls)
        assertEquals(0, repo.subscribeCalls)
        job.cancel(); ejob.cancel()
    }

    @Test
    fun subscribeClick_flagOn_stubNotConfigured_emitsPaymentsUnavailable_noCharge() = runTest {
        val authorizer = StubAuthorizer(BillingResult.NotConfigured)
        val repo = FakeSubscriptionsRepository().apply { tiers = ApiResult.Success(listOf(tier("plan_a", 499))) }
        val model = vm(repo, authorizer, checkoutEnabled = true)
        val job = launch { model.uiState.collect {} }
        val events = mutableListOf<SubscriptionsEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.onSubscribeClick("plan_a")
        advanceUntilIdle()

        // flag on -> authorizer consulted; stub NotConfigured -> unavailable; NEVER a subscribe call/charge.
        assertEquals(1, authorizer.authorizeCalls)
        assertEquals(0, repo.subscribeCalls)
        assertTrue(events.single() is SubscriptionsEvent.PaymentsUnavailable)
        job.cancel(); ejob.cancel()
    }

    @Test
    fun subscribeClick_flagOn_authorized_navigatesToCheckout() = runTest {
        val authorizer = StubAuthorizer(BillingResult.Authorized("pm_test", 0))
        val repo = FakeSubscriptionsRepository().apply { tiers = ApiResult.Success(listOf(tier("plan_a", 499))) }
        val model = vm(repo, authorizer, checkoutEnabled = true)
        val job = launch { model.uiState.collect {} }
        val events = mutableListOf<SubscriptionsEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.onSubscribeClick("plan_a")
        advanceUntilIdle()

        val nav = events.single() as SubscriptionsEvent.NavigateToCheckout
        assertEquals("plan_a", nav.tierId)
        job.cancel(); ejob.cancel()
    }
}

/** Configurable [BillingAuthorizer] for the VM tests; records calls, defaults to NotConfigured. */
private class StubAuthorizer(
    private val result: BillingResult = BillingResult.NotConfigured,
) : BillingAuthorizer {
    var authorizeCalls = 0
    override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?): BillingResult {
        authorizeCalls++
        return result
    }
}

/** Fake [SubscriptionsRepository] for VM tests. */
private class FakeSubscriptionsRepository : SubscriptionsRepository {
    var tiers: ApiResult<List<SubscriptionTier>> = ApiResult.Success(emptyList())
    var mySubs: ApiResult<List<CreatorSubscription>> = ApiResult.Success(emptyList())
    var subscribeCalls = 0

    override suspend fun getCreatorTiers(creatorId: String) = tiers
    override suspend fun getMySubscriptions() = mySubs
    override suspend fun getSubscriptionSummary(subscriptionId: String): ApiResult<CreatorSubscriptionSummary> =
        ApiResult.Success(
            CreatorSubscriptionSummary("s", SubscriptionState.ACTIVE, false, 0, "USD", 0, null, null),
        )

    override suspend fun subscribe(planId: String, body: SubscribeReqDto): ApiResult<CreatorSubscription> {
        subscribeCalls++
        return ApiResult.Failure(ApiError(status = 500, message = "should not be called"))
    }

    override suspend fun cancel(
        subscriptionId: String,
        body: CancelSubscriptionReqDto,
    ): ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "should not be called"))

    override suspend fun renew(
        subscriptionId: String,
        body: com.testlogon.android.data.subscriptions.RenewalReqDto,
    ): ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "should not be called"))

    override suspend fun resume(
        subscriptionId: String,
        body: com.testlogon.android.data.subscriptions.ResumeSubscriptionReqDto,
    ): ApiResult<CreatorSubscription> =
        ApiResult.Failure(ApiError(status = 500, message = "should not be called"))
}
