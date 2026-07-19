package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.subscriptions.SubscriptionFeatureFlags
import com.testlogon.android.data.subscriptions.TestSubscriptionsRepository
import com.testlogon.android.data.subscriptions.sampleSubscription
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-236 — [SubscribeViewModel] transitions:
 *  - flag OFF -> PaymentsUnavailable; NO authorize, NO subscribe call, NO charge.
 *  - flag ON + stub NotConfigured -> PaymentsUnavailable; authorize consulted but NO subscribe call.
 *  - flag ON + Authorized -> subscribe called exactly once, result mapped to Success + Activated event.
 *  - subscribe failure -> Error state (mapped via BillingErrorMapper), retryable back to Reviewing.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SubscribeViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun args() = SavedStateHandle(
        mapOf(
            SubscribeViewModel.ARG_PLAN_ID to "plan_basic",
            SubscribeViewModel.ARG_CREATOR_ID to "usr_42",
            SubscribeViewModel.ARG_TIER_NAME to "Supporter",
            SubscribeViewModel.ARG_PRICE_CENTS to 499L,
            SubscribeViewModel.ARG_CURRENCY to "USD",
            SubscribeViewModel.ARG_INTERVAL to "month",
        ),
    )

    private fun vm(
        repo: TestSubscriptionsRepository,
        authorizer: BillingAuthorizer,
        checkoutEnabled: Boolean,
    ) = SubscribeViewModel(
        savedStateHandle = args(),
        repository = repo,
        adAttribution = com.testlogon.android.data.ads.AdClickAttributionStore(),
        billingAuthorizer = authorizer,
        featureFlags = object : SubscriptionFeatureFlags { override val checkoutEnabled = checkoutEnabled },
        errorMapper = BillingErrorMapper(),
    )

    @Test
    fun confirm_flagOff_paymentsUnavailable_noAuthorize_noSubscribe() = runTest {
        val authorizer = RecordingAuthorizer()
        val repo = TestSubscriptionsRepository()
        val model = vm(repo, authorizer, checkoutEnabled = false)

        model.confirm()
        advanceUntilIdle()

        assertEquals(SubscribeUiState.Status.PaymentsUnavailable, model.uiState.value.status)
        assertEquals(0, authorizer.calls)
        assertEquals(0, repo.subscribeCalls)
    }

    @Test
    fun confirm_flagOn_stubNotConfigured_paymentsUnavailable_noSubscribe() = runTest {
        val authorizer = RecordingAuthorizer(BillingResult.NotConfigured)
        val repo = TestSubscriptionsRepository()
        val model = vm(repo, authorizer, checkoutEnabled = true)

        model.confirm()
        advanceUntilIdle()

        assertEquals(SubscribeUiState.Status.PaymentsUnavailable, model.uiState.value.status)
        assertEquals(1, authorizer.calls)
        assertEquals(0, repo.subscribeCalls) // NEVER a subscribe call / charge when unavailable
    }

    @Test
    fun confirm_flagOn_authorized_callsSubscribeOnce_mapsSuccess() = runTest {
        val authorizer = RecordingAuthorizer(BillingResult.Authorized("pm_test", 499))
        val repo = TestSubscriptionsRepository().apply {
            subscribeResult = ApiResult.Success(sampleSubscription(subscriptionId = "sub_new", planId = "plan_basic"))
        }
        val model = vm(repo, authorizer, checkoutEnabled = true)
        val events = mutableListOf<SubscribeEvent>()
        val ejob = launch { model.events.collect { events += it } }

        model.confirm()
        advanceUntilIdle()

        assertEquals(SubscribeUiState.Status.Success, model.uiState.value.status)
        assertEquals("sub_new", model.uiState.value.subscription?.subscriptionId)
        assertEquals(1, repo.subscribeCalls)
        val activated = events.single() as SubscribeEvent.Activated
        assertEquals("sub_new", activated.subscriptionId)
        assertEquals("plan_basic", activated.planId)
        ejob.cancel()
    }

    @Test
    fun confirm_subscribeFailure_setsErrorState_thenRetryReturnsToReviewing() = runTest {
        val authorizer = RecordingAuthorizer(BillingResult.Authorized("pm_test", 499))
        val repo = TestSubscriptionsRepository().apply {
            subscribeResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(repo, authorizer, checkoutEnabled = true)
        val ejob = launch { model.events.collect {} }

        model.confirm()
        advanceUntilIdle()

        assertEquals(SubscribeUiState.Status.Error, model.uiState.value.status)
        assertTrue(model.uiState.value.errorMessage != null)
        assertEquals(1, repo.subscribeCalls)

        model.retry()
        assertEquals(SubscribeUiState.Status.Reviewing, model.uiState.value.status)
        ejob.cancel()
    }

    @Test
    fun confirm_authorizerCancelled_returnsToReviewing_noSubscribe() = runTest {
        val authorizer = RecordingAuthorizer(BillingResult.Cancelled)
        val repo = TestSubscriptionsRepository()
        val model = vm(repo, authorizer, checkoutEnabled = true)

        model.confirm()
        advanceUntilIdle()

        assertEquals(SubscribeUiState.Status.Reviewing, model.uiState.value.status)
        assertEquals(0, repo.subscribeCalls)
    }
}

/** Records authorize() calls; defaults to NotConfigured (never fakes a charge). */
private class RecordingAuthorizer(
    private val result: BillingResult = BillingResult.NotConfigured,
) : BillingAuthorizer {
    var calls = 0
    override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?): BillingResult {
        calls++
        return result
    }
}
