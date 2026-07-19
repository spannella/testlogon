package com.testlogon.android.feature.subscriptions

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.subscriptions.SubscriptionState
import com.testlogon.android.data.subscriptions.TestSubscriptionsRepository
import com.testlogon.android.data.subscriptions.sampleSubscription
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-237 — [ManageSubscriptionViewModel] transitions: load -> Content / NoSubscription / Error;
 * cancel confirm -> cancel endpoint + cancel-at-period-end reflected; renew clears scheduled cancel;
 * concurrent-mutation guard; resume billing-error routes to subscribe.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ManageSubscriptionViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val fakeAuthorizer = object : BillingAuthorizer {
        override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?): BillingResult =
            BillingResult.Authorized(paymentMethodId = "", authorizedMinorUnits = amountMinorUnits)
    }

    private fun vm(repo: TestSubscriptionsRepository) =
        ManageSubscriptionViewModel(
            savedStateHandle = androidx.lifecycle.SavedStateHandle(),
            repository = repo,
            billingAuthorizer = fakeAuthorizer,
            errorMapper = BillingErrorMapper(),
        )

    @Test
    fun load_active_rendersCancelableContent() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription()))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()

        val state = model.uiState.value as ManageSubscriptionUiState.Content
        assertEquals(SubscriptionState.ACTIVE, state.subscription.status)
        assertTrue(state.canCancel)
        assertFalse(state.isScheduledToCancel)
        job.cancel()
    }

    @Test
    fun load_emptyList_isNoSubscription() = runTest {
        val repo = TestSubscriptionsRepository().apply { mySubsResult = ApiResult.Success(emptyList()) }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(model.uiState.value is ManageSubscriptionUiState.NoSubscription)
        job.cancel()
    }

    @Test
    fun load_failure_isError() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(model.uiState.value is ManageSubscriptionUiState.Error)
        job.cancel()
    }

    @Test
    fun cancelConfirmed_callsCancel_reflectsCancelAtPeriodEnd() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription(cancelAtPeriodEnd = false)))
            cancelResult = ApiResult.Success(sampleSubscription(cancelAtPeriodEnd = true))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()

        model.onCancelClicked()
        assertTrue((model.uiState.value as ManageSubscriptionUiState.Content).confirmCancelVisible)

        model.onCancelConfirmed()
        advanceUntilIdle()

        val state = model.uiState.value as ManageSubscriptionUiState.Content
        assertEquals(1, repo.cancelCalls)
        assertTrue(state.subscription.cancelAtPeriodEnd)
        assertTrue(state.isScheduledToCancel)
        assertFalse(state.confirmCancelVisible)
        assertEquals(MutationStatus.Idle, state.mutation)
        job.cancel()
    }

    @Test
    fun cancelDismissed_hidesDialog_noCancelCall() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription()))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()

        model.onCancelClicked()
        model.onCancelDismissed()
        advanceUntilIdle()

        assertFalse((model.uiState.value as ManageSubscriptionUiState.Content).confirmCancelVisible)
        assertEquals(0, repo.cancelCalls)
        job.cancel()
    }

    @Test
    fun renewClicked_scheduledCancel_callsRenewal_clearsSchedule() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription(cancelAtPeriodEnd = true)))
            renewResult = ApiResult.Success(sampleSubscription(cancelAtPeriodEnd = false))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertTrue((model.uiState.value as ManageSubscriptionUiState.Content).isScheduledToCancel)

        model.onRenewClicked()
        advanceUntilIdle()

        val state = model.uiState.value as ManageSubscriptionUiState.Content
        assertEquals(1, repo.renewCalls)
        assertEquals(0, repo.resumeCalls)
        assertFalse(state.subscription.cancelAtPeriodEnd)
        assertTrue(state.canCancel)
        job.cancel()
    }

    @Test
    fun renewClicked_canceledSub_callsResume() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription(status = SubscriptionState.CANCELED)))
            resumeResult = ApiResult.Success(sampleSubscription(status = SubscriptionState.ACTIVE))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()

        model.onRenewClicked()
        advanceUntilIdle()

        val state = model.uiState.value as ManageSubscriptionUiState.Content
        assertEquals(1, repo.resumeCalls)
        assertEquals(0, repo.renewCalls)
        assertEquals(SubscriptionState.ACTIVE, state.subscription.status)
        job.cancel()
    }

    @Test
    fun renewClicked_canceledSub_billingError_routesToSubscribe() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription(status = SubscriptionState.CANCELED)))
            // A decline-class error: the mapper classifies card_declined as REQUIRES_NEW_METHOD.
            resumeResult = ApiResult.Failure(ApiError(status = 402, code = "card_declined", message = "declined"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        val events = mutableListOf<ManageSubscriptionEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.onRenewClicked()
        advanceUntilIdle()

        val nav = events.single() as ManageSubscriptionEvent.NavigateToSubscribe
        assertEquals("plan_basic", nav.planId)
        assertEquals("usr_42", nav.creatorId)
        // No state corruption: back to Idle content.
        val state = model.uiState.value as ManageSubscriptionUiState.Content
        assertEquals(MutationStatus.Idle, state.mutation)
        job.cancel(); ejob.cancel()
    }

    @Test
    fun cancelConfirmed_concurrentSecondCall_ignored() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription()))
            cancelResult = ApiResult.Success(sampleSubscription(cancelAtPeriodEnd = true))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()

        // First confirm transitions to Canceling synchronously; a second is a no-op until Idle.
        model.onCancelConfirmed()
        model.onCancelConfirmed()
        advanceUntilIdle()

        assertEquals(1, repo.cancelCalls)
        job.cancel()
    }

    @Test
    fun cancelConfirmed_failure_setsMutationFailed_keepsSubscription() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            mySubsResult = ApiResult.Success(listOf(sampleSubscription()))
            cancelResult = ApiResult.Failure(ApiError(status = 422, message = "bad"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()

        model.onCancelConfirmed()
        advanceUntilIdle()

        val state = model.uiState.value as ManageSubscriptionUiState.Content
        assertTrue(state.mutation is MutationStatus.Failed)
        assertFalse(state.subscription.cancelAtPeriodEnd) // unchanged; no optimistic mutation
        job.cancel()
    }
}
