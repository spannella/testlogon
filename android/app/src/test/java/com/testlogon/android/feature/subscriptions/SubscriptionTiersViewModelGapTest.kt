package com.testlogon.android.feature.subscriptions

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.subscriptions.BillingInterval
import com.testlogon.android.data.subscriptions.SubscriptionFeatureFlags
import com.testlogon.android.data.subscriptions.SubscriptionTier
import com.testlogon.android.data.subscriptions.TestSubscriptionsRepository
import com.testlogon.android.data.subscriptions.FakeAuthStateStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

/**
 * AND-242 — gap-fill for [SubscriptionTiersViewModel] paths the AND-235 unit test does not cover:
 *  - onManageClick emits NavigateToManage,
 *  - onRefresh failure WITH existing content keeps the list and surfaces a ShowMessage (stale path).
 * Does NOT duplicate the load/sort/empty/error/Subscribe-CTA cases already in SubscriptionTiersViewModelTest.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SubscriptionTiersViewModelGapTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun tier(id: String, price: Long) = SubscriptionTier(
        planId = id, creatorId = "usr_42", name = id, description = null, priceCents = price,
        currency = "USD", interval = BillingInterval.MONTH, annualPriceCents = null, status = "active",
        perks = emptyList(), createdAtEpochSeconds = null, updatedAtEpochSeconds = null,
    )

    private fun vm(repo: TestSubscriptionsRepository) = SubscriptionTiersViewModel(
        savedStateHandle = SavedStateHandle(
            mapOf(SubscriptionTiersViewModel.ARG_CREATOR_ID to "usr_42"),
        ),
        repository = repo,
        billingAuthorizer = object : BillingAuthorizer {
            override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?) =
                BillingResult.NotConfigured
        },
        featureFlags = object : SubscriptionFeatureFlags { override val checkoutEnabled = false },
        authStateStore = FakeAuthStateStore("usr_me"),
    )

    @Test
    fun onManageClick_emitsNavigateToManage() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            tiersResult = ApiResult.Success(listOf(tier("plan_a", 499)))
        }
        val model = vm(repo)
        val events = mutableListOf<SubscriptionsEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { model.events.toList(events) }
        advanceUntilIdle()

        model.onManageClick()
        advanceUntilIdle()

        assertTrue(events.any { it is SubscriptionsEvent.NavigateToManage })
        ejob.cancel()
    }

    @Test
    fun onRefresh_failureWithContent_keepsTiers_emitsShowMessage() = runTest {
        val repo = TestSubscriptionsRepository().apply {
            tiersResult = ApiResult.Success(listOf(tier("plan_a", 499)))
        }
        val model = vm(repo)
        val events = mutableListOf<SubscriptionsEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { model.events.toList(events) }
        val sjob = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertEquals(1, model.uiState.value.tiers.size)

        repo.tiersResult = ApiResult.NetworkError(IOException("offline"))
        model.onRefresh()
        advanceUntilIdle()

        // Content preserved on a refresh failure; a transient snackbar is surfaced, no destructive error.
        assertEquals(1, model.uiState.value.tiers.size)
        assertEquals(null, model.uiState.value.error)
        assertTrue(events.any { it is SubscriptionsEvent.ShowMessage })
        ejob.cancel(); sjob.cancel()
    }
}
