package com.testlogon.android.feature.videos.purchase

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.purchase.Entitlement
import com.testlogon.android.data.vod.purchase.PurchaseOutcome
import com.testlogon.android.data.vod.purchase.PurchaseTypeOption
import com.testlogon.android.data.vod.purchase.VodAccessOutDto
import com.testlogon.android.data.vod.purchase.VodOffer
import com.testlogon.android.data.vod.purchase.VodPurchaseRepository
import com.testlogon.android.data.vod.purchase.toOffer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

private class FakePurchaseRepo : VodPurchaseRepository {
    var offer: ApiResult<VodOffer> = ApiResult.Success(
        VodAccessOutDto(entitled = false, purchaseAvailable = true, priceCents = 1499, purchaseType = "permanent").toOffer(),
    )
    var outcome: PurchaseOutcome = PurchaseOutcome.PaymentsUnavailable
    var purchaseCalls = 0
    var purchaseGate: CompletableDeferred<Unit>? = null

    override fun isEntitled(videoId: String) = flowOf(false)
    override suspend fun getOffer(videoId: String) = offer
    override suspend fun purchase(videoId: String, purchaseType: String): PurchaseOutcome {
        purchaseCalls++
        purchaseGate?.await()
        return outcome
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
class PurchaseViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakePurchaseRepo()
    private fun vm() = PurchaseViewModel(repo, SavedStateHandle(mapOf("videoId" to "v1")))

    @Test
    fun loadTiers_success_populatesTiers_andDefaultsSelection() = runTest {
        val vm = vm()
        vm.loadTiers()
        advanceUntilIdle()
        val s = vm.uiState.value
        assertFalse(s.isLoadingTiers)
        assertTrue(s.tiers.any { it.type == PurchaseTypeOption.PERMANENT })
        assertEquals("permanent", s.selectedType)
    }

    @Test
    fun loadTiers_failure_setsError() = runTest {
        repo.offer = ApiResult.Failure(ApiError(500, "boom"))
        val vm = vm()
        vm.loadTiers()
        advanceUntilIdle()
        assertEquals("boom", vm.uiState.value.tiersError)
    }

    @Test
    fun confirm_success_emitsUnlocked_andMarksPurchased() = runTest {
        repo.outcome = PurchaseOutcome.Unlocked(entitlement())
        val vm = vm()
        vm.loadTiers(); advanceUntilIdle()
        vm.onTierSelected("permanent")

        val events = mutableListOf<PurchaseEvent>()
        val job = launch { vm.events.collect { events += it } }
        vm.onConfirm()
        advanceUntilIdle()
        job.cancel()

        assertTrue(vm.uiState.value.isPurchased)
        assertTrue(events.any { it is PurchaseEvent.Unlocked })
    }

    @Test
    fun confirm_alreadyOwned_unlocks() = runTest {
        repo.outcome = PurchaseOutcome.Unlocked(entitlement(alreadyOwned = true))
        val vm = vm()
        vm.loadTiers(); advanceUntilIdle()
        vm.onTierSelected("permanent")
        vm.onConfirm()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.isPurchased)
    }

    @Test
    fun confirm_reauth_emitsRequireReauth() = runTest {
        repo.outcome = PurchaseOutcome.RequireReauth
        val vm = vm()
        vm.loadTiers(); advanceUntilIdle()
        vm.onTierSelected("permanent")

        val events = mutableListOf<PurchaseEvent>()
        val job = launch { vm.events.collect { events += it } }
        vm.onConfirm()
        advanceUntilIdle()
        job.cancel()
        assertTrue(events.any { it == PurchaseEvent.RequireReauth })
    }

    @Test
    fun doubleConfirm_whileSubmitting_issuesOnePurchase() = runTest {
        repo.purchaseGate = CompletableDeferred()
        repo.outcome = PurchaseOutcome.Unlocked(entitlement())
        val vm = vm()
        vm.loadTiers(); advanceUntilIdle()
        vm.onTierSelected("permanent")

        vm.onConfirm()       // enters submitting, suspends on the gate
        advanceUntilIdle()
        vm.onConfirm()       // no-op while isSubmitting
        advanceUntilIdle()
        assertEquals(1, repo.purchaseCalls)
        repo.purchaseGate!!.complete(Unit)
        advanceUntilIdle()
    }

    @Test
    fun confirm_failure_setsPurchaseError_andStaysLocked() = runTest {
        repo.outcome = PurchaseOutcome.Failure("declined", retryable = true)
        val vm = vm()
        vm.loadTiers(); advanceUntilIdle()
        vm.onTierSelected("permanent")
        vm.onConfirm()
        advanceUntilIdle()
        assertEquals("declined", vm.uiState.value.purchaseError)
        assertFalse(vm.uiState.value.isPurchased)
    }

    private fun entitlement(alreadyOwned: Boolean = false) = Entitlement(
        videoId = "v1", purchaseType = PurchaseTypeOption.PERMANENT, alreadyOwned = alreadyOwned,
        grantType = "purchase", amountCents = 1499, purchaseId = "p1", viewsRemaining = -1,
        grantedAtSeconds = 1L, expiresAtSeconds = null, downloadAllowed = false,
    )
}
