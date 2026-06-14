package com.testlogon.android.feature.promo

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.promo.CreatePromoRequestDto
import com.testlogon.android.data.promo.DiscountType
import com.testlogon.android.data.promo.PromoCode
import com.testlogon.android.data.promo.PromoCodesRepository
import com.testlogon.android.data.promo.RedeemPromoRequestDto
import com.testlogon.android.data.promo.RedeemResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PromoCodesViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun samplePromo(id: String = "pc_1", active: Boolean = true) = PromoCode(
        codeId = id, code = "SUMMER25", discountType = DiscountType.PERCENTAGE, rawDiscountType = "percentage",
        discountValue = 25, freeTrialDays = 0, appliesTo = listOf("subscription"), minPurchaseCents = 0,
        maxUses = 100, maxUsesPerUser = 1, currentUses = 0, active = active, expiresAtEpochSeconds = 0,
        createdAtEpochSeconds = 0,
    )

    private class FakeRepo : PromoCodesRepository {
        var listResult: ApiResult<List<PromoCode>> = ApiResult.Success(emptyList())
        var createResult: ApiResult<PromoCode> = ApiResult.Failure(ApiError(500, "x"))
        var deactivateResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var listCount = 0
        var lastCreate: CreatePromoRequestDto? = null
        override suspend fun listCodes(): ApiResult<List<PromoCode>> { listCount++; return listResult }
        override suspend fun create(request: CreatePromoRequestDto): ApiResult<PromoCode> {
            lastCreate = request; return createResult
        }
        override suspend fun deactivate(codeId: String): ApiResult<Unit> = deactivateResult
        override suspend fun redeem(request: RedeemPromoRequestDto): ApiResult<RedeemResult> =
            ApiResult.Success(RedeemResult(true, 0))
    }

    @Test
    fun load_empty_movesToEmpty() = runTest {
        val repo = FakeRepo().apply { listResult = ApiResult.Success(emptyList()) }
        val vm = PromoCodesViewModel(repo)
        advanceUntilIdle()
        assertEquals(PromoCodesUiState.Phase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun load_withCodes_movesToContent() = runTest {
        val repo = FakeRepo().apply { listResult = ApiResult.Success(listOf(samplePromo())) }
        val vm = PromoCodesViewModel(repo)
        advanceUntilIdle()
        assertEquals(PromoCodesUiState.Phase.Content, vm.uiState.value.phase)
        assertEquals(1, vm.uiState.value.codes.size)
    }

    @Test
    fun onCreate_blankCode_returnsValidationError_noNetworkCall() = runTest {
        val repo = FakeRepo().apply { listResult = ApiResult.Success(emptyList()) }
        val vm = PromoCodesViewModel(repo)
        advanceUntilIdle()
        val countBefore = repo.listCount
        val error = vm.onCreate(CreatePromoForm(code = ""))
        advanceUntilIdle()
        assertEquals(PromoFormError.CODE_REQUIRED, error)
        // No create -> no extra list re-fetch.
        assertEquals(countBefore, repo.listCount)
        assertNull(repo.lastCreate)
    }

    @Test
    fun onCreate_success_reloadsList_andUppercasesCode() = runTest {
        val repo = FakeRepo().apply {
            listResult = ApiResult.Success(emptyList())
            createResult = ApiResult.Success(samplePromo())
        }
        val vm = PromoCodesViewModel(repo)
        advanceUntilIdle()
        val before = repo.listCount
        val error = vm.onCreate(CreatePromoForm(code = "summer25", discountValue = 25))
        advanceUntilIdle()
        assertNull(error)
        assertEquals("SUMMER25", repo.lastCreate?.code)
        assertTrue("expected list re-fetch after create", repo.listCount > before)
    }

    @Test
    fun onCreate_failure_surfacesDetailMessage() = runTest {
        val repo = FakeRepo().apply {
            listResult = ApiResult.Success(listOf(samplePromo()))
            createResult = ApiResult.Failure(ApiError(422, "Code must be at least 3 characters"))
        }
        val vm = PromoCodesViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<PromoCodesEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onCreate(CreatePromoForm(code = "GOODCODE", discountValue = 25))
        advanceUntilIdle()
        job.cancel()

        val err = effects.filterIsInstance<PromoCodesEffect.ShowError>().single()
        assertEquals("Code must be at least 3 characters", err.message)
    }

    @Test
    fun onDeactivate_success_reloadsList() = runTest {
        val repo = FakeRepo().apply {
            listResult = ApiResult.Success(listOf(samplePromo()))
            deactivateResult = ApiResult.Success(Unit)
        }
        val vm = PromoCodesViewModel(repo)
        advanceUntilIdle()
        val before = repo.listCount
        vm.onDeactivate("pc_1")
        advanceUntilIdle()
        assertTrue(repo.listCount > before)
    }
}
