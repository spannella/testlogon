package com.testlogon.android.feature.licenses

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.licenses.IssuedLicense
import com.testlogon.android.data.licenses.IssuedLicensesPage
import com.testlogon.android.data.licenses.LicenseRequest
import com.testlogon.android.data.licenses.LicenseRequestsPage
import com.testlogon.android.data.licenses.LicensesRepository
import com.testlogon.android.data.licenses.RevenuePage
import com.testlogon.android.data.licenses.RevenueSummary
import com.testlogon.android.data.licenses.RevenueTransaction
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class LicensesViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    // ---- Fixtures ----

    private fun issuedLicense(id: String = "lic_1") = IssuedLicense(
        id = id,
        contentId = "content_1",
        licenseeId = "user_1",
        licenseMode = "per_user",
        status = "active",
        createdAtSeconds = 1_700_000_000L,
    )

    private fun issuedPage(items: List<IssuedLicense> = listOf(issuedLicense())) =
        IssuedLicensesPage(items = items, nextCursor = "next_issued")

    private fun licenseRequest(id: String = "req_1") = LicenseRequest(
        id = id,
        contentId = "content_2",
        contentType = "video",
        ownerDisplayName = "Owner",
        status = "pending",
        terms = null,
        denialReason = "",
        message = "please",
        createdAtSeconds = 1_700_000_100L,
    )

    private fun requestsPage(items: List<LicenseRequest> = listOf(licenseRequest())) =
        LicenseRequestsPage(items = items, nextCursor = "next_req")

    private fun revenuePage(
        transactions: List<RevenueTransaction> = listOf(
            RevenueTransaction(
                id = "txn_1",
                contentId = "content_3",
                sourceType = "purchase",
                splitAmountCents = 500,
                splitType = "revenue_share",
                currency = "USD",
                createdAtSeconds = 1_700_000_200L,
            ),
        ),
        totalTransactions: Int = 1,
    ) = RevenuePage(
        summary = RevenueSummary(
            totalCents = 500,
            totalTransactions = totalTransactions,
            lastTransactionAtSeconds = 1_700_000_200L,
            currency = "USD",
        ),
        transactions = transactions,
        nextCursor = "next_rev",
    )

    // ---- Fake repository ----

    private class FakeLicensesRepository : LicensesRepository {
        var issuedResult: ApiResult<IssuedLicensesPage> = ApiResult.Failure(ApiError(500, "x"))
        var requestsResult: ApiResult<LicenseRequestsPage> = ApiResult.Failure(ApiError(500, "x"))
        var revenueResult: ApiResult<RevenuePage> = ApiResult.Failure(ApiError(500, "x"))

        var issuedCache: IssuedLicensesPage? = null
        var requestsCache: LicenseRequestsPage? = null
        var revenueCache: RevenuePage? = null

        override suspend fun loadIssued(): ApiResult<IssuedLicensesPage> = issuedResult
        override suspend fun loadRequests(): ApiResult<LicenseRequestsPage> = requestsResult
        override suspend fun loadRevenue(): ApiResult<RevenuePage> = revenueResult

        override fun cachedIssued(): IssuedLicensesPage? = issuedCache
        override fun cachedRequests(): LicenseRequestsPage? = requestsCache
        override fun cachedRevenue(): RevenuePage? = revenueCache

        override fun clear() {}
    }

    // ---- Init load ----

    @Test
    fun init_issuedSuccessWithData_movesToContent() = runTest {
        val repo = FakeLicensesRepository().apply { issuedResult = ApiResult.Success(issuedPage()) }
        val vm = LicensesViewModel(repo)
        advanceUntilIdle()
        assertEquals(LicensesUiState.Phase.Content, vm.uiState.value.phase)
        assertEquals(LicensesTab.ISSUED, vm.uiState.value.tab)
        assertEquals(issuedPage().items, vm.uiState.value.issued?.items)
    }

    @Test
    fun init_issuedSuccessEmpty_movesToEmpty() = runTest {
        val repo = FakeLicensesRepository().apply {
            issuedResult = ApiResult.Success(issuedPage(items = emptyList()))
        }
        val vm = LicensesViewModel(repo)
        advanceUntilIdle()
        assertEquals(LicensesUiState.Phase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun init_issuedFailure500_movesToError() = runTest {
        val repo = FakeLicensesRepository().apply {
            issuedResult = ApiResult.Failure(ApiError(500, "boom"))
        }
        val vm = LicensesViewModel(repo)
        advanceUntilIdle()
        assertEquals(LicensesUiState.Phase.Error, vm.uiState.value.phase)
        assertEquals("boom", vm.uiState.value.errorMessage)
    }

    @Test
    fun init_issuedNetworkError_withCache_showsStaleContent() = runTest {
        val cached = issuedPage()
        val repo = FakeLicensesRepository().apply {
            issuedResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            issuedCache = cached
        }
        val vm = LicensesViewModel(repo)
        advanceUntilIdle()
        assertEquals(LicensesUiState.Phase.Content, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.isStale)
        assertEquals(cached.items, vm.uiState.value.issued?.items)
    }

    @Test
    fun init_issuedNetworkError_noCache_movesToOffline() = runTest {
        val repo = FakeLicensesRepository().apply {
            issuedResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            issuedCache = null
        }
        val vm = LicensesViewModel(repo)
        advanceUntilIdle()
        assertEquals(LicensesUiState.Phase.Offline, vm.uiState.value.phase)
    }

    @Test
    fun init_issuedFailure401_movesToSessionExpired() = runTest {
        val repo = FakeLicensesRepository().apply {
            issuedResult = ApiResult.Failure(ApiError(401, "unauthorized"))
        }
        val vm = LicensesViewModel(repo)
        advanceUntilIdle()
        assertEquals(LicensesUiState.Phase.SessionExpired, vm.uiState.value.phase)
    }

    // ---- Tab switching ----

    @Test
    fun onSelectTab_issuedToRequests_updatesTabAndLoadsRequests() = runTest {
        val repo = FakeLicensesRepository().apply {
            issuedResult = ApiResult.Success(issuedPage())
            requestsResult = ApiResult.Success(requestsPage())
        }
        val vm = LicensesViewModel(repo)
        advanceUntilIdle()

        vm.onSelectTab(LicensesTab.REQUESTS)
        advanceUntilIdle()

        assertEquals(LicensesTab.REQUESTS, vm.uiState.value.tab)
        assertEquals(LicensesUiState.Phase.Content, vm.uiState.value.phase)
        assertEquals(requestsPage().items, vm.uiState.value.requests?.items)
    }

    @Test
    fun onSelectTab_requestsToRevenue_updatesTabAndLoadsRevenue() = runTest {
        val repo = FakeLicensesRepository().apply {
            issuedResult = ApiResult.Success(issuedPage())
            requestsResult = ApiResult.Success(requestsPage())
            revenueResult = ApiResult.Success(revenuePage())
        }
        val vm = LicensesViewModel(repo)
        advanceUntilIdle()

        vm.onSelectTab(LicensesTab.REQUESTS)
        advanceUntilIdle()
        vm.onSelectTab(LicensesTab.REVENUE)
        advanceUntilIdle()

        assertEquals(LicensesTab.REVENUE, vm.uiState.value.tab)
        assertEquals(LicensesUiState.Phase.Content, vm.uiState.value.phase)
        assertEquals(500L, vm.uiState.value.revenue?.summary?.totalCents)
    }

    @Test
    fun onSelectTab_sameTab_isNoOp() = runTest {
        val repo = FakeLicensesRepository().apply { issuedResult = ApiResult.Success(issuedPage()) }
        val vm = LicensesViewModel(repo)
        advanceUntilIdle()

        vm.onSelectTab(LicensesTab.ISSUED)
        advanceUntilIdle()

        assertEquals(LicensesTab.ISSUED, vm.uiState.value.tab)
        assertEquals(LicensesUiState.Phase.Content, vm.uiState.value.phase)
    }

    @Test
    fun onSelectTab_revenueEmpty_movesToEmpty() = runTest {
        val repo = FakeLicensesRepository().apply {
            issuedResult = ApiResult.Success(issuedPage())
            revenueResult = ApiResult.Success(revenuePage(transactions = emptyList(), totalTransactions = 0))
        }
        val vm = LicensesViewModel(repo)
        advanceUntilIdle()

        vm.onSelectTab(LicensesTab.REVENUE)
        advanceUntilIdle()

        assertEquals(LicensesTab.REVENUE, vm.uiState.value.tab)
        assertEquals(LicensesUiState.Phase.Empty, vm.uiState.value.phase)
    }
}
