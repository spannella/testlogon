package com.testlogon.android.feature.privacy

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.privacy.ExportStatus
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-385 - PrivacyExportViewModel unit tests (TC-AND-385-07, plus download-set + retry + offline). Uses a
 * fake repository; no nested runTest. The stateIn flow is kept hot with a backgroundScope collector; the
 * StandardTestDispatcher is driven with runCurrent / advanceTimeBy (NOT advanceUntilIdle, which would drain
 * the bounded poll loop unpredictably). The io seam points at the test dispatcher so the poll delay is
 * virtual-time controlled.
 */
class PrivacyExportViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakePrivacyExportRepository()

    private fun vm() = PrivacyExportViewModel(repo).also {
        it.io = mainRule.dispatcher
        it.now = { FIXED_NOW }
    }

    private fun hot(vm: PrivacyExportViewModel) {
        // Keep WhileSubscribed active so the combined state is produced.
        vm.uiState.onEach { }.launchIn(backgroundScopeRef!!)
    }

    private var backgroundScopeRef: kotlinx.coroutines.CoroutineScope? = null

    // TC-AND-385-07
    @Test
    fun canRequest_falseWhileNonTerminal_andPollingStopsAtTerminal() = runTest {
        backgroundScopeRef = backgroundScope
        repo.cache.value = listOf(
            FakePrivacyExportRepository.sample("exp1", ExportStatus.PROCESSING),
        )
        repo.refreshResult = ApiResult.Success(repo.cache.value)
        // The poll's single-status GET resolves the request to COMPLETED (terminal).
        repo.refreshOneResult = ApiResult.Success(
            FakePrivacyExportRepository.sample("exp1", ExportStatus.COMPLETED),
        )

        val vm = vm()
        hot(vm)
        vm.load()
        runCurrent()

        // A non-terminal request gates the CTA.
        assertFalse(vm.uiState.value.canRequest)

        // First poll tick (10s) flips it to COMPLETED -> CTA re-enabled, polling stops.
        vm.advanceAndSettle(this)
        assertEquals(listOf("exp1"), repo.refreshOneCalls)
        assertEquals(ExportStatus.COMPLETED, vm.uiState.value.requests.single().status)
        assertTrue(vm.uiState.value.canRequest)

        // No further polls after terminal even if time advances a lot.
        advanceTimeBy(60_000)
        runCurrent()
        assertEquals(1, repo.refreshOneCalls.size)
    }

    @Test
    fun pollingIsBounded_atMaxPolls_whenNeverTerminal() = runTest {
        backgroundScopeRef = backgroundScope
        repo.cache.value = listOf(
            FakePrivacyExportRepository.sample("exp1", ExportStatus.PROCESSING),
        )
        repo.refreshResult = ApiResult.Success(repo.cache.value)
        // Stays non-terminal forever.
        repo.refreshOneResult = ApiResult.Success(
            FakePrivacyExportRepository.sample("exp1", ExportStatus.PROCESSING),
        )

        val vm = vm()
        hot(vm)
        vm.load()
        runCurrent()

        // Drive well past 5 * 10s.
        advanceTimeBy(PrivacyExportViewModel.POLL_INTERVAL_MS * 10)
        runCurrent()
        assertEquals(PrivacyExportViewModel.MAX_POLLS, repo.refreshOneCalls.size)
    }

    @Test
    fun download_addsThenRemovesFromDownloadingSet_andSurfacesError() = runTest {
        // android.net.Uri is not available in plain JVM tests, so the success-Uri path is covered by an
        // instrumented test; here we drive the FAILURE branch to assert the downloading-set lifecycle.
        backgroundScopeRef = backgroundScope
        repo.cache.value = listOf(
            FakePrivacyExportRepository.sample("exp1", ExportStatus.COMPLETED),
        )
        repo.refreshResult = ApiResult.Success(repo.cache.value)
        repo.downloadResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))

        val vm = vm()
        hot(vm)
        vm.load()
        runCurrent()

        vm.onDownload("exp1")
        runCurrent()
        assertEquals(listOf("exp1"), repo.downloadCalls)
        assertFalse(vm.uiState.value.downloading.contains("exp1"))
        assertEquals(PrivacyExportViewModel.DOWNLOAD_FAILED, vm.uiState.value.error?.message)
    }

    @Test
    fun retry_issuesANewRequest() = runTest {
        backgroundScopeRef = backgroundScope
        repo.cache.value = listOf(
            FakePrivacyExportRepository.sample("exp1", ExportStatus.FAILED),
        )
        repo.refreshResult = ApiResult.Success(repo.cache.value)
        repo.requestResult = ApiResult.Success(
            FakePrivacyExportRepository.sample("exp2", ExportStatus.PENDING),
        )

        val vm = vm()
        hot(vm)
        vm.load()
        runCurrent()

        // A FAILED request is terminal -> CTA enabled; retry == a fresh create.
        assertTrue(vm.uiState.value.canRequest)
        vm.onRetry("exp1")
        runCurrent()
        assertEquals(1, repo.requestCount)
    }

    @Test
    fun offline_refreshFailure_setsOfflineFlag_keepsRows() = runTest {
        backgroundScopeRef = backgroundScope
        repo.cache.value = listOf(
            FakePrivacyExportRepository.sample("exp1", ExportStatus.COMPLETED),
        )
        repo.refreshResult = ApiResult.NetworkError(java.io.IOException("offline"))

        val vm = vm()
        hot(vm)
        vm.load()
        runCurrent()

        assertTrue(vm.uiState.value.isOffline)
        assertEquals(listOf("exp1"), vm.uiState.value.requests.map { it.id })
    }

    @Test
    fun requestExport_failure_surfacesAuthMessageOn401() = runTest {
        backgroundScopeRef = backgroundScope
        repo.refreshResult = ApiResult.Success(emptyList())
        repo.requestResult = ApiResult.Failure(ApiError(status = 401, message = "x"))

        val vm = vm()
        hot(vm)
        vm.load()
        runCurrent()

        vm.onRequestExport()
        runCurrent()
        assertEquals(PrivacyExportViewModel.AUTH_MESSAGE, vm.uiState.value.error?.message)
        assertFalse(vm.uiState.value.requestInFlight)
    }

    private fun PrivacyExportViewModel.advanceAndSettle(scope: kotlinx.coroutines.test.TestScope) {
        scope.advanceTimeBy(POLL_INTERVAL_MS_PLUS)
        scope.runCurrent()
    }

    private companion object {
        const val FIXED_NOW = 1_800_000_000_000L
        const val POLL_INTERVAL_MS_PLUS = 10_001L
    }
}
