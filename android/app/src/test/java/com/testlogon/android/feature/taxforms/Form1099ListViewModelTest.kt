package com.testlogon.android.feature.taxforms

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.taxforms.Form1099
import com.testlogon.android.data.taxforms.Form1099Money
import com.testlogon.android.data.taxforms.Form1099Status
import com.testlogon.android.data.taxforms.TaxForm1099Repository
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-247/250 — [Form1099ListViewModel] transitions: list load (content/error), the download one-shot
 * event (resolves download_url -> ViewPdf), the empty-URL / failure -> DownloadError effect, and the
 * in-flight download guard.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class Form1099ListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val mapper = BillingErrorMapper()

    private class FakeRepo : TaxForm1099Repository {
        var listResult: ApiResult<List<Form1099>> = ApiResult.Success(emptyList())
        var urlResult: ApiResult<String> = ApiResult.Success("https://files.example/1099.pdf")
        var urlCalls = 0
            private set

        override suspend fun list1099s(): ApiResult<List<Form1099>> = listResult
        override suspend fun get1099(taxYear: Int): ApiResult<Form1099> =
            (listResult as? ApiResult.Success)?.data?.firstOrNull { it.taxYear == taxYear }
                ?.let { ApiResult.Success(it) } ?: ApiResult.Failure(ApiError(404, "not found"))

        override suspend fun downloadUrl(taxYear: Int): ApiResult<String> {
            urlCalls++
            return urlResult
        }
    }

    private fun sample1099(year: Int = 2025) = Form1099(
        taxYear = year,
        formId = "tf_$year",
        totalEarnings = Form1099Money(1_284_500),
        qualifies = true,
        status = Form1099Status.GENERATED,
        statusRaw = "generated",
        correctionCount = 0,
        payerName = "TestLogon, Inc.",
        payerTinLast4 = "6789",
        generatedAtEpochSeconds = 1_738_310_400L,
        updatedAtEpochSeconds = 1_738_310_400L,
        downloadUrl = null,
    )

    @Test
    fun load_success_populatesForms() = runTest {
        val repo = FakeRepo().apply { listResult = ApiResult.Success(listOf(sample1099())) }
        val vm = Form1099ListViewModel(repo, mapper)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()
        assertEquals(1, vm.uiState.value.forms.size)
        assertNull(vm.uiState.value.error)
        job.cancel()
    }

    @Test
    fun load_error_surfacesError() = runTest {
        val repo = FakeRepo().apply { listResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = Form1099ListViewModel(repo, mapper)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(vm.uiState.value.error != null)
        job.cancel()
    }

    @Test
    fun download_success_emitsViewPdf_withResolvedUrl() = runTest {
        val repo = FakeRepo().apply {
            listResult = ApiResult.Success(listOf(sample1099()))
            urlResult = ApiResult.Success("https://files.example/1099/2025.pdf?sig=abc")
        }
        val vm = Form1099ListViewModel(repo, mapper)
        val events = mutableListOf<Form1099Event>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        advanceUntilIdle()

        vm.onDownloadClicked(sample1099())
        advanceUntilIdle()

        val pdf = events.single() as Form1099Event.ViewPdf
        assertEquals("https://files.example/1099/2025.pdf?sig=abc", pdf.url)
        assertNull(vm.uiState.value.downloadingYear)
        ejob.cancel()
    }

    @Test
    fun download_emptyUrl_emitsDownloadError() = runTest {
        val repo = FakeRepo().apply { urlResult = ApiResult.Success("") }
        val vm = Form1099ListViewModel(repo, mapper)
        val events = mutableListOf<Form1099Event>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        advanceUntilIdle()

        vm.onDownloadClicked(sample1099())
        advanceUntilIdle()

        assertTrue(events.single() is Form1099Event.DownloadError)
        ejob.cancel()
    }

    @Test
    fun download_failure_emitsDownloadError() = runTest {
        val repo = FakeRepo().apply { urlResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = Form1099ListViewModel(repo, mapper)
        val events = mutableListOf<Form1099Event>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        advanceUntilIdle()

        vm.onDownloadClicked(sample1099())
        advanceUntilIdle()

        assertTrue(events.single() is Form1099Event.DownloadError)
        ejob.cancel()
    }
}
