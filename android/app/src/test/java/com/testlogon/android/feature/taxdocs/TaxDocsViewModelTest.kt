package com.testlogon.android.feature.taxdocs

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.taxdocs.TaxDocsRepository
import com.testlogon.android.data.taxdocs.TaxDocument
import com.testlogon.android.data.taxdocs.TaxMoney
import com.testlogon.android.feature.billing.error.BillingErrorMapper
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

/** AND-246 — list load (content/empty/error) + download one-shot event (with year, and null-year no-op). */
@OptIn(ExperimentalCoroutinesApi::class)
class TaxDocsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val mapper = BillingErrorMapper()

    private class FakeTaxDocsRepository : TaxDocsRepository {
        var listResult: ApiResult<List<TaxDocument>> = ApiResult.Success(emptyList())
        override suspend fun listTaxDocuments(): ApiResult<List<TaxDocument>> = listResult
        override fun pdfUrl(year: Int): String = "http://dev.example/ui/tax-documents/document/$year/pdf"
    }

    private fun doc(year: Int? = 2024): TaxDocument = TaxDocument(
        docId = "txd_$year",
        docType = "annual_summary",
        year = year,
        grandTotal = TaxMoney(254013, "usd"),
        transactionCount = 87,
        createdAtEpochSeconds = 1_738_281_600L,
    )

    @Test
    fun load_success_populatesDocuments() = runTest {
        val repo = FakeTaxDocsRepository().apply { listResult = ApiResult.Success(listOf(doc())) }
        val vm = TaxDocsViewModel(repo, mapper)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()
        assertEquals(1, vm.uiState.value.documents.size)
        assertTrue(vm.uiState.value.error == null)
        job.cancel()
    }

    @Test
    fun load_error_surfacesError() = runTest {
        val repo = FakeTaxDocsRepository().apply {
            listResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val vm = TaxDocsViewModel(repo, mapper)
        val job = launch { vm.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(vm.uiState.value.error != null)
        job.cancel()
    }

    @Test
    fun download_withYear_emitsViewPdfEvent() = runTest {
        val repo = FakeTaxDocsRepository()
        val vm = TaxDocsViewModel(repo, mapper)
        val events = mutableListOf<TaxDocsEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        advanceUntilIdle()

        vm.onDownloadClicked(doc(2024))
        advanceUntilIdle()
        val event = events.single() as TaxDocsEvent.ViewPdf
        assertEquals("http://dev.example/ui/tax-documents/document/2024/pdf", event.url)
        ejob.cancel()
    }

    @Test
    fun download_nullYear_isNoOp() = runTest {
        val repo = FakeTaxDocsRepository()
        val vm = TaxDocsViewModel(repo, mapper)
        val events = mutableListOf<TaxDocsEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { vm.events.toList(events) }
        advanceUntilIdle()

        vm.onDownloadClicked(doc(null))
        advanceUntilIdle()
        assertTrue(events.isEmpty())
        ejob.cancel()
    }
}
