package com.testlogon.android.feature.invoices

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.invoices.InvoiceMoney
import com.testlogon.android.data.invoices.InvoiceTax
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
 * AND-249/250 — [InvoiceTaxViewModel]: flat breakdown from the invoice scalars (subtotal/tax/total),
 * arithmetic consistency, retryable vs 404-non-retryable error mapping, and retry re-load.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class InvoiceTaxViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: FakeInvoicesRepository) = InvoiceTaxViewModel(
        repository = repo,
        errorMapper = BillingErrorMapper(),
        savedStateHandle = SavedStateHandle(
            mapOf(InvoiceTaxViewModel.ARG_INVOICE_NUMBER to "INV-1"),
        ),
    )

    @Test
    fun load_success_exposesFlatBreakdown() = runTest {
        val repo = FakeInvoicesRepository().apply {
            taxResult = ApiResult.Success(
                InvoiceTax(
                    invoiceNumber = "INV-1",
                    subtotal = InvoiceMoney(120000, "usd"),
                    tax = InvoiceMoney(9900, "usd"),
                    total = InvoiceMoney(129900, "usd"),
                ),
            )
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        val content = model.uiState.value as InvoiceTaxUiState.Content
        assertEquals(120000L, content.tax.subtotal.cents)
        assertEquals(9900L, content.tax.tax.cents)
        assertEquals(129900L, content.tax.total.cents)
        // amount + tax == total
        assertEquals(content.tax.total.cents, content.tax.subtotal.cents + content.tax.tax.cents)
        job.cancel()
    }

    @Test
    fun load_derivesFromDetail_whenTaxResultUnset() = runTest {
        // taxResult == null -> the fake derives the projection from detailResult (the default sample).
        val repo = FakeInvoicesRepository()
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        val content = model.uiState.value as InvoiceTaxUiState.Content
        assertEquals(4500L, content.tax.subtotal.cents)
        assertEquals(400L, content.tax.tax.cents)
        assertEquals(4900L, content.tax.total.cents)
        job.cancel()
    }

    @Test
    fun load_serverError_isRetryable() = runTest {
        val repo = FakeInvoicesRepository().apply {
            taxResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertTrue((model.uiState.value as InvoiceTaxUiState.Error).retryable)
        job.cancel()
    }

    @Test
    fun load_404_isNonRetryable_thenRetrySucceeds() = runTest {
        val repo = FakeInvoicesRepository().apply {
            taxResult = ApiResult.Failure(ApiError(status = 404, message = "Invoice not found"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertFalse((model.uiState.value as InvoiceTaxUiState.Error).retryable)

        repo.taxResult = ApiResult.Success(
            InvoiceTax("INV-1", InvoiceMoney(1, "usd"), InvoiceMoney(0, "usd"), InvoiceMoney(1, "usd")),
        )
        model.retry()
        advanceUntilIdle()
        assertTrue(model.uiState.value is InvoiceTaxUiState.Content)
        job.cancel()
    }
}
