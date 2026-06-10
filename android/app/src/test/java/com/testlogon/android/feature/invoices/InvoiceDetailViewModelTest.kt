package com.testlogon.android.feature.invoices

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.invoices.EmailInvoiceResult
import com.testlogon.android.feature.billing.error.BillingErrorMapper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-243 — [InvoiceDetailViewModel] transitions: load -> Content / Error(retryable) / Error(404
 * non-retryable); email Idle->Sending->Sent / ->Error with the in-flight guard preventing a duplicate
 * POST; the View-PDF one-shot event carries the absolute URL.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class InvoiceDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: FakeInvoicesRepository) = InvoiceDetailViewModel(
        repository = repo,
        errorMapper = BillingErrorMapper(),
        savedStateHandle = SavedStateHandle(
            mapOf(InvoiceDetailViewModel.ARG_INVOICE_NUMBER to "INV-1"),
        ),
    )

    @Test
    fun load_success_emitsContent() = runTest {
        val repo = FakeInvoicesRepository().apply { detailResult = ApiResult.Success(sampleInvoiceDetail()) }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(model.uiState.value is InvoiceDetailUiState.Content)
        job.cancel()
    }

    @Test
    fun load_serverError_isRetryable() = runTest {
        val repo = FakeInvoicesRepository().apply {
            detailResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        val state = model.uiState.value as InvoiceDetailUiState.Error
        assertTrue(state.retryable)
        job.cancel()
    }

    @Test
    fun load_404_isNonRetryable() = runTest {
        val repo = FakeInvoicesRepository().apply {
            detailResult = ApiResult.Failure(ApiError(status = 404, message = "Invoice not found"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        val state = model.uiState.value as InvoiceDetailUiState.Error
        assertFalse(state.retryable)
        job.cancel()
    }

    @Test
    fun email_success_transitionsToSent_withRecipient() = runTest {
        val repo = FakeInvoicesRepository().apply {
            emailResult = ApiResult.Success(EmailInvoiceResult(ok = true, emailedTo = "a@b.com", message = "ok"))
        }
        val model = vm(repo)
        val job = launch { model.emailState.collect {} }
        advanceUntilIdle()

        model.onEmailClicked()
        advanceUntilIdle()

        val sent = model.emailState.value as EmailUiState.Sent
        assertEquals("a@b.com", sent.emailedTo)
        assertEquals(1, repo.emailCalls)
        job.cancel()
    }

    @Test
    fun email_failure_transitionsToError() = runTest {
        val repo = FakeInvoicesRepository().apply {
            emailResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(repo)
        val job = launch { model.emailState.collect {} }
        advanceUntilIdle()

        model.onEmailClicked()
        advanceUntilIdle()

        assertTrue(model.emailState.value is EmailUiState.Error)
        job.cancel()
    }

    @Test
    fun email_doubleTap_inFlight_sendsOnlyOnePost() = runTest {
        val repo = FakeInvoicesRepository().apply {
            emailResult = ApiResult.Success(EmailInvoiceResult(ok = true, emailedTo = "a@b.com", message = "ok"))
        }
        val model = vm(repo)
        val job = launch { model.emailState.collect {} }
        advanceUntilIdle()

        // First tap flips to Sending synchronously; the second is swallowed by the in-flight guard.
        model.onEmailClicked()
        model.onEmailClicked()
        advanceUntilIdle()

        assertEquals(1, repo.emailCalls)
        job.cancel()
    }

    @Test
    fun viewPdf_emitsViewPdfEvent_withUrl() = runTest {
        val repo = FakeInvoicesRepository()
        val model = vm(repo)
        val events = mutableListOf<InvoiceDetailEvent>()
        val ejob = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch { model.events.toList(events) }
        advanceUntilIdle()

        model.onViewPdfClicked()
        advanceUntilIdle()

        val pdf = events.single() as InvoiceDetailEvent.ViewPdf
        assertEquals("http://dev.example/ui/invoices/INV-1/pdf", pdf.url)
        ejob.cancel()
    }
}
