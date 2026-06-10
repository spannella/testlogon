package com.testlogon.android.feature.invoices

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.invoices.EmailInvoiceResult
import com.testlogon.android.data.invoices.InvoiceDetail
import com.testlogon.android.data.invoices.InvoiceMoney
import com.testlogon.android.data.invoices.InvoicePage
import com.testlogon.android.data.invoices.InvoiceStatus
import com.testlogon.android.data.invoices.InvoiceSummary
import com.testlogon.android.data.invoices.InvoicesRepository

/**
 * AND-243 — a configurable [InvoicesRepository] test double for the paging-source + detail-VM tests.
 *
 * Records call counts (so tests can assert the email POST is hit exactly once / paging cursors are
 * threaded) and lets each method's result be programmed. NOT named like an interface member: sample
 * builders are [sampleInvoiceSummary] / [sampleInvoiceDetail] (per the test-helper gotcha).
 */
class FakeInvoicesRepository : InvoicesRepository {

    /** cursor -> page result. A null key is the first page. */
    var pages: MutableMap<String?, ApiResult<InvoicePage>> = mutableMapOf(
        null to ApiResult.Success(InvoicePage(emptyList(), null)),
    )
    var detailResult: ApiResult<InvoiceDetail> = ApiResult.Success(sampleInvoiceDetail())
    var emailResult: ApiResult<EmailInvoiceResult> =
        ApiResult.Success(EmailInvoiceResult(ok = true, emailedTo = "x@y.com", message = "ok"))

    var emailCalls = 0
        private set
    val requestedCursors = mutableListOf<String?>()

    override suspend fun getInvoices(cursor: String?, limit: Int): ApiResult<InvoicePage> {
        requestedCursors += cursor
        return pages[cursor] ?: ApiResult.Failure(ApiError(status = 500, message = "no page for $cursor"))
    }

    override suspend fun getInvoice(invoiceNumber: String): ApiResult<InvoiceDetail> = detailResult

    override suspend fun emailInvoice(invoiceNumber: String): ApiResult<EmailInvoiceResult> {
        emailCalls++
        return emailResult
    }

    override fun pdfUrl(invoiceNumber: String): String = "http://dev.example/ui/invoices/$invoiceNumber/pdf"
}

fun sampleInvoiceSummary(number: String = "INV-1"): InvoiceSummary = InvoiceSummary(
    invoiceNumber = number,
    invoiceId = "in_$number",
    invoiceType = "subscription",
    status = InvoiceStatus.GENERATED,
    total = InvoiceMoney(4900, "usd"),
    createdAtEpochSeconds = 1_746_100_800L,
)

fun sampleInvoiceDetail(number: String = "INV-1"): InvoiceDetail = InvoiceDetail(
    invoiceNumber = number,
    invoiceId = "in_$number",
    invoiceType = "subscription",
    status = InvoiceStatus.GENERATED,
    sellerName = "TestLogon Inc.",
    buyerName = "Sean P.",
    buyerEmail = "spannella@gmail.com",
    paymentMethodSummary = "Visa •••• 4242",
    lineItems = emptyList(),
    amount = InvoiceMoney(4500, "usd"),
    tax = InvoiceMoney(400, "usd"),
    total = InvoiceMoney(4900, "usd"),
    createdAtEpochSeconds = 1_746_100_800L,
)
