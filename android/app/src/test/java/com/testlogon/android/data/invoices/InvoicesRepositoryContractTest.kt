package com.testlogon.android.data.invoices

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-243 — contract tests for [InvoicesRepositoryImpl] against MockWebServer using the production
 * Moshi/Retrofit config. Covers: list round-trip (path/query + bare {invoices,next_cursor} envelope +
 * epoch/minor-unit mapping), detail (string invoice_number path param, no unit_amount), email POST (path
 * + no body + no auto-retry on a 5xx), 404/422 error mapping, and the pdfUrl builder.
 */
class InvoicesRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): InvoicesRepositoryImpl {
        val api = backend.retrofit(moshi).create(InvoicesApi::class.java)
        return InvoicesRepositoryImpl(
            api = api,
            errorParser = ApiErrorParser(moshi),
            baseUrlProvider = { "http://dev.example/" },
        )
    }

    private val listBody = """
        {
          "invoices": [
            { "invoice_id": "in_1052", "invoice_number": "INV-2026-001052",
              "invoice_type": "subscription", "user_sub": "user_abc",
              "amount_cents": 4500, "tax_cents": 400, "total_cents": 4900, "currency": "usd",
              "status": "generated", "seller_name": "TestLogon Inc.",
              "line_items": [ { "description": "Pro plan", "quantity": 1, "amount_cents": 4500 } ],
              "payment_method_summary": "Visa •••• 4242", "created_at": 1746100800 }
          ],
          "next_cursor": null
        }
    """.trimIndent()

    @Test
    fun getInvoices_parsesEnvelope_mapsMoneyAndEpoch_andSendsLimit() = runTest {
        backend.enqueue(Fixtures.okBody(listBody))
        val result = repo().getInvoices(cursor = null, limit = 20)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(1, page.invoices.size)
        assertEquals("INV-2026-001052", page.invoices[0].invoiceNumber)
        assertEquals(4900L, page.invoices[0].total.cents)
        assertEquals(1746100800L, page.invoices[0].createdAtEpochSeconds)
        assertNull(page.nextCursor)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/invoices", req.requestUrl?.encodedPath)
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun getInvoices_passesCursor_whenPaging() = runTest {
        backend.enqueue(Fixtures.okBody("""{"invoices":[],"next_cursor":"c3"}"""))
        val result = repo().getInvoices(cursor = "c2", limit = 20)
        assertTrue(result is ApiResult.Success)
        assertEquals("c3", (result as ApiResult.Success).data.nextCursor)
        val req = backend.takeRequest()
        assertEquals("c2", req.requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun getInvoice_usesStringNumberPathParam_andMapsLineItems() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"invoice_id":"in_1","invoice_number":"INV-2026-001052","invoice_type":"shop",
                   "user_sub":"u1","amount_cents":1000,"tax_cents":0,"total_cents":1000,"currency":"usd",
                   "status":"emailed",
                   "line_items":[{"description":"Item","quantity":2,"amount_cents":1000}]}""",
            ),
        )
        val result = repo().getInvoice("INV-2026-001052")
        assertTrue(result is ApiResult.Success)
        val detail = (result as ApiResult.Success).data
        assertEquals(InvoiceStatus.EMAILED, detail.status)
        assertEquals(1, detail.lineItems.size)
        assertEquals(2, detail.lineItems[0].quantity)
        assertEquals(1000L, detail.lineItems[0].amount.cents)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/invoices/INV-2026-001052", req.requestUrl?.encodedPath)
    }

    @Test
    fun emailInvoice_postsToEmailPath_withNoBody_mapsRecipient() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"ok":true,"emailed_to":"x@y.com","message":"Invoice emailed."}"""),
        )
        val result = repo().emailInvoice("INV-2026-001052")
        assertTrue(result is ApiResult.Success)
        assertEquals("x@y.com", (result as ApiResult.Success).data.emailedTo)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/invoices/INV-2026-001052/email", req.requestUrl?.encodedPath)
        assertEquals(0L, req.bodySize)
    }

    @Test
    fun emailInvoice_serverError_isFailure_andNotAutoRetried() = runTest {
        backend.enqueue(Fixtures.okBody("boom", code = 500))
        val result = repo().emailInvoice("INV-2026-001052")
        assertTrue(result is ApiResult.Failure)
        // Exactly one POST reached the server (the email POST is never auto-retried by the repo).
        assertEquals(1, backend.requestCount)
        backend.takeRequest()
    }

    @Test
    fun getInvoice_404_mapsFailureWithStatus() = runTest {
        backend.enqueue(Fixtures.error("\"Invoice not found\"", 404))
        val result = repo().getInvoice("missing")
        assertTrue(result is ApiResult.Failure)
        assertEquals(404, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getInvoices_422_mapsFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query","cursor"],"msg":"bad","type":"value_error"}]""", 422))
        val result = repo().getInvoices(cursor = "x", limit = 20)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getInvoices_malformedBody_mapsFailure_neverCrashes() = runTest {
        backend.enqueue(Fixtures.malformed())
        val result = repo().getInvoices(cursor = null, limit = 20)
        // A parse failure surfaces as a (non-2xx-shaped) failure, not a thrown exception.
        assertTrue(result is ApiResult.Failure || result is ApiResult.NetworkError)
    }

    @Test
    fun pdfUrl_buildsAbsoluteEncodedUrl() {
        assertEquals(
            "http://dev.example/ui/invoices/INV-2026-001052/pdf",
            repo().pdfUrl("INV-2026-001052"),
        )
    }
}
