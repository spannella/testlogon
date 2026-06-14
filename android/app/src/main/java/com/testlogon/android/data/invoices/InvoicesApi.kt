package com.testlogon.android.data.invoices

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-243 — Retrofit interface + Moshi DTOs for the real invoices surface (extends the AND-223 billing
 * surface). These are the `/ui/invoices` endpoints; distinct from the AND-223 ledger/payments reads.
 *
 * VERIFIED against reference/openapi.index.txt + reference/src/api/endpoints/invoices.ts +
 * reference/src/api/types.ts (Invoice L8501, InvoiceLineItem L8495, InvoiceList L8521,
 * InvoiceEmailResult L8526). Money is uniformly integer cents (`*_cents`); timestamps are epoch-seconds
 * Longs. Session cookies + Authorization Bearer + X-CSRF-Token are attached by core-network interceptors.
 *
 * Endpoint citations (reference/openapi.index.txt):
 *  - GET  ui/invoices                          op=list_invoices_ui_invoices_get   resp=200:InvoiceListOut
 *      params=type,date_from,date_to,limit,cursor,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN
 *  - GET  ui/invoices/{invoice_number}         op=get_invoice_...                 resp=200:app__models__InvoiceOut
 *  - POST ui/invoices/{invoice_number}/email   op=email_invoice_...               resp=200:InvoiceEmailOut (empty body)
 *  - GET  ui/invoices/{invoice_number}/pdf      op=download_invoice_pdf_...        resp=200 (binary; opened in a browser)
 *
 * GAP NOTE: the web client (invoices.ts) does NOT paginate — it fetches limit:100 once and filters
 * client-side. Android uses cursor paging (next_cursor) as a forward-looking improvement; ordering is
 * backend-defined (no sort param exists). There is NO `has_more` boolean (next_cursor==null = end).
 * The list endpoint is a distinct invoices endpoint, NOT the AND-223 billing ledger.
 */
interface InvoicesApi {

    /** Paged invoice list (bare envelope {invoices, next_cursor}). date_from/date_to are epoch SECONDS. */
    @GET("ui/invoices")
    suspend fun listInvoices(
        @Query("cursor") cursor: String?,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
        @Query("type") type: String? = null,
        @Query("date_from") dateFrom: Long? = null,
        @Query("date_to") dateTo: Long? = null,
    ): InvoiceListDto

    /** Invoice detail. Path param is the STRING invoice_number (NOT a numeric id). Idempotent GET. */
    @GET("ui/invoices/{invoice_number}")
    suspend fun getInvoice(@Path("invoice_number") invoiceNumber: String): InvoiceDto

    /** Email a copy of the invoice. Empty body; recipient is server-determined. Non-idempotent. */
    @POST("ui/invoices/{invoice_number}/email")
    suspend fun emailInvoice(@Path("invoice_number") invoiceNumber: String): InvoiceEmailDto

    companion object {
        const val DEFAULT_LIMIT = 20
    }
}

// ---- DTOs (AND-243) ----

/** InvoiceListOut. Verified: types.ts InvoiceList (L8521). Wrapper field is `invoices` (NOT items). */
@JsonClass(generateAdapter = true)
data class InvoiceListDto(
    @Json(name = "invoices") val invoices: List<InvoiceDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/**
 * Invoice (app__models__InvoiceOut). Verified: types.ts Invoice (L8501). All amounts integer cents;
 * created_at is epoch SECONDS. Only invoice_id/invoice_number/invoice_type/user_sub/amount_cents/
 * total_cents are required upstream — everything else has a server default.
 */
@JsonClass(generateAdapter = true)
data class InvoiceDto(
    @Json(name = "invoice_id") val invoiceId: String,
    @Json(name = "invoice_number") val invoiceNumber: String,
    @Json(name = "invoice_type") val invoiceType: String,
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "tax_cents") val taxCents: Long = 0,
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "currency") val currency: String = "usd",
    @Json(name = "status") val status: String = "generated",
    @Json(name = "seller_id") val sellerId: String = "",
    @Json(name = "seller_name") val sellerName: String = "",
    @Json(name = "buyer_name") val buyerName: String = "",
    @Json(name = "buyer_email") val buyerEmail: String = "",
    @Json(name = "line_items") val lineItems: List<InvoiceLineItemDto> = emptyList(),
    @Json(name = "payment_method_summary") val paymentMethodSummary: String = "",
    @Json(name = "ledger_entry_id") val ledgerEntryId: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
)

/** InvoiceLineItemOut. Verified: types.ts InvoiceLineItem (L8495). No unit_amount; amount_cents only. */
@JsonClass(generateAdapter = true)
data class InvoiceLineItemDto(
    @Json(name = "description") val description: String = "",
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "quantity") val quantity: Int = 1,
)

/** InvoiceEmailOut. Verified: types.ts InvoiceEmailResult (L8526). Recipient is `emailed_to`. */
@JsonClass(generateAdapter = true)
data class InvoiceEmailDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "emailed_to") val emailedTo: String = "",
    @Json(name = "message") val message: String = "",
)
