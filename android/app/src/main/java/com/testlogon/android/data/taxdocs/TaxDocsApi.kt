package com.testlogon.android.data.taxdocs

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-246 — Retrofit interface + Moshi DTOs for the real tax-documents (annual earnings summaries)
 * surface. Distinct from the 1099 forms under `/ui/tax-forms/1099s*` (AND-247).
 *
 * VERIFIED against reference/openapi.index.txt + reference/src/api/types.ts:
 *  - GET ui/tax-documents/history             op=get_history_...   resp=200:TaxDocumentListOut
 *      (openapi.index.txt L1973; NO query params for the user-facing list)
 *  - GET ui/tax-documents/document/{year}/pdf op=download_document_pdf_... resp=200 (binary PDF)
 *      (openapi.index.txt L1971; keyed by YEAR)
 *
 * PAR-24 — adds the EARNINGS summary (FIN-004):
 *  - GET ui/tax-documents/summary?year={year}  resp=200:TaxSpendingSummaryOut
 *      cpp h_ctax_summary (main.cpp). REQUIRES a `year` (or a date range) → 422 if none, so the
 *      client ALWAYS passes a year (defaulting to the current year). Category money field is
 *      `total_cents` (NOT amount_cents), verified in handlers_c8.cpp ctax_earnings_summary.
 *
 * TaxDocument (types.ts L9476): doc_id (the only required field) + doc_type/year?/date_from/date_to/
 * grand_total_cents/transaction_count/currency/created_at (all server-defaulted). TaxDocumentList
 * (types.ts L9488) wraps them under the `documents` key. Money is integer cents; dates are epoch SECONDS.
 *
 * The PDF is opened in a Custom Tab via the absolute URL built by the repository (reusing the AND-243
 * InvoicePdfLauncher pattern), so the session cookies ride along — no @Streaming/FileProvider needed here.
 */
interface TaxDocsApi {

    /** List the user's generated tax documents (no query params). Idempotent GET. */
    @GET("ui/tax-documents/history")
    suspend fun listTaxDocuments(): TaxDocumentListDto

    /**
     * PAR-24 — earnings summary for a single [year] (total + per-category + txn count). MUST send a
     * year or the backend returns 422. Idempotent GET.
     */
    @GET("ui/tax-documents/summary")
    suspend fun getSummary(@Query("year") year: Int): TaxSpendingSummaryDto
}

// ---- DTOs (AND-246) ----

/** TaxDocumentListOut. Envelope key is `documents` (verified types.ts L9488). */
@JsonClass(generateAdapter = true)
data class TaxDocumentListDto(
    @Json(name = "documents") val documents: List<TaxDocumentDto> = emptyList(),
)

/** TaxDocumentOut (types.ts L9476). Only doc_id is required; everything else server-defaults. */
@JsonClass(generateAdapter = true)
data class TaxDocumentDto(
    @Json(name = "doc_id") val docId: String,
    @Json(name = "doc_type") val docType: String = "annual_summary",
    @Json(name = "year") val year: Int? = null,
    @Json(name = "date_from") val dateFrom: Long = 0,
    @Json(name = "date_to") val dateTo: Long = 0,
    @Json(name = "grand_total_cents") val grandTotalCents: Long = 0,
    @Json(name = "transaction_count") val transactionCount: Int = 0,
    @Json(name = "currency") val currency: String = "usd",
    @Json(name = "created_at") val createdAt: Long = 0,
)

// ---- DTOs (PAR-24 earnings summary) ----

/**
 * TaxSpendingSummaryOut (semantically an EARNINGS summary, FIN-004). Verified against
 * handlers_c8.cpp `ctax_earnings_summary`/`ctax_compute_summary`: date_from/date_to (epoch seconds),
 * categories, grand_total_cents, transaction_count, currency.
 */
@JsonClass(generateAdapter = true)
data class TaxSpendingSummaryDto(
    @Json(name = "date_from") val dateFrom: Long = 0,
    @Json(name = "date_to") val dateTo: Long = 0,
    @Json(name = "categories") val categories: List<SpendingCategoryDto> = emptyList(),
    @Json(name = "grand_total_cents") val grandTotalCents: Long = 0,
    @Json(name = "transaction_count") val transactionCount: Int = 0,
    @Json(name = "currency") val currency: String = "usd",
)

/** A single earnings category row. Money field is `total_cents` (verified cpp, NOT amount_cents). */
@JsonClass(generateAdapter = true)
data class SpendingCategoryDto(
    @Json(name = "category") val category: String = "other",
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "transaction_count") val transactionCount: Int = 0,
)
