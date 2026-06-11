package com.testlogon.android.data.taxdocs

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET

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
