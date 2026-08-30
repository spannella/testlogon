package com.testlogon.android.data.tradingdocs

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * FE-170 (EPIC H) — Retrofit interface + Moshi DTOs for the "Trading Documents" surface (broker
 * statements, 1099s, trade confirmations, fills, pnl) exposed in the file manager.
 *
 * Backend contract (BE-171 list / BE-172 download) — built against the assumed contract, DEGRADES ON
 * 404 (the backend may not be deployed yet):
 *   - GET ui/trading-documents?type=<statement|1099|confirmation|fills|pnl>
 *       -> { documents: [ { doc_id, type, title, period_start?, period_end?, tax_year?,
 *                           format:"pdf"|"csv", size_bytes?, status:"ready"|"generating",
 *                           created_at, download_url? } ] }
 *       `type` is OPTIONAL (omitted => all types). Idempotent GET.
 *   - GET ui/trading-documents/{doc_id}/download -> { download_url } (presigned) OR streamed bytes.
 *
 * Mirrors the AND-246 TaxDocsApi idiom (envelope DTO + all-but-id server-defaulted fields). Money/size
 * are integers; timestamps are epoch seconds. Download is opened in a Custom Tab via the presigned
 * download_url (reusing the AND-243 InvoicePdfLauncher pattern), so session cookies ride along.
 */
interface TradingDocsApi {

    /** List the user's trading documents, optionally filtered by [type]. Idempotent GET. */
    @GET("ui/trading-documents")
    suspend fun listTradingDocuments(
        @Query("type") type: String? = null,
    ): TradingDocListDto

    /** Resolve a presigned download URL for [docId] (used when the list row carried no download_url). */
    @GET("ui/trading-documents/{doc_id}/download")
    suspend fun getDownload(
        @Path("doc_id") docId: String,
    ): TradingDocDownloadDto
}

// ---- DTOs ----

/** List envelope; documents under the `documents` key (mirrors TaxDocumentListDto). */
@JsonClass(generateAdapter = true)
data class TradingDocListDto(
    @Json(name = "documents") val documents: List<TradingDocDto> = emptyList(),
)

/** A single trading document. Only doc_id is required; every other field server-defaults. */
@JsonClass(generateAdapter = true)
data class TradingDocDto(
    @Json(name = "doc_id") val docId: String,
    @Json(name = "type") val type: String = "statement",
    @Json(name = "title") val title: String? = null,
    @Json(name = "period_start") val periodStart: Long? = null,
    @Json(name = "period_end") val periodEnd: Long? = null,
    @Json(name = "tax_year") val taxYear: Int? = null,
    @Json(name = "format") val format: String = "pdf",
    @Json(name = "size_bytes") val sizeBytes: Long? = null,
    @Json(name = "status") val status: String = "ready",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "download_url") val downloadUrl: String? = null,
)

/** Download resolution response (presigned URL). */
@JsonClass(generateAdapter = true)
data class TradingDocDownloadDto(
    @Json(name = "download_url") val downloadUrl: String? = null,
)
