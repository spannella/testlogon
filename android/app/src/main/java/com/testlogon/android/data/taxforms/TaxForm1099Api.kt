package com.testlogon.android.data.taxforms

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Path

/**
 * AND-247 — Retrofit interface + Moshi DTOs for the creator-scoped 1099-NEC tax-forms surface.
 *
 * This is a DEDICATED 1099 endpoint family (NOT a filter of the AND-246 tax-documents history). The
 * backend issues 1099-NEC only — there is no form-type discriminator on the wire.
 *
 * VERIFIED against reference/openapi.index.txt (lines 1976..1979) + reference/src/api/endpoints/
 * taxForm1099.ts + openapi.pretty.json (TaxForm1099Out / TaxForm1099ListOut / TaxForm1099DownloadOut):
 *  - GET ui/tax-forms/1099s                       op=list_my_1099s_...     resp=200:TaxForm1099ListOut
 *      envelope key is `items` (NOT `documents`/`forms`)
 *  - GET ui/tax-forms/1099s/{tax_year}            op=get_my_1099_...       resp=200:TaxForm1099Out
 *      keyed by tax_year (integer), NOT a formId
 *  - GET ui/tax-forms/1099s/{tax_year}/download   op=download_my_1099_...  resp=200:TaxForm1099DownloadOut
 *      returns JSON { download_url } — NOT raw application/pdf bytes
 *
 * TaxForm1099Out: every field server-defaults (form_id may be ""; generated_at/updated_at are epoch
 * SECONDS integers; status is a free string default "generated"; correction_count int default 0;
 * total_earnings_cents integer minor units; payer_tin_last4 is last-4 only — no full/recipient TIN;
 * download_url is nullable on the list). Session cookies + Authorization Bearer + X-CSRF-Token are
 * attached by core-network interceptors.
 *
 * GAP NOTE: the `POST .../generate` creator endpoint exists but is out of scope (view/download only,
 * per AND-247 §13 OQ4). The PDF is opened from the JSON download_url via the AND-243 Custom Tabs
 * launcher (the URL may be presigned/external — treated as short-lived, never persisted/logged).
 */
interface TaxForm1099Api {

    /** List the user's 1099-NEC forms (no query params). Idempotent GET. Envelope key is `items`. */
    @GET("ui/tax-forms/1099s")
    suspend fun list1099s(): Form1099ListDto

    /** A single 1099-NEC, keyed by tax year (integer). Idempotent GET. */
    @GET("ui/tax-forms/1099s/{tax_year}")
    suspend fun get1099(@Path("tax_year") taxYear: Int): Form1099Dto

    /** The JSON download URL for the year's 1099 PDF (the bytes live at download_url). Idempotent GET. */
    @GET("ui/tax-forms/1099s/{tax_year}/download")
    suspend fun download1099Url(@Path("tax_year") taxYear: Int): Form1099DownloadDto
}

// ---- DTOs (AND-247) ----

/** TaxForm1099ListOut. Envelope key is `items` (verified openapi.pretty.json L72965). */
@JsonClass(generateAdapter = true)
data class Form1099ListDto(
    @Json(name = "items") val items: List<Form1099Dto> = emptyList(),
)

/**
 * TaxForm1099Out (openapi.pretty.json L72978). All fields server-default; tax_year is the row identity
 * (one 1099-NEC per user per year). generated_at/updated_at are epoch SECONDS.
 */
@JsonClass(generateAdapter = true)
data class Form1099Dto(
    @Json(name = "form_id") val formId: String = "",
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "tax_year") val taxYear: Int = 0,
    @Json(name = "total_earnings_cents") val totalEarningsCents: Long = 0,
    @Json(name = "qualifies") val qualifies: Boolean = false,
    @Json(name = "status") val status: String = "generated",
    @Json(name = "correction_count") val correctionCount: Int = 0,
    @Json(name = "payer_name") val payerName: String = "",
    @Json(name = "payer_tin_last4") val payerTinLast4: String = "",
    @Json(name = "generated_at") val generatedAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "download_url") val downloadUrl: String? = null,
)

/** TaxForm1099DownloadOut (openapi.pretty.json L72952). Single field `download_url`. */
@JsonClass(generateAdapter = true)
data class Form1099DownloadDto(
    @Json(name = "download_url") val downloadUrl: String = "",
)
