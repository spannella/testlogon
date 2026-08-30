package com.testlogon.android.data.fees

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt
import com.testlogon.android.core.network.json.LenientLong
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * FE-152 — pay-any-coin fee QUOTE + checkout-order PAY, the Android mirror of the shipped web contract
 * (frontend/src/api/endpoints/fees.ts). A user can pay a USD-cent checkout total with ANY supported
 * coin from their custody balance:
 *
 *   1. POST me/fees/quote {amount_cents, pay_with} -> FeeQuoteDto (SHOWN rate + per-coin conversion
 *      fee + total native units + a 60s-locked, signed quote_token + expires_at).
 *   2. On confirm, POST ui/checkout/orders/{order_id}/pay {pay_with, quote_token} so the server honors
 *      the LOCKED rate. If the token expired the server returns 409 quote_expired -> re-quote.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; the
 * session cookie, Authorization: Bearer and X-CSRF-Token are attached by core-network interceptors.
 * These non-idempotent POSTs are never auto-retried. A non-2xx surfaces as retrofit2.HttpException;
 * the quote endpoint 404s on backends that predate pay-any-coin -> the repository degrades that to a
 * soft "crypto pay unavailable" rather than an error.
 */
interface FeesApi {

    /** POST me/fees/quote -> a 60s rate-locked FeeQuote for paying [FeeQuoteReqDto.amountCents]. */
    @Headers("Content-Type: application/json")
    @POST("me/fees/quote")
    suspend fun quoteFee(@Body body: FeeQuoteReqDto): FeeQuoteDto

    /** POST ui/checkout/orders/{order_id}/pay {pay_with, quote_token} -> pay result. */
    @Headers("Content-Type: application/json")
    @POST("ui/checkout/orders/{order_id}/pay")
    suspend fun payCheckoutOrder(
        @Path("order_id") orderId: String,
        @Body body: CheckoutPayReqDto,
    ): CheckoutPayResultDto
}

// ---- Request DTOs ----

/** Body for POST me/fees/quote. `pay_with` is a coin symbol ("USD"|"USDC"|"BTC"|"ETH"|"SOL"|...). */
@JsonClass(generateAdapter = true)
data class FeeQuoteReqDto(
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "pay_with") val payWith: String,
)

/** Body for POST ui/checkout/orders/{id}/pay: the locked quote is honored via {pay_with, quote_token}. */
@JsonClass(generateAdapter = true)
data class CheckoutPayReqDto(
    @Json(name = "pay_with") val payWith: String,
    @Json(name = "quote_token") val quoteToken: String,
)

// ---- Response DTOs (codegen Moshi; numerics lenient/defaulted so a partial shape parses) ----

/** Nested `rate` object of the fee quote. */
@JsonClass(generateAdapter = true)
data class FeeQuoteRateDto(
    @LenientLong @Json(name = "usd_cents_per_coin_native") val usdCentsPerCoinNative: Long? = null,
    @Json(name = "usd_per_whole_coin") val usdPerWholeCoin: Double? = null,
    @Json(name = "source") val source: String? = null,
)

/**
 * POST me/fees/quote response. Native amounts are integer base units (Long); rate/pct are display
 * Doubles. `quote_token` is the opaque signed token passed back to the pay call; `expires_at` is unix
 * seconds until which the locked rate is valid. Every field defaulted so an extra/partial body parses.
 */
@JsonClass(generateAdapter = true)
data class FeeQuoteDto(
    @Json(name = "pay_with") val payWith: String? = null,
    @LenientInt @Json(name = "asset_id") val assetId: Int? = null,
    @LenientLong @Json(name = "amount_cents") val amountCents: Long? = null,
    @Json(name = "rate") val rate: FeeQuoteRateDto? = null,
    @LenientInt @Json(name = "conversion_fee_bps") val conversionFeeBps: Int? = null,
    @Json(name = "conversion_fee_pct") val conversionFeePct: Double? = null,
    @LenientLong @Json(name = "coin_native") val coinNative: Long? = null,
    @LenientLong @Json(name = "conversion_fee_native") val conversionFeeNative: Long? = null,
    @LenientLong @Json(name = "total_native") val totalNative: Long? = null,
    @LenientLong @Json(name = "expires_at") val expiresAt: Long? = null,
    @LenientInt @Json(name = "locked_seconds") val lockedSeconds: Int? = null,
    @Json(name = "quote_token") val quoteToken: String? = null,
    @Json(name = "convertible") val convertible: Boolean? = null,
    @Json(name = "note") val note: String? = null,
)

/** POST ui/checkout/orders/{id}/pay result. Free-ish; the fields the confirm UX reads are typed. */
@JsonClass(generateAdapter = true)
data class CheckoutPayResultDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "currency") val currency: String? = null,
    @LenientLong @Json(name = "amount_cents") val amountCents: Long? = null,
    @LenientLong @Json(name = "coin_native_debited") val coinNativeDebited: Long? = null,
    @Json(name = "order_id") val orderId: String? = null,
    @Json(name = "txn_id") val txnId: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)
