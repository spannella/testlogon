package com.testlogon.android.data.cash

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt
import com.testlogon.android.core.network.json.LenientLong
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * Retrofit interface for the FIAT (USD) wallet — the SAME real /ui/billing/wallet surface the web app
 * uses (frontend/src/api/endpoints/billing.ts). This is the `pay_with: "USD"` cash balance used for
 * trading, margin & fees. Paths are relative (no leading slash) so they resolve against the shared
 * Retrofit base URL; the session cookie + CSRF header are attached by the core-network interceptor
 * chain. All methods are suspend and return the typed DTO; a non-2xx surfaces as retrofit2.HttpException.
 *
 * A distinct thin API (rather than reusing data/billing/BillingApi) keeps the Cash feature self-contained
 * and adds the deposit/withdraw mutations that BillingApi does not carry.
 */
interface CashApi {

    /** GET ui/billing/wallet -> {wallet_balance_cents, currency}. Read degrades on 404. */
    @GET("ui/billing/wallet")
    suspend fun wallet(): WalletDto

    /** GET ui/billing/payment-methods -> BARE ARRAY of payment methods. Read degrades on 404. */
    @GET("ui/billing/payment-methods")
    suspend fun paymentMethods(): List<CashPaymentMethodDto>

    /** POST ui/billing/wallet/deposit {amount_cents, payment_method_id?} -> deposit result. */
    @Headers("Content-Type: application/json")
    @POST("ui/billing/wallet/deposit")
    suspend fun deposit(@Body body: WalletDepositRequestDto): WalletDepositResultDto

    /** POST ui/billing/wallet/withdraw {amount_cents} -> {ok, wallet_balance_cents}. */
    @Headers("Content-Type: application/json")
    @POST("ui/billing/wallet/withdraw")
    suspend fun withdraw(@Body body: WalletWithdrawRequestDto): WalletWithdrawResultDto
}

// ---- Wire DTOs (codegen-only Moshi; numerics lenient; every field defaulted so a partial shape parses) ----

/** GET ui/billing/wallet. wallet_balance_cents integer cents; currency e.g. "USD". */
@JsonClass(generateAdapter = true)
data class WalletDto(
    @LenientLong @Json(name = "wallet_balance_cents") val walletBalanceCents: Long? = null,
    @Json(name = "currency") val currency: String? = null,
    @LenientLong @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** One saved payment method (subset consumed by the deposit picker). */
@JsonClass(generateAdapter = true)
data class CashPaymentMethodDto(
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
    @Json(name = "method_type") val methodType: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "brand") val brand: String? = null,
    @Json(name = "last4") val last4: String? = null,
    @LenientInt @Json(name = "priority") val priority: Int? = null,
    @Json(name = "is_default") val isDefault: Boolean? = null,
)

/** Body for POST ui/billing/wallet/deposit. */
@JsonClass(generateAdapter = true)
data class WalletDepositRequestDto(
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

/** POST ui/billing/wallet/deposit result: {status, payment_intent_id, wallet_balance_cents}. */
@JsonClass(generateAdapter = true)
data class WalletDepositResultDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "payment_intent_id") val paymentIntentId: String? = null,
    @LenientLong @Json(name = "wallet_balance_cents") val walletBalanceCents: Long? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)

/** Body for POST ui/billing/wallet/withdraw. */
@JsonClass(generateAdapter = true)
data class WalletWithdrawRequestDto(
    @Json(name = "amount_cents") val amountCents: Long,
)

/** POST ui/billing/wallet/withdraw result: {ok, wallet_balance_cents}. */
@JsonClass(generateAdapter = true)
data class WalletWithdrawResultDto(
    @Json(name = "ok") val ok: Boolean? = null,
    @LenientLong @Json(name = "wallet_balance_cents") val walletBalanceCents: Long? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)
