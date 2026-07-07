package com.testlogon.android.data.billing

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-223 — Retrofit interface + Moshi DTOs for the real billing surface.
 *
 * Verified against reference/openapi.index.txt (lines 1173..1201) and
 * reference/src/api/endpoints/billing.ts + reference/src/api/types.ts. Money is uniformly integer
 * cents (every backend amount field ends in `_cents`); timestamps are epoch numbers (ts/updated_at)
 * or ISO-8601 strings (next_billing_date). Session cookies, Authorization Bearer and X-CSRF-Token are
 * attached by core-network interceptors.
 *
 * Endpoint citations (reference/openapi.index.txt):
 *  - GET    ui/billing/config            L1176  (BillingConfig)
 *  - GET    ui/billing/settings          L1196  (BillingSettings)
 *  - GET    ui/billing/balance           L1173  (BillingBalance)
 *  - GET    ui/billing/subscriptions     L1199  (items wrapper)
 *  - GET    ui/billing/ledger            L1180  (items wrapper)
 *  - GET    ui/billing/payments          L1191  (items wrapper)
 *  - GET    ui/billing/wallet            L1201  (WalletBalance)
 *  - GET    ui/billing/payment-methods   L1185  (BARE ARRAY of PaymentMethod)
 *  - POST   ui/billing/payment-methods/default   L1187  (SetDefaultReq -> OkResp)
 *  - DELETE ui/billing/payment-methods/{id}      L1189  (-> OkResp, HTTP 200)
 *  - POST   ui/billing/checkout_session  L1175  (BillingCheckoutReq -> session_id,url)
 *  - POST   ui/billing/setup-intent/card L1197  (empty body -> client_secret) [AND-225/226 backend seam]
 *
 * GAP NOTE: setup-intent/card returns ONLY `client_secret` (no customer_id / ephemeral_key_secret /
 * publishable_key). The publishable key comes from GET ui/billing/config. See [BillingApi.createCardSetupIntent].
 */
interface BillingApi {

    @GET("ui/billing/config")
    suspend fun getConfig(): BillingConfigDto

    @GET("ui/billing/settings")
    suspend fun getSettings(): BillingSettingsDto

    @GET("ui/billing/balance")
    suspend fun getBalance(): BillingBalanceDto

    @GET("ui/billing/subscriptions")
    suspend fun getSubscriptions(@Query("limit") limit: Int = DEFAULT_LIMIT): SubscriptionListDto

    @GET("ui/billing/ledger")
    suspend fun getLedger(@Query("limit") limit: Int = DEFAULT_LIMIT): LedgerPageDto

    @GET("ui/billing/payments")
    suspend fun getPayments(@Query("limit") limit: Int = DEFAULT_LIMIT): LedgerPageDto

    @GET("ui/billing/wallet")
    suspend fun getWallet(): WalletBalanceDto

    /** Bare JSON array `PaymentMethod[]` — the default is each item's own `is_default` flag. */
    @GET("ui/billing/payment-methods")
    suspend fun getPaymentMethods(): List<PaymentMethodDto>

    /** Set-default takes the id in the JSON body (NOT a path segment). Returns OkResp. */
    @POST("ui/billing/payment-methods/default")
    suspend fun setDefaultPaymentMethod(@Body body: SetDefaultReqDto): OkRespDto

    /** Delete returns OkResp at HTTP 200 (NOT 204). */
    @DELETE("ui/billing/payment-methods/{payment_method_id}")
    suspend fun deletePaymentMethod(@Path("payment_method_id") paymentMethodId: String): OkRespDto

    /** TIP-102 - the per-user tip-default payment method (distinct from the general default). */
    @GET("ui/billing/payment-methods/tip-default")
    suspend fun getTipDefault(): TipDefaultDto

    /** TIP-102/104 - set the tip-default PM (same body shape as set-default). Returns OkResp. */
    @POST("ui/billing/payment-methods/tip-default")
    suspend fun setTipDefault(@Body body: SetDefaultReqDto): OkRespDto

    @POST("ui/billing/checkout_session")
    suspend fun createCheckoutSession(@Body body: CheckoutSessionRequestDto): CheckoutSessionDto

    /**
     * AND-225/226 backend seam. Empty body; returns ONLY `{ client_secret }`. Confirming this
     * SetupIntent (and tokenizing a card) requires the Stripe Android SDK, which is FLAGGED and NOT
     * integrated — see [CardTokenizer] / [StubCardTokenizer]. The add-card UI never calls this.
     */
    @POST("ui/billing/setup-intent/card")
    suspend fun createCardSetupIntent(): SetupIntentDto

    /**
     * DEV/TEST add-card (BK-C backend hotfix). Mirrors the web client's "type a fake test card"
     * flow: posts the raw test card number/exp/cvc directly (NO Stripe.js / on-device tokenization),
     * the backend creates the PaymentMethod against the prod stripe-mock. Returns the created method.
     * Works in DEV_MODE; card-add also works against a real provider. Auth = ui session cookie.
     */
    @POST("ui/billing/payment-methods/card")
    suspend fun addCard(@Body body: AddCardReqDto): AddPaymentMethodResultDto

    /**
     * DEV/TEST add-bank (BK-C backend hotfix). Adds a FAKE US bank checking/savings account directly
     * from routing + account numbers (NO Stripe Financial Connections). DEV_MODE only — the backend
     * 400s in real production (use the hosted bank flow there). Returns the created method.
     */
    @POST("ui/billing/payment-methods/us-bank")
    suspend fun addBank(@Body body: AddBankReqDto): AddPaymentMethodResultDto

    companion object {
        const val DEFAULT_LIMIT = 50
    }
}

// ---- DTOs (AND-223) ----

/** Subscription (types.ts: Subscription L658). plan_id required; period is next_billing_date (ISO). */
@JsonClass(generateAdapter = true)
data class SubscriptionDto(
    @Json(name = "subscription_id") val subscriptionId: String,
    @Json(name = "plan_id") val planId: String,
    @Json(name = "status") val status: String,
    @Json(name = "billing_cycle") val billingCycle: String? = null,
    @Json(name = "next_billing_date") val nextBillingDate: String? = null,
)

@JsonClass(generateAdapter = true)
data class SubscriptionListDto(
    @Json(name = "items") val items: List<SubscriptionDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class BillingConfigDto(
    @Json(name = "publishable_key") val publishableKey: String? = null,
    @Json(name = "currency") val currency: String,
)

@JsonClass(generateAdapter = true)
data class BillingSettingsDto(
    @Json(name = "autopay_enabled") val autopayEnabled: Boolean,
    @Json(name = "currency") val currency: String,
    @Json(name = "default_payment_method_id") val defaultPaymentMethodId: String? = null,
    @Json(name = "default_payment_token_id") val defaultPaymentTokenId: String? = null,
)

/** All amounts integer cents; updated_at epoch seconds. */
@JsonClass(generateAdapter = true)
data class BillingBalanceDto(
    @Json(name = "currency") val currency: String,
    @Json(name = "owed_pending_cents") val owedPendingCents: Long,
    @Json(name = "owed_settled_cents") val owedSettledCents: Long,
    @Json(name = "payments_pending_cents") val paymentsPendingCents: Long,
    @Json(name = "payments_settled_cents") val paymentsSettledCents: Long,
    @Json(name = "due_pending_cents") val duePendingCents: Long? = null,
    @Json(name = "due_settled_cents") val dueSettledCents: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** LedgerEntry (types.ts L648). amount_cents integer; ts epoch number. */
@JsonClass(generateAdapter = true)
data class LedgerEntryDto(
    @Json(name = "sk") val sk: String,
    @Json(name = "type") val type: String,
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "state") val state: String,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "ts") val ts: Long,
)

@JsonClass(generateAdapter = true)
data class LedgerPageDto(
    @Json(name = "items") val items: List<LedgerEntryDto> = emptyList(),
)

/** PaymentMethod (types.ts L634). Key field is payment_method_id; brand/last4/exp_* optional. */
@JsonClass(generateAdapter = true)
data class PaymentMethodDto(
    @Json(name = "payment_method_id") val paymentMethodId: String,
    @Json(name = "method_type") val methodType: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "brand") val brand: String? = null,
    @Json(name = "last4") val last4: String? = null,
    @Json(name = "exp_month") val expMonth: Int? = null,
    @Json(name = "exp_year") val expYear: Int? = null,
    @Json(name = "priority") val priority: Int,
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "provider_method_id") val providerMethodId: String? = null,
    @Json(name = "is_default") val isDefault: Boolean,
)

@JsonClass(generateAdapter = true)
data class WalletBalanceDto(
    @Json(name = "wallet_balance_cents") val walletBalanceCents: Long,
    @Json(name = "currency") val currency: String,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** BillingCheckoutReq (types.ts L767). amount_cents required. */
@JsonClass(generateAdapter = true)
data class CheckoutSessionRequestDto(
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "description") val description: String? = null,
)

@JsonClass(generateAdapter = true)
data class CheckoutSessionDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "url") val url: String,
)

/** SetDefaultReq (types.ts L763). */
@JsonClass(generateAdapter = true)
data class SetDefaultReqDto(
    @Json(name = "payment_method_id") val paymentMethodId: String,
)

/** TIP-102 - GET tip-default response: the tip-default PM id (null when unset). */
@JsonClass(generateAdapter = true)
data class TipDefaultDto(
    @Json(name = "tip_default_payment_method_id") val tipDefaultPaymentMethodId: String? = null,
)

/** OkResp (types.ts L2840). Generic mutation envelope. */
@JsonClass(generateAdapter = true)
data class OkRespDto(
    @Json(name = "ok") val ok: Boolean? = null,
)

/** setup-intent/card response — ONLY client_secret. See [BillingApi.createCardSetupIntent] gap note. */
@JsonClass(generateAdapter = true)
data class SetupIntentDto(
    @Json(name = "client_secret") val clientSecret: String,
)

/**
 * BK-C add-card request. Plain test-card fields (e.g. 4242 4242 4242 4242). Sent ONLY in dev/test —
 * mirrors the web client's manual card entry. No real PAN should ever be typed here.
 */
@JsonClass(generateAdapter = true)
data class AddCardReqDto(
    @Json(name = "card_number") val cardNumber: String,
    @Json(name = "exp_month") val expMonth: Int,
    @Json(name = "exp_year") val expYear: Int,
    @Json(name = "cvc") val cvc: String,
    @Json(name = "cardholder_name") val cardholderName: String? = null,
)

/**
 * BK-C add-bank request. Routing (9 digits) + account number (4-17 digits) for a FAKE US bank account.
 * account_holder_type: "individual"|"company"; account_type: "checking"|"savings".
 */
@JsonClass(generateAdapter = true)
data class AddBankReqDto(
    @Json(name = "routing_number") val routingNumber: String,
    @Json(name = "account_number") val accountNumber: String,
    @Json(name = "account_holder_type") val accountHolderType: String = "individual",
    @Json(name = "account_type") val accountType: String = "checking",
    @Json(name = "account_holder_name") val accountHolderName: String? = null,
)

/**
 * BK-C add-card / add-bank response. The endpoints return the newly created method (a subset of the
 * list DTO's fields); only `payment_method_id` is needed to confirm success — the screen re-fetches
 * the authoritative list afterward. All other fields are optional/defensive.
 */
@JsonClass(generateAdapter = true)
data class AddPaymentMethodResultDto(
    @Json(name = "payment_method_id") val paymentMethodId: String,
    @Json(name = "method_type") val methodType: String? = null,
    @Json(name = "brand") val brand: String? = null,
    @Json(name = "bank_name") val bankName: String? = null,
    @Json(name = "last4") val last4: String? = null,
    @Json(name = "label") val label: String? = null,
)
