package com.testlogon.android.data.payments

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.POST

/**
 * AND-228/229/230 — Retrofit interface + Moshi DTOs for the redirect-based payment providers.
 *
 * Verified against reference/openapi.index.txt + reference/src/api/endpoints/billing.ts:
 *  - POST api/billing/paypal/capture-order        L41  req=CaptureOrderIn  resp=200 (UNTYPED schema {})
 *  - POST api/billing/ccbill/frontend-oauth       L21  req=NONE  resp=200 (UNTYPED schema {})  [BACKEND GAP shapes]
 *  - POST ui/billing/us-bank/verify-microdeposits L1200 req=VerifyMicrodepositsReq resp=200:{additionalProperties:string}
 *  - POST ui/billing/setup-intent/us-bank         L1198 req=NONE resp=200 (client_secret) [initiation; AND-224/225]
 *
 * Session cookies, Authorization: Bearer and X-CSRF-Token are attached by core-network interceptors
 * (same shared stack as BillingApi). These are non-idempotent POSTs and are never auto-retried.
 *
 * GAP NOTES (cited in the spec audits):
 *  - PayPal capture-order 200 body is UNTYPED in OpenAPI (schema {}); capture_id/status field names are
 *    an unverified assumption — parsed defensively as an open map ([PayPalCaptureDto]). There is NO
 *    backend create-order / approval-url endpoint (BACKEND GAP, AND-228 §5); the approval-URL creation
 *    is therefore routed through the BillingAuthorizer stub and is INERT under NotConfigured.
 *  - CCBill frontend-oauth declares NO request body and an empty 200 schema; the request/response field
 *    names below are unverified assumptions (AND-229 §5). Real session creation is gated by the stub.
 *  - verify-microdeposits is the one fully-verified contract: req VerifyMicrodepositsReq
 *    {setup_intent_id (req), amounts:int[]?, descriptor_code?}; 200 = string map {"status": ...}.
 */
interface PaymentRedirectApi {

    /**
     * AND-228 — PayPal order capture (the only VERIFIED PayPal order endpoint). order_id is in the
     * BODY (not the path). Response is untyped in OpenAPI — parsed as an open map.
     */
    @POST("api/billing/paypal/capture-order")
    suspend fun capturePayPalOrder(@Body body: CaptureOrderRequestDto): Map<String, Any?>

    /**
     * AND-229 — CCBill frontend-OAuth authorization-URL fetch. Body shape is UNVERIFIED (OpenAPI
     * declares none); kept optional/defensive. Real session creation never reaches here under the stub.
     */
    @POST("api/billing/ccbill/frontend-oauth")
    suspend fun ccbillFrontendOauth(@Body body: CcbillOauthRequestDto): CcbillOauthResponseDto

    /** AND-230 — verify the two microdeposit amounts for a pending US bank setup intent (VERIFIED). */
    @POST("ui/billing/us-bank/verify-microdeposits")
    suspend fun verifyMicrodeposits(@Body body: VerifyMicrodepositsRequestDto): Map<String, String>
}

// ---- PayPal (AND-228) ----

/** CaptureOrderIn (openapi.pretty.json L14546). required: order_id; optional: idempotency_key. */
@JsonClass(generateAdapter = true)
data class CaptureOrderRequestDto(
    @Json(name = "order_id") val orderId: String,
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
)

/** Defensive view of the untyped capture 200 body. Field names unverified (OpenAPI schema {}). */
data class PayPalCaptureDto(
    val orderId: String?,
    val captureId: String?,
    val status: String?,
)

// ---- CCBill (AND-229) ----

/** ASSUMED CCBill request (OpenAPI declares no body; AND-229 §5 / OA-1). Confirm with backend. */
@JsonClass(generateAdapter = true)
data class CcbillOauthRequestDto(
    @Json(name = "flow_type") val flowType: String,
    @Json(name = "checkout_session_id") val checkoutSessionId: String? = null,
    @Json(name = "state") val state: String,
    @Json(name = "return_url") val returnUrl: String,
)

/** ASSUMED CCBill response (OpenAPI 200 schema is empty {}; AND-229 §5 / OA-2). Confirm with backend. */
@JsonClass(generateAdapter = true)
data class CcbillOauthResponseDto(
    @Json(name = "authorization_url") val authorizationUrl: String,
    @Json(name = "correlation_id") val correlationId: String? = null,
    @Json(name = "expires_at") val expiresAt: String? = null,
)

// ---- US bank micro-deposits (AND-230) ----

/** VerifyMicrodepositsReq (openapi.pretty.json L80423). required: setup_intent_id. amounts are cents. */
@JsonClass(generateAdapter = true)
data class VerifyMicrodepositsRequestDto(
    @Json(name = "setup_intent_id") val setupIntentId: String,
    @Json(name = "amounts") val amounts: List<Int>? = null,
    @Json(name = "descriptor_code") val descriptorCode: String? = null,
)
