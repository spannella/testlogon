package com.testlogon.android.data.payouts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path

/**
 * PAY-13 — Retrofit interface + Moshi DTOs for the ROUTABLE payout-method surface (PAY-10..12 backend).
 *
 * Endpoint citations (app/routers/creator_payouts.py):
 *  - GET    ui/payouts/methods                       -> PayoutMethodListOut
 *  - POST   ui/payouts/methods                       (PayoutMethodIn)       -> 201 PayoutMethodOut
 *  - PUT    ui/payouts/methods/{method_id}           (PayoutMethodUpdateIn) -> PayoutMethodOut
 *  - DELETE ui/payouts/methods/{method_id}           -> 204
 *  - POST   ui/payouts/methods/{method_id}/default   -> PayoutMethodOut
 *  - POST   ui/payouts/methods/{method_id}/verify    -> PayoutMethodOut   (PAY-12 verification seam)
 *  - GET    ui/payouts/connect                       -> ConnectAccountOut
 *  - POST   ui/payouts/connect/account               -> 201 ConnectAccountOut (PAY-11)
 *  - POST   ui/payouts/connect/onboarding-link       -> ConnectOnboardingOut  (PAY-11)
 *
 * SEC-004: the bank `account_number`/`routing_number` are WRITE-ONLY inputs — sent on POST, tokenized
 * server-side, and NEVER returned. The server only ever echoes `account_last4`/`routing_last4` + an
 * opaque `external_account_ref`. This app therefore never persists/displays a full account number.
 * Session cookies + Authorization Bearer + X-CSRF-Token are attached by core-network interceptors.
 */
interface PayoutMethodsApi {

    /** List the current user's routable payout methods (with status + default flag). Idempotent GET. */
    @GET("ui/payouts/methods")
    suspend fun listMethods(): PayoutMethodListDto

    /** Add a routable destination. Bank number/routing are tokenized server-side. Mutation (CSRF). */
    @POST("ui/payouts/methods")
    suspend fun addMethod(@Body body: PayoutMethodInDto): PayoutMethodOutDto

    /** Rename a method. Mutation (CSRF). */
    @PUT("ui/payouts/methods/{method_id}")
    suspend fun updateMethod(
        @Path("method_id") methodId: String,
        @Body body: PayoutMethodUpdateDto,
    ): PayoutMethodOutDto

    /** Remove a method (204). Mutation (CSRF). */
    @DELETE("ui/payouts/methods/{method_id}")
    suspend fun deleteMethod(@Path("method_id") methodId: String): Response<Unit>

    /** Set a method as the default payout destination. Mutation (CSRF). */
    @POST("ui/payouts/methods/{method_id}/default")
    suspend fun setDefault(@Path("method_id") methodId: String): PayoutMethodOutDto

    /** PAY-12 — verify a method (mock -> verified; real -> micro-deposit/instant). Mutation (CSRF). */
    @POST("ui/payouts/methods/{method_id}/verify")
    suspend fun verifyMethod(@Path("method_id") methodId: String): PayoutMethodOutDto

    /** PAY-11 — the creator's Stripe Connect account status (creates none). Idempotent GET. */
    @GET("ui/payouts/connect")
    suspend fun getConnect(): ConnectAccountDto

    /** PAY-11 — create (or return) the creator's Connect account id. Mutation (CSRF). */
    @POST("ui/payouts/connect/account")
    suspend fun createConnectAccount(): ConnectAccountDto

    /** PAY-11 — a Connect onboarding link (real AccountLink when keyed; mock completes). Mutation. */
    @POST("ui/payouts/connect/onboarding-link")
    suspend fun createConnectOnboardingLink(): ConnectOnboardingDto
}

// ---- DTOs (PAY-13) ----

/**
 * PayoutMethodIn. `account_number`/`routing_number` are WRITE-ONLY (SEC-004) — tokenized server-side.
 * `method_type` in {bank_ach, bank_wire, paypal, check, stripe_connect}. Retrofit serializes every
 * field; the server ignores those irrelevant to the chosen type.
 */
@JsonClass(generateAdapter = true)
data class PayoutMethodInDto(
    @Json(name = "method_type") val methodType: String,
    @Json(name = "account_number") val accountNumber: String = "",
    @Json(name = "routing_number") val routingNumber: String = "",
    @Json(name = "paypal_email") val paypalEmail: String = "",
    @Json(name = "connect_account_id") val connectAccountId: String = "",
    @Json(name = "nickname") val nickname: String = "",
    @Json(name = "set_as_default") val setAsDefault: Boolean = false,
)

/** PayoutMethodUpdateIn — rename only. */
@JsonClass(generateAdapter = true)
data class PayoutMethodUpdateDto(
    @Json(name = "nickname") val nickname: String,
)

/**
 * PayoutMethodOut. Never carries a full account number — only last-4 + an opaque `external_account_ref`
 * (SEC-004). `method_status` in {unverified, verifying, verified, failed}.
 */
@JsonClass(generateAdapter = true)
data class PayoutMethodOutDto(
    @Json(name = "method_id") val methodId: String,
    @Json(name = "method_type") val methodType: String = "",
    @Json(name = "account_last4") val accountLast4: String = "",
    @Json(name = "routing_last4") val routingLast4: String = "",
    @Json(name = "paypal_email") val paypalEmail: String = "",
    @Json(name = "nickname") val nickname: String = "",
    @Json(name = "is_default") val isDefault: Boolean = false,
    @Json(name = "method_status") val methodStatus: String = "unverified",
    @Json(name = "connect_account_id") val connectAccountId: String = "",
    @Json(name = "external_account_ref") val externalAccountRef: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

/** PayoutMethodListOut. */
@JsonClass(generateAdapter = true)
data class PayoutMethodListDto(
    @Json(name = "methods") val methods: List<PayoutMethodOutDto> = emptyList(),
)

/** ConnectAccountOut (PAY-11). */
@JsonClass(generateAdapter = true)
data class ConnectAccountDto(
    @Json(name = "connect_account_id") val connectAccountId: String = "",
    @Json(name = "onboarding_status") val onboardingStatus: String = "pending",
    @Json(name = "payouts_enabled") val payoutsEnabled: Boolean = false,
)

/** ConnectOnboardingOut (PAY-11). `onboarding_url` is empty under the mock (which self-completes). */
@JsonClass(generateAdapter = true)
data class ConnectOnboardingDto(
    @Json(name = "connect_account_id") val connectAccountId: String = "",
    @Json(name = "onboarding_url") val onboardingUrl: String = "",
    @Json(name = "onboarding_status") val onboardingStatus: String = "pending",
    @Json(name = "payouts_enabled") val payoutsEnabled: Boolean = false,
    @Json(name = "real") val real: Boolean = false,
)
