package com.testlogon.android.data.payouts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-259 — Retrofit interface + Moshi DTOs for the real KYC tier surface that drives the payout gate.
 *
 * VERIFIED against reference/openapi.index.txt + reference/src/api/endpoints/kyc-tiers.ts +
 * reference/src/api/types.ts (TierDetails L5597, TierRequirements L5605).
 *
 * Endpoint citations (reference/openapi.index.txt) — note there is NO `/api` prefix:
 *  - GET  v1/kyc/tiers/me                           op=get_my_tier_...           resp=200 (untyped {}, shape from types.ts)
 *  - GET  v1/kyc/tiers/me/requirements/{target_tier} op=check_my_requirements_... resp=200 (TierRequirements)
 *  - POST v1/kyc/tiers/me/evaluate                   op=evaluate_my_tier_...       resp=200 (TierDetails)
 *
 * This is the tier READ surface only. The IDENTITY-VERIFICATION launch (Stripe Identity / Persona /
 * Onfido) is a HUMAN-DECISION vendor SDK and is NOT performed here — see [KycVerifier]. `evaluate` is a
 * mutation (CSRF) used to refresh tier state after a (scaffolded) verification return; it does NOT
 * launch a vendor flow, it only asks the backend to re-derive the tier from already-submitted evidence.
 */
interface KycApi {

    /** Current KYC tier rank + name (TierDetails). Idempotent GET. */
    @GET("v1/kyc/tiers/me")
    suspend fun getMyTier(): TierDetailsDto

    /** Requirements toward [targetTier]: met/unmet code arrays + eligible boolean. Idempotent GET. */
    @GET("v1/kyc/tiers/me/requirements/{target_tier}")
    suspend fun getRequirements(@Path("target_tier") targetTier: Int): TierRequirementsDto

    /** Re-evaluate the tier from submitted evidence (refresh after KYC return). Mutation; not retried. */
    @POST("v1/kyc/tiers/me/evaluate")
    suspend fun evaluate(): TierDetailsDto
}

// ---- DTOs (AND-259) ----

/**
 * TierDetails. OpenAPI declares the 200 body as untyped `{}`; field names are sourced from
 * types.ts (authoritative). `current_tier` is an INTEGER rank (NOT a string enum); `tier_name` is a
 * server-supplied label. There is NO `required_tier_for_payouts` and NO `missing_requirements` here.
 */
@JsonClass(generateAdapter = true)
data class TierDetailsDto(
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "current_tier") val currentTier: Int = 0,
    @Json(name = "tier_name") val tierName: String = "",
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** TierRequirements. met/unmet are requirement CODE strings; `eligible` drives the gate. */
@JsonClass(generateAdapter = true)
data class TierRequirementsDto(
    @Json(name = "target_tier") val targetTier: Int = 0,
    @Json(name = "current_tier") val currentTier: Int = 0,
    @Json(name = "met") val met: List<String> = emptyList(),
    @Json(name = "unmet") val unmet: List<String> = emptyList(),
    @Json(name = "eligible") val eligible: Boolean = false,
)
