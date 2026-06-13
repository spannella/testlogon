package com.testlogon.android.data.account

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.data.preferences.AccountStatusDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * AND-387 - Retrofit interface for the account lifecycle MUTATIONS (closure start/finalize, suspend,
 * reactivate). The idempotent status READ is owned by AND-082's `AccountStatusApi`
 * (`GET ui/account/status`) and is reused, not duplicated here.
 *
 * Verified (CORRECTED) against `reference/openapi.pretty.json` + `src/api/endpoints/account.ts`
 * (spec AND-387 §5 / §16):
 *   POST ui/account/closure/start     NO body      -> 200 ClosureStartDto {auth_required, challenge_id, required_factors}
 *   POST ui/account/closure/finalize  {challenge_id} -> 200 StatusOutDto {status}
 *   POST ui/account/suspend           {reason?}     -> 200 AccountStatusDto (AccountState)
 *   POST ui/account/reactivate        {reason?} (web sends none) -> 200 AccountStatusDto (AccountState)
 *
 * Provided on the SHARED authenticated Retrofit by [AccountLifecycleApiModule] - no new OkHttp/Retrofit.
 * Paths are relative (no leading slash) so they resolve against the shared base URL; cookies and the
 * `X-CSRF-Token` header are attached project-wide by the core-network interceptor chain (AND-011/012), so
 * this interface stays header-agnostic. ALL four POSTs are non-idempotent and are NEVER auto-retried
 * (spec FR-7). Responses are RAW DTOs wrapped in Retrofit [Response] so the repository's call{} pattern can
 * map a non-2xx (incl. 422 / undocumented 409) via [com.testlogon.android.core.network.error.ApiErrorParser].
 */
interface AccountLifecycleApi {

    @POST("ui/account/closure/start")
    suspend fun startClosure(): Response<ClosureStartDto>

    @Headers("Content-Type: application/json")
    @POST("ui/account/closure/finalize")
    suspend fun finalizeClosure(
        @Body body: ClosureFinalizeDto,
    ): Response<StatusOutDto>

    @Headers("Content-Type: application/json")
    @POST("ui/account/suspend")
    suspend fun suspendAccount(
        @Body body: AccountStatusReqDto,
    ): Response<AccountStatusDto>

    @Headers("Content-Type: application/json")
    @POST("ui/account/reactivate")
    suspend fun reactivateAccount(
        @Body body: AccountStatusReqDto,
    ): Response<AccountStatusDto>
}

/**
 * AND-387 - the `closure/start` 200 body (web `startAccountClosure` return type). CORRECTED: the re-auth
 * challenge originates HERE at start, not at finalize (spec §5 / §16 claim 5). Defensive defaults so a
 * partial / extra-key body never throws; [challengeId] is sensitive and is never fully logged (spec §8).
 */
@JsonClass(generateAdapter = true)
data class ClosureStartDto(
    @Json(name = "auth_required") val authRequired: Boolean = false,
    @Json(name = "challenge_id") val challengeId: String? = null,
    @Json(name = "required_factors") val requiredFactors: List<String> = emptyList(),
)

/**
 * AND-387 - the `closure/finalize` request = AccountClosureFinalizeReq. CORRECTED: the single REQUIRED field
 * is `challenge_id` (NOT `closure_id`) - spec §5 / §16 claim 3. The value is the [ClosureStartDto.challengeId]
 * obtained from start after the re-auth challenge is satisfied.
 */
@JsonClass(generateAdapter = true)
data class ClosureFinalizeDto(
    @Json(name = "challenge_id") val challengeId: String,
)

/**
 * AND-387 - the `closure/finalize` 200 body (web return type `{status}`). The OpenAPI declares an empty `{}`
 * schema, so the field name comes from the web client's declared return type (spec §5 / §16 claim 8). A
 * successful finalize returns `status == "closed"`.
 */
@JsonClass(generateAdapter = true)
data class StatusOutDto(
    @Json(name = "status") val status: String? = null,
)

/**
 * AND-387 - the suspend/reactivate request = AccountStatusReq. CORRECTED: the ONLY field is optional `reason`;
 * there is NO `duration_days` (spec §5 / §16 claim 6). Suspend is indefinite-until-reactivate. A null/blank
 * reason serializes as `null` (Moshi omits or nulls it); the web client sends no body on reactivate, which is
 * equivalent to `{reason:null}` against this schema (no required properties).
 */
@JsonClass(generateAdapter = true)
data class AccountStatusReqDto(
    @Json(name = "reason") val reason: String? = null,
)
