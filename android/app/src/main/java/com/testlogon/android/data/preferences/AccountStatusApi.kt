package com.testlogon.android.data.preferences

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.AccountStatus
import retrofit2.http.GET

/**
 * AND-082 — Retrofit interface + DTO for account status.
 *
 * Verified against OpenAPI + `src/api/types.ts: AccountState`:
 *  - GET ui/account/status -> { status, reason?, updated_at?, closed_at? } (op account_status_...)
 *
 * Timestamps are epoch SECONDS. The 200 schema is untyped server-side, so unknown `status` values
 * map to AccountState.UNKNOWN and additive fields are ignored.
 */
interface AccountStatusApi {

    @GET("ui/account/status")
    suspend fun getStatus(): AccountStatusDto
}

@JsonClass(generateAdapter = true)
data class AccountStatusDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "closed_at") val closedAt: Long? = null,
)

internal fun AccountStatusDto.toDomain(): AccountStatus = AccountStatus(
    state = AccountStatus.stateFromWire(status),
    rawState = status.orEmpty(),
    reason = reason,
    updatedAtEpochSeconds = updatedAt,
    closedAtEpochSeconds = closedAt,
)
