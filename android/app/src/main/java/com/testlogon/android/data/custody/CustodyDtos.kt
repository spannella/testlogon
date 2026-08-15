package com.testlogon.android.data.custody

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt
import com.testlogon.android.core.network.json.LenientLong

/*
 * Wire DTOs for the session-authed custody surface (GET/POST the /ui/custody endpoints).
 *
 * Every serialized DTO carries @JsonClass(generateAdapter = true) so the :app unit-test Moshi
 * (codegen-only, no reflection) can parse it. Money-ish fields (balance / amount) arrive as either a
 * JSON number OR a numeric string depending on the backend encoder, so they are typed as String and
 * parsed defensively at the domain boundary; whole-number wire fields (decimals / confirmations /
 * approval counts / timestamps) use the existing @LenientInt / @LenientLong qualifiers, which tolerate
 * a number, a numeric string, or an empty string.
 */

@JsonClass(generateAdapter = true)
data class CustodyAssetDto(
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "chain") val chain: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "symbol") val symbol: String? = null,
    @LenientInt @Json(name = "decimals") val decimals: Int? = null,
    @Json(name = "network") val network: String? = null,
    @Json(name = "balance") val balance: String? = null,
    @Json(name = "address_available") val addressAvailable: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class CustodyDepositAddressDto(
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "chain") val chain: String? = null,
    @Json(name = "network") val network: String? = null,
    @Json(name = "address") val address: String? = null,
    @Json(name = "memo") val memo: String? = null,
)

@JsonClass(generateAdapter = true)
data class CustodyDepositDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "chain") val chain: String? = null,
    @Json(name = "amount") val amount: String? = null,
    @Json(name = "status") val status: String? = null,
    @LenientInt @Json(name = "confirmations") val confirmations: Int? = null,
)

/** Body for POST /ui/custody/withdrawals. */
@JsonClass(generateAdapter = true)
data class CustodyWithdrawalRequestDto(
    @Json(name = "asset") val asset: String,
    @Json(name = "chain") val chain: String,
    @Json(name = "amount") val amount: String,
    @Json(name = "destination") val destination: String,
    @Json(name = "memo") val memo: String? = null,
)

/**
 * The immediate POST /ui/custody/withdrawals result. status in signed | pending_approval | blocked |
 * rejected. The detail / error / category / source fields carry the human-readable reason on a
 * blocked/rejected outcome.
 */
@JsonClass(generateAdapter = true)
data class CustodyWithdrawalResultDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "chain") val chain: String? = null,
    @Json(name = "amount") val amount: String? = null,
    @Json(name = "destination") val destination: String? = null,
    @Json(name = "signature") val signature: String? = null,
    @Json(name = "digest") val digest: String? = null,
    @LenientInt @Json(name = "approvals_required") val approvalsRequired: Int? = null,
    @LenientInt @Json(name = "approvals") val approvals: Int? = null,
    @Json(name = "error") val error: String? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "source") val source: String? = null,
    @Json(name = "detail") val detail: String? = null,
)

/**
 * A single withdrawal record from GET /ui/custody/withdrawals[/{id}] (also the officer approvals feed).
 * The list projection is a subset; the detail projection adds chain_ref / network / recipient /
 * approvals[] / timelock / created_ms. All fields optional so either projection parses.
 */
@JsonClass(generateAdapter = true)
data class CustodyWithdrawalDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "chain") val chain: String? = null,
    @Json(name = "chain_ref") val chainRef: String? = null,
    @Json(name = "network") val network: String? = null,
    @Json(name = "recipient") val recipient: String? = null,
    @Json(name = "destination") val destination: String? = null,
    @Json(name = "amount") val amount: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "approvals") val approvals: List<String>? = null,
    @LenientInt @Json(name = "approvals_count") val approvalsCount: Int? = null,
    @LenientInt @Json(name = "approvals_required") val approvalsRequired: Int? = null,
    @Json(name = "signature") val signature: String? = null,
    @Json(name = "digest") val digest: String? = null,
    @Json(name = "error") val error: String? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "source") val source: String? = null,
    @LenientLong @Json(name = "timelock_until_ms") val timelockUntilMs: Long? = null,
    @LenientLong @Json(name = "created_ms") val createdMs: Long? = null,
)

/** Result of POST /ui/custody/withdrawals/{id}/approve. */
@JsonClass(generateAdapter = true)
data class CustodyApproveRequestDto(
    @Json(name = "approver") val approver: String? = null,
)

@JsonClass(generateAdapter = true)
data class CustodyApproveResultDto(
    @Json(name = "withdrawal_id") val withdrawalId: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "approvals") val approvals: List<String>? = null,
    @LenientInt @Json(name = "approvals_required") val approvalsRequired: Int? = null,
)

/** Result of POST /ui/custody/withdrawals/{id}/release. */
@JsonClass(generateAdapter = true)
data class CustodyReleaseResultDto(
    @Json(name = "withdrawal_id") val withdrawalId: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "signature") val signature: String? = null,
    @Json(name = "digest") val digest: String? = null,
)

@JsonClass(generateAdapter = true)
data class CustodyAuditEntryDto(
    @LenientLong @Json(name = "seq") val seq: Long? = null,
    @Json(name = "action") val action: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @LenientLong @Json(name = "ts_ms") val tsMs: Long? = null,
    @Json(name = "prev") val prev: String? = null,
    @Json(name = "hash") val hash: String? = null,
)

@JsonClass(generateAdapter = true)
data class CustodyAuditDto(
    @Json(name = "entries") val entries: List<CustodyAuditEntryDto>? = null,
)

@JsonClass(generateAdapter = true)
data class CustodyAuditVerifyDto(
    @Json(name = "ok") val ok: Boolean? = null,
    @LenientInt @Json(name = "entries") val entries: Int? = null,
)
