package com.testlogon.android.data.custody

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/*
 * Wire DTOs for the PRODUCTION custody surface (the three /me/custody endpoints).
 *
 * Every serialized DTO carries @JsonClass(generateAdapter = true) so the :app unit-test Moshi
 * (codegen-only, no reflection) can parse it.
 *
 * BALANCES number-or-string: the per-asset balance values may arrive as a JSON number OR a numeric
 * string depending on the gateway/edge encoder. Rather than register a custom qualifier (which would
 * live outside this feature), the map value is typed as Any? — Moshi's built-in adapter decodes a JSON
 * number to a Double and a JSON string to a String — and the repository coerces each value to a Double
 * / display string at the domain boundary (see toDomain), matching how the app already treats money as
 * String -> Double.
 */

/** GET me/custody/balance -> vault id + tier + asset-symbol -> amount (number or numeric string). */
@JsonClass(generateAdapter = true)
data class BalanceDto(
    @Json(name = "vault") val vault: String? = null,
    @Json(name = "tier") val tier: String? = null,
    @Json(name = "balances") val balances: Map<String, Any?>? = null,
)

/** GET me/custody/deposit-address?chain=<id> -> a per-chain deposit address + provenance metadata. */
@JsonClass(generateAdapter = true)
data class DepositAddressDto(
    @Json(name = "address") val address: String? = null,
    @Json(name = "chain") val chain: String? = null,
    @Json(name = "family") val family: String? = null,
    @Json(name = "derivation") val derivation: String? = null,
    @Json(name = "domain") val domain: String? = null,
)

/** Body for POST me/custody/withdraw. amount / to are strings; token is "native" or an ERC-20 addr. */
@JsonClass(generateAdapter = true)
data class WithdrawRequestDto(
    @Json(name = "chain") val chain: String,
    @Json(name = "to") val to: String,
    @Json(name = "amount") val amount: String,
    @Json(name = "token") val token: String? = null,
    @Json(name = "nonce") val nonce: String? = null,
    @Json(name = "gas_price") val gasPrice: String? = null,
    @Json(name = "gas_limit") val gasLimit: String? = null,
    @Json(name = "expiry") val expiry: String? = null,
    @Json(name = "client_ref") val clientRef: String? = null,
)

/**
 * The gateway withdraw result. status in signed | pending_approval | blocked | rejected | error.
 * On signed the signature / digest / withdrawal_id are populated; on pending_approval the intent_id
 * identifies the governed intent; on blocked / rejected / error the detail / error / reason / category
 * fields carry the human-readable reason. All fields nullable so any status shape parses.
 */
@JsonClass(generateAdapter = true)
data class WithdrawResultDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "withdrawal_id") val withdrawalId: String? = null,
    @Json(name = "signature") val signature: String? = null,
    @Json(name = "digest") val digest: String? = null,
    @Json(name = "client_ref") val clientRef: String? = null,
    @Json(name = "intent_id") val intentId: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "category") val category: String? = null,
)
