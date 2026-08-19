package com.testlogon.android.data.custody

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientLong

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
/**
 * GET me/custody/deposits (NEW; not on every backend -> 404 handled as graceful-empty by the repo).
 * A scanned incoming on-chain transfer credited (or de-duplicated) into the vault. amount/txhash/asset
 * are strings; seq/ts are int64 but the edge may stringify them, so both use @LenientLong. ts is a unix
 * time whose unit (seconds vs ms) is detected at the domain edge. Newest first.
 */
@JsonClass(generateAdapter = true)
data class CustodyDepositDto(
    @Json(name = "chain") val chain: String? = null,
    @Json(name = "txhash") val txhash: String? = null,
    @Json(name = "log_index") val logIndex: String? = null,
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "amount") val amount: String? = null,
    @Json(name = "status") val status: String? = null,
    @LenientLong @Json(name = "seq") val seq: Long? = null,
    @LenientLong @Json(name = "ts") val ts: Long? = null,
)

/** GET me/custody/deposits envelope: the vault id + the (newest-first) list of scanned deposits. */
@JsonClass(generateAdapter = true)
data class CustodyDepositsDto(
    @Json(name = "vault") val vault: String? = null,
    @Json(name = "deposits") val deposits: List<CustodyDepositDto>? = null,
)

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

// ==== Sub-accounts + transfers (custody-exchange-gaps) ====

/**
 * One sub-account vault under the caller's base vault (GET me/custody/subaccounts). [balances] is a
 * number-or-string map like [BalanceDto.balances]; coerced at the domain edge. The base (default)
 * vault is NOT listed here — it is returned separately as [SubAccountsDto.defaultVault].
 */
@JsonClass(generateAdapter = true)
data class SubAccountDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "tier") val tier: String? = null,
    @Json(name = "balances") val balances: Map<String, Any?>? = null,
)

/** GET me/custody/subaccounts envelope: the default (base) vault id + the named sub-accounts. */
@JsonClass(generateAdapter = true)
data class SubAccountsDto(
    @Json(name = "default_vault") val defaultVault: String? = null,
    @Json(name = "subaccounts") val subaccounts: List<SubAccountDto>? = null,
)

/** Body for POST me/custody/subaccounts — the sub-account label (sanitized server-side). */
@JsonClass(generateAdapter = true)
data class CreateSubAccountDto(
    @Json(name = "label") val label: String,
)

/**
 * POST me/custody/subaccounts response: the gateway's created-vault object with {label, vault} added.
 * Loose shape — only the added fields are consumed; the rest are ignored by Moshi.
 */
@JsonClass(generateAdapter = true)
data class CreateSubAccountResultDto(
    @Json(name = "label") val label: String? = null,
    @Json(name = "vault") val vault: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "id") val id: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)

/** Body for POST me/custody/subaccounts/transfer — move an asset between two OWN sub-account vaults. */
@JsonClass(generateAdapter = true)
data class SubAccountTransferDto(
    @Json(name = "from_label") val fromLabel: String? = null,
    @Json(name = "to_label") val toLabel: String? = null,
    @Json(name = "asset") val asset: String,
    @Json(name = "amount") val amount: String,
)

/**
 * POST me/custody/subaccounts/transfer response. This route is a documented pure no-op (the gateway
 * has no vault<->vault move), so [stub] is always true and it moves no balance.
 */
@JsonClass(generateAdapter = true)
data class SubAccountTransferResultDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "stub") val stub: Boolean? = null,
    @Json(name = "from") val from: String? = null,
    @Json(name = "to") val to: String? = null,
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "amount") val amount: String? = null,
    @Json(name = "note") val note: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)

/** Body for POST me/custody/transfer — the custody<->trading bridge. [asset] is the engine asset id. */
@JsonClass(generateAdapter = true)
data class CustodyBridgeTransferDto(
    @Json(name = "direction") val direction: String,
    @Json(name = "asset") val asset: Int,
    @Json(name = "amount") val amount: Long,
)

/**
 * POST me/custody/transfer response (custody<->trading bridge). [stub] is true (the bridge is not
 * atomic); on to_trading [tradingCredited] reflects whether the in-process engine credited the spot
 * ledger. No real custody balance moves either way.
 */
@JsonClass(generateAdapter = true)
data class CustodyBridgeTransferResultDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "stub") val stub: Boolean? = null,
    @Json(name = "direction") val direction: String? = null,
    @Json(name = "asset") val asset: Int? = null,
    @Json(name = "amount") val amount: Long? = null,
    @Json(name = "trading_credited") val tradingCredited: Boolean? = null,
    @Json(name = "note") val note: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)
