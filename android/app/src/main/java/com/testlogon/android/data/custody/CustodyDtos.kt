package com.testlogon.android.data.custody

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/*
 * Wire DTOs for the PRODUCTION custody surface (the /me/custody endpoints), repointed to the REAL
 * (now-merged) backend shapes. NONE of these responses carry a stub flag any more - the bridge and
 * vault<->vault transfer are real; the shapes below are the settled contracts.
 *
 * Every serialized DTO carries @JsonClass(generateAdapter = true) so the :app unit-test Moshi
 * (codegen-only, no reflection) can parse it. Numerics are tolerated as JSON number OR string:
 * balances stay Map<String, Any?> (coerced at the domain edge) and integer/bps fields are Int?.
 */

/** GET me/custody/balance -> vault id + tier + asset-symbol -> amount (number or numeric string). */
@JsonClass(generateAdapter = true)
data class BalanceDto(
    @Json(name = "vault") val vault: String? = null,
    @Json(name = "tier") val tier: String? = null,
    @Json(name = "balances") val balances: Map<String, Any?>? = null,
)

/**
 * GET me/custody/deposits -> one scanned incoming on-chain transfer credited (or de-duplicated) into
 * the vault. REAL shape: {vault, asset, amount, chain, txhash, log_index, dedup_key}. No status / seq /
 * ts fields exist any more. amount/txhash/asset/chain are strings.
 */
@JsonClass(generateAdapter = true)
data class CustodyDepositDto(
    @Json(name = "vault") val vault: String? = null,
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "amount") val amount: String? = null,
    @Json(name = "chain") val chain: String? = null,
    @Json(name = "txhash") val txhash: String? = null,
    @Json(name = "log_index") val logIndex: String? = null,
    @Json(name = "dedup_key") val dedupKey: String? = null,
)

/** GET me/custody/deposits envelope: the vault id + the deposits list + a count. */
@JsonClass(generateAdapter = true)
data class CustodyDepositsDto(
    @Json(name = "vault") val vault: String? = null,
    @Json(name = "deposits") val deposits: List<CustodyDepositDto>? = null,
    @Json(name = "count") val count: Int? = null,
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

// ==== Sub-accounts + transfers (REAL backend) ====

/**
 * One sub-account vault under the caller's base vault (GET me/custody/subaccounts). REAL shape is just
 * {label, vault} - no balances / tier / default_vault.
 */
@JsonClass(generateAdapter = true)
data class SubAccountDto(
    @Json(name = "label") val label: String? = null,
    @Json(name = "vault") val vault: String? = null,
)

/** GET me/custody/subaccounts envelope: just the list of {label, vault}. */
@JsonClass(generateAdapter = true)
data class SubAccountsDto(
    @Json(name = "subaccounts") val subaccounts: List<SubAccountDto>? = null,
)

/** Body for POST me/custody/subaccounts - the sub-account label (sanitized server-side). */
@JsonClass(generateAdapter = true)
data class CreateSubAccountDto(
    @Json(name = "label") val label: String,
)

/** POST me/custody/subaccounts response (201): {created, label, vault}. */
@JsonClass(generateAdapter = true)
data class CreateSubAccountResultDto(
    @Json(name = "created") val created: Boolean? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "vault") val vault: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)

/**
 * Body for POST me/custody/subaccounts/transfer - move an asset between two OWN sub-account vaults.
 * asset defaults to "native" server-side when omitted.
 */
@JsonClass(generateAdapter = true)
data class SubAccountTransferDto(
    @Json(name = "from_label") val fromLabel: String? = null,
    @Json(name = "to_label") val toLabel: String? = null,
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "amount") val amount: String,
)

/**
 * POST me/custody/subaccounts/transfer response (REAL - no stub). Balance moves for real; the response
 * echoes the resulting from/to balances.
 */
@JsonClass(generateAdapter = true)
data class SubAccountTransferResultDto(
    @Json(name = "transferred") val transferred: Boolean? = null,
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "amount") val amount: String? = null,
    @Json(name = "from") val from: String? = null,
    @Json(name = "to") val to: String? = null,
    @Json(name = "from_balance") val fromBalance: String? = null,
    @Json(name = "to_balance") val toBalance: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)

// ==== Custody <-> trading bridge (FOUR REAL routes) ====

/** Body for the four bridge routes: {token: asset-symbol, amount: decimal string}. */
@JsonClass(generateAdapter = true)
data class BridgeRequestDto(
    @Json(name = "token") val token: String,
    @Json(name = "amount") val amount: String,
)

/**
 * POST me/custody/fund-spot / fund-margin (200). {funded:true, token, asset_id, amount, me_amount,
 * spot|margin}. On 422 {funded:false, reason}. All fields nullable so both shapes parse.
 */
@JsonClass(generateAdapter = true)
data class FundResultDto(
    @Json(name = "funded") val funded: Boolean? = null,
    @Json(name = "token") val token: String? = null,
    @Json(name = "asset_id") val assetId: String? = null,
    @Json(name = "amount") val amount: String? = null,
    @Json(name = "me_amount") val meAmount: String? = null,
    @Json(name = "spot") val spot: String? = null,
    @Json(name = "margin") val margin: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)

/**
 * POST me/custody/settle-spot / settle-margin (200). {settled:true, token, amount, me_amount,
 * spot|margin, custody}. On 422 {settled:false, reason:"insufficient_spot_available"}.
 */
@JsonClass(generateAdapter = true)
data class SettleResultDto(
    @Json(name = "settled") val settled: Boolean? = null,
    @Json(name = "token") val token: String? = null,
    @Json(name = "amount") val amount: String? = null,
    @Json(name = "me_amount") val meAmount: String? = null,
    @Json(name = "spot") val spot: String? = null,
    @Json(name = "margin") val margin: String? = null,
    @Json(name = "custody") val custody: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)
