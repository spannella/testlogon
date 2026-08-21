package com.testlogon.android.data.custody

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt

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

// ==== Staking (custody-gated; real gateway-backed) ====
// The custody edge proxies these to the MPC staking gateway. Providers + positions are reads; stake is
// a write. Amounts arrive as strings. Not deployed on every backend -> a 404/403 folds to a graceful
// "unavailable" empty state in the repository. All fields nullable/optional so a partial shape parses.

/** One stakeable provider (a chain/protocol staking contract). */
@JsonClass(generateAdapter = true)
data class StakingProviderDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "chain") val chain: String? = null,
    @Json(name = "contract") val contract: String? = null,
    @Json(name = "kind") val kind: String? = null,
    @Json(name = "asset") val asset: String? = null,
)

/** GET me/staking/providers envelope. */
@JsonClass(generateAdapter = true)
data class StakingProvidersDto(
    @Json(name = "providers") val providers: List<StakingProviderDto>? = null,
)

/**
 * One open staking position. amounts (principal/rewards/total) are decimal strings; the gateway echoes
 * the provider id + vault + status.
 */
@JsonClass(generateAdapter = true)
data class StakingPositionDto(
    @Json(name = "position_id") val positionId: String? = null,
    @Json(name = "vault") val vault: String? = null,
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "chain") val chain: String? = null,
    @Json(name = "asset") val asset: String? = null,
    @Json(name = "principal") val principal: String? = null,
    @Json(name = "rewards") val rewards: String? = null,
    @Json(name = "total") val total: String? = null,
    @Json(name = "status") val status: String? = null,
)

/** GET me/staking/positions envelope. */
@JsonClass(generateAdapter = true)
data class StakingPositionsDto(
    @Json(name = "positions") val positions: List<StakingPositionDto>? = null,
    @Json(name = "count") val count: Int? = null,
    @Json(name = "vault") val vault: String? = null,
)

/** Body for POST me/staking/stake: {provider, amount (decimal string)}. */
@JsonClass(generateAdapter = true)
data class StakeRequestBodyDto(
    @Json(name = "provider") val provider: String,
    @Json(name = "amount") val amount: String,
)

/**
 * POST me/staking/stake ack. staked=true on success; the gateway may echo the created position_id +
 * provider + amount + status. On rejection staked=false and detail/error/reason carries the message.
 */
@JsonClass(generateAdapter = true)
data class StakeAckDto(
    @Json(name = "staked") val staked: Boolean? = null,
    @Json(name = "position_id") val positionId: String? = null,
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "amount") val amount: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
    @Json(name = "reason") val reason: String? = null,
)

// ==== External custody providers (Fireblocks / BitGo / internal gateway) ====
// Provider creds are SERVER-SIDE only: these routes only initiate a connection + report status; no
// provider secret is ever sent from or returned to the client. NONE are deployed on every backend --
// a 404 folds to a soft "provider integration pending" state in the repository (reads only). All
// fields nullable/defaulted so a partial shape parses. Integer/count fields use @LenientInt so a JSON
// number OR numeric string both decode.

/** One custody provider (GET me/custody/providers). kind in internal|fireblocks|bitgo. */
@JsonClass(generateAdapter = true)
data class CustodyProviderDto(
    @Json(name = "id") val id: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "kind") val kind: String? = null,
    @Json(name = "connected") val connected: Boolean? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "features") val features: List<String>? = null,
)

/** GET me/custody/providers envelope. */
@JsonClass(generateAdapter = true)
data class CustodyProvidersDto(
    @Json(name = "providers") val providers: List<CustodyProviderDto>? = null,
)

/**
 * POST me/custody/providers/{id}/connect (body {label?}) and .../disconnect response. connect returns
 * {ok,status}; disconnect returns an ack ({ok} and/or {disconnected}). All fields nullable so both
 * shapes parse. detail/error carry a rejection message.
 */
@JsonClass(generateAdapter = true)
data class ProviderConnectResultDto(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "disconnected") val disconnected: Boolean? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)

/** Body for POST me/custody/providers/{id}/connect -- an optional human label for the connection. */
@JsonClass(generateAdapter = true)
data class ProviderConnectRequestDto(
    @Json(name = "label") val label: String? = null,
)

/**
 * GET me/custody/providers/{id}/status. balances_attested is a tri-state (true/false/absent);
 * pending_approvals is an integer count (lenient). last_reconciled_ts is left as a raw string
 * (epoch or ISO -- displayed verbatim).
 */
@JsonClass(generateAdapter = true)
data class ProviderStatusDto(
    @Json(name = "status") val status: String? = null,
    @Json(name = "balances_attested") val balancesAttested: Boolean? = null,
    @Json(name = "last_reconciled_ts") val lastReconciledTs: String? = null,
    @LenientInt @Json(name = "pending_approvals") val pendingApprovals: Int? = null,
)

/** One vault row (GET me/custody/vaults). provider optional -> defaults to "internal" at the edge. */
@JsonClass(generateAdapter = true)
data class VaultDto(
    @Json(name = "vault") val vault: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "balances") val balances: Map<String, Any?>? = null,
)

/** GET me/custody/vaults envelope. */
@JsonClass(generateAdapter = true)
data class VaultsDto(
    @Json(name = "vaults") val vaults: List<VaultDto>? = null,
)

/** Body for PUT me/custody/vaults/{vault}/provider -- the provider to back the vault with. */
@JsonClass(generateAdapter = true)
data class SetVaultProviderRequestDto(
    @Json(name = "provider") val provider: String,
)

/** PUT me/custody/vaults/{vault}/provider ack ({ok, provider}). */
@JsonClass(generateAdapter = true)
data class SetVaultProviderResultDto(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "vault") val vault: String? = null,
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "detail") val detail: String? = null,
    @Json(name = "error") val error: String? = null,
)

/** One approver who has signed off on a withdrawal (GET me/custody/withdrawals/{id}/approval). */
@JsonClass(generateAdapter = true)
data class WithdrawalApproverDto(
    @Json(name = "approver") val approver: String? = null,
    @Json(name = "at") val at: String? = null,
)

/**
 * GET me/custody/withdrawals/{id}/approval. status in
 * pending_approval|approved|signed|broadcast|rejected. quorum is the required approvals (lenient int);
 * approvals lists who has signed so far.
 */
@JsonClass(generateAdapter = true)
data class WithdrawalApprovalDto(
    @Json(name = "status") val status: String? = null,
    @LenientInt @Json(name = "quorum") val quorum: Int? = null,
    @Json(name = "approvals") val approvals: List<WithdrawalApproverDto>? = null,
)
