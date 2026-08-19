package com.testlogon.android.data.custody

/*
 * Domain models + the static asset registry for the custody feature: null-safe, UI-ready projections
 * of the PRODUCTION /me/custody wire DTOs (now repointed to the REAL merged backend). The repository
 * maps DTO -> domain (coercing balance number-or-string to a Double, resolving each symbol against the
 * registry, normalizing the withdraw status to a sealed enum) so composables never touch raw wire
 * shapes. Nothing here is "simulated" any more - the bridge and vault<->vault transfer are real.
 */

// ---------------- Asset registry ----------------

/**
 * A known custodial asset: which chain it lives on and how it is addressed on the withdraw path.
 * [token] is "native" for the chain's gas coin, or the ERC-20 contract address for a token.
 */
data class CustodyAsset(
    val symbol: String,
    val name: String,
    val chainId: Int,
    val chainName: String,
    val network: String,
    val token: String,
    val decimals: Int,
) {
    val isNative: Boolean get() = token.equals("native", ignoreCase = true)
    /** Stable list key. */
    val key: String get() = symbol
}

/**
 * Static registry of the assets this client understands, plus helpers to resolve a symbol and to merge
 * a live balance map into a full displayable list.
 */
object CustodyAssets {

    const val NATIVE = "native"

    val ALL: List<CustodyAsset> = listOf(
        CustodyAsset("ETH", "Ether", 1, "Ethereum", "Ethereum Mainnet", NATIVE, 18),
        CustodyAsset("USDC", "USD Coin", 1, "Ethereum", "Ethereum Mainnet", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6),
        CustodyAsset("USDT", "Tether USD", 1, "Ethereum", "Ethereum Mainnet", "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6),
        CustodyAsset("BNB", "BNB", 56, "BNB Smart Chain", "BSC Mainnet", NATIVE, 18),
        CustodyAsset("POL", "Polygon", 137, "Polygon", "Polygon Mainnet", NATIVE, 18),
    )

    /** The asset symbols accepted by the custody<->trading bridge (fund/settle spot/margin). */
    val BRIDGE_TOKENS: List<String> = ALL.map { it.symbol }

    /**
     * Human chain name for a chain id (from the registry, else a generic "Chain <id>"). Used to label
     * scanned deposits whose `chain` arrives as a numeric id string.
     */
    fun chainName(chainId: Int?): String {
        if (chainId == null) return "Unknown chain"
        return ALL.firstOrNull { it.chainId == chainId }?.chainName ?: "Chain $chainId"
    }

    /** Case-insensitive symbol lookup against the registry. */
    fun findAsset(symbol: String?): CustodyAsset? {
        val s = symbol?.trim() ?: return null
        return ALL.firstOrNull { it.symbol.equals(s, ignoreCase = true) }
    }

    /**
     * Produces a displayable balance row for EVERY registry asset (0 when absent from [balances]),
     * followed by any balance key not in the registry - flagged [CustodyBalance.known] = false with
     * safe fallbacks (chain 1 / native).
     */
    fun mergeBalances(balances: Map<String, Double>): List<CustodyBalance> {
        val byUpper = balances.mapKeys { it.key.trim().uppercase() }
        val registryRows = ALL.map { asset ->
            val amt = byUpper[asset.symbol.uppercase()] ?: 0.0
            CustodyBalance(asset = asset, amount = amt, known = true)
        }
        val extras = balances.keys
            .filter { key -> ALL.none { it.symbol.equals(key.trim(), ignoreCase = true) } }
            .map { key ->
                val sym = key.trim().ifBlank { "?" }
                CustodyBalance(
                    asset = CustodyAsset(
                        symbol = sym,
                        name = sym,
                        chainId = 1,
                        chainName = "Ethereum",
                        network = "Ethereum Mainnet",
                        token = NATIVE,
                        decimals = 18,
                    ),
                    amount = balances[key] ?: 0.0,
                    known = false,
                )
            }
        return registryRows + extras
    }
}

/** One displayable balance row: a resolved asset + its amount, with an unknown-asset flag. */
data class CustodyBalance(
    val asset: CustodyAsset,
    val amount: Double,
    val known: Boolean,
) {
    val symbol: String get() = asset.symbol
    val key: String get() = asset.symbol
    /** Trimmed display text (drops a trailing ".0" for whole amounts). */
    val amountText: String
        get() = if (amount == amount.toLong().toDouble()) amount.toLong().toString() else amount.toString()
}

// ---------------- Balance / vault ----------------

/** The whole custody balance response: the vault id, its tier, and the merged asset rows. */
data class CustodyBalances(
    val vault: String,
    val tier: String,
    val rows: List<CustodyBalance>,
) {
    /** Short vault id for a subtle header (keeps head + tail). */
    val vaultShort: String
        get() = if (vault.length <= 14) vault else "${vault.take(8)}…${vault.takeLast(4)}"

    fun funded(): List<CustodyBalance> = rows.filter { it.amount > 0.0 }
    fun rowFor(key: String?): CustodyBalance? = rows.firstOrNull { it.key == key }
}

// ---------------- Deposit ----------------

data class CustodyDepositAddress(
    val address: String,
    val chain: String,
    val family: String?,
    val derivation: String?,
    val domain: String?,
)

// ---------------- Incoming deposits (scanned) ----------------

/**
 * One scanned incoming on-chain transfer, resolved to a display-ready row. The REAL backend exposes
 * {vault, asset, amount, chain, txhash, log_index, dedup_key} - there is no status or timestamp.
 */
data class CustodyDeposit(
    val chainId: Int?,
    val chainName: String,
    val asset: String,
    val amount: String,
    val txHash: String,
    val logIndex: String?,
    val dedupKey: String?,
) {
    /** Short 0x… head+tail form of the tx hash for a compact row. */
    val txShort: String
        get() = txHash.let { if (it.length <= 14) it else "${it.take(8)}…${it.takeLast(4)}" }
}

/** The whole deposits response: the vault id + the rows, plus an "unavailable" flag. */
data class CustodyDeposits(
    val vault: String,
    val rows: List<CustodyDeposit>,
    /** True when the backend does not expose deposit scanning (endpoint 404) - a soft, non-error state. */
    val unavailable: Boolean = false,
) {
    val isEmpty: Boolean get() = rows.isEmpty()

    companion object {
        fun unavailable(): CustodyDeposits = CustodyDeposits(vault = "", rows = emptyList(), unavailable = true)
    }
}

// ---------------- Withdraw ----------------

/** Normalized immediate withdraw outcome. */
enum class WithdrawStatus(val wire: String, val label: String) {
    SIGNED("signed", "Signed"),
    PENDING_APPROVAL("pending_approval", "Pending approval"),
    BLOCKED("blocked", "Blocked"),
    REJECTED("rejected", "Rejected"),
    ERROR("error", "Error"),
    UNKNOWN("", "Unknown");

    companion object {
        fun from(wire: String?): WithdrawStatus =
            entries.firstOrNull { it.wire == wire?.trim()?.lowercase() } ?: UNKNOWN
    }
}

/** The immediate result of submitting a withdrawal via the gateway. */
data class CustodyWithdrawResult(
    val status: WithdrawStatus,
    val withdrawalId: String?,
    val signature: String?,
    val digest: String?,
    val clientRef: String?,
    val intentId: String?,
    /** Best-effort human reason on a blocked/rejected/error outcome. */
    val reason: String?,
    val category: String?,
)

// ---------------- Sub-accounts ----------------

/**
 * A custody sub-account vault. The REAL backend returns only {label, vault} - no tier / balances.
 */
data class CustodySubAccount(
    val label: String,
    val vault: String,
) {
    val displayLabel: String get() = label.ifBlank { "Sub-account" }
    val vaultShort: String get() = if (vault.length <= 14) vault else "${vault.take(8)}…${vault.takeLast(4)}"
}

/**
 * The sub-accounts response: the named sub-accounts, plus an "unavailable" flag for when the backend
 * does not expose the route (404 -> soft empty state).
 */
data class CustodySubAccounts(
    val subAccounts: List<CustodySubAccount>,
    val unavailable: Boolean = false,
) {
    val isEmpty: Boolean get() = subAccounts.isEmpty()

    companion object {
        fun unavailable(): CustodySubAccounts =
            CustodySubAccounts(subAccounts = emptyList(), unavailable = true)
    }
}

// ---------------- Custody <-> trading bridge ----------------

/**
 * The four custody<->trading bridge actions. [fund] moves custody value INTO an exchange ledger;
 * [settle] moves it BACK to custody. [venue] is which exchange ledger (spot or margin).
 */
enum class BridgeVenue(val label: String) { SPOT("Spot"), MARGIN("Margin") }

enum class BridgeAction(val venue: BridgeVenue, val fund: Boolean, val label: String) {
    FUND_SPOT(BridgeVenue.SPOT, true, "Fund spot"),
    SETTLE_SPOT(BridgeVenue.SPOT, false, "Settle spot"),
    FUND_MARGIN(BridgeVenue.MARGIN, true, "Fund margin"),
    SETTLE_MARGIN(BridgeVenue.MARGIN, false, "Settle margin");

    val isSettle: Boolean get() = !fund
}

/**
 * Result of a bridge fund/settle. [ok] reflects funded/settled=true; on a 200 the ledger + custody
 * balances are echoed. On a 422 [ok] is false and [reason] carries the rejection (e.g.
 * "insufficient_spot_available"). All amounts are decimal strings as returned by the backend.
 */
data class CustodyBridgeResult(
    val ok: Boolean,
    val action: BridgeAction,
    val token: String?,
    val amount: String?,
    /** The engine-side amount actually moved (me_amount), when returned. */
    val meAmount: String?,
    /** The resulting spot/margin ledger balance (whichever this action touched), when returned. */
    val ledger: String?,
    /** The resulting custody balance (settle path), when returned. */
    val custody: String?,
    val reason: String?,
)

// ---------------- Sub-account transfer ----------------

/**
 * Result of a between-sub-accounts transfer (REAL - balance moves). On success the resulting from/to
 * balances are echoed; on failure [reason] carries the gateway message.
 */
data class SubAccountTransferResult(
    val ok: Boolean,
    val from: String?,
    val to: String?,
    val asset: String?,
    val amount: String?,
    val fromBalance: String?,
    val toBalance: String?,
    val reason: String?,
)

// ---------------- Staking (custody-gated) ----------------

/** One stakeable provider (chain/protocol staking contract), display-ready. */
data class StakingProvider(
    val id: String,
    val chain: String,
    val contract: String,
    val kind: String,
    val asset: String,
) {
    val displayId: String get() = id.ifBlank { "provider" }
    val contractShort: String
        get() = if (contract.length <= 14) contract else "${contract.take(8)}…${contract.takeLast(4)}"
}

/** One open staking position, display-ready. Amounts stay as backend decimal strings. */
data class StakingPosition(
    val positionId: String,
    val vault: String,
    val provider: String,
    val chain: String,
    val asset: String,
    val principal: String,
    val rewards: String,
    val total: String,
    val status: String,
) {
    val statusLabel: String get() = status.ifBlank { "—" }
}

/**
 * The staking dashboard read (providers + positions). [unavailable] is true when the backend does not
 * expose staking (404/403) — a soft, non-error empty state the UI degrades to.
 */
data class StakingDashboard(
    val vault: String,
    val providers: List<StakingProvider>,
    val positions: List<StakingPosition>,
    val unavailable: Boolean = false,
) {
    val hasProviders: Boolean get() = providers.isNotEmpty()
    val hasPositions: Boolean get() = positions.isNotEmpty()

    companion object {
        fun unavailable(): StakingDashboard =
            StakingDashboard(vault = "", providers = emptyList(), positions = emptyList(), unavailable = true)
    }
}

/** Result of submitting a stake. [ok] reflects staked=true; [reason] carries any gateway message. */
data class StakeResult(
    val ok: Boolean,
    val positionId: String?,
    val provider: String?,
    val amount: String?,
    val status: String?,
    val reason: String?,
)
