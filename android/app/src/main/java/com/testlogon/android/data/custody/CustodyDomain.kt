package com.testlogon.android.data.custody

/*
 * Domain models + the static asset registry for the custody feature: null-safe, UI-ready projections
 * of the PRODUCTION /me/custody wire DTOs. The repository maps DTO -> domain (coercing balance
 * number-or-string to a Double, resolving each symbol against the registry, normalizing the withdraw
 * status to a sealed enum) so composables never touch raw wire shapes.
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
     * followed by any balance key not in the registry — flagged [CustodyBalance.known] = false with
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

/** Whether a scanned incoming transfer was credited or ignored as a duplicate. */
enum class DepositStatus(val wire: String, val label: String) {
    CREDITED("credited", "Credited"),
    DUPLICATE("duplicate", "Duplicate"),
    UNKNOWN("", "Pending");

    companion object {
        fun from(wire: String?): DepositStatus =
            entries.firstOrNull { it.wire == wire?.trim()?.lowercase() } ?: UNKNOWN
    }
}

/** One scanned incoming on-chain transfer, resolved to a display-ready row. */
data class CustodyDeposit(
    val chainId: Int?,
    val chainName: String,
    val asset: String,
    val amount: String,
    val txHash: String,
    val status: DepositStatus,
    /** Unix epoch in MILLISECONDS (seconds-vs-ms detected at mapping time), or null if absent. */
    val timestampMs: Long?,
    val seq: Long?,
) {
    /** Short 0x… head+tail form of the tx hash for a compact row. */
    val txShort: String
        get() = txHash.let { if (it.length <= 14) it else "${it.take(8)}…${it.takeLast(4)}" }
}

/** The whole deposits response: the vault id + the (newest-first) rows, plus an "unavailable" flag. */
data class CustodyDeposits(
    val vault: String,
    val rows: List<CustodyDeposit>,
    /** True when the backend does not expose deposit scanning (endpoint 404) — a soft, non-error state. */
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
