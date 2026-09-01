package com.testlogon.android.data.banking

/*
 * Null-safe, UI-ready domain models for the OpenBankProject banking-accounts surface. The repository
 * maps wire DTO -> domain so composables never touch raw wire shapes. List reads carry an
 * [unavailable] flag: when the feature-flag-gated router 404s (or any read errors) the repository
 * returns a soft "unavailable" success so the UI degrades to an honest "banking is not available"
 * empty state rather than an error.
 */

data class Bank(
    val bankId: String,
    val name: String,
    val shortName: String,
    val logoUrl: String?,
    val website: String?,
)

data class AccountAttribute(
    val name: String,
    val type: String,
    val value: String,
)

data class BankAccount(
    val accountId: String,
    val bankId: String,
    val label: String,
    val accountType: String,
    val productCode: String,
    val currency: String,
    val owners: List<String>,
    val isDefault: Boolean,
    val walletBacked: Boolean,
    val iban: String?,
    val routingNumber: String?,
    val accountNumberMasked: String?,
    val attributes: List<AccountAttribute>,
    val createdAt: Long,
    val updatedAt: Long,
)

/** The linked-accounts list read, with a soft-unavailable flag for the flag-off (404) case. */
data class BankAccounts(
    val accounts: List<BankAccount>,
    val unavailable: Boolean = false,
) {
    companion object {
        fun unavailable() = BankAccounts(accounts = emptyList(), unavailable = true)
    }
}

data class AccountBalance(
    val currency: String,
    /** Dollars (not cents); available == current in this tier (no holds). */
    val current: Double,
    val available: Double,
)

data class TransactionAmount(
    val currency: String,
    /** Decimal string, e.g. "12.50" (signed). */
    val value: String,
)

data class BankTransaction(
    val transactionId: String,
    val accountId: String,
    val type: String,
    val amount: TransactionAmount,
    val status: String,
    val postedAt: Long,
    val description: String,
    val provider: String?,
    val newBalance: TransactionAmount,
    val hasMetadata: Boolean,
    val metadata: TransactionMetadata?,
)

/** A page of transactions + the opaque forward cursor (null == last page). */
data class BankTransactions(
    val transactions: List<BankTransaction>,
    val cursor: String?,
    val unavailable: Boolean = false,
) {
    companion object {
        fun unavailable() = BankTransactions(transactions = emptyList(), cursor = null, unavailable = true)
    }
}

// ─── Transaction metadata ─────────────────────────────────────────────────────

data class Narrative(
    val text: String,
    val authorSub: String,
    val updatedAt: Long,
)

data class Geotag(
    val lat: Double,
    val lon: Double,
    val label: String?,
    val authorSub: String,
    val updatedAt: Long,
)

data class TransactionImage(
    val imageId: String,
    val url: String,
    val authorSub: String,
    val createdAt: Long,
)

data class TransactionTag(
    val tagId: String,
    val value: String,
    val authorSub: String,
    val createdAt: Long,
)

data class TransactionComment(
    val commentId: String,
    val text: String,
    val authorSub: String,
    val createdAt: Long,
)

data class TransactionMetadata(
    val narrative: Narrative?,
    val geotag: Geotag?,
    val image: TransactionImage?,
    val tags: List<TransactionTag>,
    val comments: List<TransactionComment>,
) {
    companion object {
        fun empty() = TransactionMetadata(
            narrative = null,
            geotag = null,
            image = null,
            tags = emptyList(),
            comments = emptyList(),
        )
    }
}

// ─── Account holders ──────────────────────────────────────────────────────────

data class AccountHolder(
    val userSub: String,
    val addedAt: Long,
    val isPrimaryOwner: Boolean,
)

data class AccountHolders(
    val holders: List<AccountHolder>,
    val unavailable: Boolean = false,
) {
    companion object {
        fun unavailable() = AccountHolders(holders = emptyList(), unavailable = true)
    }
}
