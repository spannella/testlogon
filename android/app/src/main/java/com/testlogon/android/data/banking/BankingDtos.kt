package com.testlogon.android.data.banking

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/*
 * Wire DTOs for the OpenBankProject banking-accounts surface (`/ui/banking`, ACC-001..ACC-004),
 * mirroring `frontend/src/api/endpoints/bankAccounts.ts` field-for-field.
 *
 * Every serialized DTO carries @JsonClass(generateAdapter = true) so the :app unit-test Moshi
 * (codegen-only, no reflection) can parse it. All fields are nullable / defaulted so any partial shape
 * decodes; the repository resolves nulls to safe domain defaults.
 */

// ─── Banks ────────────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class BankDto(
    @Json(name = "bank_id") val bankId: String? = null,
    @Json(name = "name") val name: String? = null,
    @Json(name = "short_name") val shortName: String? = null,
    @Json(name = "logo_url") val logoUrl: String? = null,
    @Json(name = "website") val website: String? = null,
)

@JsonClass(generateAdapter = true)
data class BankListDto(
    @Json(name = "banks") val banks: List<BankDto>? = null,
)

// ─── Accounts ───────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class AccountAttributeDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "type") val type: String? = null,
    @Json(name = "value") val value: String? = null,
)

@JsonClass(generateAdapter = true)
data class AccountDto(
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "bank_id") val bankId: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "account_type") val accountType: String? = null,
    @Json(name = "product_code") val productCode: String? = null,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "owners") val owners: List<String>? = null,
    @Json(name = "is_default") val isDefault: Boolean? = null,
    @Json(name = "wallet_backed") val walletBacked: Boolean? = null,
    @Json(name = "iban") val iban: String? = null,
    @Json(name = "routing_number") val routingNumber: String? = null,
    @Json(name = "account_number_masked") val accountNumberMasked: String? = null,
    @Json(name = "attributes") val attributes: List<AccountAttributeDto>? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class AccountListDto(
    @Json(name = "accounts") val accounts: List<AccountDto>? = null,
)

@JsonClass(generateAdapter = true)
data class AccountUpdateDto(
    @Json(name = "label") val label: String? = null,
    @Json(name = "attributes") val attributes: List<AccountAttributeDto>? = null,
    @Json(name = "iban") val iban: String? = null,
    @Json(name = "routing_number") val routingNumber: String? = null,
    @Json(name = "account_number_masked") val accountNumberMasked: String? = null,
)

// ─── Balance ──────────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class AccountBalanceDto(
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "current") val current: Double? = null,
    @Json(name = "available") val available: Double? = null,
)

// ─── Transactions ─────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class TransactionAmountDto(
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "value") val value: String? = null,
)

@JsonClass(generateAdapter = true)
data class TransactionDto(
    @Json(name = "transaction_id") val transactionId: String? = null,
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "type") val type: String? = null,
    @Json(name = "amount") val amount: TransactionAmountDto? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "posted_at") val postedAt: Long? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "new_balance") val newBalance: TransactionAmountDto? = null,
    @Json(name = "has_metadata") val hasMetadata: Boolean? = null,
    @Json(name = "metadata") val metadata: TransactionMetadataDto? = null,
)

@JsonClass(generateAdapter = true)
data class TransactionListDto(
    @Json(name = "transactions") val transactions: List<TransactionDto>? = null,
    @Json(name = "cursor") val cursor: String? = null,
)

// ─── Transaction metadata ─────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class NarrativeDto(
    @Json(name = "text") val text: String? = null,
    @Json(name = "author_sub") val authorSub: String? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class GeotagDto(
    @Json(name = "lat") val lat: Double? = null,
    @Json(name = "lon") val lon: Double? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "author_sub") val authorSub: String? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class TransactionImageDto(
    @Json(name = "image_id") val imageId: String? = null,
    @Json(name = "url") val url: String? = null,
    @Json(name = "author_sub") val authorSub: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class TransactionTagDto(
    @Json(name = "tag_id") val tagId: String? = null,
    @Json(name = "value") val value: String? = null,
    @Json(name = "author_sub") val authorSub: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class TransactionCommentDto(
    @Json(name = "comment_id") val commentId: String? = null,
    @Json(name = "text") val text: String? = null,
    @Json(name = "author_sub") val authorSub: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class TransactionMetadataDto(
    @Json(name = "narrative") val narrative: NarrativeDto? = null,
    @Json(name = "geotag") val geotag: GeotagDto? = null,
    @Json(name = "image") val image: TransactionImageDto? = null,
    @Json(name = "tags") val tags: List<TransactionTagDto>? = null,
    @Json(name = "comments") val comments: List<TransactionCommentDto>? = null,
)

// ─── Metadata mutation bodies ──────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class PutNarrativeDto(
    @Json(name = "text") val text: String,
)

@JsonClass(generateAdapter = true)
data class PutGeotagDto(
    @Json(name = "lat") val lat: Double,
    @Json(name = "lon") val lon: Double,
    @Json(name = "label") val label: String? = null,
)

@JsonClass(generateAdapter = true)
data class AddTagDto(
    @Json(name = "value") val value: String,
)

@JsonClass(generateAdapter = true)
data class AddCommentDto(
    @Json(name = "text") val text: String,
)

// ─── Account holders ────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class AccountHolderDto(
    @Json(name = "user_sub") val userSub: String? = null,
    @Json(name = "added_at") val addedAt: Long? = null,
    @Json(name = "is_primary_owner") val isPrimaryOwner: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class AccountHoldersDto(
    @Json(name = "holders") val holders: List<AccountHolderDto>? = null,
)
