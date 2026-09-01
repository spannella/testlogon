package com.testlogon.android.data.banking

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer for the OpenBankProject banking-accounts surface (`/ui/banking`, ACC-001..ACC-004). Maps
 * wire DTOs to null-safe domain models and folds transport failures into [ApiResult].
 *
 * DEGRADE-ON-404: the whole router is FEATURE-FLAG-GATED server-side (`open_bank_project_enabled AND
 * banking_accounts_enabled`) — when off, EVERY route returns a true 404. So the READS
 * ([getAccounts]/[getTransactions]/[getMetadata]/[getHolders]) fold any HTTP error into a soft
 * "unavailable" success, letting the UI render an honest "banking is not available" empty state rather
 * than an error. Network errors (no HTTP response) still surface as [ApiResult.NetworkError].
 * MUTATIONS (narrative/geotag/tag/comment/update/delete) surface HTTP errors as [ApiResult.Failure]
 * (there is nothing to write when the feature is off, so failing loudly is correct).
 * CancellationException is always re-thrown.
 */
@Singleton
class BankingRepository @Inject constructor(
    private val api: BankingApi,
    private val errorParser: ApiErrorParser,
) {
    private val io: CoroutineDispatcher = Dispatchers.IO

    // ─── Reads (soft-degrade on HTTP error) ──────────────────────────────────

    /** List the caller's linked banking accounts. 404 (flag off) -> soft-unavailable empty state. */
    suspend fun getAccounts(): ApiResult<BankAccounts> = softRead(BankAccounts.unavailable()) {
        BankAccounts(accounts = api.listAccounts().accounts.orEmpty().map { it.toDomain() })
    }

    /** Fetch one account. This IS a Failure-on-error read (the caller navigated to a known id). */
    suspend fun getAccount(accountId: String): ApiResult<BankAccount> = call {
        api.getAccount(accountId.trim()).toDomain()
    }

    /** Account balance (dollars, not cents). Failure-on-error (opened from a known account). */
    suspend fun getBalance(accountId: String): ApiResult<AccountBalance> = call {
        api.getBalance(accountId.trim()).toDomain()
    }

    /** A page of the account's transactions. 404 -> soft-unavailable empty state. */
    suspend fun getTransactions(
        accountId: String,
        from: String? = null,
        to: String? = null,
        limit: Int? = null,
        cursor: String? = null,
        order: String? = null,
    ): ApiResult<BankTransactions> = softRead(BankTransactions.unavailable()) {
        val dto = api.listTransactions(
            accountId = accountId.trim(),
            from = from?.trim()?.takeIf { it.isNotEmpty() },
            to = to?.trim()?.takeIf { it.isNotEmpty() },
            limit = limit,
            cursor = cursor?.trim()?.takeIf { it.isNotEmpty() },
            order = order?.trim()?.takeIf { it.isNotEmpty() },
        )
        BankTransactions(
            transactions = dto.transactions.orEmpty().map { it.toDomain() },
            cursor = dto.cursor?.trim()?.takeIf { it.isNotEmpty() },
        )
    }

    /** One transaction (with inline metadata). Failure-on-error (opened from a known txn). */
    suspend fun getTransaction(accountId: String, transactionId: String): ApiResult<BankTransaction> = call {
        api.getTransaction(accountId.trim(), transactionId.trim()).toDomain()
    }

    /** Transaction metadata. 404 -> soft-empty metadata (feature off / no metadata yet). */
    suspend fun getMetadata(accountId: String, transactionId: String): ApiResult<TransactionMetadata> =
        softRead(TransactionMetadata.empty()) {
            api.getTransactionMetadata(accountId.trim(), transactionId.trim()).toDomain()
        }

    /** Account holders (co-access). 404 -> soft-unavailable empty state. */
    suspend fun getHolders(accountId: String): ApiResult<AccountHolders> = softRead(AccountHolders.unavailable()) {
        AccountHolders(holders = api.listHolders(accountId.trim()).holders.orEmpty().map { it.toDomain() })
    }

    // ─── Mutations (surface HTTP errors as Failure) ──────────────────────────

    suspend fun updateAccount(
        accountId: String,
        label: String? = null,
        iban: String? = null,
        routingNumber: String? = null,
        accountNumberMasked: String? = null,
    ): ApiResult<BankAccount> = call {
        api.updateAccount(
            accountId.trim(),
            AccountUpdateDto(
                label = label?.trim()?.takeIf { it.isNotEmpty() },
                iban = iban?.trim(),
                routingNumber = routingNumber?.trim(),
                accountNumberMasked = accountNumberMasked?.trim(),
            ),
        ).toDomain()
    }

    suspend fun deleteAccount(accountId: String): ApiResult<Unit> = call {
        api.deleteAccount(accountId.trim())
    }

    suspend fun putNarrative(accountId: String, transactionId: String, text: String): ApiResult<Narrative> = call {
        api.putNarrative(accountId.trim(), transactionId.trim(), PutNarrativeDto(text = text.trim())).toDomain()
    }

    suspend fun putGeotag(
        accountId: String,
        transactionId: String,
        lat: Double,
        lon: Double,
        label: String? = null,
    ): ApiResult<Geotag> = call {
        api.putGeotag(
            accountId.trim(),
            transactionId.trim(),
            PutGeotagDto(lat = lat, lon = lon, label = label?.trim()?.takeIf { it.isNotEmpty() }),
        ).toDomain()
    }

    suspend fun addTag(accountId: String, transactionId: String, value: String): ApiResult<TransactionTag> = call {
        api.addTag(accountId.trim(), transactionId.trim(), AddTagDto(value = value.trim())).toDomain()
    }

    suspend fun removeTag(accountId: String, transactionId: String, tagId: String): ApiResult<Unit> = call {
        api.removeTag(accountId.trim(), transactionId.trim(), tagId.trim())
    }

    suspend fun addComment(accountId: String, transactionId: String, text: String): ApiResult<TransactionComment> = call {
        api.addComment(accountId.trim(), transactionId.trim(), AddCommentDto(text = text.trim())).toDomain()
    }

    suspend fun deleteComment(accountId: String, transactionId: String, commentId: String): ApiResult<Unit> = call {
        api.deleteComment(accountId.trim(), transactionId.trim(), commentId.trim())
    }

    // ─── Internals ────────────────────────────────────────────────────────────

    /**
     * A read that soft-degrades: any [HttpException] (notably the flag-off 404) folds into a Success
     * carrying [fallback]. Network errors still surface. Cancellation re-throws.
     */
    private suspend fun <T> softRead(fallback: T, block: suspend () -> T): ApiResult<T> = withContext(io) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(fallback)
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = withContext(io) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}

// ---- DTO -> domain mappers ----

private fun BankDto.toDomain(): Bank = Bank(
    bankId = bankId?.trim().orEmpty(),
    name = name?.trim().orEmpty(),
    shortName = shortName?.trim().orEmpty(),
    logoUrl = logoUrl?.trim()?.takeIf { it.isNotEmpty() },
    website = website?.trim()?.takeIf { it.isNotEmpty() },
)

private fun AccountAttributeDto.toDomain(): AccountAttribute = AccountAttribute(
    name = name?.trim().orEmpty(),
    type = type?.trim().orEmpty().ifEmpty { "STRING" },
    value = value?.trim().orEmpty(),
)

private fun AccountDto.toDomain(): BankAccount = BankAccount(
    accountId = accountId?.trim().orEmpty(),
    bankId = bankId?.trim().orEmpty(),
    label = label?.trim().orEmpty().ifEmpty { "Account" },
    accountType = accountType?.trim().orEmpty(),
    productCode = productCode?.trim().orEmpty(),
    currency = currency?.trim().orEmpty().ifEmpty { "usd" },
    owners = owners.orEmpty().mapNotNull { it?.trim()?.takeIf(String::isNotEmpty) },
    isDefault = isDefault == true,
    walletBacked = walletBacked == true,
    iban = iban?.trim()?.takeIf { it.isNotEmpty() },
    routingNumber = routingNumber?.trim()?.takeIf { it.isNotEmpty() },
    accountNumberMasked = accountNumberMasked?.trim()?.takeIf { it.isNotEmpty() },
    attributes = attributes.orEmpty().map { it.toDomain() },
    createdAt = createdAt ?: 0L,
    updatedAt = updatedAt ?: 0L,
)

private fun AccountBalanceDto.toDomain(): AccountBalance = AccountBalance(
    currency = currency?.trim().orEmpty().ifEmpty { "usd" },
    current = current ?: 0.0,
    available = available ?: (current ?: 0.0),
)

private fun TransactionAmountDto.toDomain(): TransactionAmount = TransactionAmount(
    currency = currency?.trim().orEmpty().ifEmpty { "usd" },
    value = value?.trim().orEmpty().ifEmpty { "0" },
)

private fun TransactionDto.toDomain(): BankTransaction = BankTransaction(
    transactionId = transactionId?.trim().orEmpty(),
    accountId = accountId?.trim().orEmpty(),
    type = type?.trim().orEmpty(),
    amount = amount?.toDomain() ?: TransactionAmount("usd", "0"),
    status = status?.trim().orEmpty(),
    postedAt = postedAt ?: 0L,
    description = description?.trim().orEmpty(),
    provider = provider?.trim()?.takeIf { it.isNotEmpty() },
    newBalance = newBalance?.toDomain() ?: TransactionAmount("usd", "0"),
    hasMetadata = hasMetadata == true,
    metadata = metadata?.toDomain(),
)

private fun NarrativeDto.toDomain(): Narrative = Narrative(
    text = text?.trim().orEmpty(),
    authorSub = authorSub?.trim().orEmpty(),
    updatedAt = updatedAt ?: 0L,
)

private fun GeotagDto.toDomain(): Geotag = Geotag(
    lat = lat ?: 0.0,
    lon = lon ?: 0.0,
    label = label?.trim()?.takeIf { it.isNotEmpty() },
    authorSub = authorSub?.trim().orEmpty(),
    updatedAt = updatedAt ?: 0L,
)

private fun TransactionImageDto.toDomain(): TransactionImage = TransactionImage(
    imageId = imageId?.trim().orEmpty(),
    url = url?.trim().orEmpty(),
    authorSub = authorSub?.trim().orEmpty(),
    createdAt = createdAt ?: 0L,
)

private fun TransactionTagDto.toDomain(): TransactionTag = TransactionTag(
    tagId = tagId?.trim().orEmpty(),
    value = value?.trim().orEmpty(),
    authorSub = authorSub?.trim().orEmpty(),
    createdAt = createdAt ?: 0L,
)

private fun TransactionCommentDto.toDomain(): TransactionComment = TransactionComment(
    commentId = commentId?.trim().orEmpty(),
    text = text?.trim().orEmpty(),
    authorSub = authorSub?.trim().orEmpty(),
    createdAt = createdAt ?: 0L,
)

private fun TransactionMetadataDto.toDomain(): TransactionMetadata = TransactionMetadata(
    narrative = narrative?.toDomain(),
    geotag = geotag?.toDomain(),
    image = image?.toDomain(),
    tags = tags.orEmpty().map { it.toDomain() },
    comments = comments.orEmpty().map { it.toDomain() },
)

private fun AccountHolderDto.toDomain(): AccountHolder = AccountHolder(
    userSub = userSub?.trim().orEmpty(),
    addedAt = addedAt ?: 0L,
    isPrimaryOwner = isPrimaryOwner == true,
)

/** Provides the banking Retrofit API (mirrors the custody data module's provider style). */
@Module
@InstallIn(SingletonComponent::class)
object BankingDataModule {

    @Provides
    @Singleton
    fun provideBankingApi(retrofit: Retrofit): BankingApi = retrofit.create(BankingApi::class.java)
}
