package com.testlogon.android.data.custody

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
 * Data layer for the PRODUCTION custody surface. Maps wire DTOs to null-safe domain models and folds
 * transport failures into [ApiResult] (HttpException -> Failure carrying the HTTP status; IOException
 * -> NetworkError). CancellationException is always re-thrown. Reads are safe to retry; the withdraw
 * POST is not auto-retried.
 */
@Singleton
class CustodyRepository @Inject constructor(
    private val api: CustodyApi,
    private val errorParser: ApiErrorParser,
) {
    private val io: CoroutineDispatcher = Dispatchers.IO

    suspend fun getBalance(): ApiResult<CustodyBalances> = call {
        api.balance().toDomain()
    }

    suspend fun getDepositAddress(chainId: Int): ApiResult<CustodyDepositAddress> = call {
        api.depositAddress(chainId).toDomain()
    }

    /**
     * Recent scanned incoming transfers. This endpoint is not on every backend: a 404 (or any HTTP
     * error) is folded into a soft "unavailable" success rather than a Failure, so the deposit tab can
     * degrade to an explanatory empty state instead of an error. Network errors still surface as such.
     */
    suspend fun getDeposits(): ApiResult<CustodyDeposits> = withContext(io) {
        try {
            ApiResult.Success(api.getDeposits().toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(CustodyDeposits.unavailable())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    suspend fun withdraw(
        chain: String,
        to: String,
        amount: String,
        token: String?,
        clientRef: String? = null,
    ): ApiResult<CustodyWithdrawResult> = call {
        api.withdraw(
            WithdrawRequestDto(
                chain = chain,
                to = to.trim(),
                amount = amount.trim(),
                token = token?.takeIf { it.isNotBlank() },
                clientRef = clientRef?.takeIf { it.isNotBlank() },
            ),
        ).toDomain()
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

/**
 * Coerces a balances wire value (a JSON number decoded to Double, a numeric String, or null) to a
 * Double. Any non-numeric shape falls back to 0.
 */
private fun coerceAmount(value: Any?): Double = when (value) {
    null -> 0.0
    is Double -> value
    is Number -> value.toDouble()
    is String -> value.trim().toDoubleOrNull() ?: 0.0
    else -> value.toString().trim().toDoubleOrNull() ?: 0.0
}

private fun BalanceDto.toDomain(): CustodyBalances {
    val coerced: Map<String, Double> = balances.orEmpty()
        .entries
        .filter { it.key.isNotBlank() }
        .associate { it.key.trim() to coerceAmount(it.value) }
    return CustodyBalances(
        vault = vault?.trim().orEmpty(),
        tier = tier?.trim()?.takeIf { it.isNotBlank() } ?: "—",
        rows = CustodyAssets.mergeBalances(coerced),
    )
}

private fun DepositAddressDto.toDomain(): CustodyDepositAddress =
    CustodyDepositAddress(
        address = address?.trim().orEmpty(),
        chain = chain?.trim().orEmpty(),
        family = family?.takeIf { it.isNotBlank() },
        derivation = derivation?.takeIf { it.isNotBlank() },
        domain = domain?.takeIf { it.isNotBlank() },
    )

private fun CustodyDepositsDto.toDomain(): CustodyDeposits = CustodyDeposits(
    vault = vault?.trim().orEmpty(),
    rows = deposits.orEmpty().map { it.toDomain() },
    unavailable = false,
)

private fun CustodyDepositDto.toDomain(): CustodyDeposit {
    val chainId = chain?.trim()?.toIntOrNull()
    return CustodyDeposit(
        chainId = chainId,
        chainName = if (chainId != null) CustodyAssets.chainName(chainId) else (chain?.trim().orEmpty().ifBlank { "Unknown chain" }),
        asset = asset?.trim().orEmpty().ifBlank { "?" },
        amount = amount?.trim().orEmpty(),
        txHash = txhash?.trim().orEmpty(),
        status = DepositStatus.from(status),
        timestampMs = ts?.let { normalizeToMs(it) },
        seq = seq,
    )
}

/** ts may arrive in seconds or milliseconds; anything below ~1e12 is treated as seconds. */
private fun normalizeToMs(ts: Long): Long = if (ts in 1L until 100_000_000_000L) ts * 1000L else ts

private fun WithdrawResultDto.toDomain(): CustodyWithdrawResult =
    CustodyWithdrawResult(
        status = WithdrawStatus.from(status),
        withdrawalId = withdrawalId?.takeIf { it.isNotBlank() },
        signature = signature?.takeIf { it.isNotBlank() },
        digest = digest?.takeIf { it.isNotBlank() },
        clientRef = clientRef?.takeIf { it.isNotBlank() },
        intentId = intentId?.takeIf { it.isNotBlank() },
        reason = listOfNotNull(detail, reason, error)
            .firstOrNull { it.isNotBlank() },
        category = category?.takeIf { it.isNotBlank() },
    )

/** Provides the custody Retrofit API (mirrors the auth data module's provider style). */
@Module
@InstallIn(SingletonComponent::class)
object CustodyDataModule {

    @Provides
    @Singleton
    fun provideCustodyApi(retrofit: Retrofit): CustodyApi = retrofit.create(CustodyApi::class.java)
}
