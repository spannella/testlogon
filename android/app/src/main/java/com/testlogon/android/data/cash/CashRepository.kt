package com.testlogon.android.data.cash

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
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
 * Data layer for the FIAT (USD) cash wallet over [CashApi] (the real /ui/billing/wallet surface).
 *
 * READS ([wallet], [paymentMethods]) DEGRADE on 404/HTTP-error to an honest "unavailable"/empty value
 * so the screen shows a truthful empty state rather than an error; a real transport failure surfaces as
 * [ApiResult.NetworkError] so the UI can offer retry. MUTATIONS ([deposit], [withdraw]) pass failures
 * through as [ApiResult.Failure]/[ApiResult.NetworkError] — a rejection (or undeployed 404) surfaces as
 * a clear error and NEVER a silent success. CancellationException is always re-thrown.
 */
interface CashRepository {
    suspend fun wallet(): ApiResult<CashWallet>
    suspend fun paymentMethods(): ApiResult<List<CashPaymentMethod>>
    suspend fun deposit(amountCents: Long, paymentMethodId: String?): ApiResult<CashDepositResult>
    suspend fun withdraw(amountCents: Long): ApiResult<CashWithdrawResult>
}

@Singleton
class CashRepositoryImpl @Inject constructor(
    private val api: CashApi,
    private val errorParser: ApiErrorParser,
) : CashRepository {
    private val io: CoroutineDispatcher = Dispatchers.IO

    /** Wallet balance. A 404 (undeployed) degrades to an honest unavailable wallet; network errors surface. */
    override suspend fun wallet(): ApiResult<CashWallet> = withContext(io) {
        try {
            ApiResult.Success(api.wallet().toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(CashWallet.unavailable())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    /** Payment methods. A 404 degrades to an empty list; network errors surface. */
    override suspend fun paymentMethods(): ApiResult<List<CashPaymentMethod>> = withContext(io) {
        try {
            ApiResult.Success(api.paymentMethods().mapNotNull { it.toDomain() })
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(emptyList())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    override suspend fun deposit(amountCents: Long, paymentMethodId: String?): ApiResult<CashDepositResult> = call {
        api.deposit(
            WalletDepositRequestDto(
                amountCents = amountCents,
                paymentMethodId = paymentMethodId?.trim()?.takeIf { it.isNotBlank() },
            ),
        ).toDomain()
    }

    override suspend fun withdraw(amountCents: Long): ApiResult<CashWithdrawResult> = call {
        api.withdraw(WalletWithdrawRequestDto(amountCents = amountCents)).toDomain()
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

private fun WalletDto.toDomain(): CashWallet = CashWallet(
    balanceCents = walletBalanceCents ?: 0L,
    currency = currency?.trim()?.takeIf { it.isNotBlank() } ?: "USD",
    available = true,
)

private fun CashPaymentMethodDto.toDomain(): CashPaymentMethod? {
    val id = paymentMethodId?.trim()?.takeIf { it.isNotBlank() } ?: return null
    val brandLast4 = listOfNotNull(
        brand?.trim()?.takeIf { it.isNotBlank() }?.replaceFirstChar { it.uppercase() },
        last4?.trim()?.takeIf { it.isNotBlank() }?.let { "····$it" },
    ).joinToString(" ")
    val label = label?.trim()?.takeIf { it.isNotBlank() }
        ?: brandLast4.takeIf { it.isNotBlank() }
        ?: methodType?.trim()?.takeIf { it.isNotBlank() }
        ?: "Payment method"
    return CashPaymentMethod(id = id, label = label, isDefault = isDefault == true)
}

private fun WalletDepositResultDto.toDomain(): CashDepositResult {
    val statusNorm = status?.trim()?.lowercase()
    // A missing status but a returned balance still counts as accepted (honest-mock returns {status:"succeeded"}).
    val ok = statusNorm in setOf("succeeded", "success", "ok", "processing", "pending") || walletBalanceCents != null
    return CashDepositResult(
        ok = ok,
        status = status?.trim()?.takeIf { it.isNotBlank() },
        paymentIntentId = paymentIntentId?.trim()?.takeIf { it.isNotBlank() },
        newBalanceCents = walletBalanceCents,
        reason = listOfNotNull(detail, error).firstOrNull { it.isNotBlank() },
    )
}

private fun WalletWithdrawResultDto.toDomain(): CashWithdrawResult = CashWithdrawResult(
    ok = ok == true,
    newBalanceCents = walletBalanceCents,
    reason = listOfNotNull(detail, error).firstOrNull { it.isNotBlank() },
)

/** Provides [CashApi] on the shared authenticated Retrofit + binds the repository impl. */
@Module
@InstallIn(SingletonComponent::class)
object CashApiModule {
    @Provides
    @Singleton
    fun provideCashApi(retrofit: Retrofit): CashApi = retrofit.create(CashApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class CashDataModule {
    @Binds
    @Singleton
    abstract fun bindCashRepository(impl: CashRepositoryImpl): CashRepository
}
