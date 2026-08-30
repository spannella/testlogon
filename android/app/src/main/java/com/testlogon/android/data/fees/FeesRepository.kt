package com.testlogon.android.data.fees

import com.testlogon.android.core.model.ApiError
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
 * FE-152 — null-safe domain projection of a pay-any-coin fee quote (DTO -> domain lives here so the
 * ViewModel never touches wire shapes). Native amounts are integer base units (Long); the shown FX
 * rate + conversion-fee percent are display-only Doubles. [quoteToken] is the signed token the pay
 * call passes back to honor the LOCKED rate.
 */
data class FeeQuote(
    val payWith: String,
    val amountCents: Long,
    val usdCentsPerCoinNative: Long,
    val usdPerWholeCoin: Double?,
    val rateSource: String?,
    val conversionFeeBps: Int,
    val conversionFeePct: Double,
    val coinNative: Long,
    val conversionFeeNative: Long,
    val totalNative: Long,
    val expiresAt: Long,
    val lockedSeconds: Int,
    val quoteToken: String,
    /** false = the USD wallet 1:1 path (no FX conversion). null when the field is absent. */
    val convertible: Boolean?,
    val note: String?,
)

/** DTO -> domain. `pay_with` falls back to the requested coin when the server omits it. */
internal fun FeeQuoteDto.toDomain(requestedPayWith: String): FeeQuote = FeeQuote(
    payWith = payWith ?: requestedPayWith,
    amountCents = amountCents ?: 0L,
    usdCentsPerCoinNative = rate?.usdCentsPerCoinNative ?: 0L,
    usdPerWholeCoin = rate?.usdPerWholeCoin,
    rateSource = rate?.source,
    conversionFeeBps = conversionFeeBps ?: 0,
    conversionFeePct = conversionFeePct ?: 0.0,
    coinNative = coinNative ?: 0L,
    conversionFeeNative = conversionFeeNative ?: 0L,
    totalNative = totalNative ?: 0L,
    expiresAt = expiresAt ?: 0L,
    lockedSeconds = lockedSeconds ?: 0,
    quoteToken = quoteToken.orEmpty(),
    convertible = convertible,
    note = note,
)

/** Outcome of paying a checkout order with a locked crypto quote. */
data class CheckoutPayResult(
    val status: String?,
    val orderId: String?,
    val txnId: String?,
    val coinNativeDebited: Long?,
)

internal fun CheckoutPayResultDto.toDomain(): CheckoutPayResult = CheckoutPayResult(
    status = status,
    orderId = orderId,
    txnId = txnId,
    coinNativeDebited = coinNativeDebited,
)

/**
 * FE-152 — pay-any-coin data layer over [FeesApi].
 *
 * [quoteFee] degrades a 404 (backend predates pay-any-coin) into a soft Success(null) so the checkout
 * screen can hide/disable the crypto option with a "crypto pay unavailable" note rather than showing
 * an error; every other HTTP error folds to Failure carrying the status/code (409 quote_expired, 402
 * insufficient, 422 unsupported_coin) which the ViewModel renders. [payCheckoutOrder] is a real charge
 * and is never auto-retried; its errors always surface (never degraded).
 */
interface FeesRepository {
    /** Returns Success(null) when pay-any-coin quoting is unavailable on this backend (404). */
    suspend fun quoteFee(amountCents: Long, payWith: String): ApiResult<FeeQuote?>
    suspend fun payCheckoutOrder(orderId: String, quote: FeeQuote): ApiResult<CheckoutPayResult>
}

@Singleton
class FeesRepositoryImpl @Inject constructor(
    private val api: FeesApi,
    private val errorParser: ApiErrorParser,
) : FeesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun quoteFee(amountCents: Long, payWith: String): ApiResult<FeeQuote?> =
        withContext(io) {
            try {
                ApiResult.Success(api.quoteFee(FeeQuoteReqDto(amountCents, payWith)).toDomain(payWith))
            } catch (e: CancellationException) {
                throw e
            } catch (e: HttpException) {
                // Degrade-on-404: pay-any-coin quoting not deployed on this backend.
                if (e.code() == 404) ApiResult.Success(null)
                else ApiResult.Failure(errorParser.from(e))
            } catch (e: IOException) {
                ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
            }
        }

    override suspend fun payCheckoutOrder(
        orderId: String,
        quote: FeeQuote,
    ): ApiResult<CheckoutPayResult> = withContext(io) {
        try {
            ApiResult.Success(
                api.payCheckoutOrder(
                    orderId = orderId,
                    body = CheckoutPayReqDto(payWith = quote.payWith, quoteToken = quote.quoteToken),
                ).toDomain(),
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}

@Module
@InstallIn(SingletonComponent::class)
object FeesApiModule {
    @Provides
    @Singleton
    fun provideFeesApi(retrofit: Retrofit): FeesApi = retrofit.create(FeesApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class FeesDataModule {
    @Binds
    @Singleton
    abstract fun bindFeesRepository(impl: FeesRepositoryImpl): FeesRepository
}
