package com.testlogon.android.data.broadcast.tips

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-282 — broadcast tips + goals data layer.
 *
 * Holds in-memory [MutableStateFlow]s for the single active session's summary + goals (tips/goals are
 * session-ephemeral, no Room cache). [submitTip] authorizes via BillingAuthorizer at the VM layer; this
 * repo only POSTs once authorization yielded a payment_method_id, and never auto-retries the POST
 * (non-idempotent — would double-charge). On a successful tip (and on a tip-bearing chat:message event,
 * via [refresh]) the authoritative summary + goals GETs win over any optimistic local bump.
 */
interface TipsRepository {

    fun observeTipsSummary(): Flow<TipsSummary?>

    fun observeGoals(): Flow<List<Goal>>

    /** Re-GETs summary + goals; the authoritative result replaces the in-memory flows. */
    suspend fun refresh(sessionId: String): ApiResult<Unit>

    /**
     * POSTs the tip (paymentMethodId REQUIRED). NOT auto-retried. On success the returned [TipMessage]
     * is a chat message; callers should [refresh] to reconcile summary/goals (the 201 carries no snapshot).
     */
    suspend fun submitTip(
        sessionId: String,
        amountCents: Long,
        paymentMethodId: String,
        text: String?,
        currency: String = "USD",
    ): ApiResult<TipMessage>
}

@Singleton
class TipsRepositoryImpl @Inject constructor(
    private val api: BroadcastTipsApi,
    private val errorParser: ApiErrorParser,
) : TipsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    private val summaryFlow = MutableStateFlow<TipsSummary?>(null)
    private val goalsFlow = MutableStateFlow<List<Goal>>(emptyList())

    override fun observeTipsSummary(): Flow<TipsSummary?> = summaryFlow.asStateFlow()

    override fun observeGoals(): Flow<List<Goal>> = goalsFlow.asStateFlow()

    override suspend fun refresh(sessionId: String): ApiResult<Unit> = withContext(io) {
        val summaryResult = call { api.getTipsSummary(sessionId) }
        when (summaryResult) {
            is ApiResult.Success -> summaryResult.data?.toDomain()?.let { summaryFlow.value = it }
            is ApiResult.Failure -> return@withContext summaryResult
            is ApiResult.NetworkError -> return@withContext summaryResult
        }
        when (val goalsResult = call { api.getGoals(sessionId) }) {
            is ApiResult.Success -> {
                goalsFlow.value = goalsResult.data?.toDomain() ?: emptyList()
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> goalsResult
            is ApiResult.NetworkError -> goalsResult
        }
    }

    override suspend fun submitTip(
        sessionId: String,
        amountCents: Long,
        paymentMethodId: String,
        text: String?,
        currency: String,
    ): ApiResult<TipMessage> = withContext(io) {
        val body = BroadcastChatTipDto(
            amountCents = amountCents,
            paymentMethodId = paymentMethodId,
            text = text,
            currency = currency,
        )
        when (val result = call { api.submitTip(sessionId, body) }) {
            is ApiResult.Success -> {
                val data = result.data
                    ?: return@withContext ApiResult.Failure(
                        errorParser.fromThrowable(JsonDataException("empty tip body")),
                    )
                ApiResult.Success(data.toDomain())
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    /**
     * Folds a Retrofit [Response] into [ApiResult]; non-2xx -> Failure via the shared parser. The
     * JsonEncodingException catch precedes IOException (it is an IOException subtype). Cancellation is
     * re-thrown.
     */
    private suspend fun <T> call(block: suspend () -> Response<T>): ApiResult<T?> = try {
        val response = block()
        if (response.isSuccessful) {
            ApiResult.Success(response.body())
        } else {
            ApiResult.Failure(errorParser.from(HttpException(response)))
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

/** AND-282 — provides [BroadcastTipsApi] + binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object BroadcastTipsApiModule {

    @Provides
    @Singleton
    fun provideBroadcastTipsApi(retrofit: Retrofit): BroadcastTipsApi =
        retrofit.create(BroadcastTipsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class BroadcastTipsDataModule {

    @Binds
    @Singleton
    abstract fun bindTipsRepository(impl: TipsRepositoryImpl): TipsRepository
}
