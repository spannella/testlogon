package com.testlogon.android.data.broadcast

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
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/** AND-279 — domain result of registering a reminder ({ ok, remind_at }). */
data class ReminderRegistration(
    val ok: Boolean,
    /** When the server intends to remind the viewer (≈T-30m before start), or null if not echoed. */
    val remindAt: Instant?,
)

/**
 * AND-279 — write-only remind-me data layer over [BroadcastReminderApi].
 *
 * Wraps each call in [ApiResult] exactly like [BroadcastRepositoryImpl] (Failure for HTTP errors via
 * [ApiErrorParser]; NetworkError for transport; Failure(parse) for malformed JSON). These are
 * NON-idempotent writes — the ViewModel never auto-retries them (AND-279 FR-5/§7). There is no
 * server-sourced `reminder_set` flag, so reminder on-state is held as client/local state only.
 */
interface BroadcastReminderRepository {

    /** Registers a reminder for [sessionId] (POST). */
    suspend fun setReminder(sessionId: String): ApiResult<ReminderRegistration>

    /** Clears a reminder for [sessionId] (DELETE). */
    suspend fun clearReminder(sessionId: String): ApiResult<Unit>
}

@Singleton
class BroadcastReminderRepositoryImpl @Inject constructor(
    private val api: BroadcastReminderApi,
    private val errorParser: ApiErrorParser,
) : BroadcastReminderRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun setReminder(sessionId: String): ApiResult<ReminderRegistration> =
        withContext(io) {
            call { api.registerReminder(sessionId) }.let { result ->
                when (result) {
                    is ApiResult.Success -> {
                        val body = result.data
                        ApiResult.Success(
                            ReminderRegistration(
                                ok = body?.ok ?: true,
                                remindAt = body?.remindAt?.let { Instant.ofEpochSecond(it) },
                            ),
                        )
                    }
                    is ApiResult.Failure -> result
                    is ApiResult.NetworkError -> result
                }
            }
        }

    override suspend fun clearReminder(sessionId: String): ApiResult<Unit> =
        withContext(io) {
            when (val result = call { api.cancelReminder(sessionId) }) {
                is ApiResult.Success -> ApiResult.Success(Unit)
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }

    /**
     * Folds a Retrofit [Response] into [ApiResult]. A non-2xx response is surfaced as Failure via the
     * shared [ApiErrorParser] (wrapping it in the same HttpException path); a 2xx with an empty body
     * yields a null payload (the DELETE accepts an empty body). Cancellation is re-thrown.
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

/** AND-279 — provides [BroadcastReminderApi] on the shared Retrofit and binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object BroadcastReminderApiModule {

    @Provides
    @Singleton
    fun provideBroadcastReminderApi(retrofit: Retrofit): BroadcastReminderApi =
        retrofit.create(BroadcastReminderApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class BroadcastReminderDataModule {

    @Binds
    @Singleton
    abstract fun bindBroadcastReminderRepository(
        impl: BroadcastReminderRepositoryImpl,
    ): BroadcastReminderRepository
}
