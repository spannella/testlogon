package com.testlogon.android.data.broadcast.chat

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-281 — broadcast live-chat data layer: merges the [BroadcastChatStream] SSE with the
 * [BroadcastChatApi] send/react/history mutations, all in [ApiResult]. Live chat is ephemeral (no Room
 * persistence). `isSelf` is derived from the current [AuthStateStore.userSub].
 */
interface BroadcastChatRepository {

    /** Cold flow of connection-state + decoded chat events for a session (wraps the SSE stream). */
    fun chatEvents(sessionId: String): Flow<ChatStreamSignal>

    /** Recent-history seed (idempotent GET). */
    suspend fun loadHistory(sessionId: String, limit: Int = 100): ApiResult<List<ChatMessage>>

    /** Sends a text message; returns the authoritative server [ChatMessage] (no client_id on the wire). */
    suspend fun send(sessionId: String, text: String): ApiResult<ChatMessage>

    /** Reacts to a message; returns the server reactions_counts map. */
    suspend fun reactToMessage(
        sessionId: String,
        messageId: String,
        emoji: String,
        action: String = "add",
    ): ApiResult<Map<String, Int>>

    /** The current viewer's user-sub, used by the VM to flag own/self messages and reactions. */
    fun selfId(): String?
}

@Singleton
class BroadcastChatRepositoryImpl @Inject constructor(
    private val api: BroadcastChatApi,
    private val stream: BroadcastChatStream,
    private val authStateStore: AuthStateStore,
    private val errorParser: ApiErrorParser,
) : BroadcastChatRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun selfId(): String? = authStateStore.userSub.value

    override fun chatEvents(sessionId: String): Flow<ChatStreamSignal> =
        stream.events(sessionId, selfId())

    override suspend fun loadHistory(sessionId: String, limit: Int): ApiResult<List<ChatMessage>> =
        withContext(io) {
            call { api.history(sessionId, limit) }.let { result ->
                when (result) {
                    is ApiResult.Success ->
                        ApiResult.Success(result.data?.messages?.map { it.toDomain(selfId()) } ?: emptyList())
                    is ApiResult.Failure -> result
                    is ApiResult.NetworkError -> result
                }
            }
        }

    override suspend fun send(sessionId: String, text: String): ApiResult<ChatMessage> =
        withContext(io) {
            when (val result = call { api.send(sessionId, SendChatDto(text = text)) }) {
                is ApiResult.Success -> {
                    val body = result.data
                        ?: return@withContext ApiResult.Failure(
                            errorParser.fromThrowable(JsonDataException("empty send body")),
                        )
                    ApiResult.Success(body.toDomain(selfId()))
                }
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }

    override suspend fun reactToMessage(
        sessionId: String,
        messageId: String,
        emoji: String,
        action: String,
    ): ApiResult<Map<String, Int>> = withContext(io) {
        when (val result = call { api.reactToMessage(sessionId, messageId, ReactionDto(emoji, action)) }) {
            is ApiResult.Success -> ApiResult.Success(result.data?.reactionsCounts ?: emptyMap())
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    /**
     * Folds a Retrofit [Response] into [ApiResult]; non-2xx -> Failure via the shared parser; a 2xx
     * with an empty body yields a null payload. The JsonEncodingException catch precedes IOException
     * (it is an IOException subtype). Cancellation is re-thrown.
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

/** AND-281 — provides [BroadcastChatApi] + binds the repository and SSE stream. */
@Module
@InstallIn(SingletonComponent::class)
object BroadcastChatApiModule {

    @Provides
    @Singleton
    fun provideBroadcastChatApi(retrofit: Retrofit): BroadcastChatApi =
        retrofit.create(BroadcastChatApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class BroadcastChatDataModule {

    @Binds
    @Singleton
    abstract fun bindBroadcastChatRepository(impl: BroadcastChatRepositoryImpl): BroadcastChatRepository

    @Binds
    @Singleton
    abstract fun bindBroadcastChatStream(impl: SseBroadcastChatStream): BroadcastChatStream
}
