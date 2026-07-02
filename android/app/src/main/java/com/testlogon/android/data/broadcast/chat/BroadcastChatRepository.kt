package com.testlogon.android.data.broadcast.chat

import android.net.Uri
import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.feed.PostComposeRepository
import com.testlogon.android.data.videos.VideoUploadRepository
import com.testlogon.android.data.videos.VideosApi
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
 * AND-281 / BCAST-016 — broadcast live-chat data layer: merges the [BroadcastChatStream] SSE with the
 * [BroadcastChatApi] send/react/unlock/view/history mutations, all in [ApiResult]. Live chat is ephemeral
 * (no Room persistence). `isSelf` is derived from the current [AuthStateStore.userSub].
 *
 * BCAST-016 rich types: `send` carries reply/media/gating options; `unlock` pays-to-reveal a PPV message;
 * `consumeView` records a view-once. Chat media has no dedicated broadcast presign, so image uploads reuse
 * the generic `POST uploads/image` (via [PostComposeRepository]) and video uploads reuse the VOD pipeline
 * (via [VideoUploadRepository] + a [VideosApi] detail lookup for the servable HLS + poster urls).
 */
interface BroadcastChatRepository {

    /** Cold flow of connection-state + decoded chat events for a session (wraps the SSE stream). */
    fun chatEvents(sessionId: String): Flow<ChatStreamSignal>

    /** Recent-history seed (idempotent GET). */
    suspend fun loadHistory(sessionId: String, limit: Int = 100): ApiResult<List<ChatMessage>>

    /** Sends a message (text and/or media + gating options); returns the authoritative server message. */
    suspend fun send(
        sessionId: String,
        text: String?,
        options: ChatComposeOptions = ChatComposeOptions(),
        imageUrl: String? = null,
        videoUrl: String? = null,
        thumbnailUrl: String? = null,
    ): ApiResult<ChatMessage>

    /** Reacts to a message; returns the server reactions_counts map. */
    suspend fun reactToMessage(
        sessionId: String,
        messageId: String,
        emoji: String,
        action: String = "add",
    ): ApiResult<Map<String, Int>>

    /** BCAST-016 — pay-to-reveal a locked/PPV message; returns the revealed message when the body carries it. */
    suspend fun unlock(sessionId: String, messageId: String, paymentMethodId: String): ApiResult<ChatMessage?>

    /** BCAST-016 — consume a view-once message (server redacts subsequent reads for this viewer). */
    suspend fun consumeView(sessionId: String, messageId: String): ApiResult<Unit>

    /** BCAST-016 — upload a picked image; returns a servable url for `image_url`. */
    suspend fun uploadImage(localUri: String): ApiResult<String>

    /** BCAST-016 — upload a picked video via the VOD pipeline; returns a servable url + poster. */
    suspend fun uploadVideo(localUri: String): ApiResult<BroadcastVideoUpload>

    /** The current viewer's user-sub, used by the VM to flag own/self messages and reactions. */
    fun selfId(): String?
}

@Singleton
class BroadcastChatRepositoryImpl @Inject constructor(
    private val api: BroadcastChatApi,
    private val stream: BroadcastChatStream,
    private val authStateStore: AuthStateStore,
    private val errorParser: ApiErrorParser,
    private val postCompose: PostComposeRepository,
    private val videoUpload: VideoUploadRepository,
    private val videosApi: VideosApi,
) : BroadcastChatRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun selfId(): String? = authStateStore.userSub.value

    override fun chatEvents(sessionId: String): Flow<ChatStreamSignal> =
        stream.events(sessionId, selfId())

    override suspend fun loadHistory(sessionId: String, limit: Int): ApiResult<List<ChatMessage>> =
        withContext(io) {
            when (val result = call { api.history(sessionId, limit) }) {
                is ApiResult.Success ->
                    ApiResult.Success(result.data?.messages?.map { it.toDomain(selfId()) } ?: emptyList())
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }

    override suspend fun send(
        sessionId: String,
        text: String?,
        options: ChatComposeOptions,
        imageUrl: String?,
        videoUrl: String?,
        thumbnailUrl: String?,
    ): ApiResult<ChatMessage> = withContext(io) {
        val body = SendChatDto(
            text = text?.takeIf { it.isNotBlank() },
            replyToMessageId = options.replyToMessageId,
            imageUrl = imageUrl,
            videoUrl = videoUrl,
            thumbnailUrl = thumbnailUrl,
            viewOnce = options.viewOnce,
            lockPriceCents = options.lockPriceCents,
            lockDescription = options.lockDescription,
            expiresInSeconds = options.expiresInSeconds,
            sendAt = options.sendAtEpochSeconds,
        )
        when (val result = call { api.send(sessionId, body) }) {
            is ApiResult.Success -> {
                val out = result.data
                    ?: return@withContext ApiResult.Failure(
                        errorParser.fromThrowable(JsonDataException("empty send body")),
                    )
                ApiResult.Success(out.toDomain(selfId()))
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

    override suspend fun unlock(
        sessionId: String,
        messageId: String,
        paymentMethodId: String,
    ): ApiResult<ChatMessage?> = withContext(io) {
        when (val result = call { api.unlock(sessionId, messageId, UnlockChatDto(paymentMethodId)) }) {
            is ApiResult.Success -> ApiResult.Success(result.data?.toDomain(selfId()))
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun consumeView(sessionId: String, messageId: String): ApiResult<Unit> =
        withContext(io) {
            when (val result = call { api.consumeView(sessionId, messageId) }) {
                is ApiResult.Success -> ApiResult.Success(Unit)
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }

    override suspend fun uploadImage(localUri: String): ApiResult<String> = withContext(io) {
        postCompose.uploadImage(Uri.parse(localUri))
    }

    override suspend fun uploadVideo(localUri: String): ApiResult<BroadcastVideoUpload> = withContext(io) {
        when (val up = videoUpload.upload(Uri.parse(localUri), title = "Live chat clip", description = "")) {
            is ApiResult.Success -> {
                val videoId = up.data
                if (videoId.isBlank()) {
                    return@withContext ApiResult.Failure(
                        errorParser.fromThrowable(IOException("video upload returned no id")),
                    )
                }
                try {
                    val detail = videosApi.getVideoDetail(videoId)
                    val url = detail.hlsManifestUrl?.takeIf { it.isNotBlank() }
                        ?: detail.thumbnailUrl?.takeIf { it.isNotBlank() }
                        ?: return@withContext ApiResult.Failure(
                            errorParser.fromThrowable(IOException("video not yet playable")),
                        )
                    ApiResult.Success(BroadcastVideoUpload(videoUrl = url, thumbnailUrl = detail.thumbnailUrl))
                } catch (e: CancellationException) {
                    throw e
                } catch (e: HttpException) {
                    ApiResult.Failure(errorParser.from(e))
                } catch (e: IOException) {
                    ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
                }
            }
            is ApiResult.Failure -> up
            is ApiResult.NetworkError -> up
        }
    }

    /**
     * Folds a Retrofit [Response] into [ApiResult]; non-2xx -> Failure via the shared parser; a 2xx
     * with an empty body yields a null payload. Cancellation is re-thrown.
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
