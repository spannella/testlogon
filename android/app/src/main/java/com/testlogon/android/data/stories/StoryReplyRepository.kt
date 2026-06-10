package com.testlogon.android.data.stories

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.flatMap
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.messaging.FindOrCreateDmReq
import com.testlogon.android.data.messaging.MessagingApi
import com.testlogon.android.data.messaging.SendTextMessageReq
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-200 — story reaction / reply data layer.
 *
 * OQ-1 (spec §5.2 / §13): there is NO `/ui/stories/{id}/react` route in the backend and no web
 * precedent for story reactions/replies — the composer is an Android-original feature. Per the spec's
 * isolation design, both a quick emoji reaction and a free-text reply are routed through the verified
 * messaging primitives: resolve/create the author DM (POST /messaging/conversations/dm/find-or-create
 * -> FindOrCreateDmIn{user_id}), then send a text message
 * (POST /messaging/conversations/{conversation_id}/messages -> SendTextMessageIn{text}). A reaction is
 * sent as an emoji text message (mechanism (i) in §5.2); there is no story-context field on
 * SendTextMessageIn, so the message carries only `text` (the fabricated `context`/`is_reaction` keys
 * were corrected out of the spec).
 *
 * The viewer depends ONLY on [reactToStory] / [replyToStory]; the wire detail is isolated here so it
 * can change without touching the ViewModel/UI. These are state-changing POSTs and are NEVER retried.
 */
interface StoryReplyRepository {

    /** Send [emoji] as a quick reaction to the story author. Resolves/creates the DM first. */
    suspend fun reactToStory(storyId: String, authorId: String, emoji: String): ApiResult<Unit>

    /** Send a free-text [text] reply to the story author. Resolves/creates the DM first. */
    suspend fun replyToStory(storyId: String, authorId: String, text: String): ApiResult<Unit>
}

@Singleton
class StoryReplyRepositoryImpl @Inject constructor(
    private val messagingApi: MessagingApi,
    private val errorParser: ApiErrorParser,
) : StoryReplyRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun reactToStory(storyId: String, authorId: String, emoji: String): ApiResult<Unit> =
        send(authorId, emoji)

    override suspend fun replyToStory(storyId: String, authorId: String, text: String): ApiResult<Unit> =
        send(authorId, text)

    /** Resolve/create the author DM, then send [text]; folds the two-step flow into one ApiResult. */
    private suspend fun send(authorId: String, text: String): ApiResult<Unit> = withContext(io) {
        call { messagingApi.findOrCreateDm(FindOrCreateDmReq(userId = authorId)) }
            .flatMap { conversation ->
                call { messagingApi.sendMessage(conversation.conversationId, SendTextMessageReq(text = text)) }
            }
            .map { }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
