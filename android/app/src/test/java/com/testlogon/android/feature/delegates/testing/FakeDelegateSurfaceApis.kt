package com.testlogon.android.feature.delegates.testing

import com.testlogon.android.core.network.delegates.DelegateBroadcastApi
import com.testlogon.android.core.network.delegates.DelegateFeedApi
import com.testlogon.android.core.network.delegates.DelegateMessagingApi
import com.testlogon.android.core.network.delegates.DelegatedConversationOut
import com.testlogon.android.core.network.delegates.DelegatedMessageOut
import com.testlogon.android.core.network.delegates.DelegatedModerationIn
import com.testlogon.android.core.network.delegates.DelegatedPostCreateIn
import com.testlogon.android.core.network.delegates.DelegatedPostOut
import com.testlogon.android.core.network.delegates.DelegatedScheduleSessionIn
import com.testlogon.android.core.network.delegates.DelegatedSendMessageIn
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-360 - in-memory fakes of the delegate-PATH APIs for app repository tests (NO Moshi - the app-test
 * classpath has no reflective KotlinJsonAdapterFactory). Each fake RECORDS its call args BEFORE honouring
 * a configured throw, so a test can assert the delegate path / creatorId was used even on the failure path.
 * Set [throwHttp] to make the next call throw an HttpException with that status (e.g. 403). Helper field
 * names are distinct across the three fakes so they never collide.
 */

private fun httpError(status: Int): HttpException = HttpException(
    Response.error<Any>(status, """{"detail":"boom"}""".toResponseBody("application/json".toMediaType())),
)

/** AND-360 - fake [DelegateFeedApi] recording createPost / listPosts / deletePost calls. */
class FakeDelegateFeedApi(
    var posts: List<DelegatedPostOut> = emptyList(),
    var throwHttp: Int? = null,
) : DelegateFeedApi {

    val createPostCalls = mutableListOf<Pair<String, DelegatedPostCreateIn>>()
    val listPostsCalls = mutableListOf<Pair<String, Int>>()
    val deletePostCalls = mutableListOf<Pair<String, String>>()

    override suspend fun createPost(creatorId: String, body: DelegatedPostCreateIn): DelegatedPostOut {
        createPostCalls += creatorId to body
        throwHttp?.let { throw httpError(it) }
        return DelegatedPostOut(postId = "p_new", text = body.text)
    }

    override suspend fun listPosts(creatorId: String, limit: Int): List<DelegatedPostOut> {
        listPostsCalls += creatorId to limit
        throwHttp?.let { throw httpError(it) }
        return posts
    }

    override suspend fun deletePost(creatorId: String, postId: String): Response<Unit> {
        deletePostCalls += creatorId to postId
        throwHttp?.let { throw httpError(it) }
        return Response.success(Unit)
    }
}

/** AND-360 - fake [DelegateMessagingApi] recording conversations / messages / send calls. */
class FakeDelegateMessagingApi(
    var conversationList: List<DelegatedConversationOut> = emptyList(),
    var messageList: List<DelegatedMessageOut> = emptyList(),
    var throwHttp: Int? = null,
) : DelegateMessagingApi {

    val conversationCalls = mutableListOf<String>()
    val messageCalls = mutableListOf<Pair<String, String>>()
    val sendCalls = mutableListOf<Triple<String, String, DelegatedSendMessageIn>>()

    override suspend fun conversations(creatorId: String): List<DelegatedConversationOut> {
        conversationCalls += creatorId
        throwHttp?.let { throw httpError(it) }
        return conversationList
    }

    override suspend fun messages(creatorId: String, cid: String): List<DelegatedMessageOut> {
        messageCalls += creatorId to cid
        throwHttp?.let { throw httpError(it) }
        return messageList
    }

    override suspend fun send(
        creatorId: String,
        cid: String,
        body: DelegatedSendMessageIn,
    ): DelegatedMessageOut {
        sendCalls += Triple(creatorId, cid, body)
        throwHttp?.let { throw httpError(it) }
        return DelegatedMessageOut(messageId = "m_new", text = body.text, sentByDelegate = true)
    }
}

/** AND-360 - fake [DelegateBroadcastApi] recording control + moderation calls. */
class FakeDelegateBroadcastApi(
    var throwHttp: Int? = null,
) : DelegateBroadcastApi {

    val startCalls = mutableListOf<Pair<String, String>>()
    val stopCalls = mutableListOf<Pair<String, String>>()
    val scheduleCalls = mutableListOf<Pair<String, DelegatedScheduleSessionIn>>()
    val muteCalls = mutableListOf<Triple<String, String, DelegatedModerationIn>>()
    val banCalls = mutableListOf<Triple<String, String, DelegatedModerationIn>>()

    override suspend fun startSession(creatorId: String, sid: String): Response<Unit> {
        startCalls += creatorId to sid
        throwHttp?.let { throw httpError(it) }
        return Response.success(Unit)
    }

    override suspend fun stopSession(creatorId: String, sid: String): Response<Unit> {
        stopCalls += creatorId to sid
        throwHttp?.let { throw httpError(it) }
        return Response.success(Unit)
    }

    override suspend fun scheduleSession(
        creatorId: String,
        body: DelegatedScheduleSessionIn,
    ): Response<Unit> {
        scheduleCalls += creatorId to body
        throwHttp?.let { throw httpError(it) }
        return Response.success(Unit)
    }

    override suspend fun muteViewer(
        creatorId: String,
        sid: String,
        body: DelegatedModerationIn,
    ): Response<Unit> {
        muteCalls += Triple(creatorId, sid, body)
        throwHttp?.let { throw httpError(it) }
        return Response.success(Unit)
    }

    override suspend fun banViewer(
        creatorId: String,
        sid: String,
        body: DelegatedModerationIn,
    ): Response<Unit> {
        banCalls += Triple(creatorId, sid, body)
        throwHttp?.let { throw httpError(it) }
        return Response.success(Unit)
    }
}
