package com.testlogon.android.data.fanclub

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.subscriptions.BillingInterval
import com.testlogon.android.data.subscriptions.CreatorSubscription
import com.testlogon.android.data.subscriptions.SubscriptionState
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-238/239/240 — contract tests for [FanClubRepositoryImpl] against MockWebServer (real Retrofit/Moshi).
 * Verifies the verified fan-club wire contract: paths/params/verbs, bare-array deserialization, DTO->domain
 * mapping (epoch-seconds, reactions map, tier grouping/access via the active subscription join), and error
 * folding.
 */
class FanClubRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(
        userSub: String? = "me",
        subs: ApiResult<List<CreatorSubscription>> = ApiResult.Success(emptyList()),
    ): FanClubRepositoryImpl {
        val api = backend.retrofit(moshi).create(FanClubApi::class.java)
        return FanClubRepositoryImpl(
            api = api,
            errorParser = ApiErrorParser(moshi),
            authStateStore = FakeAuthStateStore(userSub),
            subscriptionsRepository = FakeSubscriptionsRepository(subs),
        )
    }

    private fun sub(planId: String, status: SubscriptionState = SubscriptionState.ACTIVE) = CreatorSubscription(
        subscriptionId = "s_$planId",
        planId = planId,
        creatorId = "creator_1",
        subscriberId = "me",
        interval = BillingInterval.MONTH,
        provider = null,
        status = status,
        startAtEpochSeconds = null,
        currentPeriodEndEpochSeconds = null,
        cancelAtPeriodEnd = false,
        priceCents = null,
        currency = null,
        autoRenew = true,
    )

    @Test
    fun channels_bareArray_groupedByTier_withAccessFromActiveSub() = runTest {
        // channels (bare array) then tiers (bare array). Active sub = plan_bronze (level 1).
        backend.enqueue(
            Fixtures.okBody(
                """
                [
                  {"channel_id":"c_free","name":"general","min_tier_level":0,"last_message_at":10,"last_message_preview":"hi"},
                  {"channel_id":"c_gold","name":"gold-lounge","min_tier_level":3},
                  {"channel_id":"c_bronze","name":"bronze","min_tier_level":1}
                ]
                """.trimIndent(),
            ),
        )
        backend.enqueue(
            Fixtures.okBody(
                """
                [
                  {"tier_id":"t_bronze","plan_id":"plan_bronze","name":"Bronze","level":1,"sort_order":1,"member_count":5,"active":true},
                  {"tier_id":"t_gold","plan_id":"plan_gold","name":"Gold","level":3,"sort_order":2,"member_count":2,"active":true}
                ]
                """.trimIndent(),
            ),
        )
        val result = repo(subs = ApiResult.Success(listOf(sub("plan_bronze")))).getChannelsByTier("creator_1")

        assertTrue(result is ApiResult.Success)
        val sections = (result as ApiResult.Success).data
        assertEquals(listOf(0, 1, 3), sections.map { it.level })
        // free + bronze accessible (active level 1); gold locked.
        assertTrue(sections[0].channels.single().isAccessible)
        assertTrue(sections[1].channels.single().isAccessible)
        assertFalse(sections[2].channels.single().isAccessible)

        val channelsReq = backend.takeRequest()
        assertEquals("GET", channelsReq.method)
        assertEquals("/ui/fan-club/channels", channelsReq.requestUrl?.encodedPath)
        assertEquals("creator_1", channelsReq.requestUrl?.queryParameter("creator_id"))
    }

    @Test
    fun channels_500_foldsToFailure_neverThrows() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        val result = repo().getChannelsByTier(null)
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun channels_timeout_foldsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().getChannelsByTier(null)
        assertTrue(result is ApiResult.NetworkError)
        assertTrue((result as ApiResult.NetworkError).isTimeout)
    }

    @Test
    fun messages_bareArray_mapsReactionsAndDerivesReactedByMe() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [
                  {"message_id":"m1","channel_id":"c","sender_id":"usr_9","sender_display_name":"Ada",
                   "text":"hello","kind":"text","created_at":1749124800,"deleted":false,
                   "reactions":{"🔥":{"usr_1":true,"me":true}}}
                ]
                """.trimIndent(),
            ),
        )
        val result = repo(userSub = "me").getMessages("c", before = null, limit = 30)

        assertTrue(result is ApiResult.Success)
        val msg = (result as ApiResult.Success).data.single()
        assertEquals("m1", msg.id)
        assertEquals(1749124800L, msg.createdAtEpochSeconds)
        assertEquals(2, msg.reactions.single().count)
        assertTrue(msg.reactions.single().reactedByMe)

        val req = backend.takeRequest()
        assertEquals("/ui/fan-club/channels/c/messages", req.requestUrl?.encodedPath)
        assertEquals("30", req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("before"))
    }

    @Test
    fun postText_sendsChannelMessageInBody_returnsMappedMessage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"message_id":"m_new","sender_id":"me","sender_display_name":"Me","text":"yo","kind":"text","created_at":1,"deleted":false,"reactions":{}}""",
                code = 201,
            ),
        )
        val result = repo(userSub = "me").postText("c", "yo")
        assertTrue(result is ApiResult.Success)
        assertEquals("m_new", (result as ApiResult.Success).data.id)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/fan-club/channels/c/messages", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"text\":\"yo\""))
        assertFalse(body.contains("client_token"))
        assertFalse(body.contains("\"type\""))
    }

    @Test
    fun react_postsToReactPath_andTreats200AsSuccess() = runTest {
        backend.enqueue(Fixtures.okBody("{}", code = 200))
        val result = repo().toggleReaction("c", "m1", "🔥")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/fan-club/channels/c/messages/m1/react", req.requestUrl?.encodedPath)
    }

    @Test
    fun delete_treats200AsSuccess() = runTest {
        backend.enqueue(Fixtures.okBody("", code = 200))
        val result = repo().deleteMessage("c", "m1")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/ui/fan-club/channels/c/messages/m1", req.requestUrl?.encodedPath)
    }

    @Test
    fun post_403_foldsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"You can't post here\"", 403))
        val result = repo().postText("c", "hi")
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun tierMembers_envelope_mapsAndThreadsCursorAndLimit() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"items":[
                  {"user_id":"u1","username":"kestrel","display_name":"Kestrel","subscribed_since":1700000000},
                  {"user_id":null,"username":"ghost"}
                ],"next_cursor":"c2","total":128}
                """.trimIndent(),
            ),
        )
        val result = repo().getTierMembers("tier_gold", cursor = null, limit = 50)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(1, page.members.size) // null user_id row dropped
        assertEquals("Kestrel", page.members.single().displayName)
        assertEquals("c2", page.nextCursor)
        assertEquals(128, page.total)

        val req = backend.takeRequest()
        assertEquals("/ui/fan-club/tiers/tier_gold/members", req.requestUrl?.encodedPath)
        assertEquals("50", req.requestUrl?.queryParameter("limit"))
        assertNull(req.requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun tiers_422_foldsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"msg":"bad","type":"value_error"}]""", 422))
        val result = repo().getTiers(null)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
