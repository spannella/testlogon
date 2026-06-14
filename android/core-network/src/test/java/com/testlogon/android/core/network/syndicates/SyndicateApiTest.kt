package com.testlogon.android.core.network.syndicates

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-356 - hermetic request-shape / decode tests for the [SyndicateApi] (mirrors AND-355 GroupsApiTest).
 *
 * Everything is hermetic: MockWebServer only, a production-style Moshi (BigDecimalAdapter + the reflective
 * KotlinJsonAdapterFactory, like NetworkModule.provideMoshi), and runTest. The syndicate DTOs use no enum
 * adapters (mode is a plain String on the wire; the typed SplitMode lives in core-model). core-network has
 * no test dependency on core-testing, so the JSON bodies are inline. KDoc avoids the comment-terminator pair.
 */
class SyndicateApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun api(): SyndicateApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(SyndicateApi::class.java)

    private fun jsonResponse(body: String, code: Int = 200) =
        MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)

    @Before
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun getProfile_decodes_andSubstitutesSyndicateIdPath() = runTest {
        server.enqueue(
            jsonResponse(
                """{"id":"syn_1","name":"Aces","member_count":4,"admin_user_id":"usr_admin",
                    "currency":"usd","is_member":true}""",
            ),
        )

        val profile = api().getProfile("syn_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/syndicates/syn_1", recorded.requestUrl?.encodedPath)
        assertEquals("Aces", profile.name)
        assertEquals(4, profile.memberCount)
        assertEquals("usr_admin", profile.adminUserId)
        assertEquals("usd", profile.currency)
        assertEquals(true, profile.isMember)
    }

    @Test
    fun getFeed_decodesPostsEnvelope_withCursor() = runTest {
        server.enqueue(
            jsonResponse(
                """{"posts":[
                     {"post_id":"p1","author_name":"Ann","author_avatar_url":"https://x/a.png",
                      "created_at":1780000000,"text":"hi","image_url":"https://x/i.png",
                      "reaction_count":2,"comment_count":1,"tip_count":0},
                     {"post_id":"p2","created_at":1779999999,"text":"yo"}
                   ],"is_member":true,"next_cursor":"c2"}""",
            ),
        )

        val feed = api().getFeed("syn_1", cursor = "c1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/syndicates/syn_1/feed", recorded.requestUrl?.encodedPath)
        assertEquals("c1", recorded.requestUrl?.queryParameter("cursor"))
        assertEquals(2, feed.posts.size)
        assertEquals("p1", feed.posts[0].postId)
        assertEquals("Ann", feed.posts[0].authorName)
        assertEquals(1780000000L, feed.posts[0].createdAt)
        assertEquals("c2", feed.nextCursor)
        assertEquals(true, feed.isMember)
    }

    @Test
    fun getTreasury_decodesSummary_andLedger() = runTest {
        server.enqueue(
            jsonResponse(
                """{"balance_cents":150000,"total_deposited_cents":200000,
                    "total_disbursed_cents":50000,"currency":"usd","ledger":[
                      {"entry_id":"e1","direction":"credit","amount_cents":10000,"reason":"tip",
                       "ts":1780000000,"counterparty_user_id":"usr_x"},
                      {"entry_id":"e2","direction":"debit","amount_cents":2500,"ts":1779999999}
                    ],"next_cursor":"lc2"}""",
            ),
        )

        val treasury = api().getTreasury("syn_1")

        val recorded = server.takeRequest()
        assertEquals("/ui/syndicates/syn_1/treasury", recorded.requestUrl?.encodedPath)
        assertEquals(150000, treasury.balanceCents)
        assertEquals(200000, treasury.totalDepositedCents)
        assertEquals(50000, treasury.totalDisbursedCents)
        assertEquals(2, treasury.ledger.size)
        assertEquals("credit", treasury.ledger[0].direction)
        assertEquals(10000, treasury.ledger[0].amountCents)
        assertEquals("lc2", treasury.nextCursor)
    }

    @Test
    fun getRevenueSplit_decodesWeightedConfig_withWeightsMap() = runTest {
        server.enqueue(
            jsonResponse(
                """{"mode":"weighted","platform_fee_bps":500,"updated_at":1780000000,
                    "updated_by":"usr_admin","weights_bps":{"usr_a":6000,"usr_b":4000}}""",
            ),
        )

        val split = api().getRevenueSplit("syn_1")

        val recorded = server.takeRequest()
        assertEquals("/ui/syndicates/syn_1/revenue-split", recorded.requestUrl?.encodedPath)
        assertEquals("weighted", split.mode)
        assertEquals(500, split.platformFeeBps)
        assertEquals(6000, split.weightsBps?.get("usr_a"))
        assertEquals(4000, split.weightsBps?.get("usr_b"))
    }

    // ---- AND-357: open-licensing ----

    @Test
    fun getOpenLicensingContent_decodesItemsEnvelope_andSubstitutesPath() = runTest {
        server.enqueue(
            jsonResponse(
                """{"items":[
                     {"content_id":"vid_1","content_type":"video","creator_id":"usr_a",
                      "exempt":true,"registered_at":1780000000},
                     {"content_id":"clip_2","content_type":"clip"}
                   ]}""",
            ),
        )

        val response = api().getOpenLicensingContent("syn_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/syndicates/open-licensing/syn_1/content", recorded.requestUrl?.encodedPath)
        assertEquals(2, response.items.size)
        assertEquals("vid_1", response.items[0].contentId)
        assertEquals("video", response.items[0].contentType)
        assertEquals("usr_a", response.items[0].creatorId)
        assertEquals(true, response.items[0].exempt)
        assertEquals(1780000000L, response.items[0].registeredAt)
        assertEquals("clip_2", response.items[1].contentId)
    }

    @Test
    fun registerOpenLicensing_postsBody_toRegisterPath_andDecodesReceipt() = runTest {
        server.enqueue(
            jsonResponse(
                """{"content_id":"vid_1","syndicate_id":"syn_1","licenses_created":3}""",
            ),
        )

        val receipt = api().registerOpenLicensing(
            "syn_1",
            SyndicateOpenLicensingRegisterIn(contentId = "vid_1", contentType = "video"),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/syndicates/open-licensing/syn_1/register", recorded.requestUrl?.encodedPath)
        val sentBody = recorded.body.readUtf8()
        assertTrue(sentBody.contains("\"content_id\":\"vid_1\""))
        assertTrue(sentBody.contains("\"content_type\":\"video\""))
        assertEquals("vid_1", receipt.contentId)
        assertEquals("syn_1", receipt.syndicateId)
        assertEquals(3, receipt.licensesCreated)
    }

    @Test
    fun registerOpenLicensing_422_surfacesAsHttpException() = runTest {
        server.enqueue(
            jsonResponse(
                """{"detail":[{"loc":["body","content_id"],"msg":"required","type":"value_error"}]}""",
                code = 422,
            ),
        )

        val error = runCatching {
            api().registerOpenLicensing(
                "syn_1",
                SyndicateOpenLicensingRegisterIn(contentId = "", contentType = "video"),
            )
        }.exceptionOrNull()

        val recorded = server.takeRequest()
        assertEquals("/ui/syndicates/open-licensing/syn_1/register", recorded.requestUrl?.encodedPath)
        assertTrue(error is HttpException)
        assertEquals(422, (error as HttpException).code())
    }
}
