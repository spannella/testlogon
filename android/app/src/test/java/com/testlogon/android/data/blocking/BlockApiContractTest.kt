package com.testlogon.android.data.blocking

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.Interceptor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-382 - contract tests for [BlockApi] against MockWebServer (real Retrofit/Moshi).
 *
 * Verifies the CORRECTED ui/social contract: block/unblock are body POSTs with target_user_id,
 * list is GET /ui/social/blocked, status is GET /ui/social/block-status/{id}; response shapes parse
 * with the verified keys (blocked_users / blocked_at / total_count, is_blocked_by_me / is_blocking_me)
 * and NO handle/created_at/items. Also asserts X-CSRF-Token presence on the mutating POSTs.
 *
 * Traces TC-AND-382-01/02/03 + the CSRF half of TC-14.
 */
class BlockApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): BlockApi = backend.retrofit(moshi).create(BlockApi::class.java)

    /** A client that mirrors the production CsrfInterceptor: stamps X-CSRF-Token on mutating verbs. */
    private fun csrfApi(token: String = "csrf-xyz"): BlockApi {
        val csrf = Interceptor { chain ->
            val req = chain.request()
            val out = if (req.method in setOf("POST", "PUT", "PATCH", "DELETE")) {
                req.newBuilder().header("X-CSRF-Token", token).build()
            } else {
                req
            }
            chain.proceed(out)
        }
        val client = defaultTestClient().newBuilder().addInterceptor(csrf).build()
        return backend.retrofit(moshi, client = client).create(BlockApi::class.java)
    }

    @Test
    fun block_postPathBodyAndCsrf() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"ok":true,"status":"blocked","target_user_id":"usr_abc"}"""),
        )

        val resp = csrfApi().block(BlockRequestDto(targetUserId = "usr_abc"))

        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/social/block", recorded.requestUrl?.encodedPath)
        assertEquals("csrf-xyz", recorded.getHeader("X-CSRF-Token"))
        val body = recorded.body.readUtf8()
        assertTrue(body.contains("\"target_user_id\":\"usr_abc\""))
        // reason is null -> omitted from the wire.
        assertTrue(!body.contains("reason"))
        assertEquals("blocked", resp.body()?.status)
        assertTrue(resp.isSuccessful)
    }

    @Test
    fun unblock_isPostNotDelete_withBodyAndCsrf() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"ok":true,"status":"unblocked","target_user_id":"usr_abc"}"""),
        )

        val resp = csrfApi().unblock(UnblockRequestDto(targetUserId = "usr_abc"))

        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/social/unblock", recorded.requestUrl?.encodedPath)
        assertEquals("csrf-xyz", recorded.getHeader("X-CSRF-Token"))
        assertTrue(recorded.body.readUtf8().contains("\"target_user_id\":\"usr_abc\""))
        assertEquals("unblocked", resp.body()?.status)
    }

    @Test
    fun listBlocks_pathParamsAndDeserialization() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {
                  "blocked_users": [
                    {"user_id":"usr_abc","display_name":"Alice","profile_photo_url":null,"blocked_at":"2026-06-05T12:00:00Z"}
                  ],
                  "next_cursor": null,
                  "total_count": 1
                }
                """.trimIndent(),
            ),
        )

        val dto = api().listBlocks().body()!!

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/social/blocked", recorded.requestUrl?.encodedPath)
        assertEquals("50", recorded.requestUrl?.queryParameter("limit"))
        assertNull(recorded.requestUrl?.queryParameter("cursor"))
        assertEquals(1, dto.totalCount)
        assertEquals("usr_abc", dto.blockedUsers[0].userId)
        assertEquals("Alice", dto.blockedUsers[0].displayName)
        assertNull(dto.blockedUsers[0].profilePhotoUrl)
        assertEquals("2026-06-05T12:00:00Z", dto.blockedUsers[0].blockedAt)
    }

    @Test
    fun blockStatus_pathAndFlags() = runTest {
        backend.enqueue(Fixtures.okBody("""{"is_blocked_by_me":true,"is_blocking_me":false}"""))

        val dto = api().blockStatus("usr_abc").body()!!

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/social/block-status/usr_abc", recorded.requestUrl?.encodedPath)
        assertTrue(dto.isBlockedByMe)
        assertTrue(!dto.isBlockingMe)
    }

    @Test
    fun blockedUserItem_tolerates_sparsePayload() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"blocked_users":[{"user_id":"usr_only"}],"next_cursor":null,"total_count":1}""",
            ),
        )
        val dto = api().listBlocks().body()!!
        val item = dto.blockedUsers.single()
        assertEquals("usr_only", item.userId)
        assertNull(item.displayName)
        assertEquals("", item.blockedAt)
    }
}
