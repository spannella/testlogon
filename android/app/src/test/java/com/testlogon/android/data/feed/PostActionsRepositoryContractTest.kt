package com.testlogon.android.data.feed

import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.feed.PostSuppressionKind
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-175 — contract tests for [PostActionsRepositoryImpl] against MockWebServer (real Retrofit/Moshi)
 * + an in-memory DAO. Verifies POST /feed/hide body { post_id }, not-interested ALSO posts /feed/hide
 * (NOT /feed/interesting), optimistic suppression + rollback, 404 = success-equivalent, and unhide.
 */
class PostActionsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(dao: FakePostSuppressionDao = FakePostSuppressionDao()): PostActionsRepositoryImpl {
        val api = backend.retrofit(moshi).create(EngagementApi::class.java)
        return PostActionsRepositoryImpl(api, dao, ApiErrorParser(moshi))
    }

    @Test
    fun hide_postsFeedHide_withBody_suppresses_andClearsPending() = runTest {
        val dao = FakePostSuppressionDao()
        val r = repo(dao)
        backend.enqueue(Fixtures.okBody("""{"ok":true,"post_id":"p1","hidden":true}"""))

        val result = r.hide("p1")
        assertTrue(result is ApiResult.Success)
        assertTrue(r.suppressed.first().contains("p1"))
        val row = dao.snapshot().first { it.postId == "p1" }
        assertEquals(PostSuppressionKind.HIDDEN.name, row.kind)
        assertFalse(row.pending) // pending cleared on success

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/feed/hide", req.requestUrl?.encodedPath)
        assertTrue(req.body.readUtf8().contains("\"post_id\":\"p1\""))
    }

    @Test
    fun notInterested_postsFeedHide_notInteresting_taggedKind() = runTest {
        val dao = FakePostSuppressionDao()
        val r = repo(dao)
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))

        val result = r.notInterested("p2")
        assertTrue(result is ApiResult.Success)
        assertEquals(PostSuppressionKind.NOT_INTERESTED.name, dao.snapshot().first { it.postId == "p2" }.kind)
        assertEquals("/feed/hide", backend.takeRequest().requestUrl?.encodedPath) // NOT /feed/interesting
    }

    @Test
    fun hide_500_rollsBack() = runTest {
        val dao = FakePostSuppressionDao()
        val r = repo(dao)
        backend.enqueue(Fixtures.error(""""boom"""", 500))

        val result = r.hide("p1")
        assertTrue(result is ApiResult.Failure)
        assertFalse(r.suppressed.first().contains("p1")) // rolled back
        assertTrue(dao.snapshot().none { it.postId == "p1" })
    }

    @Test
    fun hide_404_keepsSuppression_asSuccessEquivalent() = runTest {
        val dao = FakePostSuppressionDao()
        val r = repo(dao)
        backend.enqueue(Fixtures.error(""""gone"""", 404))

        val result = r.hide("p1")
        assertTrue(result is ApiResult.Success)
        assertTrue(r.suppressed.first().contains("p1")) // kept
        assertFalse(dao.snapshot().first { it.postId == "p1" }.pending)
    }

    @Test
    fun unhide_postsFeedUnhide_removesSuppression() = runTest {
        val dao = FakePostSuppressionDao()
        val r = repo(dao)
        // Pre-suppress, then unhide.
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        r.hide("p1")
        backend.takeRequest()

        backend.enqueue(Fixtures.okBody("""{"ok":true,"post_id":"p1","hidden":false}"""))
        val result = r.unhide("p1")
        assertTrue(result is ApiResult.Success)
        assertFalse(r.suppressed.first().contains("p1"))
        assertEquals("/feed/unhide", backend.takeRequest().requestUrl?.encodedPath)
    }
}
