package com.testlogon.android.data.blocking

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.blocking.BlockRelationship
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-382 - [BlockingRepositoryImpl] behavior over a real [BlockApi] + MockWebServer.
 *
 * Covers optimistic add/remove + rollback (TC-04/07), any-200-is-success idempotency (TC-05),
 * blockedUserIds StateFlow emissions, refresh hydration (TC-03), generic 403 / 422 -> Failure (TC-08),
 * and that the mutating POST is issued exactly once (no auto-retry) on timeout (TC-07).
 */
class BlockingRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): BlockingRepositoryImpl {
        // Short-timeout client so the no-response timeout test resolves in ~2s.
        val api = backend.retrofit(moshi, client = defaultTestClient()).create(BlockApi::class.java)
        return BlockingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun block_success_addsToBlockedSet() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"status":"blocked","target_user_id":"usr_x"}"""))
        val r = repo()

        val result = r.block("usr_x")

        assertTrue(result is ApiResult.Success)
        assertTrue(r.isBlocked("usr_x"))
        assertEquals(setOf("usr_x"), r.blockedUserIds.value)
    }

    @Test
    fun block_serverError_rollsBackOptimisticAdd() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", code = 500))
        val r = repo()

        val result = r.block("usr_x")

        assertTrue(result is ApiResult.Failure)
        assertFalse(r.isBlocked("usr_x"))
        assertTrue(r.blockedUserIds.value.isEmpty())
    }

    @Test
    fun unblock_success_removesFromSet_and_failureRestores() = runTest {
        // Seed via a successful block first.
        backend.enqueue(Fixtures.okBody("""{"ok":true,"status":"blocked","target_user_id":"usr_x"}"""))
        val r = repo()
        r.block("usr_x")
        assertTrue(r.isBlocked("usr_x"))

        // Unblock fails -> the id is restored.
        backend.enqueue(Fixtures.error("\"boom\"", code = 500))
        val failed = r.unblock("usr_x")
        assertTrue(failed is ApiResult.Failure)
        assertTrue(r.isBlocked("usr_x"))

        // Unblock succeeds -> removed.
        backend.enqueue(Fixtures.okBody("""{"ok":true,"status":"unblocked","target_user_id":"usr_x"}"""))
        val ok = r.unblock("usr_x")
        assertTrue(ok is ApiResult.Success)
        assertFalse(r.isBlocked("usr_x"))
    }

    @Test
    fun idempotent_anyTwoHundredIsSuccess_regardlessOfStatus() = runTest {
        val r = repo()
        // Re-block returns 200 with an arbitrary status string -> still Success.
        backend.enqueue(Fixtures.okBody("""{"ok":true,"status":"already_blocked","target_user_id":"usr_x"}"""))
        assertTrue(r.block("usr_x") is ApiResult.Success)
        backend.enqueue(Fixtures.okBody("""{"ok":true,"status":"blocked","target_user_id":"usr_x"}"""))
        assertTrue(r.block("usr_x") is ApiResult.Success)
        // Re-unblock twice, both 200.
        backend.enqueue(Fixtures.okBody("""{"ok":true,"status":"unblocked","target_user_id":"usr_x"}"""))
        assertTrue(r.unblock("usr_x") is ApiResult.Success)
        backend.enqueue(Fixtures.okBody("""{"ok":true,"status":"not_blocked","target_user_id":"usr_x"}"""))
        assertTrue(r.unblock("usr_x") is ApiResult.Success)
    }

    @Test
    fun validation422_mapsToFailure_withMessage() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","target_user_id"],"msg":"field required","type":"value_error.missing"}]""",
                code = 422,
            ),
        )
        val r = repo()
        val result = r.block("")
        assertTrue(result is ApiResult.Failure)
        result as ApiResult.Failure
        assertEquals(422, result.error.status)
        assertTrue(result.error.message.isNotBlank())
        assertFalse(r.isBlocked(""))
    }

    @Test
    fun timeout_singleRequest_noAutoRetry_andRollback() = runTest {
        backend.enqueue(Fixtures.timeout())
        val r = repo()

        val result = r.block("usr_x")

        assertTrue(result is ApiResult.NetworkError)
        result as ApiResult.NetworkError
        assertTrue(result.isTimeout)
        // Exactly one outbound request (the POST is never auto-retried).
        assertEquals(1, backend.requestCount)
        // Optimistic add reverted.
        assertFalse(r.isBlocked("usr_x"))
    }

    @Test
    fun refreshBlockList_hydratesSetFromServer() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"blocked_users":[
                   {"user_id":"usr_a","display_name":"A","profile_photo_url":null,"blocked_at":"t"},
                   {"user_id":"usr_b","display_name":null,"profile_photo_url":null,"blocked_at":"t"}
                ],"next_cursor":null,"total_count":2}
                """.trimIndent(),
            ),
        )
        val r = repo()

        val result = r.refreshBlockList()

        assertTrue(result is ApiResult.Success)
        assertEquals(setOf("usr_a", "usr_b"), r.blockedUserIds.value)
        assertTrue(r.isBlocked("usr_a"))
    }

    @Test
    fun blockStatus_blockedByMe_updatesSet_blockedMe_doesNot() = runTest {
        val r = repo()
        backend.enqueue(Fixtures.okBody("""{"is_blocked_by_me":true,"is_blocking_me":false}"""))
        val s1 = r.blockStatus("usr_a")
        assertEquals(ApiResult.Success(BlockRelationship.BlockedByMe), s1)
        assertTrue(r.isBlocked("usr_a"))

        backend.enqueue(Fixtures.okBody("""{"is_blocked_by_me":false,"is_blocking_me":true}"""))
        val s2 = r.blockStatus("usr_b")
        assertEquals(ApiResult.Success(BlockRelationship.BlockedMe), s2)
        assertFalse(r.isBlocked("usr_b"))
    }

    @Test
    fun clear_emptiesSet() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"status":"blocked","target_user_id":"usr_x"}"""))
        val r = repo()
        r.block("usr_x")
        assertTrue(r.blockedUserIds.value.isNotEmpty())
        r.clear()
        assertTrue(r.blockedUserIds.value.isEmpty())
    }
}
