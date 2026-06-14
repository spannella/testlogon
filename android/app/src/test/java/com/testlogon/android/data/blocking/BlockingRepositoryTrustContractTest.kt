package com.testlogon.android.data.blocking

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
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
 * AND-389 - trust and safety contract gaps for the block surface not already pinned by
 * [BlockingRepositoryContractTest] (which covers 200/500/422-list/timeout) or [BlockApiContractTest]
 * (path/body/CSRF). Additive-only: it does NOT re-test the shapes those suites already lock down.
 *
 * Fills the AC-6 / AC-7 gaps for the block endpoint specifically (the report surface already covers
 * the three detail shapes in [com.testlogon.android.data.report.ReportFlowRepositoryContractTest]):
 *
 *  - TC-AND-389-08 - the STRING `detail` passthrough ("User not found") and the OBJECT
 *    `detail:{code,message}` shapes map to [ApiResult.Failure] with the human-readable message /
 *    extracted `code`, and leave the blocked set unchanged (no optimistic stickiness on failure).
 *  - TC-AND-389-09 - a `401` on the non-idempotent block POST surfaces as [ApiResult.Failure] with
 *    status 401, the POST is issued EXACTLY ONCE at the repository tier (the single
 *    refresh-then-retry is the transparent job of the core-network SessionAuthenticator on the
 *    shared OkHttp client, NOT the repository), and the optimistic add is rolled back.
 *
 * Hermetic: real Retrofit/Moshi/OkHttp over loopback MockWebServer, no virtual-time delays, no
 * real host (FR-10 / AC-10). Synthetic ids only (no PII; spec sec.8).
 */
class BlockingRepositoryTrustContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): BlockingRepositoryImpl {
        val api = backend.retrofit(moshi, client = defaultTestClient()).create(BlockApi::class.java)
        return BlockingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    // TC-AND-389-08 - string `detail` shape passes through verbatim; state reverts (AC-6 / FR-8).
    @Test
    fun block_404_stringDetail_mapsToFailure_andRollsBack() = runTest {
        backend.enqueue(Fixtures.error("\"User not found\"", code = 404))
        val r = repo()

        val result = r.block("u42")

        assertTrue(result is ApiResult.Failure)
        result as ApiResult.Failure
        assertEquals(404, result.error.status)
        assertEquals("User not found", result.error.message)
        // No optimistic stickiness: the failed block leaves the set empty.
        assertFalse(r.isBlocked("u42"))
        assertTrue(r.blockedUserIds.value.isEmpty())
    }

    // TC-AND-389-08 - object `detail:{code,message}` shape -> message + extracted code (AC-6 / FR-8).
    @Test
    fun block_403_objectCodeDetail_mapsToFailure_withCode() = runTest {
        backend.enqueue(
            Fixtures.error(
                """{"code":"role_required","message":"You are not allowed to do that"}""",
                code = 403,
            ),
        )
        val r = repo()

        val result = r.block("u42")

        assertTrue(result is ApiResult.Failure)
        result as ApiResult.Failure
        assertEquals(403, result.error.status)
        assertEquals("role_required", result.error.code)
        assertTrue(result.error.message.isNotBlank())
        assertFalse(r.isBlocked("u42"))
    }

    // TC-AND-389-09 - a 401 surfaces as Failure(401); the POST is issued exactly once at the repo
    // tier (no repository-level auto-retry of the non-idempotent mutation) and the optimistic add
    // is rolled back (AC-7 / FR-9 retry-boundary half).
    @Test
    fun block_401_isFailure_postIssuedOnce_noRepoLevelRetry() = runTest {
        backend.enqueue(Fixtures.error("\"Not authenticated\"", code = 401))
        val r = repo()

        val result = r.block("u42")

        assertTrue(result is ApiResult.Failure)
        result as ApiResult.Failure
        assertEquals(401, result.error.status)
        // Exactly one outbound block POST: the repository never retries the mutation itself; the
        // transparent single refresh-then-retry belongs to the SessionAuthenticator on the shared
        // client, which is not wired into this repository-only client.
        assertEquals(1, backend.requestCount)
        assertFalse(r.isBlocked("u42"))
        assertTrue(r.blockedUserIds.value.isEmpty())
    }

    // TC-AND-389-09 (companion) - a 401 on unblock likewise surfaces cleanly and restores the
    // optimistically-removed id (no stale state on failure; AC-6 / AC-7).
    @Test
    fun unblock_401_isFailure_restoresOptimisticallyRemovedId() = runTest {
        // Seed a blocked id via a successful block.
        backend.enqueue(Fixtures.okBody("""{"ok":true,"status":"blocked","target_user_id":"u42"}"""))
        val r = repo()
        r.block("u42")
        assertTrue(r.isBlocked("u42"))

        backend.enqueue(Fixtures.error("\"Not authenticated\"", code = 401))
        val result = r.unblock("u42")

        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
        // The optimistic remove is undone -> the id is restored so content stays hidden.
        assertTrue(r.isBlocked("u42"))
    }
}
