package com.testlogon.android.data.messaging.helpdesk

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.auth.FakeAuthStateStore
import com.testlogon.android.feature.messaging.helpdesk.ClaimError
import com.testlogon.android.feature.messaging.helpdesk.ClaimErrorMapper
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-165 — GAP-FILL tests for AND-162 helpdesk claim that the existing [HelpdeskRepositoryContractTest]
 * does NOT cover:
 *  - a self re-claim returning 200 with `idempotent: true` (resolves the §13 open question; the existing
 *    suite only covers idempotent:false success paths),
 *  - the THREE real `detail.code` authorization errors verified from the web mapper
 *    (`helpdesk_claim_required`, `helpdesk_assignee_required`, `helpdesk_claim_not_available`) parsing
 *    into `ApiError.code` end-to-end (MockWebServer -> ApiErrorParser -> repo Failure),
 *  - that those codes flow through to distinct [ClaimError]s via the shared [ClaimErrorMapper].
 *
 * No duplication: success/other-agent/403/422 paths stay in HelpdeskRepositoryContractTest.
 */
class HelpdeskClaimErrorGapTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private val auth = FakeAuthStateStore().apply { runBlocking { setAuthenticated("usr_me") } }

    private fun repo(): HelpdeskRepositoryImpl = HelpdeskRepositoryImpl(
        api = backend.retrofit(moshi).create(HelpdeskApi::class.java),
        errorParser = ApiErrorParser(moshi),
        authStateStore = auth,
        helpdeskGroupId = "e2e-helpdesk",
    )

    @Test
    fun claim_selfReclaim_idempotentTrue_isSuccess() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"conversation_id":"c_7","state":"assigned",
                   "assigned_agent_user_id":"usr_me","assignment_version":3,"idempotent":true}""",
            ),
        )
        val r = repo().claim("c_7")
        assertTrue(r is ApiResult.Success)
        val data = (r as ApiResult.Success).data
        assertEquals(HelpdeskAssignment.ASSIGNED_TO_ME, data.assignment)
        assertTrue(data.idempotent)
    }

    @Test
    fun claim_claimRequiredCode_parsesIntoApiErrorCode() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"helpdesk_claim_required"}""", 403))
        val r = repo().claim("c_7")
        assertTrue(r is ApiResult.Failure)
        assertEquals("helpdesk_claim_required", (r as ApiResult.Failure).error.code)
    }

    @Test
    fun claim_assigneeRequiredCode_parsesIntoApiErrorCode() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"helpdesk_assignee_required"}""", 403))
        val r = repo().claim("c_7")
        assertEquals("helpdesk_assignee_required", (r as ApiResult.Failure).error.code)
    }

    @Test
    fun claim_notAvailableCode_parsesAndMapsToNotAvailable() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"helpdesk_claim_not_available"}""", 403))
        val r = repo().claim("c_7")
        assertTrue(r is ApiResult.Failure)
        val err = (r as ApiResult.Failure).error
        assertEquals("helpdesk_claim_not_available", err.code)
        // And the shared mapper turns it into the distinct NOT_AVAILABLE (non-retryable) claim error.
        val (mapped, retryable) = ClaimErrorMapper.map(err)
        assertEquals(ClaimError.NOT_AVAILABLE, mapped)
        assertFalse(retryable)
    }
}
