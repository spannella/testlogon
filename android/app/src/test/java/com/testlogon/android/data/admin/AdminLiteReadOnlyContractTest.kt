package com.testlogon.android.data.admin

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.admin.DashboardChannel
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-406 - cross-flow READ-ONLY / GET-only contract for the whole admin-lite surface (FR-4 / FR-5 / AC-3 /
 * TC-07). The per-feature contract tests (AdminRepositoryContractTest / MessagingDashboardRepositoryContractTest)
 * already assert each repo's happy/error paths; this ticket adds the single combined guarantee that AND-406
 * actually requires: across EVERY admin-lite read (AND-403 jobs+webhooks health AND AND-404 email+sms
 * stats+deliveries) the client issues ONLY idempotent GETs, hits ONLY the verified read-only dashboard/health
 * paths, and NEVER constructs a request to any mutation path in the `ui/admin` namespace
 * (`...suppressed`, `...send-test`, `...notifications/templates...`) - the namespace is NOT globally GET-only
 * on the backend (spec §3 NOTE / §16 claim 8), so the assertion is scoped to "the feature never builds those".
 *
 * The only non-GET the wider stack is allowed to issue is `POST /ui/session/refresh` on a 401; no admin-lite
 * read here triggers a 401, so the recorded set is expected to be 100% GET. No live host is contacted - all
 * network is the loopback MockWebServer (AC-8). A path-keyed [Dispatcher] keeps the concurrent fan-outs
 * order-independent. Plain Moshi (the @JsonClass codegen adapters resolve without reflection).
 */
class AdminLiteReadOnlyContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private val roleProvider = object : AdminRoleProvider {
        override fun currentRole(): AdminRole = AdminRole.UNKNOWN
    }

    private fun adminRepo(): DefaultAdminRepository = DefaultAdminRepository(
        api = backend.retrofit(moshi).create(AdminApi::class.java),
        errorParser = ApiErrorParser(moshi),
        roleProvider = roleProvider,
    )

    private fun messagingRepo(): DefaultMessagingDashboardRepository = DefaultMessagingDashboardRepository(
        api = backend.retrofit(moshi).create(MessagingDashboardApi::class.java),
        errorParser = ApiErrorParser(moshi),
        roleProvider = roleProvider,
    )

    // ---- Verified read-only fixtures (shapes per AND-403/AND-404 §5) ----

    private val jobsBody = """
        {"jobs":[{"name":"payouts","label":"Payouts","health":"healthy","last_finished_at":100}],"timestamp":1717200000}
    """.trimIndent()

    private val webhookBody = """
        {"total_endpoints":5,"enabled_endpoints":4,"disabled_endpoints":1,"total_deliveries_24h":120,
         "success_count_24h":118,"failed_count_24h":2,"dead_letter_count_24h":0}
    """.trimIndent()

    private val emailStatsBody = """
        {"sent":1280,"delivered":1240,"bounced":22,"complained":3,"failed":15,"suppressed":7,"total":1280,
         "delivery_rate":96.9,"bounce_rate":1.7,"complaint_rate":0.2,"period_days":7}
    """.trimIndent()

    private val smsStatsBody = """
        {"sent":540,"delivered":511,"failed":29,"total":540,"total_segments":712,"estimated_cost_usd":4.98,
         "suppressed_numbers":4,"delivery_rate":94.6,"failure_rate":5.4,"period_days":7}
    """.trimIndent()

    private val deliveriesBody = """{"items":[],"next_cursor":null}"""

    /** Serves every verified read-only admin-lite path; any unexpected (e.g. mutation) path 404s loudly. */
    private val readOnlyDispatcher = object : Dispatcher() {
        override fun dispatch(request: RecordedRequest): MockResponse {
            val path = request.path.orEmpty().substringBefore('?')
            val body = when {
                path.endsWith("/ui/admin/jobs/health") -> jobsBody
                path.endsWith("/ui/admin/webhooks/health") -> webhookBody
                path.endsWith("/ui/admin/email/dashboard/stats") -> emailStatsBody
                path.endsWith("/ui/admin/sms/dashboard/stats") -> smsStatsBody
                path.endsWith("/ui/admin/email/deliveries") -> deliveriesBody
                path.endsWith("/ui/admin/sms/deliveries") -> deliveriesBody
                else -> return MockResponse().setResponseCode(404).setBody("""{"detail":"unexpected path"}""")
            }
            return MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(body)
        }
    }

    /** The complete set of paths the admin-lite feature is permitted to read (verified GET-only endpoints). */
    private val allowedReadPaths = setOf(
        "/ui/admin/jobs/health",
        "/ui/admin/webhooks/health",
        "/ui/admin/email/dashboard/stats",
        "/ui/admin/sms/dashboard/stats",
        "/ui/admin/email/deliveries",
        "/ui/admin/sms/deliveries",
    )

    /** Mutation paths in the `ui/admin` namespace the feature must NEVER construct (spec §16 claim 8). */
    private val forbiddenMutationFragments = listOf(
        "/suppressed",
        "/send-test",
        "/notifications/templates",
    )

    @Test
    fun allAdminLiteReads_areGetOnly_toAllowedPaths_neverMutationPaths() = runTest {
        backend.server.dispatcher = readOnlyDispatcher

        // Drive EVERY admin-lite flow: AND-403 aggregated dashboard + AND-404 both channels.
        assertTrue(adminRepo().loadDashboard() is ApiResult.Success)
        assertTrue(messagingRepo().dashboard(DashboardChannel.EMAIL) is ApiResult.Success)
        assertTrue(messagingRepo().dashboard(DashboardChannel.SMS) is ApiResult.Success)

        // jobs+webhooks (2) + email stats+deliveries (2) + sms stats+deliveries (2) = 6 reads.
        val expected = 6
        assertEquals(expected, backend.requestCount)

        val recorded = (1..expected).map { backend.takeRequest() }
        for (req in recorded) {
            val path = req.requestUrl?.encodedPath.orEmpty()

            // FR-4: only idempotent GETs are ever issued by the read-only feature.
            assertEquals("Non-GET issued to admin-lite path $path", "GET", req.method)

            // AC-3: every read targets a verified read-only path (no stray/unknown admin path).
            assertTrue("Unexpected admin-lite path: $path", allowedReadPaths.contains(path))

            // AC-3 / §16 claim 8: the feature never constructs a request to a known mutation path.
            for (fragment in forbiddenMutationFragments) {
                assertTrue(
                    "Admin-lite feature must NEVER build a mutation request ($fragment): $path",
                    !path.contains(fragment),
                )
            }
        }
    }

    @Test
    fun adminLiteApis_exposeNoMutationMethods() {
        // FR-5 (interface level): a reflective sweep proves neither Retrofit API declares a non-GET verb, so the
        // feature is structurally incapable of issuing a POST/PUT/PATCH/DELETE to the admin namespace.
        val httpVerbAnnotations = setOf(
            "retrofit2.http.POST",
            "retrofit2.http.PUT",
            "retrofit2.http.PATCH",
            "retrofit2.http.DELETE",
            "retrofit2.http.HEAD",
            "retrofit2.http.OPTIONS",
        )
        for (api in listOf(AdminApi::class.java, MessagingDashboardApi::class.java)) {
            for (method in api.declaredMethods) {
                val verbs = method.annotations.map { it.annotationClass.qualifiedName }
                for (verb in httpVerbAnnotations) {
                    assertTrue(
                        "${api.simpleName}.${method.name} must not declare $verb (read-only feature)",
                        !verbs.contains(verb),
                    )
                }
            }
        }
    }
}
