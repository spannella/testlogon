package com.testlogon.android.feature.jira

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.jira.JiraApi
import com.testlogon.android.core.network.jira.JiraConflictResolveReq
import com.testlogon.android.core.network.jira.JiraConflictResolveResp
import com.testlogon.android.core.network.jira.JiraConnectReq
import com.testlogon.android.core.network.jira.JiraConnectResp
import com.testlogon.android.core.network.jira.JiraDisconnectReq
import com.testlogon.android.core.network.jira.JiraLinkExistingReq
import com.testlogon.android.core.network.jira.JiraLinkResp
import com.testlogon.android.core.network.jira.JiraPreferencesReq
import com.testlogon.android.core.network.jira.JiraPreferencesResp
import com.testlogon.android.core.network.jira.JiraProjectsResp
import com.testlogon.android.core.network.jira.JiraStatusResp
import com.testlogon.android.core.network.jira.JiraUnlinkResp
import com.testlogon.android.core.network.jira.TicketSyncStatusResp
import com.testlogon.android.feature.jira.data.JiraRepository
import com.testlogon.android.feature.jira.data.JiraRepositoryImpl
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response

/**
 * JIRA-AND-1 - tests for [JiraRepositoryImpl]. The key behaviour is DEGRADE-ON-404: the READ surfaces
 * (status / projects / preferences / syncStatus) map a 404 to an honest not-connected / empty / not_linked
 * Success, while non-404 errors surface as Failure. Also checks a successful link + idempotency-key length,
 * and that mutation 404s do NOT degrade.
 */
class JiraRepositoryTest {

    private fun parser() = ApiErrorParser(Moshi.Builder().build())
    private fun repo(api: JiraApi) = JiraRepositoryImpl(api = api, errorParser = parser())

    private fun http(code: Int): HttpException =
        HttpException(Response.error<Any>(code, "{}".toResponseBody("application/json".toMediaType())))

    @Test
    fun status_success_passesThrough() = runTest {
        val api = FakeJiraApi(statusResp = { JiraStatusResp(connected = true) })
        val res = repo(api).status("ws1")
        assertTrue(res is ApiResult.Success)
        assertTrue((res as ApiResult.Success).data.connected)
    }

    @Test
    fun status_404_degradesToNotConnected() = runTest {
        val api = FakeJiraApi(statusResp = { throw http(404) })
        val res = repo(api).status("ws1")
        assertTrue(res is ApiResult.Success)
        assertFalse((res as ApiResult.Success).data.connected)
        assertTrue(res.data.items.isEmpty())
    }

    @Test
    fun status_500_isFailure() = runTest {
        val api = FakeJiraApi(statusResp = { throw http(500) })
        val res = repo(api).status("ws1")
        assertTrue(res is ApiResult.Failure)
        assertEquals(500, (res as ApiResult.Failure).error.status)
    }

    @Test
    fun projects_404_degradesToEmpty() = runTest {
        val api = FakeJiraApi(projectsResp = { throw http(404) })
        val res = repo(api).projects("ws1", "cloud1")
        assertTrue(res is ApiResult.Success)
        assertTrue((res as ApiResult.Success).data.items.isEmpty())
    }

    @Test
    fun preferences_404_degradesToEmptyForCloud() = runTest {
        val api = FakeJiraApi(prefsResp = { throw http(404) })
        val res = repo(api).getPreferences("ws1", "cloud1")
        assertTrue(res is ApiResult.Success)
        assertEquals("cloud1", (res as ApiResult.Success).data.cloudId)
        assertTrue(res.data.projectKeys.isEmpty())
    }

    @Test
    fun syncStatus_404_degradesToNotLinked() = runTest {
        val api = FakeJiraApi(syncResp = { throw http(404) })
        val res = repo(api).syncStatus("t1")
        assertTrue(res is ApiResult.Success)
        val d = (res as ApiResult.Success).data
        assertFalse(d.linked)
        assertEquals("not_linked", d.syncState)
    }

    @Test
    fun linkExisting_sendsIdempotencyKeyOfAdequateLength() = runTest {
        val api = FakeJiraApi(linkResp = { JiraLinkResp(linkId = "l1", externalIssueKey = "ABC-1", syncState = "queued") })
        val res = repo(api).linkExisting("t1", "ws1", "ABC-1")
        assertTrue(res is ApiResult.Success)
        assertEquals("l1", (res as ApiResult.Success).data.linkId)
        assertTrue((api.lastIdempotencyKey?.length ?: 0) >= 8)
    }

    @Test
    fun linkExisting_404_isFailure_notDegraded() = runTest {
        val api = FakeJiraApi(linkResp = { throw http(404) })
        val res = repo(api).linkExisting("t1", "ws1", "ABC-1")
        assertTrue(res is ApiResult.Failure)
        assertEquals(404, (res as ApiResult.Failure).error.status)
    }

    @Test
    fun unlink_success() = runTest {
        val api = FakeJiraApi(unlinkResp = { JiraUnlinkResp(linkId = "l1", syncState = "not_linked") })
        val res = repo(api).unlink("t1", "l1")
        assertTrue(res is ApiResult.Success)
    }

    @Test
    fun disconnect_success_mapsToUnit() = runTest {
        val api = FakeJiraApi(disconnectResp = { mapOf("ok" to true) })
        val res = repo(api).disconnect("ws1", "conn1")
        assertTrue(res is ApiResult.Success)
    }

    @Test
    fun connect_success_returnsUrlAndState() = runTest {
        val api = FakeJiraApi(connectResp = { JiraConnectResp(connectUrl = "https://x/auth", state = "st1") })
        val res = repo(api).connect("ws1", "https://cb")
        assertTrue(res is ApiResult.Success)
        assertEquals("st1", (res as ApiResult.Success).data.state)
    }

    @Test
    fun resolveConflict_success() = runTest {
        val api = FakeJiraApi(resolveResp = { JiraConflictResolveResp(linkId = "l1", syncState = "in_sync") })
        val res = repo(api).resolveConflict("t1", "l1", "ws1", "keep_jira")
        assertTrue(res is ApiResult.Success)
        assertEquals("in_sync", (res as ApiResult.Success).data.syncState)
    }
}

/**
 * A recording fake of [JiraApi]: each call delegates to a lambda (default returns a benign empty response). The
 * link call records the Idempotency-Key so the repo test can assert its length.
 */
private class FakeJiraApi(
    private val statusResp: () -> JiraStatusResp = { JiraStatusResp() },
    private val connectResp: () -> JiraConnectResp = { JiraConnectResp("", "") },
    private val disconnectResp: () -> Map<String, Any?> = { emptyMap() },
    private val projectsResp: () -> JiraProjectsResp = { JiraProjectsResp() },
    private val prefsResp: () -> JiraPreferencesResp = { JiraPreferencesResp() },
    private val putPrefsResp: () -> JiraPreferencesResp = { JiraPreferencesResp() },
    private val syncResp: () -> TicketSyncStatusResp = { TicketSyncStatusResp(ticketId = "t1") },
    private val linkResp: () -> JiraLinkResp = { JiraLinkResp() },
    private val unlinkResp: () -> JiraUnlinkResp = { JiraUnlinkResp() },
    private val resolveResp: () -> JiraConflictResolveResp = { JiraConflictResolveResp() },
) : JiraApi {
    var lastIdempotencyKey: String? = null

    override suspend fun status(workspaceId: String): JiraStatusResp = statusResp()
    override suspend fun connect(body: JiraConnectReq): JiraConnectResp = connectResp()
    override suspend fun callback(code: String, state: String) =
        com.testlogon.android.core.network.jira.JiraCallbackResp(status = "connected")
    override suspend fun disconnect(body: JiraDisconnectReq): Map<String, Any?> = disconnectResp()
    override suspend fun projects(workspaceId: String, cloudId: String, limit: Int, cursor: String?): JiraProjectsResp = projectsResp()
    override suspend fun getPreferences(workspaceId: String, cloudId: String): JiraPreferencesResp = prefsResp()
    override suspend fun putPreferences(body: JiraPreferencesReq): JiraPreferencesResp = putPrefsResp()
    override suspend fun ticketSyncStatus(ticketId: String): TicketSyncStatusResp = syncResp()
    override suspend fun linkExisting(ticketId: String, idempotencyKey: String, body: JiraLinkExistingReq): JiraLinkResp {
        lastIdempotencyKey = idempotencyKey
        return linkResp()
    }
    override suspend fun unlink(ticketId: String, linkId: String): JiraUnlinkResp = unlinkResp()
    override suspend fun resolveConflict(ticketId: String, linkId: String, body: JiraConflictResolveReq): JiraConflictResolveResp = resolveResp()
}
