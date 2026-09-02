package com.testlogon.android.feature.jira.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.jira.JiraApi
import com.testlogon.android.core.network.jira.JiraConnectReq
import com.testlogon.android.core.network.jira.JiraConnectResp
import com.testlogon.android.core.network.jira.JiraConflictResolveReq
import com.testlogon.android.core.network.jira.JiraConflictResolveResp
import com.testlogon.android.core.network.jira.JiraDisconnectReq
import com.testlogon.android.core.network.jira.JiraLinkExistingReq
import com.testlogon.android.core.network.jira.JiraLinkResp
import com.testlogon.android.core.network.jira.JiraPreferencesReq
import com.testlogon.android.core.network.jira.JiraPreferencesResp
import com.testlogon.android.core.network.jira.JiraProjectsResp
import com.testlogon.android.core.network.jira.JiraStatusResp
import com.testlogon.android.core.network.jira.JiraUnlinkResp
import com.testlogon.android.core.network.jira.TicketSyncStatusResp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * JIRA-AND-1 - data layer for the Jira integration surface over the [JiraApi]. Folds each RAW DTO return into
 * [ApiResult] via [call] (mirrors the AND-372 TicketsRepositoryImpl). Transport / HTTP / JSON failures are
 * classified exactly like the tickets repo.
 *
 * DEGRADE-ON-404: the READ surfaces ([status], [projects], [getPreferences], [syncStatus]) map a 404 (feature
 * flag off / not connected / not linked) to an HONEST not-connected empty value ([JiraStatusResp] connected=false,
 * empty projects, empty preferences, not_linked sync-status) rather than a Failure. Every OTHER status (401 /
 * 403 / 409 / 5xx) still surfaces as Failure so the ViewModel can act (re-auth / show the server message).
 *
 * The MUTATION surfaces (connect / disconnect / putPreferences / linkExisting / unlink / resolveConflict) do NOT
 * degrade a 404 - a 404 there is a real error (unknown ticket / link) and surfaces as Failure.
 */
interface JiraRepository {

    /** GET connection status for a workspace; 404 -> honest not-connected empty. */
    suspend fun status(workspaceId: String): ApiResult<JiraStatusResp>

    /** POST begin an OAuth connect; returns the authorize URL + state to open in a Custom Tab. */
    suspend fun connect(workspaceId: String, redirectUri: String): ApiResult<JiraConnectResp>

    /** POST disconnect a connection. */
    suspend fun disconnect(workspaceId: String, connectionId: String): ApiResult<Unit>

    /** GET discover projects for a cloud; 404 -> empty. */
    suspend fun projects(workspaceId: String, cloudId: String): ApiResult<JiraProjectsResp>

    /** GET saved project-key preferences; 404 -> empty preferences for that cloud. */
    suspend fun getPreferences(workspaceId: String, cloudId: String): ApiResult<JiraPreferencesResp>

    /** PUT project-key preferences. */
    suspend fun putPreferences(
        workspaceId: String,
        cloudId: String,
        projectKeys: List<String>,
    ): ApiResult<JiraPreferencesResp>

    /** GET a ticket's sync status; 404 -> not_linked. */
    suspend fun syncStatus(ticketId: String): ApiResult<TicketSyncStatusResp>

    /** POST link an existing Jira issue to a ticket (idempotency key generated per attempt). */
    suspend fun linkExisting(
        ticketId: String,
        workspaceId: String,
        issueKey: String,
        linkMode: String = "bidirectional",
    ): ApiResult<JiraLinkResp>

    /** DELETE unlink an external link from a ticket. */
    suspend fun unlink(ticketId: String, linkId: String): ApiResult<JiraUnlinkResp>

    /** POST resolve a sync conflict. */
    suspend fun resolveConflict(
        ticketId: String,
        linkId: String,
        workspaceId: String,
        action: String,
        currentTicket: Map<String, Any?> = emptyMap(),
    ): ApiResult<JiraConflictResolveResp>

    companion object {
        /**
         * JIRA-AND-1 - build a fresh Idempotency-Key for a link attempt (>=8 chars, server-required). Mirrors
         * the web `ui-link-<ts>-<rand>` shape. Pure enough to keep here; the impl calls it.
         */
        fun newIdempotencyKey(now: Long, nonce: String): String = "ui-link-$now-$nonce"
    }
}

@Singleton
class JiraRepositoryImpl @Inject constructor(
    private val api: JiraApi,
    private val errorParser: ApiErrorParser,
) : JiraRepository {

    override suspend fun status(workspaceId: String): ApiResult<JiraStatusResp> =
        withContext(Dispatchers.IO) {
            callOrEmptyOn404(fallback = { JiraStatusResp(connected = false, items = emptyList()) }) {
                api.status(workspaceId)
            }
        }

    override suspend fun connect(workspaceId: String, redirectUri: String): ApiResult<JiraConnectResp> =
        withContext(Dispatchers.IO) {
            call { api.connect(JiraConnectReq(workspaceId = workspaceId, redirectUri = redirectUri)) }
        }

    override suspend fun disconnect(workspaceId: String, connectionId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call {
                api.disconnect(JiraDisconnectReq(workspaceId = workspaceId, connectionId = connectionId))
                Unit
            }
        }

    override suspend fun projects(workspaceId: String, cloudId: String): ApiResult<JiraProjectsResp> =
        withContext(Dispatchers.IO) {
            callOrEmptyOn404(fallback = { JiraProjectsResp(items = emptyList(), nextCursor = null) }) {
                api.projects(workspaceId = workspaceId, cloudId = cloudId)
            }
        }

    override suspend fun getPreferences(workspaceId: String, cloudId: String): ApiResult<JiraPreferencesResp> =
        withContext(Dispatchers.IO) {
            callOrEmptyOn404(
                fallback = { JiraPreferencesResp(workspaceId = workspaceId, cloudId = cloudId, projectKeys = emptyList()) },
            ) {
                api.getPreferences(workspaceId = workspaceId, cloudId = cloudId)
            }
        }

    override suspend fun putPreferences(
        workspaceId: String,
        cloudId: String,
        projectKeys: List<String>,
    ): ApiResult<JiraPreferencesResp> =
        withContext(Dispatchers.IO) {
            call {
                api.putPreferences(
                    JiraPreferencesReq(workspaceId = workspaceId, cloudId = cloudId, projectKeys = projectKeys),
                )
            }
        }

    override suspend fun syncStatus(ticketId: String): ApiResult<TicketSyncStatusResp> =
        withContext(Dispatchers.IO) {
            callOrEmptyOn404(
                fallback = { TicketSyncStatusResp(ticketId = ticketId, linked = false, provider = null, syncState = "not_linked") },
            ) {
                api.ticketSyncStatus(ticketId)
            }
        }

    override suspend fun linkExisting(
        ticketId: String,
        workspaceId: String,
        issueKey: String,
        linkMode: String,
    ): ApiResult<JiraLinkResp> =
        withContext(Dispatchers.IO) {
            val key = JiraRepository.newIdempotencyKey(
                now = System.currentTimeMillis(),
                nonce = java.util.UUID.randomUUID().toString().replace("-", "").take(10),
            )
            call {
                api.linkExisting(
                    ticketId = ticketId,
                    idempotencyKey = key,
                    body = JiraLinkExistingReq(
                        workspaceId = workspaceId,
                        externalIssueKey = issueKey,
                        linkMode = linkMode,
                    ),
                )
            }
        }

    override suspend fun unlink(ticketId: String, linkId: String): ApiResult<JiraUnlinkResp> =
        withContext(Dispatchers.IO) {
            call { api.unlink(ticketId = ticketId, linkId = linkId) }
        }

    override suspend fun resolveConflict(
        ticketId: String,
        linkId: String,
        workspaceId: String,
        action: String,
        currentTicket: Map<String, Any?>,
    ): ApiResult<JiraConflictResolveResp> =
        withContext(Dispatchers.IO) {
            call {
                api.resolveConflict(
                    ticketId = ticketId,
                    linkId = linkId,
                    body = JiraConflictResolveReq(
                        workspaceId = workspaceId,
                        action = action,
                        currentTicket = currentTicket,
                    ),
                )
            }
        }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], status preserved); malformed
     * JSON -> Failure; transport failures -> NetworkError. Cancellation is re-thrown. Mirrors TicketsRepositoryImpl.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    /**
     * Like [call], but a 404 degrades to Success([fallback]) - the honest not-connected / not-linked empty. Every
     * other HTTP status still surfaces as Failure. Transport / JSON failures classify exactly like [call].
     */
    private suspend fun <T> callOrEmptyOn404(
        fallback: () -> T,
        block: suspend () -> T,
    ): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == HTTP_NOT_FOUND) ApiResult.Success(fallback())
        else ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val HTTP_NOT_FOUND = 404
    }
}
