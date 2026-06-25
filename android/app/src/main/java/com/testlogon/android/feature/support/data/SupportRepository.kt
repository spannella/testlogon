package com.testlogon.android.feature.support.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.support.SupportApi
import com.testlogon.android.core.network.support.SupportAssignTicketReq
import com.testlogon.android.core.network.support.SupportCloseTicketReq
import com.testlogon.android.core.network.support.SupportCreateTicketReq
import com.testlogon.android.core.network.support.SupportTicketMessageReq
import com.testlogon.android.core.network.support.SupportTicketStatusReq
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B-SUP (batch 7) — data layer over the role-aware [SupportApi]. The SAME calls back both the USER and ADMIN
 * surfaces; the SERVER decides what a non-admin may see / do (a USER's [listTickets] returns only their own
 * tickets; the admin-only writes 403). The repo simply folds into [ApiResult]; the ViewModels branch the UX.
 */
interface SupportRepository {
    suspend fun createTicket(subject: String, description: String, priority: String): ApiResult<SupportTicket>
    suspend fun listTickets(
        status: String? = null,
        priority: String? = null,
        assigneeAdminSub: String? = null,
        cursor: String? = null,
        limit: Int? = null,
    ): ApiResult<SupportTicketPage>
    suspend fun getTicket(ticketId: String): ApiResult<SupportTicket>
    suspend fun addMessage(ticketId: String, body: String): ApiResult<SupportTicket>
    suspend fun setStatus(ticketId: String, status: String): ApiResult<SupportTicket>
    suspend fun assign(ticketId: String, assigneeAdminSub: String): ApiResult<SupportTicket>
    /** B8 #15 — owner close/cancel of one's OWN ticket. action = "close" (->done) | "cancel" (->cancelled). */
    suspend fun closeTicket(ticketId: String, action: String): ApiResult<SupportTicket>
    suspend fun adminSummary(): ApiResult<SupportAdminSummary>

    companion object {
        const val SUBJECT_MIN = 3
        const val SUBJECT_MAX = 160
        const val DESCRIPTION_MIN = 1
        const val DESCRIPTION_MAX = 4000
        const val REPLY_MIN = 1
        const val REPLY_MAX = 4000
        const val ACTION_CLOSE = "close"
        const val ACTION_CANCEL = "cancel"
    }
}

data class SupportTicketPage(val tickets: List<SupportTicket>, val nextCursor: String?)

@Singleton
class SupportRepositoryImpl @Inject constructor(
    private val api: SupportApi,
    private val errorParser: ApiErrorParser,
) : SupportRepository {

    override suspend fun createTicket(subject: String, description: String, priority: String) =
        io { api.createTicket(SupportCreateTicketReq(subject.trim(), description.trim(), priority)).ticket.toDomain() }

    override suspend fun listTickets(
        status: String?,
        priority: String?,
        assigneeAdminSub: String?,
        cursor: String?,
        limit: Int?,
    ) = io {
        val env = api.listTickets(status, priority, assigneeAdminSub, cursor, limit)
        SupportTicketPage(env.items.map { it.toDomain() }, env.nextCursor)
    }

    override suspend fun getTicket(ticketId: String) =
        io { api.getTicket(ticketId).ticket.toDomain() }

    override suspend fun addMessage(ticketId: String, body: String) =
        io { api.addMessage(ticketId, SupportTicketMessageReq(body.trim())).ticket.toDomain() }

    override suspend fun setStatus(ticketId: String, status: String) =
        io { api.setStatus(ticketId, SupportTicketStatusReq(status)).ticket.toDomain() }

    override suspend fun assign(ticketId: String, assigneeAdminSub: String) =
        io { api.assign(ticketId, SupportAssignTicketReq(assigneeAdminSub.trim())).ticket.toDomain() }

    override suspend fun closeTicket(ticketId: String, action: String) =
        io { api.closeTicket(ticketId, SupportCloseTicketReq(action)).ticket.toDomain() }

    override suspend fun adminSummary() =
        io { api.adminSummary().summary.toDomain() }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try {
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
    }
}
