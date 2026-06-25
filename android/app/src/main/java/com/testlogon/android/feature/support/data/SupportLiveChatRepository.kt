package com.testlogon.android.feature.support.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.support.HelpdeskAvailabilityDto
import com.testlogon.android.core.network.support.StartLiveChatReq
import com.testlogon.android.core.network.support.SupportLiveChatApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B8 Android #13 — the CUSTOMER side of live-agent (helpdesk) chat. Checks availability then opens a real
 * helpdesk_bridge conversation; the caller drops into the standard messaging thread to talk. Honest about
 * the realistic state: when no agent is online the chat still starts but QUEUES (the UI says so).
 *
 * The helpdesk group is configured server-side; this client targets the platform's support group id. Only
 * `e2e-helpdesk` is provisioned on the current backend (one agent), so we default to it.
 */
data class HelpdeskAvailability(val availableAgentCount: Int, val anyAvailable: Boolean)

interface SupportLiveChatRepository {
    /** The helpdesk group this build routes live chats to. */
    val groupId: String

    suspend fun availability(): ApiResult<HelpdeskAvailability>

    /** Start (or resume) a live-agent chat; returns the conversation id to open in the messaging thread. */
    suspend fun startLiveChat(): ApiResult<String>
}

@Singleton
class SupportLiveChatRepositoryImpl @Inject constructor(
    private val api: SupportLiveChatApi,
    private val errorParser: ApiErrorParser,
) : SupportLiveChatRepository {

    // The only helpdesk group provisioned on the platform backend today. Centralised so it's a one-line
    // change if a real "support" group is added.
    override val groupId: String = DEFAULT_GROUP_ID

    override suspend fun availability(): ApiResult<HelpdeskAvailability> = io {
        val dto: HelpdeskAvailabilityDto = api.availability(groupId)
        HelpdeskAvailability(dto.availableAgentCount, dto.anyAvailable)
    }

    override suspend fun startLiveChat(): ApiResult<String> = io {
        api.startLiveChat(StartLiveChatReq(helpdeskGroupId = groupId)).conversationId
    }

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

    private companion object {
        const val DEFAULT_GROUP_ID = "e2e-helpdesk"
    }
}
