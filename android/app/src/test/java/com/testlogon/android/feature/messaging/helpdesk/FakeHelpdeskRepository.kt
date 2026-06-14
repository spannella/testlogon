package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.helpdesk.HelpdeskClaimResult
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRepository
import kotlinx.coroutines.CompletableDeferred
import java.io.IOException

/** AND-161/AND-162/AND-378 — in-memory helpdesk repository for ViewModel tests. */
class FakeHelpdeskRepository : HelpdeskRepository {

    var queueResult: ApiResult<List<HelpdeskQueueItem>> = ApiResult.Success(emptyList())
    var claimResult: ApiResult<HelpdeskClaimResult> = ApiResult.NetworkError(IOException("default"))
    var refreshResult: ApiResult<HelpdeskQueueItem?> = ApiResult.Success(null)

    var loadQueueCalls = 0
    val claimedIds = mutableListOf<String>()

    /**
     * AND-378 — when set, [claim] suspends on this gate before returning, so a test can assert the
     * in-flight (double-submit-guard) window. Complete it to release the call.
     */
    var claimGate: CompletableDeferred<Unit>? = null

    override suspend fun loadQueue(state: String?, limit: Int): ApiResult<List<HelpdeskQueueItem>> {
        loadQueueCalls++
        return queueResult
    }

    override suspend fun claim(conversationId: String): ApiResult<HelpdeskClaimResult> {
        claimedIds += conversationId
        claimGate?.await()
        return claimResult
    }

    override suspend fun refreshAssignment(conversationId: String): ApiResult<HelpdeskQueueItem?> =
        refreshResult
}
