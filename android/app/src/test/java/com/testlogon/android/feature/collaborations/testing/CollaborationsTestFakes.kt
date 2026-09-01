package com.testlogon.android.feature.collaborations.testing

import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.model.collaborations.CollabContent
import com.testlogon.android.core.model.collaborations.CollabDispute
import com.testlogon.android.core.model.collaborations.CollabRevision
import com.testlogon.android.core.model.collaborations.CollabSplitRecordModel
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.CollaborationSettings
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.network.collaborations.CollabContentAssignIn
import com.testlogon.android.core.network.collaborations.CollabContentListOut
import com.testlogon.android.core.network.collaborations.CollabContentSplitTriggerIn
import com.testlogon.android.core.network.collaborations.CollabDisputeIn
import com.testlogon.android.core.network.collaborations.CollabDisputeListOut
import com.testlogon.android.core.network.collaborations.CollabDisputeResolveIn
import com.testlogon.android.core.network.collaborations.CollabOkOut
import com.testlogon.android.core.network.collaborations.CollabSplitHistoryOut
import com.testlogon.android.core.network.collaborations.CollaborationCounterIn
import com.testlogon.android.core.network.collaborations.CollaborationListOut
import com.testlogon.android.core.network.collaborations.CollaborationOut
import com.testlogon.android.core.network.collaborations.CollaborationRevisionOut
import com.testlogon.android.core.network.collaborations.CollaborationSettingsIn
import com.testlogon.android.core.network.collaborations.CollaborationSettingsOut
import com.testlogon.android.core.network.collaborations.CollaborationTerminateIn
import com.testlogon.android.core.network.collaborations.CollaborationsApi
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.collaborations.data.CollaborationsRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flowOf
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-358 / PAR-04 - in-memory fakes for the collaborations unit tests.
 *
 * The app unit-test classpath has NO moshi-kotlin KotlinJsonAdapterFactory, so :app tests use a FAKE
 * [CollaborationsApi] (no Moshi). Each call RECORDS its args / call-count BEFORE honouring a configured throw,
 * so a test can assert the @Path collabId was passed even when the call fails. Helper / recording names are
 * distinct (the -Collab- infix) and never shadow an interface method. PAR-04 adds the deal-action + revisions
 * fakes.
 */
class FakeCollaborationsApi(
    var list: () -> CollaborationListOut = { CollaborationListOut(items = emptyList(), nextCursor = null) },
    var collaboration: () -> CollaborationOut = {
        CollaborationOut(
            collabId = "c1", title = "Track", status = "active", initiatorId = "usr_a",
            recipientId = "usr_b", split = mapOf("usr_a" to 60, "usr_b" to 40), createdAt = 1L,
        )
    },
    var splits: () -> CollabSplitHistoryOut = { CollabSplitHistoryOut(items = emptyList()) },
    var revisions: () -> List<CollaborationRevisionOut> = { emptyList() },
    var settings: () -> CollaborationSettingsOut = { CollaborationSettingsOut() },
    var content: () -> CollabContentListOut = { CollabContentListOut(items = emptyList()) },
    var disputes: () -> CollabDisputeListOut = { CollabDisputeListOut(items = emptyList()) },
    var ok: () -> CollabOkOut = { CollabOkOut(ok = true, status = "resolved", disputeStatus = "disputed") },
) : CollaborationsApi {

    val listCursors = mutableListOf<String?>()
    val collaborationCollabIds = mutableListOf<String>()
    val splitsCollabIds = mutableListOf<String>()
    val revisionsCollabIds = mutableListOf<String>()
    val acceptCollabIds = mutableListOf<String>()
    val rejectCollabIds = mutableListOf<String>()
    val counterCalls = mutableListOf<Pair<String, CollaborationCounterIn>>()
    val cancelCollabIds = mutableListOf<String>()
    val terminateCalls = mutableListOf<Pair<String, CollaborationTerminateIn>>()
    val getSettingsCalls = mutableListOf<Unit>()
    val updateSettingsCalls = mutableListOf<CollaborationSettingsIn>()
    val listContentCollabIds = mutableListOf<String>()
    val assignContentCalls = mutableListOf<Pair<String, CollabContentAssignIn>>()
    val unassignContentCalls = mutableListOf<Pair<String, String>>()
    val revenueEventCalls = mutableListOf<Triple<String, String, CollabContentSplitTriggerIn>>()
    val listDisputesCalls = mutableListOf<Pair<String, String?>>()
    val fileDisputeCalls = mutableListOf<Triple<String, String, CollabDisputeIn>>()
    val resolveDisputeCalls = mutableListOf<Triple<String, String, CollabDisputeResolveIn>>()

    override suspend fun listCollaborations(cursor: String?): CollaborationListOut {
        listCursors += cursor
        return list()
    }

    override suspend fun getCollaboration(collabId: String): CollaborationOut {
        collaborationCollabIds += collabId
        return collaboration()
    }

    override suspend fun getSplits(collabId: String): CollabSplitHistoryOut {
        splitsCollabIds += collabId
        return splits()
    }

    override suspend fun getRevisions(collabId: String): List<CollaborationRevisionOut> {
        revisionsCollabIds += collabId
        return revisions()
    }

    override suspend fun acceptCollaboration(collabId: String): CollaborationOut {
        acceptCollabIds += collabId
        return collaboration()
    }

    override suspend fun rejectCollaboration(collabId: String): CollaborationOut {
        rejectCollabIds += collabId
        return collaboration()
    }

    override suspend fun counterCollaboration(collabId: String, body: CollaborationCounterIn): CollaborationOut {
        counterCalls += collabId to body
        return collaboration()
    }

    override suspend fun cancelCollaboration(collabId: String): CollaborationOut {
        cancelCollabIds += collabId
        return collaboration()
    }

    override suspend fun terminateCollaboration(collabId: String, body: CollaborationTerminateIn): CollaborationOut {
        terminateCalls += collabId to body
        return collaboration()
    }

    override suspend fun getSettings(): CollaborationSettingsOut {
        getSettingsCalls += Unit
        return settings()
    }

    override suspend fun updateSettings(body: CollaborationSettingsIn): CollaborationSettingsOut {
        updateSettingsCalls += body
        return settings()
    }

    override suspend fun listContent(collabId: String): CollabContentListOut {
        listContentCollabIds += collabId
        return content()
    }

    override suspend fun assignContent(collabId: String, body: CollabContentAssignIn): CollabOkOut {
        assignContentCalls += collabId to body
        return ok()
    }

    override suspend fun unassignContent(collabId: String, contentId: String): CollabOkOut {
        unassignContentCalls += collabId to contentId
        return ok()
    }

    override suspend fun recordRevenueEvent(
        collabId: String,
        contentId: String,
        body: CollabContentSplitTriggerIn,
    ): CollabOkOut {
        revenueEventCalls += Triple(collabId, contentId, body)
        return ok()
    }

    override suspend fun listDisputes(collabId: String, status: String?): CollabDisputeListOut {
        listDisputesCalls += collabId to status
        return disputes()
    }

    override suspend fun fileDispute(collabId: String, splitId: String, body: CollabDisputeIn): CollabOkOut {
        fileDisputeCalls += Triple(collabId, splitId, body)
        return ok()
    }

    override suspend fun resolveDispute(
        collabId: String,
        disputeId: String,
        body: CollabDisputeResolveIn,
    ): CollabOkOut {
        resolveDisputeCalls += Triple(collabId, disputeId, body)
        return ok()
    }

    companion object {
        /** Builds an HttpException with [status] (used to simulate a 401 / 500). */
        fun httpError(status: Int): HttpException = HttpException(
            Response.error<Any>(
                status,
                """{"detail":"boom"}""".toResponseBody("application/json".toMediaType()),
            ),
        )
    }
}

/** A fake AuthStateStore exposing a fixed viewer user_id (distinct name from the syndicates-package fake). */
class FakeCollabAuthStore(viewerId: String?) : AuthStateStore {
    private val sub = MutableStateFlow(viewerId)
    override val userSub: StateFlow<String?> = sub.asStateFlow()
    override val isAuthenticated: StateFlow<Boolean> = MutableStateFlow(viewerId != null).asStateFlow()
    override suspend fun setAuthenticated(userSub: String) {
        sub.value = userSub
    }
    override suspend fun clear(reason: LogoutReason) {
        sub.value = null
    }
    override suspend fun lastLogoutReason(): LogoutReason? = null
    override suspend fun clearLogoutReason() = Unit
}

/**
 * A fake [CollaborationsRepository] for the detail ViewModel tests. The collaboration + splits + revisions
 * results are independently swappable so a test can vary the second (refresh) read. The paged list returns
 * empty PagingData (the VM under test does not page). PAR-04: the deal-action results default to Success and
 * are individually swappable; each records its call count / args.
 */
class FakeCollaborationsRepo(
    var collaborationResult: ApiResult<Collaboration> = ApiResult.Success(
        Collaboration(
            id = "c1", title = "Track", status = "active",
            statusEnum = com.testlogon.android.core.model.collaborations.CollabStatus.ACTIVE,
            initiatorId = "usr_a", recipientId = "usr_b",
            split = mapOf("usr_a" to 60, "usr_b" to 40), createdAt = 1L,
        ),
    ),
    var splitsResult: ApiResult<List<SplitDistribution>> = ApiResult.Success(emptyList()),
    var revisionsResult: ApiResult<List<CollabRevision>> = ApiResult.Success(emptyList()),
    var acceptResult: ApiResult<Collaboration> = collaborationResult,
    var rejectResult: ApiResult<Collaboration> = collaborationResult,
    var counterResult: ApiResult<Collaboration> = collaborationResult,
    var cancelResult: ApiResult<Collaboration> = collaborationResult,
    var terminateResult: ApiResult<Collaboration> = collaborationResult,
    var splitRecordsResult: ApiResult<List<CollabSplitRecordModel>> = ApiResult.Success(emptyList()),
    var contentResult: ApiResult<List<CollabContent>> = ApiResult.Success(emptyList()),
    var disputesResult: ApiResult<List<CollabDispute>> = ApiResult.Success(emptyList()),
    var fileDisputeResult: ApiResult<String> = ApiResult.Success("disputed"),
    var resolveDisputeResult: ApiResult<String> = ApiResult.Success("resolved"),
    var settingsResult: ApiResult<CollaborationSettings> = ApiResult.Success(CollaborationSettings()),
    var updateSettingsResult: ApiResult<CollaborationSettings> = ApiResult.Success(CollaborationSettings()),
) : CollaborationsRepository {

    var collaborationCallCount = 0
    var splitsCallCount = 0
    var revisionsCallCount = 0
    var acceptCallCount = 0
    var rejectCallCount = 0
    var cancelCallCount = 0
    var counterSplitPcts = mutableListOf<Int>()
    var terminateReasons = mutableListOf<String?>()
    var splitRecordsCallCount = 0
    var contentCallCount = 0
    var disputesCallCount = 0
    var fileDisputeCalls = mutableListOf<Triple<String, String, Map<String, Int>?>>()
    var resolveDisputeCalls = mutableListOf<Triple<String, String, Boolean>>()
    var getSettingsCallCount = 0
    var updateSettingsCalls = mutableListOf<CollaborationSettings>()

    override fun listPager(): Flow<PagingData<Collaboration>> = flowOf(PagingData.empty())

    override suspend fun getCollaboration(collabId: String): ApiResult<Collaboration> {
        collaborationCallCount++
        return collaborationResult
    }

    override suspend fun getSplits(collabId: String): ApiResult<List<SplitDistribution>> {
        splitsCallCount++
        return splitsResult
    }

    override suspend fun getRevisions(collabId: String): ApiResult<List<CollabRevision>> {
        revisionsCallCount++
        return revisionsResult
    }

    override suspend fun accept(collabId: String): ApiResult<Collaboration> {
        acceptCallCount++
        return acceptResult
    }

    override suspend fun reject(collabId: String): ApiResult<Collaboration> {
        rejectCallCount++
        return rejectResult
    }

    override suspend fun counter(collabId: String, splitPct: Int): ApiResult<Collaboration> {
        counterSplitPcts += splitPct
        return counterResult
    }

    override suspend fun cancel(collabId: String): ApiResult<Collaboration> {
        cancelCallCount++
        return cancelResult
    }

    override suspend fun terminate(collabId: String, reason: String?): ApiResult<Collaboration> {
        terminateReasons += reason
        return terminateResult
    }

    override suspend fun getSplitRecords(collabId: String): ApiResult<List<CollabSplitRecordModel>> {
        splitRecordsCallCount++
        return splitRecordsResult
    }

    override suspend fun getContent(collabId: String): ApiResult<List<CollabContent>> {
        contentCallCount++
        return contentResult
    }

    override suspend fun getDisputes(collabId: String, status: String?): ApiResult<List<CollabDispute>> {
        disputesCallCount++
        return disputesResult
    }

    override suspend fun fileDispute(
        collabId: String,
        splitId: String,
        reason: String,
        proposedSplit: Map<String, Int>?,
    ): ApiResult<String> {
        fileDisputeCalls += Triple(splitId, reason, proposedSplit)
        return fileDisputeResult
    }

    override suspend fun resolveDispute(
        collabId: String,
        disputeId: String,
        resolution: String,
        accept: Boolean,
    ): ApiResult<String> {
        resolveDisputeCalls += Triple(disputeId, resolution, accept)
        return resolveDisputeResult
    }

    override suspend fun getSettings(): ApiResult<CollaborationSettings> {
        getSettingsCallCount++
        return settingsResult
    }

    override suspend fun updateSettings(
        acceptingRequests: Boolean?,
        minSplitPct: Int?,
        allowedContentTypes: List<String>?,
        autoExpireDays: Int?,
    ): ApiResult<CollaborationSettings> {
        updateSettingsCalls += CollaborationSettings(
            acceptingRequests = acceptingRequests ?: true,
            minSplitPct = minSplitPct ?: 1,
            allowedContentTypes = allowedContentTypes ?: emptyList(),
            autoExpireDays = autoExpireDays ?: 7,
        )
        return updateSettingsResult
    }

    companion object {
        fun failure(status: Int = 500): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom"))
    }
}
