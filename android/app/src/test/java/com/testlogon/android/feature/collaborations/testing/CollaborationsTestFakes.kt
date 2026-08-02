package com.testlogon.android.feature.collaborations.testing

import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.model.collaborations.CollabRevision
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.network.collaborations.CollabSplitHistoryOut
import com.testlogon.android.core.network.collaborations.CollaborationCounterIn
import com.testlogon.android.core.network.collaborations.CollaborationListOut
import com.testlogon.android.core.network.collaborations.CollaborationOut
import com.testlogon.android.core.network.collaborations.CollaborationRevisionOut
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
    var splits: () -> CollabSplitHistoryOut = { CollabSplitHistoryOut(records = emptyList()) },
    var revisions: () -> List<CollaborationRevisionOut> = { emptyList() },
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
) : CollaborationsRepository {

    var collaborationCallCount = 0
    var splitsCallCount = 0
    var revisionsCallCount = 0
    var acceptCallCount = 0
    var rejectCallCount = 0
    var cancelCallCount = 0
    var counterSplitPcts = mutableListOf<Int>()
    var terminateReasons = mutableListOf<String?>()

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

    companion object {
        fun failure(status: Int = 500): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom"))
    }
}
