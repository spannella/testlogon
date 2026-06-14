package com.testlogon.android.feature.collaborations

import androidx.paging.PagingSource
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.collaborations.CollabStatus
import com.testlogon.android.core.network.collaborations.CollabSplitDistribution
import com.testlogon.android.core.network.collaborations.CollabSplitHistoryOut
import com.testlogon.android.core.network.collaborations.CollabSplitRecord
import com.testlogon.android.core.network.collaborations.CollaborationListOut
import com.testlogon.android.core.network.collaborations.CollaborationOut
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.collaborations.data.CollaborationsPagingSource
import com.testlogon.android.feature.collaborations.data.CollaborationsRepositoryImpl
import com.testlogon.android.feature.collaborations.testing.FakeCollaborationsApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-358 - tests for [CollaborationsRepositoryImpl]: getCollaboration maps (id coalesce, raw+typed status,
 * split percents, splitTotalsOk); getSplits maps the flattened distributions; a 401 surfaces as
 * Failure(status=401) for the VM's SessionExpired mapping. Also a direct [CollaborationsPagingSource].load()
 * test (first-page items + nextKey, blank-cursor termination, http-error -> Error).
 */
class CollaborationsRepositoryTest {

    private fun repo(api: FakeCollaborationsApi) = CollaborationsRepositoryImpl(
        api = api,
        errorParser = ApiErrorParser(Moshi.Builder().build()),
    )

    @Test
    fun getCollaboration_maps_idStatusSplit_andTotalsOk() = runTest {
        val api = FakeCollaborationsApi(
            collaboration = {
                CollaborationOut(
                    collabId = "c1", title = "Track", status = "active", initiatorId = "usr_a",
                    recipientId = "usr_b", split = mapOf("usr_a" to 60, "usr_b" to 40), createdAt = 1L,
                )
            },
        )
        val result = repo(api).getCollaboration("c1")

        assertTrue(result is ApiResult.Success)
        val collab = (result as ApiResult.Success).data
        assertEquals("c1", collab.id)
        assertEquals("active", collab.status)
        assertEquals(CollabStatus.ACTIVE, collab.statusEnum)
        assertEquals(60, collab.split["usr_a"])
        assertTrue(collab.splitTotalsOk)
        assertEquals("c1", api.collaborationCollabIds.single())
    }

    @Test
    fun getCollaboration_freeStatus_keptRaw_typedUnknown() = runTest {
        val api = FakeCollaborationsApi(
            collaboration = { CollaborationOut(collabId = "c1", title = "X", status = "weird") },
        )
        val collab = (repo(api).getCollaboration("c1") as ApiResult.Success).data
        assertEquals("weird", collab.status)
        assertEquals(CollabStatus.UNKNOWN, collab.statusEnum)
        // empty split -> totals not ok (non-blocking warning at the UI)
        assertFalse(collab.splitTotalsOk)
    }

    @Test
    fun getCollaboration_401_isFailureWithStatus401() = runTest {
        val api = FakeCollaborationsApi(collaboration = { throw FakeCollaborationsApi.httpError(401) })
        val result = repo(api).getCollaboration("c1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
        // recorded BEFORE throwing
        assertEquals("c1", api.collaborationCollabIds.single())
    }

    @Test
    fun getSplits_flattensDistributions_acrossRecords() = runTest {
        val api = FakeCollaborationsApi(
            splits = {
                CollabSplitHistoryOut(
                    records = listOf(
                        CollabSplitRecord(
                            recordId = "r1",
                            distributions = listOf(
                                CollabSplitDistribution(userId = "usr_a", percentage = 60, amountCents = 6000),
                                CollabSplitDistribution(userId = "usr_b", percentage = 40, amountCents = 4000),
                            ),
                        ),
                    ),
                )
            },
        )
        val result = repo(api).getSplits("c1")

        assertTrue(result is ApiResult.Success)
        val dists = (result as ApiResult.Success).data
        assertEquals(2, dists.size)
        assertEquals("usr_a", dists[0].userId)
        assertEquals(60, dists[0].percent)
        assertEquals(6000, dists[0].amountCents)
        assertEquals("c1", api.splitsCollabIds.single())
    }

    @Test
    fun getSplits_failure_isFailure() = runTest {
        val api = FakeCollaborationsApi(splits = { throw FakeCollaborationsApi.httpError(500) })
        val result = repo(api).getSplits("c1")
        assertTrue(result is ApiResult.Failure)
        assertEquals("c1", api.splitsCollabIds.single())
    }

    @Test
    fun pagingSource_firstPage_mapsItems_andNextKeyFromCursor() = runTest {
        val api = FakeCollaborationsApi(
            list = {
                CollaborationListOut(
                    items = listOf(
                        CollaborationOut(collabId = "c1", title = "A"),
                        CollaborationOut(collabId = "c2", title = "B"),
                    ),
                    nextCursor = "cur2",
                )
            },
        )
        val source = CollaborationsPagingSource(api)
        val result = source.load(PagingSource.LoadParams.Refresh(null, 20, false))

        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals(listOf("c1", "c2"), page.data.map { it.id })
        assertNull(page.prevKey)
        assertEquals("cur2", page.nextKey)
    }

    @Test
    fun pagingSource_blankCursor_endsPagination() = runTest {
        val api = FakeCollaborationsApi(
            list = {
                CollaborationListOut(items = listOf(CollaborationOut(collabId = "c1")), nextCursor = "")
            },
        )
        val page = CollaborationsPagingSource(api)
            .load(PagingSource.LoadParams.Refresh(null, 20, false)) as PagingSource.LoadResult.Page
        assertNull(page.nextKey)
    }

    @Test
    fun pagingSource_httpError_becomesLoadResultError() = runTest {
        val api = FakeCollaborationsApi(list = { throw FakeCollaborationsApi.httpError(500) })
        val result = CollaborationsPagingSource(api)
            .load(PagingSource.LoadParams.Refresh(null, 20, false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }
}
