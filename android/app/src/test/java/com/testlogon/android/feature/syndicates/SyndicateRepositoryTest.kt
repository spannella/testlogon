package com.testlogon.android.feature.syndicates

import androidx.paging.PagingSource
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.SplitMode
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.syndicates.SyndicateFeedOut
import com.testlogon.android.core.network.syndicates.SyndicatePostOut
import com.testlogon.android.core.network.syndicates.SyndicateProfileOut
import com.testlogon.android.core.network.syndicates.SplitConfigOut
import com.testlogon.android.feature.syndicates.data.SyndicateFeedPagingSource
import com.testlogon.android.feature.syndicates.data.SyndicateRepositoryImpl
import com.testlogon.android.feature.syndicates.testing.FakeSyndicateApi
import com.testlogon.android.feature.syndicates.testing.FakeSyndicateAuthStore
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-356 - tests for [SyndicateRepositoryImpl]: getOverview maps the DTO (currency upper-cased + role
 * badge derived from admin_user_id == the viewer), is_member==false surfaces on the domain, a 403 surfaces
 * as Failure(status=403) for the VM's NotMember mapping, and getRevenueSplit maps mode via SplitMode.from.
 * Also a direct [SyndicateFeedPagingSource].load() test (first-page items + nextKey).
 */
class SyndicateRepositoryTest {

    private fun repo(api: FakeSyndicateApi, viewerId: String? = "usr_admin") = SyndicateRepositoryImpl(
        api = api,
        authStateStore = FakeSyndicateAuthStore(viewerId),
        errorParser = ApiErrorParser(Moshi.Builder().build()),
    )

    @Test
    fun getOverview_maps_andUppercasesCurrency_andDerivesAdminBadge() = runTest {
        val api = FakeSyndicateApi(
            profile = {
                SyndicateProfileOut(id = "syn_1", name = "Aces", memberCount = 4,
                    adminUserId = "usr_admin", currency = "usd", isMember = true)
            },
        )
        val result = repo(api, viewerId = "usr_admin").getOverview("syn_1")

        assertTrue(result is ApiResult.Success)
        val overview = (result as ApiResult.Success).data
        assertEquals("USD", overview.currency)
        assertTrue(overview.isAdmin)
        assertTrue(overview.isMember)
        // the @Path syndicateId was passed
        assertEquals("syn_1", api.profileSyndicateIds.single())
    }

    @Test
    fun getOverview_nonAdminViewer_isMemberBadge() = runTest {
        val api = FakeSyndicateApi(
            profile = {
                SyndicateProfileOut(id = "syn_1", name = "Aces", adminUserId = "usr_admin",
                    currency = "usd", isMember = true)
            },
        )
        val overview = (repo(api, viewerId = "usr_other").getOverview("syn_1") as ApiResult.Success).data
        assertFalse(overview.isAdmin)
    }

    @Test
    fun getOverview_isMemberFalse_surfacesOnDomain() = runTest {
        val api = FakeSyndicateApi(
            profile = {
                SyndicateProfileOut(id = "syn_1", name = "Aces", currency = "usd", isMember = false)
            },
        )
        val overview = (repo(api).getOverview("syn_1") as ApiResult.Success).data
        assertFalse(overview.isMember)
    }

    @Test
    fun getOverview_403_isFailureWithStatus403() = runTest {
        val api = FakeSyndicateApi(profile = { throw FakeSyndicateApi.http(403) })
        val result = repo(api).getOverview("syn_1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
        // recorded BEFORE throwing
        assertEquals("syn_1", api.profileSyndicateIds.single())
    }

    @Test
    fun getRevenueSplit_unknownMode_mapsToUnknown() = runTest {
        val api = FakeSyndicateApi(split = { SplitConfigOut(mode = "tiered", platformFeeBps = 500) })
        val split = (repo(api).getRevenueSplit("syn_1") as ApiResult.Success).data
        assertEquals(SplitMode.UNKNOWN, split.mode)
        assertEquals(500, split.platformFeeBps)
    }

    @Test
    fun feedPagingSource_firstPage_mapsItems_andNextKeyFromCursor() = runTest {
        val api = FakeSyndicateApi(
            feed = {
                SyndicateFeedOut(
                    posts = listOf(
                        SyndicatePostOut(postId = "p1", createdAt = 1L, text = "a"),
                        SyndicatePostOut(postId = "p2", createdAt = 2L, text = "b"),
                    ),
                    nextCursor = "c2",
                )
            },
        )
        val source = SyndicateFeedPagingSource(api, "syn_1")
        val result = source.load(PagingSource.LoadParams.Refresh(null, 20, false))

        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals(listOf("p1", "p2"), page.data.map { it.postId })
        assertNull(page.prevKey)
        assertEquals("c2", page.nextKey)
    }

    @Test
    fun feedPagingSource_blankCursor_endsPagination() = runTest {
        val api = FakeSyndicateApi(
            feed = { SyndicateFeedOut(posts = listOf(SyndicatePostOut("p1", createdAt = 1L)), nextCursor = "") },
        )
        val page = SyndicateFeedPagingSource(api, "syn_1")
            .load(PagingSource.LoadParams.Refresh(null, 20, false)) as PagingSource.LoadResult.Page
        assertNull(page.nextKey)
    }

    @Test
    fun feedPagingSource_httpError_becomesLoadResultError() = runTest {
        val api = FakeSyndicateApi(feed = { throw FakeSyndicateApi.http(500) })
        val result = SyndicateFeedPagingSource(api, "syn_1")
            .load(PagingSource.LoadParams.Refresh(null, 20, false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }
}
