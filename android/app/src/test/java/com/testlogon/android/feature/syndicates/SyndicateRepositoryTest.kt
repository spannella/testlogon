package com.testlogon.android.feature.syndicates

import androidx.paging.PagingSource
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.LicensingContentType
import com.testlogon.android.core.model.syndicates.SplitMode
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.syndicates.OpenLicensingContentListResponse
import com.testlogon.android.core.network.syndicates.SyndicateFeedOut
import com.testlogon.android.core.network.syndicates.SyndicateOpenLicensingContentOut
import com.testlogon.android.core.network.syndicates.SyndicateOpenLicensingRegistrationOut
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

    // ---- AND-357: open-licensing ----

    @Test
    fun getOpenLicensingContent_mapsItems_andPassesPath() = runTest {
        val api = FakeSyndicateApi(
            licensingContent = {
                OpenLicensingContentListResponse(
                    items = listOf(
                        SyndicateOpenLicensingContentOut(
                            contentId = "vid_1", contentType = "video", creatorId = "usr_a",
                            exempt = true, registeredAt = 1780000000L,
                        ),
                        SyndicateOpenLicensingContentOut(
                            contentId = "x_2", contentType = "bogus",
                        ),
                    ),
                )
            },
        )
        val result = repo(api).getOpenLicensingContent("syn_1")

        assertTrue(result is ApiResult.Success)
        val items = (result as ApiResult.Success).data
        assertEquals(2, items.size)
        assertEquals("vid_1", items[0].contentId)
        assertEquals(LicensingContentType.VIDEO, items[0].contentType)
        assertTrue(items[0].exempt)
        assertEquals(1780000000L, items[0].registeredAt)
        // unknown wire token -> UNKNOWN; exempt defaults false
        assertEquals(LicensingContentType.UNKNOWN, items[1].contentType)
        assertFalse(items[1].exempt)
        assertEquals("syn_1", api.licensingContentSyndicateIds.single())
    }

    @Test
    fun registerOpenLicensing_mapsLicensesCreated_andSendsWireTypeAndPath() = runTest {
        val api = FakeSyndicateApi(
            register = {
                SyndicateOpenLicensingRegistrationOut(
                    contentId = "vid_1", syndicateId = "syn_1", licensesCreated = 4,
                )
            },
        )
        val result = repo(api).registerOpenLicensing("syn_1", "vid_1", LicensingContentType.VIDEO)

        assertTrue(result is ApiResult.Success)
        assertEquals(4, (result as ApiResult.Success).data.licensesCreated)
        assertEquals("syn_1", api.registerSyndicateIds.single())
        assertEquals("vid_1", api.registerBodies.single().contentId)
        assertEquals("video", api.registerBodies.single().contentType)
    }

    @Test
    fun registerOpenLicensing_422_isFailureWithStatus422_andRawDetail() = runTest {
        val api = FakeSyndicateApi(
            register = { throw FakeSyndicateApi.http422("content_id" to "must not be blank") },
        )
        val result = repo(api).registerOpenLicensing("syn_1", "", LicensingContentType.VIDEO)

        assertTrue(result is ApiResult.Failure)
        val error = (result as ApiResult.Failure).error
        assertEquals(422, error.status)
        // the raw body is preserved for the ViewModel's per-field loc-tail mapping
        assertTrue((error.raw as? String)?.contains("content_id") == true)
        // recorded BEFORE throwing
        assertEquals("syn_1", api.registerSyndicateIds.single())
    }
}
