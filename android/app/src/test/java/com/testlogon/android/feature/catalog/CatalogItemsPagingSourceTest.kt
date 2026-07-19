package com.testlogon.android.feature.catalog

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.PagingState
import androidx.paging.testing.TestPager
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.catalog.CatalogCategoryPage
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogItemPage
import com.testlogon.android.data.catalog.CatalogRepository
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-205 — [CatalogItemsPagingSource] via Paging's TestPager: cursor follow (next_token), terminal on
 * null token, and error mapping.
 */
class CatalogItemsPagingSourceTest {

    private val config = PagingConfig(pageSize = 50, initialLoadSize = 50, enablePlaceholders = false)
    private val repo = FakeCatalogRepository()

    private fun item(id: String) = CatalogItem(
        itemId = id,
        categoryId = "c",
        name = "n-$id",
        priceCents = 100,
        currency = "USD",
    )

    private fun source() = CatalogItemsPagingSource(repo, categoryId = "c")

    @Test
    fun firstPage_followsToken_prevNull() = runTest {
        repo.itemPages[null] = ApiResult.Success(CatalogItemPage(listOf(item("i1")), nextToken = "t2"))
        val result = TestPager(config, source()).refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("i1"), result.data.map { it.itemId })
        assertEquals("t2", result.nextKey)
        assertNull(result.prevKey)
    }

    @Test
    fun append_followsToken_terminatesOnNull() = runTest {
        repo.itemPages[null] = ApiResult.Success(CatalogItemPage(listOf(item("i1")), nextToken = "t2"))
        repo.itemPages["t2"] = ApiResult.Success(CatalogItemPage(listOf(item("i2")), nextToken = null))
        val pager = TestPager(config, source())
        pager.refresh()
        val appended = pager.append() as PagingSource.LoadResult.Page
        assertEquals(listOf("i2"), appended.data.map { it.itemId })
        assertNull(appended.nextKey)
    }

    @Test
    fun singlePage_nullToken_noAppend() = runTest {
        repo.itemPages[null] = ApiResult.Success(CatalogItemPage(listOf(item("i1")), nextToken = null))
        val result = TestPager(config, source()).refresh() as PagingSource.LoadResult.Page
        assertNull(result.nextKey)
    }

    @Test
    fun httpFailure_yieldsCatalogLoadException() = runTest {
        repo.itemPages[null] = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val result = TestPager(config, source()).refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
        assertTrue((result as PagingSource.LoadResult.Error).throwable is CatalogLoadException)
    }

    @Test
    fun networkError_yieldsError() = runTest {
        repo.itemPages[null] = ApiResult.NetworkError(IOException("offline"))
        assertTrue(TestPager(config, source()).refresh() is PagingSource.LoadResult.Error)
    }

    @Test
    fun getRefreshKey_isNull() {
        assertNull(source().getRefreshKey(PagingState(emptyList(), null, config, 0)))
    }
}

/** Test double for [CatalogRepository] keyed by cursor. Shared across the feature-catalog JVM suite. */
class FakeCatalogRepository : CatalogRepository {
    val itemPages = mutableMapOf<String?, ApiResult<CatalogItemPage>>()
    val searchPages = mutableMapOf<String?, ApiResult<CatalogItemPage>>()
    val searchQueries = mutableListOf<String>()
    var categoriesResult: ApiResult<CatalogCategoryPage> =
        ApiResult.Success(CatalogCategoryPage(emptyList(), nextToken = null))

    /** Overrides getItem when set; otherwise getItem derives from [itemPages] (list-then-find). */
    var getItemResult: ApiResult<CatalogItem>? = null

    override suspend fun categories(nextToken: String?, pageSize: Int): ApiResult<CatalogCategoryPage> =
        categoriesResult

    override suspend fun categoryItems(categoryId: String, cursor: String?, limit: Int): ApiResult<CatalogItemPage> =
        itemPages[cursor] ?: ApiResult.Success(CatalogItemPage(emptyList(), nextToken = null))

    override suspend fun search(query: String, cursor: String?, limit: Int): ApiResult<CatalogItemPage> {
        if (cursor == null) searchQueries += query
        return searchPages[cursor] ?: ApiResult.Success(CatalogItemPage(emptyList(), nextToken = null))
    }

    var reviewsResult: ApiResult<com.testlogon.android.data.catalog.CatalogReviewPage> =
        ApiResult.Success(com.testlogon.android.data.catalog.CatalogReviewPage(emptyList(), nextToken = null))
    val addReviewCalls = mutableListOf<Triple<String, Int, String?>>()
    var addReviewResult: ApiResult<com.testlogon.android.data.catalog.CatalogReview>? = null
    var deleteReviewResult: ApiResult<Unit> = ApiResult.Success(Unit)

    override suspend fun reviews(itemId: String, cursor: String?): ApiResult<com.testlogon.android.data.catalog.CatalogReviewPage> =
        reviewsResult

    override suspend fun addReview(
        itemId: String,
        rating: Int,
        title: String?,
        body: String?,
        reviewer: String?,
    ): ApiResult<com.testlogon.android.data.catalog.CatalogReview> {
        addReviewCalls += Triple(itemId, rating, title)
        return addReviewResult ?: ApiResult.Success(
            com.testlogon.android.data.catalog.CatalogReview(
                reviewId = "rev_${addReviewCalls.size}",
                itemId = itemId,
                rating = rating,
                title = title.orEmpty(),
                body = body.orEmpty(),
                reviewer = reviewer.orEmpty(),
                createdAt = "t",
            ),
        )
    }

    override suspend fun deleteReview(itemId: String, reviewId: String): ApiResult<Unit> = deleteReviewResult

    override suspend fun getItem(categoryId: String, itemId: String): ApiResult<CatalogItem> {
        getItemResult?.let { return it }
        // Mirror the impl's list-then-find over the seeded itemPages.
        var cursor: String? = null
        while (true) {
            when (val r = categoryItems(categoryId, cursor = cursor)) {
                is ApiResult.Success -> {
                    val match = r.data.items.firstOrNull { it.itemId == itemId }
                    if (match != null) return ApiResult.Success(match)
                    cursor = r.data.nextToken
                    if (cursor == null) {
                        return ApiResult.Failure(
                            com.testlogon.android.core.model.ApiError(
                                status = CatalogRepository.STATUS_ITEM_NOT_FOUND,
                                message = "Item not found",
                            ),
                        )
                    }
                }
                is ApiResult.Failure -> return r
                is ApiResult.NetworkError -> return r
            }
        }
    }
}

/**
 * P2 — [WishlistRepository] double. Backs saved/items with in-memory StateFlows; add/remove/toggle
 * mutate them. Default: empty. The shop program added this dep to Catalog/ProductDetail VMs.
 */
class FakeWishlistRepository : com.testlogon.android.data.wishlist.WishlistRepository {
    private val _saved = kotlinx.coroutines.flow.MutableStateFlow<Set<String>>(emptySet())
    override val saved: kotlinx.coroutines.flow.StateFlow<Set<String>> = _saved
    private val _items = kotlinx.coroutines.flow.MutableStateFlow<List<com.testlogon.android.data.wishlist.WishlistItem>>(emptyList())
    override val items: kotlinx.coroutines.flow.StateFlow<List<com.testlogon.android.data.wishlist.WishlistItem>> = _items
    override suspend fun ensureLoaded(): ApiResult<Unit> = ApiResult.Success(Unit)
    override suspend fun refresh(): ApiResult<List<com.testlogon.android.data.wishlist.WishlistItem>> = ApiResult.Success(_items.value)
    override suspend fun add(categoryId: String, itemId: String): ApiResult<Unit> {
        _saved.value = _saved.value + itemId
        return ApiResult.Success(Unit)
    }
    override suspend fun remove(categoryId: String, itemId: String): ApiResult<Unit> {
        _saved.value = _saved.value - itemId
        return ApiResult.Success(Unit)
    }
    override suspend fun toggle(categoryId: String, itemId: String): ApiResult<Unit> {
        _saved.value = if (itemId in _saved.value) _saved.value - itemId else _saved.value + itemId
        return ApiResult.Success(Unit)
    }
}

/** P2 — no-op [ShopAdsRepository]: serve returns no sponsored units; boost is not exercised. */
class FakeShopAdsRepository : com.testlogon.android.data.shopads.ShopAdsRepository {
    var served: List<com.testlogon.android.data.shopads.SponsoredProduct> = emptyList()
    override suspend fun serveShopSponsored(
        surface: String,
        query: String,
        categoryId: String,
        limit: Int,
    ): List<com.testlogon.android.data.shopads.SponsoredProduct> = served
    override suspend fun boostListing(
        itemId: String,
        categoryId: String,
        budgetCents: Int,
        bidCpcCents: Int,
    ): ApiResult<com.testlogon.android.data.shopads.BoostResult> =
        ApiResult.Failure(ApiError(status = 0, message = "not exercised"))
}

/** P2 — real [CurrentUserRepository] over a canned user_sub, for the catalog VMs. */
fun fakeCatalogCurrentUserRepository(sub: String? = "me") =
    com.testlogon.android.data.feed.CurrentUserRepository(
        api = object : com.testlogon.android.data.feed.CurrentUserApi {
            override suspend fun me() = com.testlogon.android.data.feed.CurrentUserDto(userSub = sub)
        },
        errorParser = com.testlogon.android.core.network.error.ApiErrorParser(
            com.squareup.moshi.Moshi.Builder().build(),
        ),
    ).apply { io = kotlinx.coroutines.Dispatchers.Unconfined }

/** P2 — no-op [AdTrackRepository] for the catalog VMs (shop-ad beacons are best-effort). */
class FakeCatalogAdTrackRepository : com.testlogon.android.data.ads.AdTrackRepository {
    override suspend fun track(
        event: com.testlogon.android.data.ads.AdEvent,
        ad: com.testlogon.android.data.feed.SponsoredInfo,
    ): ApiResult<Unit> = ApiResult.Success(Unit)
    override suspend fun clickCta(
        adClickId: String,
        action: com.testlogon.android.data.ads.CtaAction,
    ): ApiResult<Unit> = ApiResult.Success(Unit)
}
