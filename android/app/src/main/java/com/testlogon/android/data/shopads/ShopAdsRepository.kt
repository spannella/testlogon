package com.testlogon.android.data.shopads

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ADV x ECOM (B2/B4) — shop sponsored-products + seller boost data layer over [ShopAdsApi].
 *
 * [serveShopSponsored] is BEST-EFFORT: a served sponsored unit is a decoration on the shop results, so
 * any failure folds to an EMPTY list (the shop never surfaces an ad error to the shopper). [boostListing]
 * DOES fold errors into [ApiResult] (the seller must see success / not-owner / offline).
 */
interface ShopAdsRepository {

    /**
     * B2 — serve up to [limit] STANDALONE product-linked sponsored units for the shop [surface]
     * (shop_search / shop_browse) with the optional [query] / [categoryId] context. Best-effort: returns
     * an empty list on any error.
     */
    suspend fun serveShopSponsored(
        surface: String,
        query: String = "",
        categoryId: String = "",
        limit: Int = 3,
    ): List<SponsoredProduct>

    /**
     * B4 — create a product ad from the seller's catalog LISTING [itemId] (owner-checked server-side).
     * A 403 folds to a Failure the caller renders as "you do not own this listing".
     */
    suspend fun boostListing(
        itemId: String,
        categoryId: String,
        budgetCents: Int,
        bidCpcCents: Int,
    ): ApiResult<BoostResult>

    companion object {
        const val SURFACE_BROWSE = "shop_browse"
        const val SURFACE_SEARCH = "shop_search"
    }
}

@Singleton
class ShopAdsRepositoryImpl @Inject constructor(
    private val api: ShopAdsApi,
    private val errorParser: ApiErrorParser,
) : ShopAdsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun serveShopSponsored(
        surface: String,
        query: String,
        categoryId: String,
        limit: Int,
    ): List<SponsoredProduct> = withContext(io) {
        val safeSurface = if (surface == ShopAdsRepository.SURFACE_SEARCH) {
            ShopAdsRepository.SURFACE_SEARCH
        } else {
            ShopAdsRepository.SURFACE_BROWSE
        }
        try {
            val out = api.serveShop(
                ShopServeInDto(
                    surface = safeSurface,
                    query = query.trim().take(200),
                    categoryId = categoryId.trim().take(200),
                    limit = limit.coerceIn(1, 10),
                )
            )
            out.sponsored.mapNotNull { it.toDomainOrNull(categoryId) }
        } catch (e: CancellationException) {
            throw e
        } catch (_: HttpException) {
            emptyList()
        } catch (_: IOException) {
            emptyList()
        }
    }

    override suspend fun boostListing(
        itemId: String,
        categoryId: String,
        budgetCents: Int,
        bidCpcCents: Int,
    ): ApiResult<BoostResult> = withContext(io) {
        try {
            ApiResult.Success(
                api.boostProduct(
                    ProductBoostInDto(
                        itemId = itemId,
                        categoryId = categoryId,
                        budgetCents = budgetCents,
                        bidCpcCents = bidCpcCents,
                    )
                )
            ).map { it.toDomain() }
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}
