package com.testlogon.android.data.livecommerce

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
 * LIVECOM L5 — data layer over [LiveCommerceApi]. Wraps every call in [ApiResult]; CancellationException
 * is re-thrown so coroutine cancellation works; HTTP errors fold to Failure and transport failures to
 * NetworkError. Host-only writes (pin/unpin) + the owner-scoped commission set are enforced server-side;
 * a 403 surfaces here as a Failure the UI can show.
 */
interface LiveCommerceRepository {

    /** Shop-this-stream: the products a host pinned to [sessionId] (viewer-readable). */
    suspend fun streamProducts(sessionId: String): ApiResult<List<PinnedProduct>>

    /** Host pins a catalog product (own OR affiliate-any) to [sessionId]. is_affiliate is derived. */
    suspend fun pinProduct(sessionId: String, productId: String, categoryId: String): ApiResult<PinnedProduct>

    /** Host unpins a product from [sessionId]. */
    suspend fun unpinProduct(sessionId: String, productId: String): ApiResult<Unit>

    /** Reads a listing's seller-set affiliate commission (bps; default 1000 = 10%). */
    suspend fun affiliateCommissionBps(categoryId: String, itemId: String): ApiResult<Int>

    /** Owner-scoped: the seller sets a listing's affiliate commission (bps). */
    suspend fun setAffiliateCommissionBps(categoryId: String, itemId: String, bps: Int): ApiResult<Int>
}

@Singleton
class LiveCommerceRepositoryImpl @Inject constructor(
    private val api: LiveCommerceApi,
    private val errorParser: ApiErrorParser,
) : LiveCommerceRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun streamProducts(sessionId: String): ApiResult<List<PinnedProduct>> =
        withContext(io) {
            call { api.streamProducts(sessionId) }.map { resp -> resp.products.map { it.toDomain() } }
        }

    override suspend fun pinProduct(
        sessionId: String,
        productId: String,
        categoryId: String,
    ): ApiResult<PinnedProduct> = withContext(io) {
        call { api.pinProduct(sessionId, PinProductDto(productId = productId, categoryId = categoryId)) }
            .map { it.toDomain() }
    }

    override suspend fun unpinProduct(sessionId: String, productId: String): ApiResult<Unit> =
        withContext(io) { call { api.unpinProduct(sessionId, productId) }.map { } }

    override suspend fun affiliateCommissionBps(categoryId: String, itemId: String): ApiResult<Int> =
        withContext(io) {
            call { api.getAffiliateCommission(categoryId, itemId) }.map { it.affiliateCommissionBps }
        }

    override suspend fun setAffiliateCommissionBps(
        categoryId: String,
        itemId: String,
        bps: Int,
    ): ApiResult<Int> = withContext(io) {
        call { api.setAffiliateCommission(categoryId, itemId, AffiliateCommissionDto(affiliateCommissionBps = bps)) }
            .map { it.affiliateCommissionBps }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
