package com.testlogon.android.feature.broadcasthost.manage

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.broadcast.shelf.ShelfProduct
import com.testlogon.android.data.broadcast.shelf.toDomain
import com.testlogon.android.data.broadcast.tips.Goal
import com.testlogon.android.data.broadcast.tips.toDomain
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-314 — data layer for the HOST goals + products authoring surface, over [BroadcastManageApi].
 *
 * Kept DELIBERATELY SEPARATE from the AND-282 TipsRepository and the AND-283 ShelfRepository so their fakes
 * are NOT touched. The wire DTOs are REUSED from those features and mapped to the SAME domain models
 * ([Goal], [ShelfProduct]) BEFORE the typed [ApiResult], so one DTO/mapper serves both viewer + authoring.
 *
 * Each call is wrapped in [ApiResult] (Failure for HTTP errors via [ApiErrorParser], NetworkError for
 * transport failures, Failure(parse) for malformed JSON); never throws (CancellationException is re-thrown).
 * Mutations are NOT auto-retried; the two list GETs are idempotent. ACK-only mutations (deleteGoal,
 * removeProduct, reorder, clearPrice) succeed on isSuccessful WITHOUT parsing a possibly-empty body. After a
 * successful mutation the caller reconciles from the response body (the server is the source of truth for
 * discount_pct / effective_price_cents / reached).
 */
interface BroadcastManageRepository {

    suspend fun goals(sessionId: String): ApiResult<List<Goal>>

    suspend fun createGoal(
        sessionId: String,
        label: String,
        targetCents: Long,
        sortOrder: Int,
    ): ApiResult<Goal>

    suspend fun deleteGoal(sessionId: String, goalId: String): ApiResult<Unit>

    suspend fun products(sessionId: String): ApiResult<List<ShelfProduct>>

    suspend fun addProduct(
        sessionId: String,
        itemId: String,
        categoryId: String,
        displayOrder: Int,
    ): ApiResult<ShelfProduct>

    suspend fun removeProduct(sessionId: String, itemId: String): ApiResult<Unit>

    /** PATCH the order, then RE-FETCH the products list (reorder returns only an ACK, not the ordered shelf). */
    suspend fun reorder(sessionId: String, order: List<String>): ApiResult<List<ShelfProduct>>

    /**
     * PATCH the broadcast price, then merge the PriceOut into the matching item (re-fetched via [products] so
     * server-derived effective_price_cents / discount_pct are authoritative).
     */
    suspend fun setPrice(
        sessionId: String,
        itemId: String,
        cents: Long,
        expiresInSeconds: Long?,
    ): ApiResult<ShelfProduct>

    suspend fun clearPrice(sessionId: String, itemId: String): ApiResult<Unit>
}

@Singleton
class BroadcastManageRepositoryImpl @Inject constructor(
    private val api: BroadcastManageApi,
    private val errorParser: ApiErrorParser,
) : BroadcastManageRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun goals(sessionId: String): ApiResult<List<Goal>> = withContext(io) {
        when (val result = callBody { api.getGoals(sessionId) }) {
            is ApiResult.Success -> ApiResult.Success(result.data.toDomain())
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun createGoal(
        sessionId: String,
        label: String,
        targetCents: Long,
        sortOrder: Int,
    ): ApiResult<Goal> = withContext(io) {
        val body = TipGoalCreateDto(label = label, targetCents = targetCents, sortOrder = sortOrder)
        when (val result = callBody { api.createGoal(sessionId, body) }) {
            is ApiResult.Success -> ApiResult.Success(result.data.toDomain())
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun deleteGoal(sessionId: String, goalId: String): ApiResult<Unit> = withContext(io) {
        callUnit { api.deleteGoal(sessionId, goalId) }
    }

    override suspend fun products(sessionId: String): ApiResult<List<ShelfProduct>> = withContext(io) {
        when (val result = callBody { api.getProducts(sessionId) }) {
            is ApiResult.Success -> ApiResult.Success(result.data.toDomain())
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun addProduct(
        sessionId: String,
        itemId: String,
        categoryId: String,
        displayOrder: Int,
    ): ApiResult<ShelfProduct> = withContext(io) {
        val body = ShelfAddDto(itemId = itemId, categoryId = categoryId, displayOrder = displayOrder)
        when (val result = callBody { api.addProduct(sessionId, body) }) {
            is ApiResult.Success -> ApiResult.Success(result.data.toDomain())
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun removeProduct(sessionId: String, itemId: String): ApiResult<Unit> = withContext(io) {
        callUnit { api.removeProduct(sessionId, itemId) }
    }

    override suspend fun reorder(
        sessionId: String,
        order: List<String>,
    ): ApiResult<List<ShelfProduct>> = withContext(io) {
        // The reorder PATCH returns only an ACK, so RE-FETCH the products to get the authoritative ordering.
        when (val ack = callUnit { api.reorderProducts(sessionId, ShelfReorderDto(order)) }) {
            is ApiResult.Success -> products(sessionId)
            is ApiResult.Failure -> ack
            is ApiResult.NetworkError -> ack
        }
    }

    override suspend fun setPrice(
        sessionId: String,
        itemId: String,
        cents: Long,
        expiresInSeconds: Long?,
    ): ApiResult<ShelfProduct> = withContext(io) {
        val body = PriceSetDto(broadcastPriceCents = cents, expiresInSeconds = expiresInSeconds)
        when (val priceResult = callBody { api.setProductPrice(sessionId, itemId, body) }) {
            is ApiResult.Success -> {
                // Reconcile from the server (effective_price_cents / discount_pct are server-derived): re-fetch
                // the shelf and return the matching item. Fall back to a local merge of the PriceOut if the
                // re-fetch fails or the item is absent.
                val priceOut = priceResult.data
                when (val refreshed = products(sessionId)) {
                    is ApiResult.Success -> {
                        val match = refreshed.data.firstOrNull { it.itemId == itemId }
                        ApiResult.Success(match ?: mergePriceOut(itemId, priceOut))
                    }
                    is ApiResult.Failure -> ApiResult.Success(mergePriceOut(itemId, priceOut))
                    is ApiResult.NetworkError -> ApiResult.Success(mergePriceOut(itemId, priceOut))
                }
            }
            is ApiResult.Failure -> priceResult
            is ApiResult.NetworkError -> priceResult
        }
    }

    override suspend fun clearPrice(sessionId: String, itemId: String): ApiResult<Unit> = withContext(io) {
        callUnit { api.clearProductPrice(sessionId, itemId) }
    }

    /** Builds a minimal [ShelfProduct] from a PriceOut when the post-set re-fetch is unavailable. */
    private fun mergePriceOut(itemId: String, priceOut: PriceOutDto): ShelfProduct = ShelfProduct(
        itemId = itemId,
        categoryId = "",
        name = "",
        priceCents = priceOut.broadcastPriceCents,
        currency = "USD",
        imageUrl = null,
        originalPriceCents = priceOut.originalPriceCents,
        catalogPriceCents = priceOut.originalPriceCents,
        displayOrder = 0,
        isBroadcastPrice = true,
        broadcastPriceCents = priceOut.broadcastPriceCents,
        broadcastPriceExpiresAtEpochSeconds = priceOut.broadcastPriceExpiresAt,
        discountPct = priceOut.discountPct,
    )

    /**
     * Folds a [Response] with a typed JSON body (list / create / add / set-price) into [ApiResult] of a
     * non-null body. A non-2xx Response -> Failure; a 2xx with an absent body -> Failure(parse).
     */
    private suspend fun <T> callBody(block: suspend () -> Response<T>): ApiResult<T> =
        when (val result = call { block() }) {
            is ApiResult.Success -> {
                val response = result.data
                if (response.isSuccessful) {
                    val body = response.body()
                    if (body != null) {
                        ApiResult.Success(body)
                    } else {
                        ApiResult.Failure(
                            ApiError(status = ApiError.STATUS_PARSE, message = "Empty response body."),
                        )
                    }
                } else {
                    ApiResult.Failure(errorParser.from(HttpException(response)))
                }
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }

    /**
     * Folds an ACK-only [Response] of Unit (an { ok } / empty 200 mutation) into [ApiResult] of Unit. A non-2xx
     * Response is mapped through [ApiErrorParser]; an EMPTY 200 body is success — Retrofit consumes the body
     * WITHOUT JSON parsing (tolerates EOF on empty), so no DTO is parsed here.
     */
    private suspend fun callUnit(block: suspend () -> Response<Unit>): ApiResult<Unit> =
        when (val result = call { block() }) {
            is ApiResult.Success -> {
                val response = result.data
                if (response.isSuccessful) {
                    ApiResult.Success(Unit)
                } else {
                    ApiResult.Failure(errorParser.from(HttpException(response)))
                }
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }

    /**
     * Folds a single call into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); transport failures
     * -> NetworkError; malformed JSON -> Failure(parse). The JsonEncodingException catch precedes the
     * IOException catch (it is an IOException subtype). Cancellation is re-thrown.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
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

/** AND-314 — provides [BroadcastManageApi] on the shared Retrofit + binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object BroadcastManageApiModule {

    @Provides
    @Singleton
    fun provideBroadcastManageApi(retrofit: Retrofit): BroadcastManageApi =
        retrofit.create(BroadcastManageApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class BroadcastManageDataModule {

    @Binds
    @Singleton
    abstract fun bindBroadcastManageRepository(
        impl: BroadcastManageRepositoryImpl,
    ): BroadcastManageRepository
}
