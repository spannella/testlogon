package com.testlogon.android.data.cart

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.flatMap
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.catalog.CatalogItem
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
 * AND-206 — shopping-cart data layer over [CartApi], used by product-detail add-to-cart.
 *
 * [addToCart] performs the verified TWO-step flow: reuse an active cart (or create one) then POST the
 * line item. The catalog item exposes no sku, so item_id is reused as the sku (web parity). Wraps every
 * call in [ApiResult]; CancellationException is re-thrown so coroutine cancellation works; HTTP errors
 * fold to Failure and transport failures to NetworkError. The add POST is never auto-retried here.
 */
interface CartRepository {

    /**
     * Adds [quantity] of [item] to the user's active cart, creating a cart first if none is active.
     * Returns the created/updated line item on success.
     */
    suspend fun addToCart(item: CatalogItem, quantity: Int = 1): ApiResult<CartItem>
}

@Singleton
class CartRepositoryImpl @Inject constructor(
    private val api: CartApi,
    private val errorParser: ApiErrorParser,
) : CartRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun addToCart(item: CatalogItem, quantity: Int): ApiResult<CartItem> =
        withContext(io) {
            // Step 1: reuse an active cart or create one. A create failure short-circuits before the add.
            ensureCart().flatMap { cart ->
                // Step 2: add the line item (sku = item_id, per web client).
                call {
                    api.addItem(
                        cartId = cart.cartId,
                        body = CartItemInDto(
                            sku = item.itemId,
                            name = item.name,
                            unitPriceCents = item.priceCents,
                            quantity = quantity,
                            itemId = item.itemId,
                            categoryId = item.categoryId,
                            imageUrl = item.imageUrls.firstOrNull(),
                        ),
                    )
                }.map { it.toDomain() }
            }
        }

    /** Resolves an active cart, creating a new one if the user has none active. */
    private suspend fun ensureCart(): ApiResult<Cart> {
        val existing = call { api.listCarts() }
        return when (existing) {
            is ApiResult.Success -> {
                val active = existing.data.firstOrNull { it.status == CartApi.STATUS_ACTIVE }
                if (active != null) {
                    ApiResult.Success(active.toDomain())
                } else {
                    call { api.createCart() }.map { it.toDomain() }
                }
            }
            is ApiResult.Failure -> existing
            is ApiResult.NetworkError -> existing
        }
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
