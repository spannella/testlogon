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

    /**
     * AND-211 — resolves the active cart (reuse first active, else create), then composes its
     * line items + server total into a [FullCart]. Idempotent GETs; safe to retry on NetworkError.
     */
    suspend fun loadCart(): ApiResult<FullCart>

    /**
     * AND-211 — updates [sku] to [quantity] (PATCH) then re-fetches items + total. The mutation body
     * is untyped, so the authoritative cart comes from the re-fetch. Never auto-retried.
     */
    suspend fun setQuantity(sku: String, quantity: Int): ApiResult<FullCart>

    /** AND-211 — removes [sku] (full removal, DELETE) then re-fetches the cart. Never auto-retried. */
    suspend fun removeLine(sku: String): ApiResult<FullCart>

    /** AND-211 — deletes the whole cart (DELETE). Never auto-retried. */
    suspend fun clearCart(): ApiResult<OkRespDto>

    /**
     * AND-220 — reads the line items for a SPECIFIC [cartId] (idempotent GET; safe to retry on
     * NetworkError). Used by order detail to resolve a transaction's line items from its
     * metadata.cart_id without touching the active-cart resolution. Returns an empty list when the
     * cart has no items rather than throwing. Defaults to an empty success so existing fakes that do
     * not exercise order detail need no change.
     */
    suspend fun itemsForCart(cartId: String): ApiResult<List<CartItem>> =
        ApiResult.Success(emptyList())
}

@Singleton
class CartRepositoryImpl @Inject constructor(
    private val api: CartApi,
    private val errorParser: ApiErrorParser,
) : CartRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    /** Last resolved active cart id; lets mutations skip a fresh list call. Cleared on clearCart. */
    @Volatile
    private var cachedCartId: String? = null

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

    override suspend fun loadCart(): ApiResult<FullCart> = withContext(io) {
        ensureCart().flatMap { cart -> composeCart(cart.cartId) }
    }

    override suspend fun setQuantity(sku: String, quantity: Int): ApiResult<FullCart> =
        withContext(io) {
            resolveCartId().flatMap { cartId ->
                // PATCH returns an untyped 200 -> reconcile by re-fetching items + total.
                call { api.updateItemQty(cartId, sku, UpdateCartItemQtyRequest(quantity)) }
                    .flatMap { composeCart(cartId) }
            }
        }

    override suspend fun removeLine(sku: String): ApiResult<FullCart> =
        withContext(io) {
            resolveCartId().flatMap { cartId ->
                // DELETE returns {ok:true} -> reconcile by re-fetching items + total.
                call { api.removeItem(cartId, sku) }.flatMap { composeCart(cartId) }
            }
        }

    override suspend fun clearCart(): ApiResult<OkRespDto> = withContext(io) {
        resolveCartId().flatMap { cartId ->
            call { api.deleteCart(cartId) }.also {
                if (it is ApiResult.Success) cachedCartId = null
            }
        }
    }

    override suspend fun itemsForCart(cartId: String): ApiResult<List<CartItem>> = withContext(io) {
        // Reuse the existing list-items GET + mapper; empty list when the cart has no items.
        call { api.getCartItems(cartId) }.map { resp -> resp.items.orEmpty().map { it.toDomain() } }
    }

    /** Loads items + total for [cartId] and composes them into a [FullCart]. */
    private suspend fun composeCart(cartId: String): ApiResult<FullCart> =
        call { api.getCartItems(cartId) }.flatMap { itemsDto ->
            // The total is best-effort: if it fails, fall back to the derived subtotal rather than
            // failing the whole load (the item list is the load-bearing payload).
            val total = (call { api.getCartTotal(cartId) } as? ApiResult.Success)?.data?.toDomain()
            ApiResult.Success(itemsDto.toDomain(total))
        }

    /** Returns the cached active cart id, resolving (list-or-create) it once if unknown. */
    private suspend fun resolveCartId(): ApiResult<String> {
        cachedCartId?.let { return ApiResult.Success(it) }
        return ensureCart().map { it.cartId }
    }

    /** Resolves an active cart, creating a new one if the user has none active. */
    private suspend fun ensureCart(): ApiResult<Cart> {
        val existing = call { api.listCarts() }
        return when (existing) {
            is ApiResult.Success -> {
                val active = existing.data.firstOrNull { it.status in CartApi.ACTIVE_STATUSES }
                val resolved = if (active != null) {
                    ApiResult.Success(active.toDomain())
                } else {
                    call { api.createCart() }.map { it.toDomain() }
                }
                if (resolved is ApiResult.Success) cachedCartId = resolved.data.cartId
                resolved
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
