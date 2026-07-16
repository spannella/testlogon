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

    /**
     * FIX (ecom residual #1) — completes the purchase for [cartId] via the reliable one-shot endpoint
     * POST ui/shoppingcart/carts/{cart_id}/purchase (X-Idempotency-Key). This actually creates the
     * order, decrements stock, credits the seller and writes the buyer ledger entry. The app checkout
     * previously dead-ended at an external redirect and never called this. Default = not implemented
     * (existing fakes need no change).
     */
    suspend fun purchase(
        cartId: String,
        idempotencyKey: String,
        promoCode: String? = null,
        promoCodeId: String? = null,
        // ADV-405: last-click ad_click_id to attribute the checkout conversion (backend ADV-403).
        adClickId: String? = null,
        // LIVECOM L3/L5: attribute the purchase to a live broadcast session + host so the backend fires
        // the commission split (affiliate: host commission + seller net + platform; own: host keeps pool).
        broadcastSessionId: String? = null,
        hostId: String? = null,
        // ECOMX-40 (B3): the shipping address chosen in the checkout address step + shipping method.
        addressId: String? = null,
        shippingMethod: String? = null,
    ): ApiResult<CartPurchaseResult> =
        ApiResult.NetworkError(UnsupportedOperationException("purchase not implemented"), isTimeout = false)

    /**
     * LIVECOM L5 — the in-stream "buy now" path: create a FRESH cart holding ONLY this product, then
     * complete the purchase attributed to [broadcastSessionId] + [hostId]. A dedicated cart keeps the
     * order isolated (clean stream attribution + a single commission split) and leaves any pre-existing
     * shopping cart untouched. The viewer never leaves the stream. Default = not implemented so existing
     * fakes need no change.
     */
    suspend fun buyNowInStream(
        productId: String,
        categoryId: String?,
        name: String,
        unitPriceCents: Long,
        imageUrl: String?,
        broadcastSessionId: String,
        hostId: String?,
        idempotencyKey: String,
        quantity: Int = 1,
    ): ApiResult<CartPurchaseResult> =
        ApiResult.NetworkError(UnsupportedOperationException("buyNowInStream not implemented"), isTimeout = false)
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

    override suspend fun purchase(
        cartId: String,
        idempotencyKey: String,
        promoCode: String?,
        promoCodeId: String?,
        adClickId: String?,
        broadcastSessionId: String?,
        hostId: String?,
        addressId: String?,
        shippingMethod: String?,
    ): ApiResult<CartPurchaseResult> = withContext(io) {
        call {
            api.purchaseCart(
                cartId = cartId,
                idempotencyKey = idempotencyKey,
                body = CartPurchaseInDto(
                    promoCode = promoCode,
                    promoCodeId = promoCodeId,
                    adClickId = adClickId,
                    broadcastSessionId = broadcastSessionId,
                    hostId = hostId,
                    addressId = addressId,
                    shippingMethod = shippingMethod,
                ),
            )
        }.map { it.toDomain() }.also {
            // The purchased cart is consumed server-side; drop the cached handle so the next
            // add-to-cart resolves/creates a fresh cart instead of reusing the dead one.
            if (it is ApiResult.Success) cachedCartId = null
        }
    }

    override suspend fun buyNowInStream(
        productId: String,
        categoryId: String?,
        name: String,
        unitPriceCents: Long,
        imageUrl: String?,
        broadcastSessionId: String,
        hostId: String?,
        idempotencyKey: String,
        quantity: Int,
    ): ApiResult<CartPurchaseResult> = withContext(io) {
        // Step 1: a FRESH cart isolated to this in-stream buy (leaves any active shopping cart alone).
        call { api.createCart() }.map { it.toDomain() }.flatMap { cart ->
            // Step 2: add the single line (sku = product_id, per the web/add-to-cart convention).
            call {
                api.addItem(
                    cartId = cart.cartId,
                    body = CartItemInDto(
                        sku = productId,
                        name = name,
                        unitPriceCents = unitPriceCents,
                        quantity = quantity,
                        itemId = productId,
                        categoryId = categoryId,
                        imageUrl = imageUrl,
                    ),
                )
            }.flatMap {
                // Step 3: complete the purchase, attributed to the stream + host (fires the split).
                call {
                    api.purchaseCart(
                        cartId = cart.cartId,
                        idempotencyKey = idempotencyKey,
                        body = CartPurchaseInDto(
                            broadcastSessionId = broadcastSessionId,
                            hostId = hostId,
                        ),
                    )
                }.map { it.toDomain() }
            }
        }
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
