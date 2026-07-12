package com.testlogon.android.data.wishlist

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ECOM — single source of truth for the signed-in user's wishlist.
 *
 * The repository is a [Singleton] so the heart-toggle saved-set is shared across every screen
 * (product-detail + catalog cells + the Wishlist screen): a save on one surface immediately lights the
 * heart everywhere. [saved] is the derived membership set (category#item keys); [items] is the
 * newest-first render list backing the Wishlist screen. Add/remove are optimistic (flip the local state
 * first, revert on failure) so the heart feels instant. The backend upsert/delete are idempotent.
 */
interface WishlistRepository {

    /** Membership set of `category#item` keys — drives the heart filled/outlined state. */
    val saved: StateFlow<Set<String>>

    /** Newest-first saved items — backs the Wishlist screen. */
    val items: StateFlow<List<WishlistItem>>

    /** Fetches the list once (no-op after the first success). */
    suspend fun ensureLoaded(): ApiResult<Unit>

    /** Force-refreshes the list from the server. */
    suspend fun refresh(): ApiResult<List<WishlistItem>>

    /** Idempotent upsert; optimistically marks the item saved. */
    suspend fun add(categoryId: String, itemId: String): ApiResult<Unit>

    /** Idempotent remove; optimistically un-marks the item. */
    suspend fun remove(categoryId: String, itemId: String): ApiResult<Unit>

    /** Convenience toggle used by the heart button. */
    suspend fun toggle(categoryId: String, itemId: String): ApiResult<Unit>
}

@Singleton
class WishlistRepositoryImpl @Inject constructor(
    private val api: WishlistApi,
    private val errorParser: ApiErrorParser,
) : WishlistRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    private val _saved = MutableStateFlow<Set<String>>(emptySet())
    override val saved: StateFlow<Set<String>> = _saved.asStateFlow()

    private val _items = MutableStateFlow<List<WishlistItem>>(emptyList())
    override val items: StateFlow<List<WishlistItem>> = _items.asStateFlow()

    @Volatile
    private var loaded = false

    override suspend fun ensureLoaded(): ApiResult<Unit> {
        if (loaded) return ApiResult.Success(Unit)
        return when (val r = refresh()) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun refresh(): ApiResult<List<WishlistItem>> = withContext(io) {
        call { api.list() }.also { r ->
            if (r is ApiResult.Success) {
                val mapped = r.data.items.map { it.toDomain() }
                _items.value = mapped
                _saved.value = mapped.map { it.key }.toSet()
                loaded = true
            }
        }.let { r ->
            when (r) {
                is ApiResult.Success -> ApiResult.Success(r.data.items.map { it.toDomain() })
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }
    }

    override suspend fun add(categoryId: String, itemId: String): ApiResult<Unit> = withContext(io) {
        val key = wishlistKey(categoryId, itemId)
        val alreadySaved = _saved.value.contains(key)
        _saved.update { it + key }
        when (val r = call { api.add(WishlistAddDto(categoryId, itemId)) }) {
            is ApiResult.Success -> {
                val item = r.data.toDomain()
                _items.update { current ->
                    if (current.any { it.key == key }) current else listOf(item) + current
                }
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> {
                if (!alreadySaved) _saved.update { it - key }
                r
            }
            is ApiResult.NetworkError -> {
                if (!alreadySaved) _saved.update { it - key }
                r
            }
        }
    }

    override suspend fun remove(categoryId: String, itemId: String): ApiResult<Unit> = withContext(io) {
        val key = wishlistKey(categoryId, itemId)
        val previousItems = _items.value
        val wasSaved = _saved.value.contains(key)
        _saved.update { it - key }
        _items.update { list -> list.filterNot { it.key == key } }
        when (val r = call { api.remove(categoryId, itemId) }) {
            is ApiResult.Success -> ApiResult.Success(Unit)
            is ApiResult.Failure -> {
                if (wasSaved) _saved.update { it + key }
                _items.value = previousItems
                r
            }
            is ApiResult.NetworkError -> {
                if (wasSaved) _saved.update { it + key }
                _items.value = previousItems
                r
            }
        }
    }

    override suspend fun toggle(categoryId: String, itemId: String): ApiResult<Unit> =
        if (_saved.value.contains(wishlistKey(categoryId, itemId))) {
            remove(categoryId, itemId)
        } else {
            add(categoryId, itemId)
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
