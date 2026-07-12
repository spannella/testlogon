package com.testlogon.android.data.sellerstore

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.catalog.CatalogCategory
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.toRequestBody
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ECOM (seller store) — seller-side catalog mutation data layer over [SellerCatalogApi]. Wraps every
 * call in [ApiResult] and maps the wire item/category responses back to the shared catalog domain (the
 * same [CatalogItem] / [CatalogCategory] the storefront reads use). Network-only; never throws
 * (CancellationException re-thrown).
 */
interface SellerCatalogRepository {

    suspend fun createCategory(name: String, description: String?): ApiResult<CatalogCategory>

    suspend fun deleteCategory(categoryId: String): ApiResult<Unit>

    suspend fun createItem(
        categoryId: String,
        name: String,
        description: String?,
        priceCents: Long,
        currency: String,
        stockCount: Int?,
    ): ApiResult<CatalogItem>

    suspend fun updateItem(
        categoryId: String,
        itemId: String,
        name: String?,
        description: String?,
        priceCents: Long?,
        stockCount: Int?,
    ): ApiResult<CatalogItem>

    suspend fun deleteItem(categoryId: String, itemId: String): ApiResult<Unit>

    /** Uploads already-encoded image bytes (multipart `file`); returns the updated item with the new url. */
    suspend fun uploadItemImage(
        categoryId: String,
        itemId: String,
        bytes: ByteArray,
        contentType: String,
        fileName: String,
    ): ApiResult<CatalogItem>
}

@Singleton
class SellerCatalogRepositoryImpl @Inject constructor(
    private val api: SellerCatalogApi,
    private val errorParser: ApiErrorParser,
) : SellerCatalogRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun createCategory(name: String, description: String?): ApiResult<CatalogCategory> =
        withContext(io) {
            call {
                api.createCategory(SellerCategoryCreateDto(name = name, description = description?.takeIf { it.isNotBlank() }))
            }.map { it.toDomain() }
        }

    override suspend fun deleteCategory(categoryId: String): ApiResult<Unit> =
        withContext(io) { call { api.deleteCategory(categoryId) }.map { } }

    override suspend fun createItem(
        categoryId: String,
        name: String,
        description: String?,
        priceCents: Long,
        currency: String,
        stockCount: Int?,
    ): ApiResult<CatalogItem> = withContext(io) {
        call {
            api.createItem(
                categoryId = categoryId,
                body = SellerItemCreateDto(
                    name = name,
                    description = description?.takeIf { it.isNotBlank() },
                    priceCents = priceCents,
                    currency = currency,
                    stockCount = stockCount,
                ),
            )
        }.map { it.toDomain() }
    }

    override suspend fun updateItem(
        categoryId: String,
        itemId: String,
        name: String?,
        description: String?,
        priceCents: Long?,
        stockCount: Int?,
    ): ApiResult<CatalogItem> = withContext(io) {
        call {
            api.updateItem(
                categoryId = categoryId,
                itemId = itemId,
                body = SellerItemPatchDto(
                    name = name,
                    description = description,
                    priceCents = priceCents,
                    stockCount = stockCount,
                ),
            )
        }.map { it.toDomain() }
    }

    override suspend fun deleteItem(categoryId: String, itemId: String): ApiResult<Unit> =
        withContext(io) { call { api.deleteItem(categoryId, itemId) }.map { } }

    override suspend fun uploadItemImage(
        categoryId: String,
        itemId: String,
        bytes: ByteArray,
        contentType: String,
        fileName: String,
    ): ApiResult<CatalogItem> = withContext(io) {
        val body = bytes.toRequestBody(contentType.toMediaType())
        val part = MultipartBody.Part.createFormData("file", fileName, body)
        call { api.uploadItemImage(categoryId, itemId, part) }.map { it.toDomain() }
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
