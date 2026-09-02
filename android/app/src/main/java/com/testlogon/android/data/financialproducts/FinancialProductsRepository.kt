package com.testlogon.android.data.financialproducts

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.admin.AdminRoleProvider
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
 * Data layer over [FinancialProductsApi] for CUS-004 Financial Products + Collections.
 *
 * Gating: reuses the AND-403 [AdminRoleProvider] client pre-check ([isAdmin]); the backend
 * `require_admin_or_root` 403 is the authority. Degrade-on-404: the whole router 404s when the OBP /
 * financial-products flags are off, so reads fold a 404 into honest-EMPTY; mutations surface the failure
 * so the user sees "not enabled". Every call is wrapped in [ApiResult].
 */
interface FinancialProductsRepository {
    fun isAdmin(): Boolean

    suspend fun loadProducts(): ApiResult<List<FinancialProduct>>
    suspend fun createProduct(
        productCode: String,
        name: String,
        category: String?,
        description: String?,
    ): ApiResult<FinancialProduct>

    suspend fun loadAttributes(productCode: String): ApiResult<List<ProductAttribute>>
    suspend fun setAttribute(
        productCode: String,
        name: String,
        type: FinancialProductsMath.AttributeType,
        value: String,
    ): ApiResult<ProductAttribute>
    suspend fun deleteAttribute(productCode: String, attributeId: String): ApiResult<Unit>

    suspend fun loadCollections(): ApiResult<List<ProductCollection>>
    suspend fun createCollection(
        collectionCode: String,
        name: String,
        productCodes: List<String>,
    ): ApiResult<ProductCollection>
}

@Singleton
class FinancialProductsRepositoryImpl @Inject constructor(
    private val api: FinancialProductsApi,
    private val errorParser: ApiErrorParser,
    private val roleProvider: AdminRoleProvider,
) : FinancialProductsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun isAdmin(): Boolean = roleProvider.mayAttemptAdminReads()

    override suspend fun loadProducts(): ApiResult<List<FinancialProduct>> = withContext(io) {
        readOrEmpty(emptyList()) { api.listProducts().items.map { it.toDomain() } }
    }

    override suspend fun createProduct(
        productCode: String,
        name: String,
        category: String?,
        description: String?,
    ): ApiResult<FinancialProduct> = withContext(io) {
        call {
            api.createProduct(
                FinancialProductCreateDto(
                    productCode = productCode.trim(),
                    name = name.trim(),
                    category = category?.trim()?.takeIf { it.isNotEmpty() },
                    description = description?.trim()?.takeIf { it.isNotEmpty() },
                ),
            ).toDomain()
        }
    }

    override suspend fun loadAttributes(productCode: String): ApiResult<List<ProductAttribute>> =
        withContext(io) {
            readOrEmpty(emptyList()) { api.listAttributes(productCode).attributes.map { it.toDomain() } }
        }

    override suspend fun setAttribute(
        productCode: String,
        name: String,
        type: FinancialProductsMath.AttributeType,
        value: String,
    ): ApiResult<ProductAttribute> = withContext(io) {
        call {
            api.setAttribute(
                productCode,
                ProductAttributeSetDto(name = name.trim(), type = type.wire, value = value.trim()),
            ).toDomain()
        }
    }

    override suspend fun deleteAttribute(productCode: String, attributeId: String): ApiResult<Unit> =
        withContext(io) {
            call {
                api.deleteAttribute(productCode, attributeId)
                Unit
            }
        }

    override suspend fun loadCollections(): ApiResult<List<ProductCollection>> = withContext(io) {
        readOrEmpty(emptyList()) { api.listCollections().items.map { it.toDomain() } }
    }

    override suspend fun createCollection(
        collectionCode: String,
        name: String,
        productCodes: List<String>,
    ): ApiResult<ProductCollection> = withContext(io) {
        call {
            api.upsertCollection(
                collectionCode.trim(),
                ProductCollectionUpsertDto(name = name.trim(), productCodes = productCodes),
            ).toDomain()
        }
    }

    private suspend fun <T> readOrEmpty(empty: T, block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == HTTP_NOT_FOUND) ApiResult.Success(empty) else ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        private const val HTTP_NOT_FOUND = 404
    }
}
