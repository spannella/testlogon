package com.testlogon.android.data.sellerstore

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
 * ECOM (catalog depth) — seller-side data layer for the advanced product endpoints over
 * [ProductDepthApi]. Wraps every call in [ApiResult] and maps wire shapes to the [ProductDepthDomain]
 * models.
 *
 * Degrade-on-404 (brief): the whole depth subsystem is behind a backend feature flag that answers
 * 404 / 501 (`product_depth_not_enabled`) when off. READS treat those two statuses as an honest-empty
 * result (empty list / null) rather than an error, so the editor renders a clean "not enabled" empty
 * state. WRITES surface the failure so the user learns the mutation didn't happen.
 */
interface ProductDepthRepository {

    suspend fun getProductType(itemId: String): ApiResult<String>
    suspend fun setProductType(itemId: String, productType: String): ApiResult<String>

    suspend fun listVariants(itemId: String): ApiResult<List<Variant>>
    suspend fun createVariant(itemId: String, featureValues: Map<String, String>, skuOverride: String?): ApiResult<Variant>
    suspend fun deleteVariant(itemId: String, variantId: String): ApiResult<Unit>

    suspend fun listPriceComponents(itemId: String, priceType: String?): ApiResult<List<PriceComponent>>
    suspend fun addPriceComponent(
        itemId: String,
        priceType: String,
        amountCents: Long,
        currency: String,
        effectiveAt: Long,
        expiresAt: Long?,
    ): ApiResult<PriceComponent>
    suspend fun effectivePrice(itemId: String, priceType: String, asOf: Long?): ApiResult<EffectivePrice>

    suspend fun listBundleComponents(itemId: String): ApiResult<List<BundleComponent>>
    suspend fun addBundleComponent(itemId: String, componentItemId: String, quantity: Int): ApiResult<BundleComponent>
    suspend fun removeBundleComponent(itemId: String, componentItemId: String): ApiResult<Unit>

    suspend fun listProductFeatures(itemId: String): ApiResult<ProductFeatures>
    suspend fun createFeatureCategory(itemId: String, name: String, position: Int): ApiResult<ProductFeatureCategory>
    suspend fun addFeatureValue(
        itemId: String,
        featureCategoryId: String,
        value: String,
        priceDeltaCents: Long,
        position: Int,
    ): ApiResult<ProductFeatureValue>
    suspend fun deleteFeatureCategory(itemId: String, featureCategoryId: String): ApiResult<Unit>

    suspend fun categoryTree(categoryId: String, maxDepth: Int): ApiResult<CategoryTreeNode?>
    suspend fun addCategoryChild(categoryId: String, childCategoryId: String, position: Int): ApiResult<Unit>
    suspend fun moveCategory(categoryId: String, newParentId: String): ApiResult<Unit>
}

@Singleton
class ProductDepthRepositoryImpl @Inject constructor(
    private val api: ProductDepthApi,
    private val errorParser: ApiErrorParser,
) : ProductDepthRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getProductType(itemId: String): ApiResult<String> = withContext(io) {
        readOrDefault(default = "standalone") { api.getProductType(itemId).productType }
    }

    override suspend fun setProductType(itemId: String, productType: String): ApiResult<String> =
        withContext(io) { call { api.setProductType(itemId, SetProductTypeReqDto(productType)).productType } }

    override suspend fun listVariants(itemId: String): ApiResult<List<Variant>> = withContext(io) {
        readOrDefault(default = emptyList()) { api.listVariants(itemId).variants.map { it.toDomain() } }
    }

    override suspend fun createVariant(itemId: String, featureValues: Map<String, String>, skuOverride: String?): ApiResult<Variant> =
        withContext(io) { call { api.createVariant(itemId, CreateVariantReqDto(featureValues, skuOverride?.takeIf { it.isNotBlank() })).toDomain() } }

    override suspend fun deleteVariant(itemId: String, variantId: String): ApiResult<Unit> =
        withContext(io) { call { api.deleteVariant(itemId, variantId) } }

    override suspend fun listPriceComponents(itemId: String, priceType: String?): ApiResult<List<PriceComponent>> =
        withContext(io) { readOrDefault(default = emptyList()) { api.listPriceComponents(itemId, priceType).components.map { it.toDomain() } } }

    override suspend fun addPriceComponent(
        itemId: String,
        priceType: String,
        amountCents: Long,
        currency: String,
        effectiveAt: Long,
        expiresAt: Long?,
    ): ApiResult<PriceComponent> = withContext(io) {
        call { api.addPriceComponent(itemId, AddPriceComponentReqDto(priceType, amountCents, currency, effectiveAt, expiresAt)).toDomain() }
    }

    override suspend fun effectivePrice(itemId: String, priceType: String, asOf: Long?): ApiResult<EffectivePrice> =
        withContext(io) { call { api.getEffectivePrice(itemId, priceType, asOf).toDomain() } }

    override suspend fun listBundleComponents(itemId: String): ApiResult<List<BundleComponent>> =
        withContext(io) { readOrDefault(default = emptyList()) { api.listBundleComponents(itemId).components.map { it.toDomain() } } }

    override suspend fun addBundleComponent(itemId: String, componentItemId: String, quantity: Int): ApiResult<BundleComponent> =
        withContext(io) { call { api.addBundleComponent(itemId, AddBundleComponentReqDto(componentItemId, quantity)).toDomain() } }

    override suspend fun removeBundleComponent(itemId: String, componentItemId: String): ApiResult<Unit> =
        withContext(io) { call { api.removeBundleComponent(itemId, componentItemId) } }

    override suspend fun listProductFeatures(itemId: String): ApiResult<ProductFeatures> = withContext(io) {
        readOrDefault(default = ProductFeatures(itemId, emptyList(), emptyList())) { api.listProductFeatures(itemId).toDomain() }
    }

    override suspend fun createFeatureCategory(itemId: String, name: String, position: Int): ApiResult<ProductFeatureCategory> =
        withContext(io) { call { api.createProductFeatureCategory(itemId, CreateProductFeatureCategoryReqDto(name, position)).toDomain() } }

    override suspend fun addFeatureValue(
        itemId: String,
        featureCategoryId: String,
        value: String,
        priceDeltaCents: Long,
        position: Int,
    ): ApiResult<ProductFeatureValue> = withContext(io) {
        call { api.addProductFeatureValue(itemId, featureCategoryId, AddProductFeatureValueReqDto(value, priceDeltaCents, position)).toDomain() }
    }

    override suspend fun deleteFeatureCategory(itemId: String, featureCategoryId: String): ApiResult<Unit> =
        withContext(io) { call { api.deleteProductFeatureCategory(itemId, featureCategoryId) } }

    override suspend fun categoryTree(categoryId: String, maxDepth: Int): ApiResult<CategoryTreeNode?> = withContext(io) {
        readOrDefault(default = null) { api.getCategoryTree(categoryId, maxDepth).toDomain() }
    }

    override suspend fun addCategoryChild(categoryId: String, childCategoryId: String, position: Int): ApiResult<Unit> =
        withContext(io) { call { api.addCategoryChild(categoryId, AddCategoryChildReqDto(childCategoryId, position)); Unit } }

    override suspend fun moveCategory(categoryId: String, newParentId: String): ApiResult<Unit> =
        withContext(io) { call { api.moveCategory(categoryId, MoveCategoryReqDto(newParentId)); Unit } }

    // ── plumbing ──

    /** Mutation wrapper: HTTP errors become Failure, transport errors NetworkError. */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    /**
     * Read wrapper with degrade-on-flag-off: a 404 or 501 (the two statuses the depth flag raises when
     * disabled) resolves to [default] Success rather than Failure, so reads render an honest-empty state.
     * Other HTTP errors and transport failures propagate normally.
     */
    private suspend fun <T> readOrDefault(default: T, block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == 404 || e.code() == 501) ApiResult.Success(default)
        else ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
