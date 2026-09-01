package com.testlogon.android.data.sellerstore

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * ECOM (catalog depth) — Retrofit interface for the advanced seller product endpoints (OFBiz catalog
 * depth). The basic seller CRUD lives on [SellerCatalogApi]; these are the depth extensions
 * (variants / price components / bundle components / per-item product features / category tree / bulk).
 * All paths are relative (resolve against the shared Retrofit base URL); session cookies + Bearer +
 * X-CSRF-Token are attached by the core-network interceptor chain.
 *
 * Every route is feature-gated on the backend (S.product_depth_enabled): reads answer 404/501 when the
 * flag is off — the repository degrades those to an honest-empty result. Mutations surface the error.
 *
 * Verified contract (app/routers/catalog.py; frontend/src/api/endpoints/productDepth.ts):
 *  - GET/POST    ui/catalog/items/{id}/product-type
 *  - GET/POST/DELETE  ui/catalog/items/{id}/variants[/{variant_id}]
 *  - GET/POST/PUT ui/catalog/items/{id}/price-components
 *  - GET         ui/catalog/items/{id}/effective-price
 *  - GET/POST/DELETE  ui/catalog/items/{id}/bundle-components[/{component_id}]
 *  - GET/POST/DELETE  ui/catalog/items/{id}/product-features[/{fc_id}[/values]]
 *  - GET         ui/catalog/categories/{id}/tree | /breadcrumb
 *  - POST        ui/catalog/categories/{id}/children ; PATCH .../move
 *  - POST        ui/catalog/items/bulk-delete | bulk-update
 */
interface ProductDepthApi {

    // ── product type ──
    @GET("ui/catalog/items/{itemId}/product-type")
    suspend fun getProductType(@Path("itemId") itemId: String): ProductTypeRespDto

    @POST("ui/catalog/items/{itemId}/product-type")
    suspend fun setProductType(
        @Path("itemId") itemId: String,
        @Body body: SetProductTypeReqDto,
    ): ProductTypeRespDto

    // ── variants ──
    @GET("ui/catalog/items/{itemId}/variants")
    suspend fun listVariants(
        @Path("itemId") itemId: String,
        @Query("limit") limit: Int = 100,
    ): VariantListDto

    @POST("ui/catalog/items/{itemId}/variants")
    suspend fun createVariant(
        @Path("itemId") itemId: String,
        @Body body: CreateVariantReqDto,
    ): VariantDto

    @DELETE("ui/catalog/items/{itemId}/variants/{variantId}")
    suspend fun deleteVariant(
        @Path("itemId") itemId: String,
        @Path("variantId") variantId: String,
    )

    // ── price components ──
    @GET("ui/catalog/items/{itemId}/price-components")
    suspend fun listPriceComponents(
        @Path("itemId") itemId: String,
        @Query("price_type") priceType: String? = null,
    ): PriceComponentListDto

    @POST("ui/catalog/items/{itemId}/price-components")
    suspend fun addPriceComponent(
        @Path("itemId") itemId: String,
        @Body body: AddPriceComponentReqDto,
    ): PriceComponentDto

    @GET("ui/catalog/items/{itemId}/effective-price")
    suspend fun getEffectivePrice(
        @Path("itemId") itemId: String,
        @Query("price_type") priceType: String = "DEFAULT",
        @Query("as_of") asOf: Long? = null,
    ): EffectivePriceDto

    // ── bundle components ──
    @GET("ui/catalog/items/{itemId}/bundle-components")
    suspend fun listBundleComponents(@Path("itemId") itemId: String): BundleComponentListDto

    @POST("ui/catalog/items/{itemId}/bundle-components")
    suspend fun addBundleComponent(
        @Path("itemId") itemId: String,
        @Body body: AddBundleComponentReqDto,
    ): BundleComponentDto

    @DELETE("ui/catalog/items/{itemId}/bundle-components/{componentItemId}")
    suspend fun removeBundleComponent(
        @Path("itemId") itemId: String,
        @Path("componentItemId") componentItemId: String,
    )

    // ── per-item product features ──
    @GET("ui/catalog/items/{itemId}/product-features")
    suspend fun listProductFeatures(@Path("itemId") itemId: String): ProductFeaturesDto

    @POST("ui/catalog/items/{itemId}/product-features")
    suspend fun createProductFeatureCategory(
        @Path("itemId") itemId: String,
        @Body body: CreateProductFeatureCategoryReqDto,
    ): ProductFeatureCategoryDto

    @POST("ui/catalog/items/{itemId}/product-features/{featureCategoryId}/values")
    suspend fun addProductFeatureValue(
        @Path("itemId") itemId: String,
        @Path("featureCategoryId") featureCategoryId: String,
        @Body body: AddProductFeatureValueReqDto,
    ): ProductFeatureValueDto

    @DELETE("ui/catalog/items/{itemId}/product-features/{featureCategoryId}")
    suspend fun deleteProductFeatureCategory(
        @Path("itemId") itemId: String,
        @Path("featureCategoryId") featureCategoryId: String,
    )

    // ── category tree ──
    @GET("ui/catalog/categories/{categoryId}/tree")
    suspend fun getCategoryTree(
        @Path("categoryId") categoryId: String,
        @Query("max_depth") maxDepth: Int = 5,
    ): CategoryTreeNodeDto

    @GET("ui/catalog/categories/{categoryId}/breadcrumb")
    suspend fun getCategoryBreadcrumb(@Path("categoryId") categoryId: String): CategoryBreadcrumbDto

    @POST("ui/catalog/categories/{categoryId}/children")
    suspend fun addCategoryChild(
        @Path("categoryId") categoryId: String,
        @Body body: AddCategoryChildReqDto,
    ): Map<String, Any?>

    @PATCH("ui/catalog/categories/{categoryId}/move")
    suspend fun moveCategory(
        @Path("categoryId") categoryId: String,
        @Body body: MoveCategoryReqDto,
    ): Map<String, Any?>

    // ── bulk ──
    @POST("ui/catalog/items/bulk-delete")
    suspend fun bulkDelete(@Body body: BulkDeleteReqDto): BulkResultDto

    @POST("ui/catalog/items/bulk-update")
    suspend fun bulkUpdate(@Body body: BulkUpdateReqDto): BulkResultDto

    // ── PUT set price components (replace-all for one price type) ──
    @PUT("ui/catalog/items/{itemId}/price-components")
    suspend fun setPriceComponents(
        @Path("itemId") itemId: String,
        @Body body: SetPriceComponentsReqDto,
    ): SetPriceComponentsRespDto
}

@com.squareup.moshi.JsonClass(generateAdapter = true)
data class SetPriceComponentsReqDto(
    @com.squareup.moshi.Json(name = "price_type") val priceType: String,
    @com.squareup.moshi.Json(name = "components") val components: List<AddPriceComponentReqDto> = emptyList(),
)

@com.squareup.moshi.JsonClass(generateAdapter = true)
data class SetPriceComponentsRespDto(
    @com.squareup.moshi.Json(name = "item_id") val itemId: String,
    @com.squareup.moshi.Json(name = "price_type") val priceType: String,
    @com.squareup.moshi.Json(name = "components") val components: List<PriceComponentDto> = emptyList(),
)
