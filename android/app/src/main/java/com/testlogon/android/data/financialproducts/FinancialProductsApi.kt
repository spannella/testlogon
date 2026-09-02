package com.testlogon.android.data.financialproducts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the CUS-004 Financial Products + Collections surface (router
 * app/routers/financial_products.py, prefix `/ui/financial-products`, all `require_admin_or_root`).
 *
 * Mirrors the web `frontend/src/api/endpoints/bankCustomers.ts` (CUS-004 section). The whole router
 * 404s unless BOTH `open_bank_project_enabled` AND `financial_products_enabled` are set (`_require_flag`),
 * so the repo degrades-on-404 (reads honest-empty). Admin-gated: a non-admin gets 403.
 *
 * Route-order note (server): collections + attribute sub-routes are declared BEFORE `/{product_code}` to
 * avoid capture; the client just calls the concrete paths. Session cookie / Bearer / X-CSRF-Token are
 * attached by the shared interceptors; paths are relative (base URL carries the trailing slash).
 * Timestamps are epoch-SECONDS (Long).
 */
interface FinancialProductsApi {

    // ---- Products ----

    @GET("ui/financial-products")
    suspend fun listProducts(
        @Query("category") category: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
    ): FinancialProductListDto

    @GET("ui/financial-products/{productCode}")
    suspend fun getProduct(@Path("productCode") productCode: String): FinancialProductDto

    @POST("ui/financial-products")
    suspend fun createProduct(@Body body: FinancialProductCreateDto): FinancialProductDto

    @PATCH("ui/financial-products/{productCode}")
    suspend fun patchProduct(
        @Path("productCode") productCode: String,
        @Body body: FinancialProductPatchDto,
    ): FinancialProductDto

    // ---- Product attributes ----

    @GET("ui/financial-products/{productCode}/attributes")
    suspend fun listAttributes(@Path("productCode") productCode: String): ProductAttributeListDto

    @PUT("ui/financial-products/{productCode}/attributes")
    suspend fun setAttribute(
        @Path("productCode") productCode: String,
        @Body body: ProductAttributeSetDto,
    ): ProductAttributeDto

    @DELETE("ui/financial-products/{productCode}/attributes/{attributeId}")
    suspend fun deleteAttribute(
        @Path("productCode") productCode: String,
        @Path("attributeId") attributeId: String,
    )

    // ---- Collections ----

    @GET("ui/financial-products/collections")
    suspend fun listCollections(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
    ): ProductCollectionListDto

    @GET("ui/financial-products/collections/{collectionCode}")
    suspend fun getCollection(@Path("collectionCode") collectionCode: String): ProductCollectionDto

    /** Upsert (PUT) a collection: create-or-replace by code. Used for the create-collection form. */
    @PUT("ui/financial-products/collections/{collectionCode}")
    suspend fun upsertCollection(
        @Path("collectionCode") collectionCode: String,
        @Body body: ProductCollectionUpsertDto,
    ): ProductCollectionDto

    @POST("ui/financial-products/collections/{collectionCode}/members")
    suspend fun addToCollection(
        @Path("collectionCode") collectionCode: String,
        @Body body: ProductCollectionMemberDto,
    ): ProductCollectionDto

    @DELETE("ui/financial-products/collections/{collectionCode}/members/{productCode}")
    suspend fun removeFromCollection(
        @Path("collectionCode") collectionCode: String,
        @Path("productCode") productCode: String,
    ): ProductCollectionDto

    companion object {
        const val DEFAULT_LIMIT = 50
    }
}

// ---- Product DTOs ----

@JsonClass(generateAdapter = true)
data class FinancialProductDto(
    @Json(name = "product_code") val productCode: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "parent_product_code") val parentProductCode: String? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "family") val family: String? = null,
    @Json(name = "super_family") val superFamily: String? = null,
    @Json(name = "more_info_url") val moreInfoUrl: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "version") val version: Int = 0,
)

@JsonClass(generateAdapter = true)
data class FinancialProductListDto(
    @Json(name = "items") val items: List<FinancialProductDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class FinancialProductCreateDto(
    @Json(name = "product_code") val productCode: String,
    @Json(name = "name") val name: String,
    @Json(name = "parent_product_code") val parentProductCode: String? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "family") val family: String? = null,
    @Json(name = "super_family") val superFamily: String? = null,
    @Json(name = "more_info_url") val moreInfoUrl: String? = null,
    @Json(name = "description") val description: String? = null,
)

@JsonClass(generateAdapter = true)
data class FinancialProductPatchDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "parent_product_code") val parentProductCode: String? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "family") val family: String? = null,
    @Json(name = "super_family") val superFamily: String? = null,
    @Json(name = "more_info_url") val moreInfoUrl: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "expected_version") val expectedVersion: Int,
)

// ---- Attribute DTOs ----

@JsonClass(generateAdapter = true)
data class ProductAttributeDto(
    @Json(name = "attribute_id") val attributeId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "type") val type: String = "",
    @Json(name = "value") val value: String = "",
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class ProductAttributeListDto(
    @Json(name = "attributes") val attributes: List<ProductAttributeDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class ProductAttributeSetDto(
    @Json(name = "name") val name: String,
    @Json(name = "type") val type: String,
    @Json(name = "value") val value: String,
)

// ---- Collection DTOs ----

@JsonClass(generateAdapter = true)
data class ProductCollectionDto(
    @Json(name = "collection_code") val collectionCode: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "product_codes") val productCodes: List<String> = emptyList(),
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class ProductCollectionListDto(
    @Json(name = "items") val items: List<ProductCollectionDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class ProductCollectionUpsertDto(
    @Json(name = "name") val name: String,
    @Json(name = "product_codes") val productCodes: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class ProductCollectionMemberDto(
    @Json(name = "product_code") val productCode: String,
)
