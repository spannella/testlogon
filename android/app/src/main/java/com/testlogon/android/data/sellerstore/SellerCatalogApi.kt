package com.testlogon.android.data.sellerstore

import com.testlogon.android.data.catalog.CatalogCategoryDto
import com.testlogon.android.data.catalog.CatalogItemDto
import com.testlogon.android.data.catalog.OkRespCatalogDto
import okhttp3.MultipartBody
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.Multipart
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * ECOM (seller store) — Retrofit interface for seller-side catalog CRUD (the buyer-facing reads live on
 * [com.testlogon.android.data.catalog.CatalogApi]). Session cookies + X-CSRF-Token are attached by the
 * core-network interceptor chain. Image upload is a single authenticated multipart POST with one part
 * named `file` (mirrors the profile-photo uploader).
 *
 * Verified contract (backend app/routers/catalog.py; prod OpenAPI):
 *  - POST   ui/catalog/categories                                      -> CatalogCategoryOut
 *  - DELETE ui/catalog/categories/{category_id}?cascade=               -> { ok:true }
 *  - POST   ui/catalog/categories/{category_id}/items                  -> CatalogItemOut
 *  - PATCH  ui/catalog/categories/{category_id}/items/{item_id}        -> CatalogItemOut
 *  - DELETE ui/catalog/categories/{category_id}/items/{item_id}        -> { ok:true }
 *  - POST   ui/catalog/categories/{category_id}/items/{item_id}/images/upload (multipart) -> CatalogItemOut
 */
interface SellerCatalogApi {

    @POST("ui/catalog/categories")
    suspend fun createCategory(@Body body: SellerCategoryCreateDto): CatalogCategoryDto

    @DELETE("ui/catalog/categories/{categoryId}")
    suspend fun deleteCategory(
        @Path("categoryId") categoryId: String,
        @Query("cascade") cascade: Boolean = true,
    ): OkRespCatalogDto

    @POST("ui/catalog/categories/{categoryId}/items")
    suspend fun createItem(
        @Path("categoryId") categoryId: String,
        @Body body: SellerItemCreateDto,
    ): CatalogItemDto

    @PATCH("ui/catalog/categories/{categoryId}/items/{itemId}")
    suspend fun updateItem(
        @Path("categoryId") categoryId: String,
        @Path("itemId") itemId: String,
        @Body body: SellerItemPatchDto,
    ): CatalogItemDto

    @DELETE("ui/catalog/categories/{categoryId}/items/{itemId}")
    suspend fun deleteItem(
        @Path("categoryId") categoryId: String,
        @Path("itemId") itemId: String,
    ): OkRespCatalogDto

    @Multipart
    @POST("ui/catalog/categories/{categoryId}/items/{itemId}/images/upload")
    suspend fun uploadItemImage(
        @Path("categoryId") categoryId: String,
        @Path("itemId") itemId: String,
        @Part file: MultipartBody.Part,
    ): CatalogItemDto
}
