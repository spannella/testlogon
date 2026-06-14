package com.testlogon.android.data.address

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT

/**
 * AND-214 — Retrofit interface + DTOs for the saved-address surface used by the checkout
 * address/shipping step.
 *
 * Verified contract (reference/openapi.index.txt lines 620-625; components.schemas.AddressIn /
 * AddressOut / AddressPrimaryReq; reference/src/api/endpoints/profile.ts getAddresses / createAddress /
 * setPrimaryAddress; reference/src/api/types.ts AddressIn / Address):
 *  - GET ui/addresses                 -> bare JSON array of AddressOut (NOT a wrapped envelope)
 *  - POST ui/addresses  req=AddressIn -> 200 AddressOut (note: 200, not 201)
 *  - PUT ui/addresses/primary  req=AddressPrimaryReq{address_id} -> 200 AddressOut
 *
 * SCOPE / GAP (spec AND-214 sections 1, 5, 16): the backend exposes NO shipping-quote /
 * shipping-option / apply-to-checkout-session endpoint and NO ShippingOption schema. The
 * checkout-session and cart-purchase surfaces carry no shipping_address_id / shipping_option_id /
 * shipping totals. The only buildable "apply" today is marking a primary mailing address
 * (PUT ui/addresses/primary), which the downstream payment step can read. The fictitious
 * shipping/quote + checkout shipping endpoints from the original draft are intentionally absent.
 *
 * Paths are relative; session cookies, Authorization: Bearer and X-CSRF-Token are attached by the
 * core-network interceptor chain. The GET is idempotent; the POST/PUT mutations are never auto-retried.
 */
interface AddressApi {

    @GET("ui/addresses")
    suspend fun listAddresses(): List<AddressOutDto>

    @POST("ui/addresses")
    suspend fun createAddress(@Body body: AddressInDto): AddressOutDto

    @PUT("ui/addresses/primary")
    suspend fun setPrimaryAddress(@Body body: AddressPrimaryReqDto): AddressOutDto
}

/**
 * Request body (schema AddressIn). ALL fields are optional server-side; the web form requires only
 * `line1` client-side (zod min(1)). There is NO full_name / region / phone / is_default.
 */
@JsonClass(generateAdapter = true)
data class AddressInDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "line1") val line1: String? = null,
    @Json(name = "line2") val line2: String? = null,
    @Json(name = "city") val city: String? = null,
    @Json(name = "state") val state: String? = null,
    @Json(name = "postal_code") val postalCode: String? = null,
    @Json(name = "country") val country: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "notes") val notes: String? = null,
)

/**
 * Response body (schema AddressOut). The only "default" notion is `is_primary_mailing`; created_at /
 * updated_at are integer epoch seconds.
 */
@JsonClass(generateAdapter = true)
data class AddressOutDto(
    @Json(name = "address_id") val addressId: String,
    @Json(name = "name") val name: String? = null,
    @Json(name = "line1") val line1: String? = null,
    @Json(name = "line2") val line2: String? = null,
    @Json(name = "city") val city: String? = null,
    @Json(name = "state") val state: String? = null,
    @Json(name = "postal_code") val postalCode: String? = null,
    @Json(name = "country") val country: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "notes") val notes: String? = null,
    @Json(name = "is_primary_mailing") val isPrimaryMailing: Boolean = false,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** Set-primary request body (schema AddressPrimaryReq). required: address_id. */
@JsonClass(generateAdapter = true)
data class AddressPrimaryReqDto(
    @Json(name = "address_id") val addressId: String,
)
