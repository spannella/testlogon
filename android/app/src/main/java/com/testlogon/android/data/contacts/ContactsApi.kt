package com.testlogon.android.data.contacts

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * Feature 1 (Contacts hub) — the saved-contacts address book + "people you may know"
 * suggestions, backed by the mounted backend router `app/routers/contacts.py`.
 *
 * All paths are RELATIVE (no leading slash) so the shared authenticated Retrofit's
 * base URL + cookie/CSRF interceptors apply, exactly like every other *Api in the app.
 */
interface ContactsApi {

    /** GET /ui/contacts — favorites-first saved contacts for the signed-in user. */
    @GET("ui/contacts")
    suspend fun listContacts(): ContactsListDto

    /** POST /ui/contacts — save a user by id; server fills display_name/photo from their profile. */
    @POST("ui/contacts")
    suspend fun addContact(@Body body: AddContactDto): ContactEntryDto

    /** PATCH /ui/contacts/{contactId} — toggle is_favorite / is_blocked. */
    @PATCH("ui/contacts/{contactId}")
    suspend fun updateContact(
        @Path("contactId") contactId: String,
        @Body body: UpdateContactDto,
    ): ContactEntryDto

    /** DELETE /ui/contacts/{contactId} — remove a saved contact (204). */
    @DELETE("ui/contacts/{contactId}")
    suspend fun deleteContact(@Path("contactId") contactId: String): Response<Unit>

    /**
     * GET /ui/contacts/suggestions — "people you may know": mutuals + follow graph +
     * recent DM peers, excluding already-saved contacts and self. Read-only.
     */
    @GET("ui/contacts/suggestions")
    suspend fun suggestions(): SuggestionsListDto
}

@JsonClass(generateAdapter = true)
data class AddContactDto(
    @Json(name = "user_id") val userId: String,
)

@JsonClass(generateAdapter = true)
data class UpdateContactDto(
    @Json(name = "is_favorite") val isFavorite: Boolean? = null,
    @Json(name = "is_blocked") val isBlocked: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class ContactsListDto(
    @Json(name = "contacts") val contacts: List<ContactEntryDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class ContactEntryDto(
    @Json(name = "owner_id") val ownerId: String,
    @Json(name = "contact_id") val contactId: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "is_favorite") val isFavorite: Boolean = false,
    @Json(name = "is_blocked") val isBlocked: Boolean = false,
    @Json(name = "added_at") val addedAt: String = "",
)

@JsonClass(generateAdapter = true)
data class SuggestionsListDto(
    @Json(name = "suggestions") val suggestions: List<SuggestionCardDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SuggestionCardDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "hint") val hint: String = "",
    @Json(name = "mutual_count") val mutualCount: Int = 0,
    @Json(name = "source") val source: String = "",
)
