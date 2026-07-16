package com.testlogon.android.data.profile

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-070 — wire DTOs for the profile surface.
 *
 * Field names are taken one-to-one from the verified web contract (reference: src/api/types.ts:
 * Profile, CrossUserProfileResp, PublicProfileData, MailingAddress, Language) and the OpenAPI index
 * (the 200 bodies are untyped, so the TS types are authoritative). Unknown JSON keys are ignored by
 * Moshi. Uses codegen adapters, consistent with the dashboard / auth DTOs.
 */

/** GET /ui/profile and PATCH /ui/profile both return the envelope { "profile": Profile }. */
@JsonClass(generateAdapter = true)
data class ProfileEnvelopeDto(
    @Json(name = "profile") val profile: ProfileDto = ProfileDto(),
)

/** The `Profile` shape. Every field is optional in the contract. */
@JsonClass(generateAdapter = true)
data class ProfileDto(
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "first_name") val firstName: String? = null,
    @Json(name = "middle_name") val middleName: String? = null,
    @Json(name = "last_name") val lastName: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "birthday") val birthday: String? = null,
    @Json(name = "gender") val gender: String? = null,
    @Json(name = "location") val location: String? = null,
    @Json(name = "displayed_email") val displayedEmail: String? = null,
    @Json(name = "displayed_telephone_number") val displayedTelephoneNumber: String? = null,
    @Json(name = "mailing_address") val mailingAddress: MailingAddressDto? = null,
    @Json(name = "languages") val languages: List<LanguageDto>? = null,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "cover_photo_url") val coverPhotoUrl: String? = null,
)

/** reference: src/api/types.ts: MailingAddress (all fields optional). */
@JsonClass(generateAdapter = true)
data class MailingAddressDto(
    @Json(name = "line1") val line1: String? = null,
    @Json(name = "line2") val line2: String? = null,
    @Json(name = "city") val city: String? = null,
    @Json(name = "state") val state: String? = null,
    @Json(name = "postal_code") val postalCode: String? = null,
    @Json(name = "country") val country: String? = null,
)

/** reference: src/api/types.ts: Language (name + level both required). */
@JsonClass(generateAdapter = true)
data class LanguageDto(
    @Json(name = "name") val name: String? = null,
    @Json(name = "level") val level: String? = null,
)

/** GET /ui/profiles/{identifier} -> CrossUserProfileResp. */
@JsonClass(generateAdapter = true)
data class CrossUserProfileDto(
    @Json(name = "identifier") val identifier: String,
    @Json(name = "canonical_identifier") val canonicalIdentifier: String? = null,
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "audience") val audience: String,
    @Json(name = "profile") val profile: ProfileDto = ProfileDto(),
)

/** GET /ui/profile/public/{identifier} -> PublicProfileData. `created_at` is epoch SECONDS. */
@JsonClass(generateAdapter = true)
data class PublicProfileDataDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "identifier") val identifier: String,
    @Json(name = "canonical_identifier") val canonicalIdentifier: String? = null,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "location") val location: String? = null,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "cover_photo_url") val coverPhotoUrl: String? = null,
    @Json(name = "follower_count") val followerCount: Int = 0,
    @Json(name = "following_count") val followingCount: Int = 0,
    @Json(name = "post_count") val postCount: Int = 0,
    @Json(name = "is_following") val isFollowing: Boolean = false,
    @Json(name = "is_followed_by") val isFollowedBy: Boolean = false,
    @Json(name = "is_mutual") val isMutual: Boolean = false,
    @Json(name = "has_subscription_plans") val hasSubscriptionPlans: Boolean = false,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "discoverability") val discoverability: String? = null,
    // TIPX-C2 - aggregate direct-creator tip support in cents.
    @Json(name = "tip_total_cents") val tipTotalCents: Int = 0,
)

/**
 * PATCH /ui/profile request body (schema ProfilePatchReq). Only the AND-072 editable basics are
 * modeled; null fields are omitted by Moshi so the partial update carries only changed fields.
 * There is no `bio` (use `description`) and no `links` field in the schema.
 */
@JsonClass(generateAdapter = true)
data class ProfilePatchReqDto(
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "location") val location: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "first_name") val firstName: String? = null,
    @Json(name = "middle_name") val middleName: String? = null,
    @Json(name = "last_name") val lastName: String? = null,
)

/**
 * POST /ui/profile/photos/{kind}/upload response. Shape from the web reference
 * (api.upload<{ profile: Profile; url: string }>); the OpenAPI 200 is untyped, so fields are
 * tolerated as nullable defensively.
 */
@JsonClass(generateAdapter = true)
data class ProfilePhotoUploadRespDto(
    @Json(name = "profile") val profile: ProfileDto? = null,
    @Json(name = "url") val url: String? = null,
)
