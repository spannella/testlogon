package com.testlogon.android.core.network.customemojis

import com.squareup.moshi.Json

/**
 * Custom-emoji transport DTOs (web parity: src/api/endpoints/customEmojis.ts + src/pages/settings/CustomEmojisPage.tsx).
 *
 * CODEGEN NOTE: core-network has NO Moshi KSP codegen; these decode via the reflective KotlinJsonAdapterFactory on
 * the shared Moshi. Every wire key is pinned with @Json(name = ...). @JsonClass is intentionally OMITTED.
 *
 * WIRE CONTRACT (verified against app/routers/custom_emojis.py, prefix /ui/emojis/custom; relative paths):
 *   GET    ui/emojis/custom            -> { emojis:[CustomEmojiDto], personal_count, global_count }
 *   POST   ui/emojis/custom (multipart: shortcode,name,alt_text,category,file) -> CustomEmojiDto (201)
 *   DELETE ui/emojis/custom/{emoji_id} -> { ok, emoji_id }
 *
 * `created_at` is EPOCH SECONDS (Long). `owner_scope` is e.g. "USER#<sub>" for personal vs "GLOBAL" for global;
 * the settings screen shows only the caller's personal emojis (owner_scope startsWith "USER#").
 */

data class CustomEmojiDto(
    @Json(name = "emoji_id") val emojiId: String = "",
    @Json(name = "shortcode") val shortcode: String = "",
    @Json(name = "name") val name: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "alt_text") val altText: String? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "owner_scope") val ownerScope: String? = null,
    @Json(name = "created_by") val createdBy: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "file_size_bytes") val fileSizeBytes: Long? = null,
)

data class CustomEmojiListDto(
    @Json(name = "emojis") val emojis: List<CustomEmojiDto> = emptyList(),
    @Json(name = "personal_count") val personalCount: Int = 0,
    @Json(name = "global_count") val globalCount: Int = 0,
)

data class DeleteEmojiResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "emoji_id") val emojiId: String? = null,
)
