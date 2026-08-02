package com.testlogon.android.data.stories

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-199 / AND-200 — wire DTOs for the Stories surface.
 *
 * Verified against the staged web reference (the OpenAPI 200 schema for these routes is empty, so the
 * frontend types are authoritative):
 *  - reference/src/api/types.ts: Story, StoryBarEntry, StoryBarResp, UserStoriesResp, StoryViewResp.
 *  - reference/src/api/endpoints/stories.ts: getStoryBar (GET /ui/stories/bar),
 *    getUserStories (GET /ui/stories/user/{user_id}), recordStoryView (POST /ui/stories/{story_id}/view).
 *
 * Only the server-required ids are mandatory; everything else is defaulted so a missing/unknown field
 * never crashes decoding (Moshi ignores unknown keys). Mapping to the redaction-safe domain happens in
 * StoriesDomain.kt — repositories never return raw DTOs.
 */

// ---- GET /ui/stories/bar -> StoryBarResp { bar: StoryBarEntry[] } ----

@JsonClass(generateAdapter = true)
data class StoryBarRespDto(
    @Json(name = "bar") val bar: List<StoryBarEntryDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class StoryBarEntryDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "latest_story_id") val latestStoryId: String = "",
    @Json(name = "latest_media_url") val latestMediaUrl: String? = null,
    @Json(name = "story_count") val storyCount: Int = 0,
    @Json(name = "has_unseen") val hasUnseen: Boolean = false,
    @Json(name = "is_own") val isOwn: Boolean = false,
)

// ---- GET /ui/stories/user/{user_id} -> UserStoriesResp { stories: Story[] } ----

@JsonClass(generateAdapter = true)
data class UserStoriesRespDto(
    @Json(name = "stories") val stories: List<StoryDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class StoryDto(
    @Json(name = "story_id") val storyId: String,
    @Json(name = "author_id") val authorId: String = "",
    @Json(name = "media_type") val mediaType: String? = null,
    @Json(name = "media_url") val mediaUrl: String = "",
    @Json(name = "text_overlay") val textOverlay: String? = null,
    @Json(name = "link_url") val linkUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "expires_at") val expiresAt: Long = 0,
    @Json(name = "view_count") val viewCount: Int = 0,
    @Json(name = "highlighted") val highlighted: Boolean = false,
)

// ---- POST /ui/stories/{story_id}/view -> StoryViewResp { ok, already_viewed } ----

@JsonClass(generateAdapter = true)
data class StoryViewRespDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "already_viewed") val alreadyViewed: Boolean = false,
)

// ---- POST /ui/stories -> create a story ----
// PAR-01 — wire DTOs for creating a story. IMAGE-first (video out of scope for v1); optional overlay
// text + a tap-through link. Nullable optionals so Moshi OMITS them from the JSON body when null,
// matching the backend contract (omit null optionals).

@JsonClass(generateAdapter = true)
data class CreateStoryReqDto(
    @Json(name = "media_type") val mediaType: String,
    @Json(name = "media_url") val mediaUrl: String,
    @Json(name = "text_overlay") val textOverlay: String? = null,
    @Json(name = "link_url") val linkUrl: String? = null,
    @Json(name = "link_label") val linkLabel: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
)

@JsonClass(generateAdapter = true)
data class CreateStoryRespDto(
    @Json(name = "story_id") val storyId: String,
    @Json(name = "expires_at") val expiresAt: Long = 0,
    @Json(name = "media_url") val mediaUrl: String = "",
    @Json(name = "created_at") val createdAt: String? = null,
)

// ---- PAR-16 — Story Highlights wire DTOs ----
// Verified against the live backend (app/routers/stories.py + app/services/stories.py) and the iOS
// CoreModel/StoriesDTOs.swift reference. The GET response is an OBJECT with a top-level "groups" key
// (NOT a bare array). Each group carries highlight_group_id / title / cover_url / created_at + its
// "stories" array (each element is the same wire shape as [StoryDto], reused here). Nullable optionals
// so Moshi OMITS them from request bodies when null (backend contract: omit null optionals).

// GET /ui/stories/highlights/{user_id} -> { "groups": HighlightGroup[] }

@JsonClass(generateAdapter = true)
data class UserHighlightsRespDto(
    @Json(name = "groups") val groups: List<HighlightGroupDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class HighlightGroupDto(
    @Json(name = "highlight_group_id") val highlightGroupId: String,
    @Json(name = "title") val title: String = "",
    @Json(name = "cover_url") val coverUrl: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "stories") val stories: List<StoryDto> = emptyList(),
)

// POST /ui/stories/highlights/groups (201) — body { title, cover_url? } -> { highlight_group_id, title, created_at }

@JsonClass(generateAdapter = true)
data class CreateHighlightGroupReqDto(
    @Json(name = "title") val title: String,
    @Json(name = "cover_url") val coverUrl: String? = null,
)

@JsonClass(generateAdapter = true)
data class CreateHighlightGroupRespDto(
    @Json(name = "highlight_group_id") val highlightGroupId: String,
    @Json(name = "title") val title: String = "",
    @Json(name = "created_at") val createdAt: String? = null,
)

// POST /ui/stories/{story_id}/highlight — body { group_id? } (omit = default/ungrouped) -> { ok }
// DELETE /ui/stories/{story_id}/highlight -> { ok }; DELETE .../groups/{group_id} -> { ok }

@JsonClass(generateAdapter = true)
data class AddStoryToHighlightReqDto(
    @Json(name = "group_id") val groupId: String? = null,
)

@JsonClass(generateAdapter = true)
data class HighlightActionRespDto(
    @Json(name = "ok") val ok: Boolean = true,
)
