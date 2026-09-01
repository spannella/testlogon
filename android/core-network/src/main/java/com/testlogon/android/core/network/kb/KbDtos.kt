package com.testlogon.android.core.network.kb

import com.squareup.moshi.Json

/**
 * KB-AND-1 - transport DTOs for the Knowledge Base READ surface (mirrors app/routers/kb_articles.py and the
 * web frontend/src/api/endpoints/knowledgeBase.ts Kb* interfaces).
 *
 * CODEGEN NOTE (identical to the AND-371 tickets DTOs): core-network does NOT apply the Moshi KSP codegen
 * plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared Moshi in
 * NetworkModule.provideMoshi. The reflective factory maps property names to JSON keys VERBATIM (Moshi does
 * NOT auto snake_case), so every wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED and NO new dependency is introduced.
 *
 * Required wire keys (article_id / category_id) have NO default, so a missing key surfaces a JsonDataException
 * (folded to Failure by the repository). Everything else is nullable with a null default (or an empty-list
 * default for collections); unknown wire keys are tolerated leniently by the reflective adapter.
 *
 * ENUM-LIKE FIELDS: status is decoded as a RAW String (draft / published / expired) - NOT a Kotlin enum, so
 * an unexpected server value NEVER fails deserialization. TIME fields are EPOCH integers typed as Long.
 *
 * FLAG GATE: the backend returns HTTP 404 for every KB route when knowledge_base_enabled is false; the
 * repository maps that to an empty/degraded result (degrade-on-404) rather than an error surface.
 *
 * WIRE CONTRACT (OpenAPI / frontend-verified; relative paths, NO leading slash):
 *   GET kb/search?q=&limit=&cursor=            -> KbSearchEnvelope     { items, query, cursor }
 *   GET kb/articles?category_id=&limit=&cursor= -> KbArticleListEnvelope { items, cursor, total }
 *   GET kb/articles/{articleId}                -> KbArticleDto (bare object; embeds attachments[])
 *   GET kb/categories                          -> KbCategoryListEnvelope { categories }
 */

/** One attachment on an article (embedded in [KbArticleDto.attachments]). All fields defensive-nullable. */
data class KbAttachmentDto(
    @Json(name = "attachment_id") val attachmentId: String? = null,
    @Json(name = "article_id") val articleId: String? = null,
    @Json(name = "filename") val filename: String? = null,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "size_bytes") val sizeBytes: Long? = null,
    @Json(name = "url") val url: String? = null,
    @Json(name = "uploaded_by") val uploadedBy: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

/**
 * One FULL article (the detail fetch GET kb/articles/{id}). `article_id` is required. `status` is an enum-like
 * raw String (draft / published / expired). The list / search fetch returns [KbArticleSummaryDto] instead
 * (NO body_html). `body_html` is raw server HTML - the presentation layer strips it to plain text for the
 * Compose renderer (see KbMath.htmlToPlainText). Timestamps are EPOCH Longs.
 */
data class KbArticleDto(
    @Json(name = "article_id") val articleId: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "body_html") val bodyHtml: String? = null,
    @Json(name = "excerpt") val excerpt: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "category_id") val categoryId: String? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "author_sub") val authorSub: String? = null,
    @Json(name = "tags") val tags: List<String> = emptyList(),
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "published_at") val publishedAt: Long? = null,
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "view_count") val viewCount: Long? = null,
    @Json(name = "helpful_count") val helpfulCount: Long? = null,
    @Json(name = "not_helpful_count") val notHelpfulCount: Long? = null,
    @Json(name = "attachments") val attachments: List<KbAttachmentDto> = emptyList(),
)

/**
 * One article SUMMARY row (returned by the list + search fetches). Carries NO body_html. `article_id` is
 * required; everything else is nullable / defaulted (a list row may omit detail-only fields).
 */
data class KbArticleSummaryDto(
    @Json(name = "article_id") val articleId: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "excerpt") val excerpt: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "category_id") val categoryId: String? = null,
    @Json(name = "category") val category: String? = null,
    @Json(name = "author_sub") val authorSub: String? = null,
    @Json(name = "tags") val tags: List<String> = emptyList(),
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "published_at") val publishedAt: Long? = null,
    @Json(name = "view_count") val viewCount: Long? = null,
    @Json(name = "helpful_count") val helpfulCount: Long? = null,
    @Json(name = "not_helpful_count") val notHelpfulCount: Long? = null,
)

/**
 * One KB category. `category_id` is required. `children` is a (possibly empty) nested list - the tree is kept
 * on the wire but this READ surface flattens to the top level (children rendered inline is DEFERRED).
 */
data class KbCategoryDto(
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "name") val name: String? = null,
    @Json(name = "parent_id") val parentId: String? = null,
    @Json(name = "path") val path: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "sort_order") val sortOrder: Int? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "children") val children: List<KbCategoryDto> = emptyList(),
)

/** Envelope for GET kb/articles (list). Carries items + cursor + total. */
data class KbArticleListEnvelope(
    @Json(name = "items") val items: List<KbArticleSummaryDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
    @Json(name = "total") val total: Int? = null,
)

/** Envelope for GET kb/search. Echoes the query and carries the summary items + a next cursor. */
data class KbSearchEnvelope(
    @Json(name = "items") val items: List<KbArticleSummaryDto> = emptyList(),
    @Json(name = "query") val query: String? = null,
    @Json(name = "cursor") val cursor: String? = null,
)

/** Envelope for GET kb/categories. */
data class KbCategoryListEnvelope(
    @Json(name = "categories") val categories: List<KbCategoryDto> = emptyList(),
)

/**
 * KB-AND-1 - documented constants for the enum-like `status` wire field. Plain String constants (NOT a Kotlin
 * enum) so an unexpected server value never fails deserialization; callers compare against these names but
 * tolerate any other value.
 */
object KbConstants {
    object ArticleStatus {
        const val DRAFT = "draft"
        const val PUBLISHED = "published"
        const val EXPIRED = "expired"
    }
}
