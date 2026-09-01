package com.testlogon.android.core.model.kb

/**
 * KB-AND-1 - domain models for the READ-ONLY Knowledge Base (help centre) surface.
 *
 * core-model has NO Moshi / core-network dependency: these are plain domain types. The wire DTOs (core-network
 * KbDtos) carry the enum-like `status` field as a RAW String; we keep it RAW here too (unknown-safe - an
 * unexpected server token never crashes the UI). The DTO -> domain bridge lives in the :app feature
 * (KbMappers) since core-model cannot depend on core-network.
 *
 * TIME: every timestamp is an EPOCH-seconds [Long] (relative-time formatting happens at the UI). Identity ids
 * (articleId / categoryId) are opaque, required Strings; everything else is nullable / defaulted because the
 * list / search fetch omits detail-only fields (e.g. body on a list row).
 */

/**
 * One article SUMMARY row (list / search result). Carries NO body. [status] is a RAW String
 * (draft / published / expired, unknown-safe). [tags] may be empty. [helpfulCount] / [notHelpfulCount] feed
 * the helpfulness ratio shown in the list.
 */
data class KbArticleSummary(
    val articleId: String,
    val title: String? = null,
    val excerpt: String? = null,
    val status: String? = null,
    val categoryId: String? = null,
    val category: String? = null,
    val tags: List<String> = emptyList(),
    val updatedAt: Long? = null,
    val viewCount: Long = 0L,
    val helpfulCount: Long = 0L,
    val notHelpfulCount: Long = 0L,
)

/**
 * One FULL article (the detail fetch). [body] is PLAIN TEXT already stripped from the server body_html by the
 * mapper (see KbMath.htmlToPlainText) - the Compose renderer never sees raw HTML. [status] is a RAW String.
 */
data class KbArticle(
    val articleId: String,
    val title: String? = null,
    val body: String? = null,
    val excerpt: String? = null,
    val status: String? = null,
    val categoryId: String? = null,
    val category: String? = null,
    val authorSub: String? = null,
    val tags: List<String> = emptyList(),
    val updatedAt: Long? = null,
    val publishedAt: Long? = null,
    val viewCount: Long = 0L,
    val helpfulCount: Long = 0L,
    val notHelpfulCount: Long = 0L,
    val attachments: List<KbAttachment> = emptyList(),
)

/** One attachment on an article. [isOpenable] gates the open CTA (absolute http(s) URL only). */
data class KbAttachment(
    val attachmentId: String? = null,
    val filename: String? = null,
    val contentType: String? = null,
    val sizeBytes: Long? = null,
    val url: String? = null,
)

/** One KB category (flat top-level; the wire tree is not expanded on this READ surface). */
data class KbCategory(
    val categoryId: String,
    val name: String? = null,
    val description: String? = null,
    val sortOrder: Int = 0,
)
