package com.testlogon.android.feature.knowledgebase.data

import com.testlogon.android.core.model.kb.KbArticle
import com.testlogon.android.core.model.kb.KbArticleSummary
import com.testlogon.android.core.model.kb.KbAttachment
import com.testlogon.android.core.model.kb.KbCategory
import com.testlogon.android.core.network.kb.KbArticleDto
import com.testlogon.android.core.network.kb.KbArticleSummaryDto
import com.testlogon.android.core.network.kb.KbAttachmentDto
import com.testlogon.android.core.network.kb.KbCategoryDto
import com.testlogon.android.data.knowledgebase.KbMath

/**
 * KB-AND-1 - DTO -> domain mappers for the READ-ONLY Knowledge Base surface.
 *
 * PLACEMENT: core-model has NO dependency on core-network's DTOs (and core-network has no domain dep), so the
 * bridging mapper lives here in the :app feature, which depends on BOTH (mirrors AND-372 TicketMappers).
 *
 * Key transforms:
 *  - the enum-like `status` field is kept RAW (unknown-safe - no enum parse, never throws).
 *  - the full article's raw body_html is stripped to PLAIN TEXT here (KbMath.htmlToPlainText) so the Compose
 *    renderer never sees markup.
 *  - counters (view / helpful / not_helpful) default to 0 when the wire omits them.
 *  - timestamps pass through as EPOCH-seconds Longs.
 */
fun KbArticleSummaryDto.toDomain(): KbArticleSummary = KbArticleSummary(
    articleId = articleId,
    title = title,
    excerpt = excerpt,
    status = status,
    categoryId = categoryId,
    category = category,
    tags = tags,
    updatedAt = updatedAt,
    viewCount = viewCount ?: 0L,
    helpfulCount = helpfulCount ?: 0L,
    notHelpfulCount = notHelpfulCount ?: 0L,
)

fun KbArticleDto.toDomain(): KbArticle = KbArticle(
    articleId = articleId,
    title = title,
    body = KbMath.htmlToPlainText(bodyHtml),
    excerpt = excerpt,
    status = status,
    categoryId = categoryId,
    category = category,
    authorSub = authorSub,
    tags = tags,
    updatedAt = updatedAt,
    publishedAt = publishedAt,
    viewCount = viewCount ?: 0L,
    helpfulCount = helpfulCount ?: 0L,
    notHelpfulCount = notHelpfulCount ?: 0L,
    attachments = attachments.map { it.toDomain() },
)

fun KbAttachmentDto.toDomain(): KbAttachment = KbAttachment(
    attachmentId = attachmentId,
    filename = filename,
    contentType = contentType,
    sizeBytes = sizeBytes,
    url = url,
)

fun KbCategoryDto.toDomain(): KbCategory = KbCategory(
    categoryId = categoryId,
    name = name,
    description = description,
    sortOrder = sortOrder ?: 0,
)
