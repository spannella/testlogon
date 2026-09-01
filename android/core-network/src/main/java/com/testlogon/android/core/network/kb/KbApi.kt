package com.testlogon.android.core.network.kb

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * KB-AND-1 - Retrofit interface for the Knowledge Base READ surface (list / search / detail / categories).
 * Transport only; the repository layer wraps these RAW DTO returns into ApiResult. All calls are idempotent
 * suspend GETs.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the codebase).
 * The shared authenticated client attaches the session cookie via the global interceptors - so these hit the
 * AUTHENTICATED /kb/ endpoints (require_ui_session), mirroring the web authenticated client (listArticles /
 * searchArticles / getArticle / listCategories). The @Path token is EXACTLY {articleId} / {categoryId}.
 *
 * A null @Query is dropped by Retrofit (cursor / categoryId sent only when non-null). The backend returns
 * HTTP 404 for every route when knowledge_base_enabled is false - the repository maps that to a degraded
 * (empty) result rather than an error surface (degrade-on-404).
 *
 * RETURN SHAPES (frontend-verified):
 *  - search       -> KbSearchEnvelope       { items, query, cursor }
 *  - listArticles -> KbArticleListEnvelope  { items, cursor, total }
 *  - getArticle   -> KbArticleDto           (BARE object, embeds attachments[])
 *  - listCategories -> KbCategoryListEnvelope { categories }
 */
interface KbApi {

    /** GET the published articles (optionally scoped to a category). Pass [cursor] to fetch the next page. */
    @GET("kb/articles")
    suspend fun listArticles(
        @Query("category_id") categoryId: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): KbArticleListEnvelope

    /** Full-text search across articles. [q] is the raw query. Pass [cursor] for the next page. */
    @GET("kb/search")
    suspend fun search(
        @Query("q") q: String,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): KbSearchEnvelope

    /** GET one full article (BARE object; embeds attachments[]). Idempotent; bumps the server view counter. */
    @GET("kb/articles/{articleId}")
    suspend fun getArticle(
        @Path("articleId") articleId: String,
    ): KbArticleDto

    /** GET the KB categories (flat top-level list; children nested on the wire). */
    @GET("kb/categories")
    suspend fun listCategories(): KbCategoryListEnvelope
}
