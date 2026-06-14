package com.testlogon.android.feature.seo.data

/**
 * AND-400 - the resource taxonomy accepted by the public SEO endpoint.
 *
 * CORRECTED per spec section 16 (citation 3): the supported types are
 * profile | event | post | video | live (NOT the draft's channel|video|playlist). The wire value
 * is the lowercase token sent as the `type` query param. Parsing tolerates an unknown value by
 * falling back to [PROFILE] rather than throwing (the endpoint is forgiving and never owner-scoped).
 */
enum class ResourceType(val wire: String) {
    PROFILE("profile"),
    EVENT("event"),
    POST("post"),
    VIDEO("video"),
    LIVE("live"),
    ;

    companion object {
        /** Resolves a wire token to a [ResourceType], defaulting to [PROFILE] on an unknown value. */
        fun from(value: String?): ResourceType =
            entries.firstOrNull { it.wire.equals(value, ignoreCase = true) } ?: PROFILE
    }
}

/**
 * AND-400 - the domain model rendered by the read-only SEO inspector (the mapper target).
 *
 * Shape mirrors the authoritative web client `SeoMetadata` type (spec section 16, citations 7-11),
 * NOT the untyped OpenAPI 200 body. The `og`/`twitter` maps are flat prefixed-key string maps with
 * blank entries already dropped by the mapper; [jsonLd] is a single pretty-printed JSON-LD block (or
 * null), never a list; there is no `robots` field.
 *
 * [isEmpty] drives the empty state: it is true when the server signalled `available == false`
 * (private/locked resources return generic defaults) OR when no field is renderable.
 */
data class SeoMetadata(
    val resourceType: String?,
    val resourceId: String?,
    val available: Boolean,
    val title: String?,
    val description: String?,
    val canonicalUrl: String?,
    val siteName: String?,
    val locale: String?,
    val og: Map<String, String>,
    val twitter: Map<String, String>,
    val image: String?,
    val jsonLd: String?,
) {
    val isEmpty: Boolean
        get() = !available || (
            title.isNullOrBlank() &&
                description.isNullOrBlank() &&
                canonicalUrl.isNullOrBlank() &&
                siteName.isNullOrBlank() &&
                locale.isNullOrBlank() &&
                og.isEmpty() &&
                twitter.isEmpty() &&
                image.isNullOrBlank() &&
                jsonLd.isNullOrBlank()
            )
}
