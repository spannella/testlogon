package com.testlogon.android.feature.seo.data

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-400 - maps [SeoMetadataDto] -> [SeoMetadata] (the DTO-&gt;domain seam lives in :app per the project
 * convention). It normalizes blank scalars to null, drops blank entries from the flat og/twitter maps,
 * and pretty-prints the single json_ld object to an indented JSON string (null when absent or when the
 * object cannot be re-serialized - the UI then shows an inline "could not display" note rather than
 * crashing, spec section 7).
 *
 * Moshi is injected (the shared instance from core-network) to re-serialize the json_ld map; the
 * Map&lt;String, Any?&gt; adapter resolves from the built-in map/scalar adapters (no reflection needed),
 * so this also works on the :app unit-test classpath when constructed with a plain Moshi.Builder().
 */
@Singleton
class SeoMetadataMapper @Inject constructor(
    moshi: Moshi,
) {
    private val jsonLdAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    ).indent("  ")

    fun toDomain(dto: SeoMetadataDto): SeoMetadata = SeoMetadata(
        resourceType = dto.resourceType?.normalize(),
        resourceId = dto.resourceId?.normalize(),
        available = dto.available,
        title = dto.title?.normalize(),
        description = dto.description?.normalize(),
        canonicalUrl = dto.canonicalUrl?.normalize(),
        siteName = dto.siteName?.normalize(),
        locale = dto.locale?.normalize(),
        og = dto.og.cleanTagMap(),
        twitter = dto.twitter.cleanTagMap(),
        image = dto.image?.normalize(),
        jsonLd = dto.jsonLd?.toPrettyJson(),
    )

    /** Trims a string and returns null when it is blank. */
    private fun String.normalize(): String? = trim().ifBlank { null }

    /** Drops null/blank keys and values from a flat tag map, trimming the kept values. */
    private fun Map<String, String?>?.cleanTagMap(): Map<String, String> {
        if (this.isNullOrEmpty()) return emptyMap()
        val out = LinkedHashMap<String, String>(size)
        for ((key, value) in this) {
            val trimmedKey = key.trim()
            val trimmedValue = value?.trim()
            if (trimmedKey.isNotEmpty() && !trimmedValue.isNullOrEmpty()) {
                out[trimmedKey] = trimmedValue
            }
        }
        return out
    }

    /** Re-serializes the json_ld object to an indented JSON string, or null if it cannot be encoded. */
    private fun Map<String, Any?>.toPrettyJson(): String? {
        if (isEmpty()) return null
        return runCatching { jsonLdAdapter.toJson(this) }.getOrNull()?.ifBlank { null }
    }
}
