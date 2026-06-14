package com.testlogon.android.core.model.locale

/**
 * AND-112/AND-113 — the authoritative set of locales the app ships catalogs for (must mirror
 * res/xml/locales_config.xml and the values-<lang> directories in :core-ui).
 *
 * [DEFAULT] is the fallback language used when a requested tag has no catalog. [normalize] performs
 * FR-5 gating: exact match -> base-language match -> default, so a server preference outside the
 * supported set is downgraded rather than applied verbatim.
 */
object SupportedLocales {

    val DEFAULT: LocaleTag = LocaleTag("en")

    /** Supported tags, in display order; keep in sync with locales_config.xml. */
    val all: List<LocaleTag> = listOf(LocaleTag("en"), LocaleTag("es"))

    private val byExact: Set<String> = all.map { it.value.lowercase() }.toSet()
    private val byLanguage: Map<String, LocaleTag> = all.associateBy { it.language }

    fun isSupported(tag: LocaleTag): Boolean = byExact.contains(tag.value.lowercase())

    /**
     * Returns the supported tag closest to [tag]: the exact tag if shipped, else the base-language
     * tag if shipped, else [DEFAULT]. Returns null only when [tag] itself is null/blank, letting
     * callers distinguish "no preference" from "unsupported preference".
     */
    fun normalize(tag: LocaleTag?): LocaleTag? {
        val raw = tag?.value?.trim().orEmpty()
        if (raw.isEmpty()) return null
        val candidate = LocaleTag(raw)
        return when {
            isSupported(candidate) -> all.first { it.value.equals(raw, ignoreCase = true) }
            byLanguage.containsKey(candidate.language) -> byLanguage.getValue(candidate.language)
            else -> DEFAULT
        }
    }
}
