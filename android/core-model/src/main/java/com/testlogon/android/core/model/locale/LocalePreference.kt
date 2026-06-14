package com.testlogon.android.core.model.locale

/**
 * AND-113/AND-114 — locale domain model (lives in :core-model so network, data, and ui layers
 * share it without depending on each other).
 */

/** A BCP-47 language tag, e.g. "en", "es", "fr-CA". */
@JvmInline
value class LocaleTag(val value: String) {
    /** The base language subtag, lower-cased (e.g. "fr-CA" -> "fr"). */
    val language: String get() = value.substringBefore('-').lowercase()
}

/** Where the effective locale was resolved from (highest-priority source wins). */
enum class LocaleSource { IN_APP_OVERRIDE, SERVER, CACHE, DEVICE, DEFAULT }

/**
 * The resolved locale state the UI renders.
 *
 * @property effective the tag currently applied to the UI.
 * @property source where [effective] came from.
 * @property pendingServerSync a local change not yet successfully written to the server.
 */
data class LocalePreference(
    val effective: LocaleTag,
    val source: LocaleSource,
    val pendingServerSync: Boolean = false,
)
