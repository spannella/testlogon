package com.testlogon.android.feature.settings.language

import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import com.testlogon.android.core.model.locale.LocaleTag
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-114 — applies a resolved locale to the running app via the per-app language API.
 *
 * [AppCompatDelegate.setApplicationLocales] is durable (backed by the framework LocaleManager on
 * API 33+, AppCompat's own store on 24–32) and triggers a configuration change, so every
 * stringResource / text() re-resolves the new values-<lang> with no manual restart (FR-2). A null /
 * empty tag clears the override and follows the device default (FR-3).
 *
 * Wrapped behind this interface so the picker ViewModel and the launch-time bootstrap stay testable
 * (the real impl touches AppCompat static state, which a JVM test fakes out).
 */
interface LocaleController {
    fun apply(tag: LocaleTag?)
}

@Singleton
class AppCompatLocaleController @Inject constructor() : LocaleController {
    override fun apply(tag: LocaleTag?) {
        val locales = if (tag == null || tag.value.isBlank()) {
            LocaleListCompat.getEmptyLocaleList()
        } else {
            LocaleListCompat.forLanguageTags(tag.value)
        }
        AppCompatDelegate.setApplicationLocales(locales)
    }
}
