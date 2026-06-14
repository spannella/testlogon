package com.testlogon.android.data.locale

import com.testlogon.android.core.model.locale.LocaleTag

/**
 * AND-113 — supplies the device/system default language as a BCP-47 tag.
 *
 * An interface so the effective-locale ladder in [LocaleRepository] is unit-testable on the JVM
 * without touching android.os.LocaleList / Locale.getDefault() at the call site.
 */
fun interface DeviceLocaleProvider {
    /** The device's primary language tag, or null if it cannot be determined. */
    fun deviceLocaleTag(): LocaleTag?
}
