package com.testlogon.android.feature.calendar.integrations

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-273 — opens the backend-supplied Google Calendar OAuth `authorization_url` (dev: a
 * /mock/google-calendar/... URL) in a Chrome Custom Tab. Mirrors
 * [com.testlogon.android.feature.payments.CustomTabsPaymentTabLauncher] (reuses androidx.browser, never a
 * WebView, with an ACTION_VIEW fallback). android.net.Uri is used ONLY here (UI/launcher layer), never in
 * JVM-unit-tested logic. SINGLE_TOP so the return deep link re-enters the same task and reaches
 * MainActivity.onNewIntent.
 */
fun interface GoogleCalendarTabLauncher {
    /** @return true if a browser/tab was launched; false when no browser is available. */
    fun launch(context: Context, authorizationUrl: String): Boolean
}

@Singleton
class CustomTabsGoogleCalendarTabLauncher @Inject constructor() : GoogleCalendarTabLauncher {
    override fun launch(context: Context, authorizationUrl: String): Boolean {
        val uri = Uri.parse(authorizationUrl)
        return try {
            val intent = CustomTabsIntent.Builder()
                .setShowTitle(true)
                .setUrlBarHidingEnabled(false)
                .setShareState(CustomTabsIntent.SHARE_STATE_OFF)
                .build()
            intent.intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            intent.launchUrl(context, uri)
            true
        } catch (_: ActivityNotFoundException) {
            try {
                context.startActivity(
                    Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                )
                true
            } catch (_: ActivityNotFoundException) {
                false
            }
        }
    }
}

@dagger.Module
@dagger.hilt.InstallIn(dagger.hilt.components.SingletonComponent::class)
abstract class GoogleCalendarTabLauncherModule {
    @dagger.Binds
    @Singleton
    abstract fun bindLauncher(impl: CustomTabsGoogleCalendarTabLauncher): GoogleCalendarTabLauncher
}
