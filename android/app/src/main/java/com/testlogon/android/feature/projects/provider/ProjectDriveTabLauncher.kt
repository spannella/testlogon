package com.testlogon.android.feature.projects.provider

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-374 - opens the backend-supplied Drive OAuth `authorization_url` in a Chrome Custom Tab. Mirrors the
 * AND-273 CustomTabsGoogleCalendarTabLauncher (reuses androidx.browser, never a WebView - so the app's session
 * cookie jar is NOT shared with the browser context - with an ACTION_VIEW fallback). android.net.Uri is used
 * ONLY here (UI/launcher layer), never in JVM-unit-tested logic. SINGLE_TOP so the return deep link re-enters
 * the same task and reaches MainActivity.onNewIntent. SHARE_STATE_OFF avoids leaking the URL out of the tab.
 */
fun interface ProjectDriveTabLauncher {
    /** @return true if a browser/tab was launched; false when no browser is available. */
    fun launch(context: Context, authorizationUrl: String): Boolean
}

@Singleton
class CustomTabsProjectDriveTabLauncher @Inject constructor() : ProjectDriveTabLauncher {
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
