package com.testlogon.android.feature.auth.sso

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import javax.inject.Inject
import javax.inject.Singleton

/** AND-063 — opens the SSO/SAML authorization URL in a trusted browser context. */
fun interface SsoTabLauncher {
    /** @return true if a browser/tab was launched; false when no browser is available. */
    fun launch(context: Context, authorizeUrl: String): Boolean
}

/**
 * Chrome Custom Tabs launcher (AndroidX `androidx.browser`) with an `ACTION_VIEW` fallback for
 * devices without a Custom Tabs provider. Never uses a WebView (credential interception / SSO-cookie
 * preservation). Returns false when no browser can handle the URL so the UI can show a clear error.
 */
@Singleton
class CustomTabsSsoTabLauncher @Inject constructor() : SsoTabLauncher {
    override fun launch(context: Context, authorizeUrl: String): Boolean {
        val uri = Uri.parse(authorizeUrl)
        return try {
            val intent = CustomTabsIntent.Builder()
                .setShowTitle(true)
                .setUrlBarHidingEnabled(false)
                .build()
            intent.intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            intent.launchUrl(context, uri)
            true
        } catch (_: ActivityNotFoundException) {
            // Fallback to a plain ACTION_VIEW to the default browser.
            try {
                val view = Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(view)
                true
            } catch (_: ActivityNotFoundException) {
                false
            }
        }
    }
}
