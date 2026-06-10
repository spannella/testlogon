package com.testlogon.android.feature.payments

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-228/229 — opens a hosted payment URL (PayPal approval / CCBill flexform / hosted checkout) in a
 * Chrome Custom Tab. Mirrors the existing
 * [com.testlogon.android.feature.auth.sso.CustomTabsSsoTabLauncher] (reuses androidx.browser, never a
 * WebView, with an ACTION_VIEW fallback). android.net.Uri is used ONLY here (UI/launcher layer), never
 * in JVM-unit-tested logic.
 *
 * SINGLE_TOP so the return deep link re-enters the same task and reaches MainActivity.onNewIntent
 * (AND-231).
 */
fun interface PaymentTabLauncher {
    /** @return true if a browser/tab was launched; false when no browser is available. */
    fun launch(context: Context, hostedUrl: String): Boolean
}

@Singleton
class CustomTabsPaymentTabLauncher @Inject constructor() : PaymentTabLauncher {
    override fun launch(context: Context, hostedUrl: String): Boolean {
        val uri = Uri.parse(hostedUrl)
        return try {
            val intent = CustomTabsIntent.Builder()
                .setShowTitle(true)
                .setUrlBarHidingEnabled(false) // keep the verified TLS origin visible
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
