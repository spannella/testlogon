package com.testlogon.android.feature.invoices

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-243 — opens an invoice PDF URL in a trusted browser context (Chrome Custom Tabs), reusing the
 * exact pattern of the AND-063 SsoTabLauncher / AND-227 PaymentTabLauncher. Opening in the system
 * browser (rather than an in-app WebView) means the PDF download carries the session cookies and the
 * platform handles the binary PDF view/download.
 */
fun interface InvoicePdfLauncher {
    /** @return true if a browser/tab was launched; false when no browser is available. */
    fun launch(context: Context, pdfUrl: String): Boolean
}

/** Chrome Custom Tabs launcher with an `ACTION_VIEW` fallback for devices without a Custom Tabs provider. */
@Singleton
class CustomTabsInvoicePdfLauncher @Inject constructor() : InvoicePdfLauncher {
    override fun launch(context: Context, pdfUrl: String): Boolean {
        val uri = Uri.parse(pdfUrl)
        return try {
            val intent = CustomTabsIntent.Builder()
                .setShowTitle(true)
                .build()
            intent.intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            intent.launchUrl(context, uri)
            true
        } catch (_: ActivityNotFoundException) {
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

/** AND-243 — binds the Custom Tabs PDF launcher. */
@Module
@InstallIn(SingletonComponent::class)
abstract class InvoicePdfLauncherModule {

    @Binds
    @Singleton
    abstract fun bindInvoicePdfLauncher(impl: CustomTabsInvoicePdfLauncher): InvoicePdfLauncher
}
