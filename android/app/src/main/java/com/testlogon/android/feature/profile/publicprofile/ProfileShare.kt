package com.testlogon.android.feature.profile.publicprofile

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import com.testlogon.android.R
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import java.net.URLEncoder
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-390 — supplies the published App Link host for building canonical https public-profile share
 * URLs (the prod/staging web host), NEVER the plaintext dev host (18.222.237.167:8000), so a shared
 * link is always https on a real, App-Link-verified host. An interface so JVM tests can supply a fake
 * host without a Context. Mirrors AND-272's PublicEventHostProvider.
 */
fun interface ProfileShareHostProvider {
    fun host(): String
}

/** Default impl that reads the `applink_host` string resource. */
@Singleton
class ResourceProfileShareHostProvider @Inject constructor(
    @ApplicationContext private val context: Context,
) : ProfileShareHostProvider {
    override fun host(): String = context.getString(R.string.applink_host)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ProfileShareHostModule {
    @Binds
    abstract fun bindProfileShareHostProvider(impl: ResourceProfileShareHostProvider): ProfileShareHostProvider
}

/**
 * AND-390 — builds the canonical, auth-free public-profile share URL, mirroring the verified web
 * canonical `/u/{identifier}` (reference src/pages/profile/PublicUserProfilePage.tsx `link rel=canonical`
 * = `${origin}/u/${canonicalIdentifier}`). Pure / JVM-unit-testable (no android.net.Uri).
 *
 * The host is the published App Link host so a shared link round-trips back into the app via the
 * verified `/u/` App Link path (FR-6). The dev base URL is never used for the share URL (TC-AND-390-04).
 */
object ProfileShareUrl {

    /** Builds `https://<host>/u/<identifier>`. */
    fun build(host: String, identifier: String): String = "https://$host/u/${enc(identifier)}"

    // Pure path-segment encoder (encodeURIComponent-equivalent) — no android.net.Uri, JVM-testable.
    private fun enc(segment: String): String =
        URLEncoder.encode(segment, "UTF-8").replace("+", "%20")
}

/**
 * AND-390 — side-effecting platform seams for the public-profile share/copy affordances, resolved in
 * composable scope (default `remember { ProfileShareIntents() }`) so a test can supply a fake and the
 * real one is never invoked directly from a composable body. Mirrors AND-272's EventIntents pattern;
 * each method takes the live [Context] and returns false when the action could not run so the caller
 * can show a Snackbar instead of crashing (§7).
 */
class ProfileShareIntents @Inject constructor() {

    /**
     * Launches the system share sheet (ACTION_SEND, text/plain) carrying the canonical [url] plus a
     * localized title ("<displayName> on TestLogon"). Returns false when no app can handle it.
     */
    fun share(context: Context, url: String, displayName: String): Boolean {
        val title = context.getString(R.string.share_profile_title, displayName)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TITLE, title)
            putExtra(Intent.EXTRA_SUBJECT, title)
            putExtra(Intent.EXTRA_TEXT, url)
        }
        val chooser = Intent.createChooser(send, context.getString(R.string.share_profile_chooser))
            .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
        return try {
            context.startActivity(chooser)
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }

    /**
     * Copies the canonical share [url] to the clipboard. Returns true on success; a missing/blocked
     * clipboard service surfaces as false (-> error snackbar) rather than a crash (§7).
     */
    fun copyLink(context: Context, url: String): Boolean = try {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            ?: return false
        clipboard.setPrimaryClip(ClipData.newPlainText("profile_link", url))
        true
    } catch (_: Exception) {
        false
    }

    /**
     * On Android 13+ (API 33) the OS shows its own clipboard confirmation, so the in-app snackbar is
     * suppressed to avoid duplicate feedback (§4.4). Returns true when the app should show its own
     * confirmation snackbar.
     */
    fun shouldShowCopyConfirmation(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU
}
