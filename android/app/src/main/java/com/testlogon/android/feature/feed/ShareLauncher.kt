package com.testlogon.android.feature.feed

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import com.testlogon.android.R
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-176 — share a post via the Android system share sheet (Intent.ACTION_SEND, text/plain).
 *
 * Platform divergence (accepted, see AND-176 §1): the web "share" DMs the post in-app; Android uses the
 * native OS chooser. The shared payload contains ONLY a public post URL (and an optional author
 * subject) — never a cookie, session token, CSRF value, bearer, or user id (asserted by test). On a
 * device with no share target ([ActivityNotFoundException]) the caller is told via [share] returning
 * false so it can fall back (snackbar / clipboard).
 *
 * Side-effecting platform call wrapped behind an injectable seam so it is testable and never invoked
 * directly from a composable body.
 */
@Singleton
class ShareLauncher @Inject constructor() {

    /** Launches the chooser. Returns false if no activity could handle the intent. */
    fun share(context: Context, content: ShareContent): Boolean {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, content.url)
            content.subject?.let { putExtra(Intent.EXTRA_SUBJECT, it) }
        }
        val chooser = Intent.createChooser(send, context.getString(R.string.feed_share_chooser_title))
            .apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
        return try {
            context.startActivity(chooser)
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }
}

/** The text payload handed to the share sheet. [url] is a public post URL; [subject] is optional. */
data class ShareContent(val url: String, val subject: String?)

/**
 * AND-176 — builds the canonical, auth-free share artifacts for a post. Pure / JVM-unit-testable.
 *
 * The verified web internal route is "/posts/{post_id}" (NOT "/p/{id}"). The public origin is an
 * unverified assumption (no public origin appears in OpenAPI or the web client); confirm before launch.
 */
object PostShare {
    // ASSUMED public origin (R1 / OA-1). The "/posts/" path segment IS verified; the host is not.
    private const val WEB_BASE = "https://app.testlogon.com"

    fun urlFor(postId: String): String = "$WEB_BASE/posts/$postId"

    /**
     * Optional share subject. FeedPost carries no author_display_name (only author_id), so the caller
     * passes whatever display name it has; null produces no subject.
     */
    fun subjectFor(authorDisplayName: String?): String? =
        authorDisplayName?.takeIf { it.isNotBlank() }?.let { "Post by $it on TestLogon" }
}
