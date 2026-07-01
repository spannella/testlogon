package com.testlogon.android.feature.kycadmin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ImageNotSupported
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import coil.compose.AsyncImage
import com.testlogon.android.BuildConfig
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

/**
 * Shared bits for the KYC-admin review-queue modules (main case queue + document / residency /
 * proof-of-funds / liveness-call / screening / id-scanner / business review). Mirrors the web
 * the admin KYC review pages. Every backend endpoint is admin-or-root gated -> a server 403 renders a
 * Forbidden state. Timestamps are epoch SECONDS. Reuses [AdminOpsErrorType] and core.ui.state.*.
 */

/** Human-readable copy for a transient error, matching the fraud/admin-ops modules. */
internal fun kycAdminErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}

/**
 * Resolve a possibly-relative media URL from the backend (e.g. a `/mock/...` or `/v1/fs/download`
 * path) against the app's API base so Coil can load it. Absolute http(s) URLs pass through unchanged.
 */
internal fun resolveMediaUrl(url: String?): String? {
    val u = url?.trim().orEmpty()
    if (u.isEmpty()) return null
    if (u.startsWith("http://", ignoreCase = true) || u.startsWith("https://", ignoreCase = true)) return u
    val base = BuildConfig.API_BASE_URL.trimEnd('/')
    return if (u.startsWith("/")) base + u else "$base/$u"
}

/** Money helper: cents -> "$1,234.56". */
internal fun centsUsd(cents: Long): String = "$%,.2f".format(cents / 100.0)

/** A submitted KYC document / ID image, shown in the review detail. Falls back to a placeholder. */
@Composable
internal fun KycAdminDocImage(
    imageUrl: String?,
    contentDescription: String,
    modifier: Modifier = Modifier,
    imageTestTag: String? = null,
) {
    val resolved = resolveMediaUrl(imageUrl)
    val base = modifier.fillMaxWidth().aspectRatio(1.6f)
    val mod = if (imageTestTag != null) base.testTag(imageTestTag) else base
    if (resolved == null) {
        Column(
            modifier = mod,
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Icon(Icons.Outlined.ImageNotSupported, contentDescription = null)
            Text("No image", style = MaterialTheme.typography.labelSmall)
        }
    } else {
        AsyncImage(
            model = resolved,
            contentDescription = contentDescription,
            contentScale = ContentScale.Fit,
            modifier = mod,
        )
    }
}
