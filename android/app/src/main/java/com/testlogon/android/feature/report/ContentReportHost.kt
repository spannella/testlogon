package com.testlogon.android.feature.report

import androidx.compose.runtime.Composable
import androidx.compose.runtime.staticCompositionLocalOf
import com.testlogon.android.data.dmca.DmcaContentType
import com.testlogon.android.data.report.ReportOutcome
import com.testlogon.android.data.report.ReportTarget

/**
 * MOD-C3 - a composition-local seam that lets any deeply-nested content surface open the DMCA claim flow
 * pre-filled with a content ref, WITHOUT threading a navigation lambda through every screen signature.
 * Provided once at the app NavHost from `navController.navigateToDmca(...)`; the default is a safe no-op
 * (previews / tests never crash).
 *
 * The argument order is (contentType, contentId) where contentType is the report surface's wire type
 * (feed_post / feed_media / video / feed_comment / video_comment); it is normalized to the DMCA content
 * enum by the host below (comment types collapse to `other`, the DMCA form's default).
 */
val LocalDmcaLauncher = staticCompositionLocalOf<(contentType: String, contentId: String) -> Unit> {
    { _, _ -> }
}

/**
 * MOD-C1..C3 - the single reusable host for the cross-cutting content report sheet. A call site holds a
 * `var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }`, sets it from its Report action,
 * and renders this once; it wires the six-category [ReportSheet] plus the licensing/IP escape hatch that
 * routes CONTENT reports into the DMCA flow via [LocalDmcaLauncher]. USER / MESSAGE targets get no
 * licensing entry (a profile photo / DM is not a copyright claim surface).
 */
@Composable
fun ContentReportSheetHost(
    target: ReportTarget?,
    onDismiss: () -> Unit,
) {
    val dmca = LocalDmcaLauncher.current
    val t = target ?: return
    ReportSheet(
        target = t,
        onDismiss = onDismiss,
        onCompleted = { _: ReportOutcome -> onDismiss() },
        onLicensing = if (t is ReportTarget.Content) {
            {
                onDismiss()
                dmca(DmcaContentType.normalize(t.contentType), t.id)
            }
        } else {
            null
        },
    )
}
