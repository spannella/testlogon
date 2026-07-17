#!/usr/bin/env python3
"""TIPX-E2 (N1/N2/N3): AlertsScreen tip dispatch — render + deep-link tip alerts.

Adds isTipAlert + a tip action_url parser (TipNavTarget) and threads
onOpenPost/onOpenThread/onOpenVideo/onOpenTips callbacks through
AlertsRoute -> AlertsScreen -> the row onClick.
"""
import io, sys
PATH = "android/app/src/main/java/com/testlogon/android/feature/alerts/AlertsScreen.kt"
src = io.open(PATH, encoding="utf-8").read()
orig = src

# --- 1. Add the tip-alert helpers + parser right after the payout helpers block
#        (anchor on the shipGroupFromActionUrl parser's closing brace, unique). ---
anchor_helpers = '''/** Parses the ship_group id from a buyer shipment alert action_url query. */
internal fun shipGroupFromActionUrl(actionUrl: String?): String? {'''
tip_block = '''/**
 * TIPX-E2 (N1/N2/N3) — tip notification events. EVERY surface routes through the backend
 * `notify_tip` choke point, emitting a `tip_received` (recipient) / `tip_sent` (tipper) /
 * `tip_reversed` / `tip_refunded` alert plus the legacy `post_tip` / `message_tip` social types.
 * All of them carry a relative `action_url` to the tipped content; tapping the row deep-links there.
 */
private val TIP_ALERT_EVENTS: Set<String> = setOf(
    "tip_received", "tip_sent", "tip_reversed", "tip_refunded",
    "post_tip", "message_tip",
)

internal fun isTipAlert(event: String?): Boolean =
    event != null && event.trim().lowercase() in TIP_ALERT_EVENTS

/** A resolved deep-link target parsed from a tip alert's action_url. */
sealed interface TipNavTarget {
    data class Post(val postId: String) : TipNavTarget
    data class Thread(val conversationId: String) : TipNavTarget
    data class Video(val videoId: String) : TipNavTarget
    /** reversal / refund receipts (and any unrecognised path) -> the tip history screen. */
    data object Tips : TipNavTarget
}

/**
 * Maps a tip alert's relative action_url to a [TipNavTarget]:
 *   /feed/posts/{id}         -> Post
 *   /messaging/thread/{id}   -> Thread
 *   /videos/{id}             -> Video
 *   /wallet/tips (or other)  -> Tips
 */
internal fun tipTargetFromActionUrl(actionUrl: String?): TipNavTarget {
    val path = (actionUrl ?: "").substringBefore('?').trim()
    fun seg(marker: String): String? {
        val i = path.indexOf(marker)
        if (i < 0) return null
        return path.substring(i + marker.length).trim('/').substringBefore('/')
            .let { android.net.Uri.decode(it) }.takeIf { it.isNotBlank() }
    }
    seg("/feed/posts/")?.let { return TipNavTarget.Post(it) }
    seg("/messaging/thread/")?.let { return TipNavTarget.Thread(it) }
    seg("/videos/")?.let { return TipNavTarget.Video(it) }
    return TipNavTarget.Tips
}

'''
assert src.count(anchor_helpers) == 1, f"helpers anchor={src.count(anchor_helpers)}"
src = src.replace(anchor_helpers, tip_block + anchor_helpers)

# --- 2. AlertsRoute signature: add tip callbacks (anchor on onOpenPayout param in AlertsRoute). ---
anchor_route_param = '''    // PAY-51: tapping a payout alert opens that payout statement/detail (by payout_id from action_url).
    onOpenPayout: (String) -> Unit = {},
    viewModel: AlertsViewModel = hiltViewModel(),'''
route_param_new = '''    // PAY-51: tapping a payout alert opens that payout statement/detail (by payout_id from action_url).
    onOpenPayout: (String) -> Unit = {},
    // TIPX-E2: tapping a tip alert deep-links to the tipped content / tip history.
    onOpenPost: (String) -> Unit = {},
    onOpenThread: (String) -> Unit = {},
    onOpenVideo: (String) -> Unit = {},
    onOpenTips: () -> Unit = {},
    viewModel: AlertsViewModel = hiltViewModel(),'''
assert src.count(anchor_route_param) == 1, f"route param anchor={src.count(anchor_route_param)}"
src = src.replace(anchor_route_param, route_param_new)

# --- 3. AlertsRoute -> AlertsScreen forwarding (anchor on onOpenPayout = onOpenPayout,  // PAY-51). ---
anchor_route_fwd = '''        onOpenPayout = onOpenPayout,  // PAY-51
        snackbarHostState = snackbarHostState,'''
route_fwd_new = '''        onOpenPayout = onOpenPayout,  // PAY-51
        onOpenPost = onOpenPost,        // TIPX-E2
        onOpenThread = onOpenThread,    // TIPX-E2
        onOpenVideo = onOpenVideo,      // TIPX-E2
        onOpenTips = onOpenTips,        // TIPX-E2
        snackbarHostState = snackbarHostState,'''
assert src.count(anchor_route_fwd) == 1, f"route fwd anchor={src.count(anchor_route_fwd)}"
src = src.replace(anchor_route_fwd, route_fwd_new)

# --- 4. AlertsScreen signature: add tip callbacks (anchor on onOpenPayout param in AlertsScreen). ---
anchor_screen_param = '''    onOpenPayout: (String) -> Unit = {},  // PAY-51: (payoutId)
    modifier: Modifier = Modifier,'''
screen_param_new = '''    onOpenPayout: (String) -> Unit = {},  // PAY-51: (payoutId)
    onOpenPost: (String) -> Unit = {},    // TIPX-E2: (postId)
    onOpenThread: (String) -> Unit = {},  // TIPX-E2: (conversationId)
    onOpenVideo: (String) -> Unit = {},   // TIPX-E2: (videoId)
    onOpenTips: () -> Unit = {},          // TIPX-E2: tip history
    modifier: Modifier = Modifier,'''
assert src.count(anchor_screen_param) == 1, f"screen param anchor={src.count(anchor_screen_param)}"
src = src.replace(anchor_screen_param, screen_param_new)

# --- 5. onClick dispatch: add the tip branch (anchor on the PAY-51 payout onClick block). ---
anchor_click = '''                                        // PAY-51: a payout alert deep-links to that payout's statement.
                                        if (isPayoutAlert(alert.event)) {
                                            payoutIdFromActionUrl(alert.actionUrl)?.let(onOpenPayout)
                                        }'''
click_new = '''                                        // PAY-51: a payout alert deep-links to that payout's statement.
                                        if (isPayoutAlert(alert.event)) {
                                            payoutIdFromActionUrl(alert.actionUrl)?.let(onOpenPayout)
                                        }
                                        // TIPX-E2 (N3): a tip alert deep-links to the tipped
                                        // post / thread / video (or tip history for reversals).
                                        if (isTipAlert(alert.event)) {
                                            when (val t = tipTargetFromActionUrl(alert.actionUrl)) {
                                                is TipNavTarget.Post -> onOpenPost(t.postId)
                                                is TipNavTarget.Thread -> onOpenThread(t.conversationId)
                                                is TipNavTarget.Video -> onOpenVideo(t.videoId)
                                                TipNavTarget.Tips -> onOpenTips()
                                            }
                                        }'''
assert src.count(anchor_click) == 1, f"click anchor={src.count(anchor_click)}"
src = src.replace(anchor_click, click_new)

if src == orig:
    print("NO CHANGE"); sys.exit(1)
io.open(PATH, "w", encoding="utf-8").write(src)
print("PATCHED AlertsScreen.kt")
