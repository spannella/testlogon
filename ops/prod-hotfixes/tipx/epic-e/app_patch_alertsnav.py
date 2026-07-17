#!/usr/bin/env python3
"""TIPX-E2: wire tip deep-link callbacks in AlertsNavigation."""
import io, sys
PATH = "android/app/src/main/java/com/testlogon/android/navigation/AlertsNavigation.kt"
src = io.open(PATH, encoding="utf-8").read()
orig = src

# import MessagingRoutes (PostDetailDest/VideoDetailDest/TipInsightsDest are same-package).
imp_anchor = "import com.testlogon.android.feature.alerts.AlertsRoute"
imp_new = ("import com.testlogon.android.feature.alerts.AlertsRoute\n"
           "import com.testlogon.android.feature.messaging.nav.MessagingRoutes")
assert src.count(imp_anchor) == 1
src = src.replace(imp_anchor, imp_new)

# Add the tip callbacks after onOpenPayout wiring (anchor on its closing block).
nav_anchor = '''            onOpenPayout = { payoutId ->
                navController.navigate(PayoutDetailDest.build(payoutId)) { launchSingleTop = true }
            },'''
nav_new = '''            onOpenPayout = { payoutId ->
                navController.navigate(PayoutDetailDest.build(payoutId)) { launchSingleTop = true }
            },
            // TIPX-E2: a tip alert deep-links to the tipped content (post/thread/video) or,
            // for reversal/refund receipts, the Tip insights history screen.
            onOpenPost = { postId ->
                navController.navigate(PostDetailDest.build(postId)) { launchSingleTop = true }
            },
            onOpenThread = { conversationId ->
                navController.navigate(MessagingRoutes.thread(conversationId)) { launchSingleTop = true }
            },
            onOpenVideo = { videoId ->
                navController.navigate(VideoDetailDest.build(videoId)) { launchSingleTop = true }
            },
            onOpenTips = {
                navController.navigate(TipInsightsDest.ROUTE) { launchSingleTop = true }
            },'''
assert src.count(nav_anchor) == 1, f"nav anchor={src.count(nav_anchor)}"
src = src.replace(nav_anchor, nav_new)

if src == orig:
    print("NO CHANGE"); sys.exit(1)
io.open(PATH, "w", encoding="utf-8").write(src)
print("PATCHED AlertsNavigation.kt")
