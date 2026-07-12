#!/usr/bin/env python3
"""SUB-E5 app deep-link wiring: subscription alerts route to manage / subscribers.
Anchored + idempotent."""
import sys, os
ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/dev/testlogon")
A = "android/app/src/main/java/com/testlogon/android/feature/alerts/AlertsScreen.kt"
N = "android/app/src/main/java/com/testlogon/android/navigation/AlertsNavigation.kt"

EDITS = [
    # 1. AlertsRoute param + pass-through
    (A, "onOpenSubscription: (String) -> Unit = {},  // SUB-E5 route(A1)",
     "    // D4: tapping a buyer shipment alert opens the buyer order-tracking view (by ship-group id).\n"
     "    onOpenTracking: (String) -> Unit = {},\n"
     "    viewModel: AlertsViewModel = hiltViewModel(),",
     "    // D4: tapping a buyer shipment alert opens the buyer order-tracking view (by ship-group id).\n"
     "    onOpenTracking: (String) -> Unit = {},\n"
     "    onOpenSubscription: (String) -> Unit = {},  // SUB-E5 route(A1)\n"
     "    viewModel: AlertsViewModel = hiltViewModel(),"),

    (A, "onOpenSubscription = onOpenSubscription,  // SUB-E5 route(A2)",
     "        onOpenModeration = onOpenModeration,\n"
     "        onOpenSale = onOpenSale,\n"
     "        onOpenTracking = onOpenTracking,\n"
     "        snackbarHostState = snackbarHostState,",
     "        onOpenModeration = onOpenModeration,\n"
     "        onOpenSale = onOpenSale,\n"
     "        onOpenTracking = onOpenTracking,\n"
     "        onOpenSubscription = onOpenSubscription,  // SUB-E5 route(A2)\n"
     "        snackbarHostState = snackbarHostState,"),

    # 2. predicate + parser helper (inserted after isOrderTrackingAlert def uses ORDER_TRACKING set)
    (A, "SUB-E5 subscription lifecycle alert events",
     "internal fun isOrderTrackingAlert(event: String?): Boolean =\n"
     "    event != null && event.trim().lowercase() in ORDER_TRACKING_ALERT_EVENTS",
     "internal fun isOrderTrackingAlert(event: String?): Boolean =\n"
     "    event != null && event.trim().lowercase() in ORDER_TRACKING_ALERT_EVENTS\n"
     "\n"
     "/**\n"
     " * SUB-E5 subscription lifecycle alert events (backend emit_social_alert). Tapping one deep-links\n"
     " * to manage-subscription (subscriber-facing) or the Subscribers screen (creator-facing); the\n"
     " * backend sets the per-recipient action_url so the app just routes on that path.\n"
     " */\n"
     "private val SUBSCRIPTION_ALERT_EVENTS: Set<String> = setOf(\n"
     "    \"subscription_started\", \"subscription_new_subscriber\", \"subscription_renewed\",\n"
     "    \"subscription_renewal_failed\", \"subscription_expiring\", \"subscription_expired\",\n"
     "    \"subscription_canceled\", \"subscription_gifted\",\n"
     ")\n"
     "\n"
     "internal fun isSubscriptionAlert(event: String?): Boolean =\n"
     "    event != null && event.trim().lowercase() in SUBSCRIPTION_ALERT_EVENTS"),

    # 3. internal AlertsScreen param
    (A, "onOpenSubscription: (String) -> Unit = {},  // SUB-E5 route(A3)",
     "    onOpenModeration: () -> Unit = {},\n"
     "    onOpenSale: (String) -> Unit = {},\n"
     "    onOpenTracking: (String) -> Unit = {},\n"
     "    modifier: Modifier = Modifier,\n"
     "    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },",
     "    onOpenModeration: () -> Unit = {},\n"
     "    onOpenSale: (String) -> Unit = {},\n"
     "    onOpenTracking: (String) -> Unit = {},\n"
     "    onOpenSubscription: (String) -> Unit = {},  // SUB-E5 route(A3)\n"
     "    modifier: Modifier = Modifier,\n"
     "    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },"),

    # 4. tap handler
    (A, "if (isSubscriptionAlert(alert.event))",
     "                                        // D4: a buyer shipment alert opens the order-tracking view.\n"
     "                                        if (isOrderTrackingAlert(alert.event)) {\n"
     "                                            shipGroupFromActionUrl(alert.actionUrl)?.let(onOpenTracking)\n"
     "                                        }",
     "                                        // D4: a buyer shipment alert opens the order-tracking view.\n"
     "                                        if (isOrderTrackingAlert(alert.event)) {\n"
     "                                            shipGroupFromActionUrl(alert.actionUrl)?.let(onOpenTracking)\n"
     "                                        }\n"
     "                                        // SUB-E5: a subscription alert deep-links via its action_url.\n"
     "                                        if (isSubscriptionAlert(alert.event)) {\n"
     "                                            onOpenSubscription(alert.actionUrl ?: \"\")\n"
     "                                        }"),

    # 5. Navigation wiring
    (N, "onOpenSubscription = { actionUrl ->  // SUB-E5",
     "            // D4: a buyer shipment alert deep-links to the buyer order-tracking view (ship group).\n"
     "            onOpenTracking = { shipGroupId ->\n"
     "                navController.navigate(OrderTrackingDest.build(shipGroupId)) { launchSingleTop = true }\n"
     "            },",
     "            // D4: a buyer shipment alert deep-links to the buyer order-tracking view (ship group).\n"
     "            onOpenTracking = { shipGroupId ->\n"
     "                navController.navigate(OrderTrackingDest.build(shipGroupId)) { launchSingleTop = true }\n"
     "            },\n"
     "            // SUB-E5: a subscription alert deep-links to Subscribers (creator) or manage-subscription.\n"
     "            onOpenSubscription = { actionUrl ->  // SUB-E5\n"
     "                val dest = if (actionUrl.contains(\"subscribers\")) CreatorSubscribersDest.ROUTE else ManageSubscriptionDest.ROUTE\n"
     "                navController.navigate(dest) { launchSingleTop = true }\n"
     "            },"),
]

def main():
    from collections import defaultdict
    byfile = defaultdict(list)
    for rel, marker, old, new in EDITS:
        byfile[rel].append((marker, old, new))
    ok = True
    for rel, edits in byfile.items():
        p = os.path.join(ROOT, rel)
        with open(p, encoding="utf-8") as f:
            src = f.read()
        orig = src
        for marker, old, new in edits:
            if marker in src:
                print("SKIP ", rel, "::", marker[:40]); continue
            c = src.count(old)
            if c != 1:
                print("FAIL count=%d" % c, rel, "::", marker[:40]); ok = False; continue
            src = src.replace(old, new, 1)
            print("APPLY", rel, "::", marker[:40])
        if src != orig:
            with open(p, "w", encoding="utf-8") as f:
                f.write(src)
    print("OVERALL", "OK" if ok else "FAIL")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
