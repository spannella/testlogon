#!/usr/bin/env python3
"""Wire the alerts-inbox feature into the 4 shared files. Idempotent + anchor-asserted."""
import sys, io

ROOT = "/home/sean/dev/testlogon/android/app/src/main"
JAVA = ROOT + "/java/com/testlogon/android"

def patch(path, anchor, insert, marker):
    with io.open(path, encoding="utf-8") as f:
        s = f.read()
    if marker in s:
        print("  already wired:", path)
        return
    if anchor not in s:
        sys.exit("ANCHOR NOT FOUND in %s:\n%r" % (path, anchor))
    s = s.replace(anchor, insert, 1)
    with io.open(path, "w", encoding="utf-8") as f:
        f.write(s)
    print("  patched:", path)

# 1) MoreRoutes.kt — const + REGISTERED entry (AlertsDest is same package, no import)
mr = JAVA + "/navigation/MoreRoutes.kt"
patch(mr,
      "    const val REFERRALS = ReferralsDest.ROUTE",
      "    const val REFERRALS = ReferralsDest.ROUTE\n\n    // Alerts (system notifications) inbox — mirrors web /alerts.\n    const val ALERTS = AlertsDest.ROUTE",
      "const val ALERTS = AlertsDest.ROUTE")
patch(mr,
      "            REFERRALS,",
      "            REFERRALS,\n            ALERTS,",
      "            ALERTS,")

# 2) MoreCatalog.kt — icon import + entry (inserted before the Files entry)
mc = JAVA + "/feature/more/MoreCatalog.kt"
patch(mc,
      "import androidx.compose.material.icons.outlined.FolderOpen",
      "import androidx.compose.material.icons.outlined.FolderOpen\nimport androidx.compose.material.icons.outlined.NotificationsActive",
      "import androidx.compose.material.icons.outlined.NotificationsActive")
entry = (
    "        MoreEntry(\n"
    "            id = \"alerts\",\n"
    "            labelRes = R.string.more_entry_alerts,\n"
    "            icon = Icons.Outlined.NotificationsActive,\n"
    "            route = MoreRoutes.ALERTS,\n"
    "            section = MoreSection.APP,\n"
    "        ),\n"
)
patch(mc,
      "        MoreEntry(\n            id = \"files\",",
      entry + "        MoreEntry(\n            id = \"files\",",
      "id = \"alerts\",")

# 3) AuthenticatedGraph.kt — register destination (same package, no import)
ag = JAVA + "/navigation/AuthenticatedGraph.kt"
patch(ag,
      "        referralsDestination(navController)",
      "        referralsDestination(navController)\n        // Alerts (system notifications) inbox.\n        alertsDestination(navController)",
      "alertsDestination(navController)")

# 4) strings.xml — labels + inbox strings (guarded on more_entry_alerts)
sx = ROOT + "/res/values/strings.xml"
block = (
    "    <!-- Alerts inbox (web /alerts parity) -->\n"
    "    <string name=\"more_entry_alerts\">Alerts</string>\n"
    "    <string name=\"alerts_inbox_title\">Alerts</string>\n"
    "    <string name=\"alerts_inbox_mark_all\">Mark all read</string>\n"
    "    <string name=\"alerts_inbox_filter_unread\">Show unread only</string>\n"
    "    <string name=\"alerts_inbox_empty_title\">No alerts</string>\n"
    "    <string name=\"alerts_inbox_empty_body\">You are all caught up. New alerts will show up here.</string>\n"
    "    <string name=\"alerts_inbox_error_generic\">We could not load your alerts.</string>\n"
    "    <string name=\"alerts_inbox_session_expired_title\">Session expired</string>\n"
    "    <string name=\"alerts_inbox_session_expired_body\">Please sign in again to view your alerts.</string>\n"
    "    <string name=\"alerts_inbox_marked_all\">All alerts marked as read</string>\n"
    "    <string name=\"alerts_inbox_mark_failed\">Could not update. Try again.</string>\n"
    "    <string name=\"alerts_inbox_refresh_failed_stale\">Showing saved alerts. Refresh failed.</string>\n"
    "    <string name=\"alerts_inbox_priority_urgent\">Urgent</string>\n"
    "</resources>"
)
patch(sx, "</resources>", block, "name=\"more_entry_alerts\"")

print("WIRE DONE")
