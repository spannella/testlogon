#!/usr/bin/env python3
"""Wire the appeals feature into the 4 shared files. Idempotent + anchor-asserted."""
import sys, io

ROOT = "/home/sean/dev/testlogon/android/app/src/main"
JAVA = ROOT + "/java/com/testlogon/android"

def patch(path, anchor, insert, marker):
    with io.open(path, encoding="utf-8") as f:
        s = f.read()
    if marker in s:
        print("  already present:", marker, "in", path.split("/")[-1])
        return
    if anchor not in s:
        sys.exit("ANCHOR NOT FOUND in %s:\n%r" % (path, anchor))
    s = s.replace(anchor, insert, 1)
    with io.open(path, "w", encoding="utf-8") as f:
        f.write(s)
    print("  patched:", path.split("/")[-1], "<-", marker)

mr = JAVA + "/navigation/MoreRoutes.kt"
patch(mr,
      "    const val ALERTS = AlertsDest.ROUTE",
      "    const val ALERTS = AlertsDest.ROUTE\n\n    // Account-action appeals - mirrors web /appeals.\n    const val APPEALS = AppealsDest.ROUTE",
      "const val APPEALS = AppealsDest.ROUTE")
patch(mr,
      "            ALERTS,",
      "            ALERTS,\n            APPEALS,",
      "            APPEALS,")

mc = JAVA + "/feature/more/MoreCatalog.kt"
# Gavel import already present per the build agent; guard anyway.
patch(mc,
      "import androidx.compose.material.icons.outlined.Gavel",
      "import androidx.compose.material.icons.outlined.Gavel",
      "import androidx.compose.material.icons.outlined.Gavel")  # marker==anchor -> always "already present"
entry = (
    "        MoreEntry(\n"
    "            id = \"appeals\",\n"
    "            labelRes = R.string.more_entry_appeals,\n"
    "            icon = Icons.Outlined.Gavel,\n"
    "            route = MoreRoutes.APPEALS,\n"
    "            section = MoreSection.SUPPORT,\n"
    "        ),\n"
)
patch(mc,
      "        MoreEntry(\n            id = \"files\",",
      entry + "        MoreEntry(\n            id = \"files\",",
      "id = \"appeals\",")

ag = JAVA + "/navigation/AuthenticatedGraph.kt"
patch(ag,
      "        alertsDestination(navController)",
      "        alertsDestination(navController)\n        // Account-action appeals.\n        appealsDestination(navController)",
      "appealsDestination(navController)")

sx = ROOT + "/res/values/strings.xml"
block = (
    "    <!-- Appeals (web /appeals parity) -->\n"
    "    <string name=\"more_entry_appeals\">Appeals</string>\n"
    "    <string name=\"appeals_title\">My appeals</string>\n"
    "    <string name=\"appeals_new\">New appeal</string>\n"
    "    <string name=\"appeals_error_generic\">Something went wrong loading your appeals.</string>\n"
    "    <string name=\"appeals_session_expired_title\">Session expired</string>\n"
    "    <string name=\"appeals_session_expired_body\">Please sign in again to view your appeals.</string>\n"
    "    <string name=\"appeals_empty_title\">No appeals yet</string>\n"
    "    <string name=\"appeals_empty_body\">If you disagree with an enforcement action, you can file an appeal here.</string>\n"
    "    <string name=\"appeals_submitted_on\">Submitted %1$s</string>\n"
    "    <string name=\"appeals_decision_label\">Decision</string>\n"
    "    <string name=\"appeals_withdraw\">Withdraw</string>\n"
    "    <string name=\"appeals_cancel\">Cancel</string>\n"
    "    <string name=\"appeals_withdraw_confirm_title\">Withdraw appeal?</string>\n"
    "    <string name=\"appeals_withdraw_confirm_body\">This appeal will be withdrawn and can no longer be reviewed. This cannot be undone.</string>\n"
    "    <string name=\"appeals_withdraw_success\">Appeal withdrawn.</string>\n"
    "    <string name=\"appeals_withdraw_failed\">Could not withdraw the appeal. Please try again.</string>\n"
    "    <string name=\"appeals_submit_title\">File an appeal</string>\n"
    "    <string name=\"appeals_submit_helper\">The Enforcement ID is shown on the enforcement notice you received.</string>\n"
    "    <string name=\"appeals_submit_action\">Submit</string>\n"
    "    <string name=\"appeals_submit_success\">Appeal submitted.</string>\n"
    "    <string name=\"appeals_submit_failed\">Could not submit the appeal. Please try again.</string>\n"
    "    <string name=\"appeals_field_enforcement_id\">Enforcement ID</string>\n"
    "    <string name=\"appeals_field_appeal_text\">Appeal text</string>\n"
    "    <string name=\"appeals_refresh_failed_stale\">Could not refresh. Showing the last loaded appeals.</string>\n"
    "    <string name=\"appeals_status_submitted\">Submitted</string>\n"
    "    <string name=\"appeals_status_under_review\">Under review</string>\n"
    "    <string name=\"appeals_status_upheld\">Upheld</string>\n"
    "    <string name=\"appeals_status_modified\">Modified</string>\n"
    "    <string name=\"appeals_status_reversed\">Reversed</string>\n"
    "    <string name=\"appeals_status_withdrawn\">Withdrawn</string>\n"
    "    <string name=\"appeals_status_unknown\">Unknown</string>\n"
    "</resources>"
)
patch(sx, "</resources>", block, "name=\"more_entry_appeals\"")
print("WIRE APPEALS DONE")
