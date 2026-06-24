#!/usr/bin/env python3
"""Wire ideas + licenses + watch-parties + bots into the 4 shared files. Idempotent + anchor-asserted.
All string VALUES are ASCII and apostrophe-free (aapt rejects unescaped apostrophes)."""
import sys, io

ROOT = "/home/sean/dev/testlogon/android/app/src/main"
JAVA = ROOT + "/java/com/testlogon/android"

def patch(path, anchor, insert, marker, label=""):
    with io.open(path, encoding="utf-8") as f:
        s = f.read()
    if marker in s:
        print("  already present:", label or marker)
        return
    if anchor not in s:
        sys.exit("ANCHOR NOT FOUND in %s:\n%r" % (path, anchor))
    s = s.replace(anchor, insert, 1)
    with io.open(path, "w", encoding="utf-8") as f:
        f.write(s)
    print("  patched:", path.split("/")[-1], "<-", label or marker)

# ---------- 1) MoreRoutes.kt ----------
mr = JAVA + "/navigation/MoreRoutes.kt"
patch(mr,
      "    const val APPEALS = AppealsDest.ROUTE",
      "    const val APPEALS = AppealsDest.ROUTE\n\n"
      "    // Web-route parity batch.\n"
      "    const val IDEAS = IdeasDest.ROUTE\n"
      "    const val LICENSES = LicensesDest.ROUTE\n"
      "    const val WATCH_PARTIES = WatchPartiesDest.LIST\n"
      "    const val BOTS = BotsDest.LIST",
      "const val IDEAS = IdeasDest.ROUTE", "MoreRoutes consts")
patch(mr,
      "            APPEALS,",
      "            APPEALS,\n            IDEAS,\n            LICENSES,\n            WATCH_PARTIES,\n            BOTS,",
      "            IDEAS,", "MoreRoutes REGISTERED")

# ---------- 2) MoreCatalog.kt: icon imports (guarded) + entries ----------
mc = JAVA + "/feature/more/MoreCatalog.kt"
for icon in ("Lightbulb", "Copyright", "SmartToy"):  # LiveTv already imported
    imp = "import androidx.compose.material.icons.outlined.%s" % icon
    patch(mc,
          "import androidx.compose.material.icons.outlined.FolderOpen",
          "import androidx.compose.material.icons.outlined.FolderOpen\n" + imp,
          imp, "import " + icon)

def entry(id_, label, icon, route, section):
    return ("        MoreEntry(\n"
            "            id = \"%s\",\n"
            "            labelRes = R.string.%s,\n"
            "            icon = Icons.Outlined.%s,\n"
            "            route = MoreRoutes.%s,\n"
            "            section = MoreSection.%s,\n"
            "        ),\n") % (id_, label, icon, route, section)

entries = (
    entry("ideas", "more_entry_ideas", "Lightbulb", "IDEAS", "SUPPORT") +
    entry("licenses", "more_entry_licenses", "Copyright", "LICENSES", "ACCOUNT") +
    entry("watch_parties", "more_entry_watch_parties", "LiveTv", "WATCH_PARTIES", "APP") +
    entry("bots", "more_entry_bots", "SmartToy", "BOTS", "APP")
)
patch(mc,
      "        MoreEntry(\n            id = \"files\",",
      entries + "        MoreEntry(\n            id = \"files\",",
      "id = \"ideas\",", "MoreCatalog entries")

# ---------- 3) AuthenticatedGraph.kt ----------
ag = JAVA + "/navigation/AuthenticatedGraph.kt"
patch(ag,
      "        appealsDestination(navController)",
      "        appealsDestination(navController)\n"
      "        ideasDestination(navController)\n"
      "        licensesDestination(navController)\n"
      "        watchPartiesDestinations(navController)\n"
      "        botsDestinations(navController)",
      "ideasDestination(navController)", "AuthenticatedGraph")

# ---------- 4) strings.xml ----------
STRINGS = [
    # ideas
    ("more_entry_ideas", "Ideas"),
    ("ideas_title", "Ideas"),
    ("ideas_new", "Submit an idea"),
    ("ideas_untitled", "Untitled idea"),
    ("ideas_submitted_on", "Submitted %1$s"),
    ("ideas_rejection_reason", "Reason: %1$s"),
    ("ideas_error_generic", "Something went wrong. Pull down to retry."),
    ("ideas_refresh_failed_stale", "Could not refresh. Showing your last saved ideas."),
    ("ideas_submit_success", "Idea submitted. Our team will triage it shortly."),
    ("ideas_submit_failed", "Could not submit your idea. Please try again."),
    ("ideas_empty_title", "No ideas yet"),
    ("ideas_empty_body", "Have a feature in mind? Share it and our team will take a look."),
    ("ideas_session_expired_title", "Session expired"),
    ("ideas_session_expired_body", "Please sign in again to view your ideas."),
    ("ideas_submit_title", "Submit a product idea"),
    ("ideas_submit_helper", "Describe the problem, who it helps, and the desired outcome."),
    ("ideas_field_title", "Title"),
    ("ideas_field_title_hint", "A short, descriptive title"),
    ("ideas_field_description", "Description"),
    ("ideas_field_description_hint", "Describe the problem, who it helps, and the desired outcome."),
    ("ideas_submit_action", "Submit idea"),
    ("ideas_cancel", "Cancel"),
    ("ideas_status_submitted", "Submitted"),
    ("ideas_status_triaging", "Triaging"),
    ("ideas_status_accepted", "Accepted"),
    ("ideas_status_rejected", "Rejected"),
    ("ideas_status_converted", "Converted"),
    ("ideas_status_unknown", "Unknown"),
    # licenses
    ("more_entry_licenses", "Licenses"),
    ("licenses_title", "Licenses"),
    ("licenses_tab_issued", "Issued"),
    ("licenses_tab_requests", "Requests"),
    ("licenses_tab_revenue", "Revenue"),
    ("licenses_error_generic", "Something went wrong loading your licenses."),
    ("licenses_refresh_failed_stale", "Could not refresh. Showing the last loaded data."),
    ("licenses_session_expired_title", "Session expired"),
    ("licenses_session_expired_body", "Please sign in again to view your licenses."),
    ("licenses_issued_empty_title", "No issued licenses"),
    ("licenses_issued_empty_body", "Licenses you have been granted will appear here."),
    ("licenses_requests_empty_title", "No license requests"),
    ("licenses_requests_empty_body", "License requests you have sent will appear here."),
    ("licenses_revenue_empty_title", "No license revenue"),
    ("licenses_revenue_empty_body", "Revenue from your licenses will appear here."),
    ("licenses_request_terms", "Fixed %1$s + %2$.0f%% revenue share"),
    ("licenses_request_denied_reason", "Denied: %1$s"),
    ("licenses_revenue_total_label", "Total earned"),
    ("licenses_revenue_transactions_count", "%1$d transactions"),
    ("licenses_revenue_source_fallback", "License"),
    # watch parties
    ("more_entry_watch_parties", "Watch parties"),
    ("watch_parties_title", "Watch parties"),
    ("watch_parties_detail_title", "Watch party"),
    ("watch_parties_error_generic", "Something went wrong. Try again."),
    ("watch_parties_empty_title", "No watch parties yet"),
    ("watch_parties_empty_body", "Create one to watch together."),
    ("watch_parties_session_expired_title", "Session expired"),
    ("watch_parties_session_expired_body", "Please sign in again to continue."),
    ("watch_parties_participants_count", "%1$d/%2$d watching"),
    ("watch_parties_invite_code", "Invite: %1$s"),
    ("watch_parties_status_waiting", "Waiting"),
    ("watch_parties_status_playing", "Playing"),
    ("watch_parties_status_paused", "Paused"),
    ("watch_parties_status_ended", "Ended"),
    ("watch_parties_status_unknown", "Unknown"),
    ("watch_parties_create_action", "Create watch party"),
    ("watch_parties_create_title", "Create watch party"),
    ("watch_parties_create_video_label", "Video ID"),
    ("watch_parties_create_title_label", "Party title (optional)"),
    ("watch_parties_create_max_label", "Max participants"),
    ("watch_parties_create_confirm", "Create"),
    ("watch_parties_create_submitting", "Creating"),
    ("watch_parties_create_video_required", "Enter a video ID."),
    ("watch_parties_create_failed", "Could not create the party. Try again."),
    ("watch_parties_refresh_failed_stale", "Could not refresh. Showing the last known list."),
    ("watch_parties_detail_sync_unavailable_title", "Live sync not available"),
    ("watch_parties_detail_sync_unavailable_body", "Real-time playback sync is not available in the app yet. You can still join, leave, and see who is here."),
    ("watch_parties_detail_participants_label", "Participants"),
    ("watch_parties_detail_invite_label", "Invite code"),
    ("watch_parties_detail_created_label", "Created"),
    ("watch_parties_detail_participants_header", "Who is here"),
    ("watch_parties_detail_participants_empty", "No active participants."),
    ("watch_parties_detail_join_action", "Join party"),
    ("watch_parties_detail_leave_action", "Leave party"),
    ("watch_parties_detail_ended_note", "This party has ended."),
    ("watch_parties_role_host", "Host"),
    ("watch_parties_role_cohost", "Co-host"),
    ("watch_parties_role_member", "Member"),
    ("watch_parties_join_success", "Joined the party."),
    ("watch_parties_join_failed", "Could not join. Try again."),
    ("watch_parties_leave_success", "You left the party."),
    ("watch_parties_leave_failed", "Could not leave. Try again."),
    ("watch_parties_invite_failed", "That invite link is invalid or expired."),
    # bots
    ("more_entry_bots", "Bots"),
    ("bots_title", "Bots"),
    ("bots_new", "New bot"),
    ("bots_message_count", "%1$d messages"),
    ("bots_action_auto_reply", "Auto-reply"),
    ("bots_action_templates", "Templates"),
    ("bots_action_pause", "Pause"),
    ("bots_action_enable", "Enable"),
    ("bots_action_delete", "Delete"),
    ("bots_status_active", "Active"),
    ("bots_status_paused", "Paused"),
    ("bots_status_disabled", "Disabled"),
    ("bots_status_unknown", "Unknown"),
    ("bots_empty_title", "No bots yet"),
    ("bots_empty_body", "Create your first bot to automate conversations."),
    ("bots_error_generic", "Something went wrong."),
    ("bots_session_expired_title", "Session expired"),
    ("bots_session_expired_body", "Sign in again to continue."),
    ("bots_create_title", "Create bot"),
    ("bots_create_action", "Create bot"),
    ("bots_field_name", "Name"),
    ("bots_field_description", "Description"),
    ("bots_field_personality", "Personality"),
    ("bots_create_success", "Bot created"),
    ("bots_create_failed", "Failed to create bot"),
    ("bots_status_success", "Bot status updated"),
    ("bots_status_failed", "Failed to update status"),
    ("bots_delete_success", "Bot deleted"),
    ("bots_delete_failed", "Failed to delete bot"),
    ("bots_delete_confirm_title", "Delete bot?"),
    ("bots_delete_confirm_body", "Delete %1$s? This cannot be undone."),
    ("bots_refresh_failed_stale", "Could not refresh. Showing saved bots."),
    ("bots_cancel", "Cancel"),
    ("bots_save", "Save"),
    ("bots_auto_reply_title", "Auto-reply rules"),
    ("bots_auto_reply_empty_title", "No auto-reply rules"),
    ("bots_auto_reply_empty_body", "Add a rule to reply automatically to matching messages."),
    ("bots_rule_new", "New rule"),
    ("bots_rule_edit", "Edit"),
    ("bots_rule_delete", "Delete"),
    ("bots_rule_priority", "Priority: %1$d"),
    ("bots_rule_disabled", "Disabled"),
    ("bots_rule_create_title", "New rule"),
    ("bots_rule_edit_title", "Edit rule"),
    ("bots_field_trigger", "Trigger pattern"),
    ("bots_field_response", "Response"),
    ("bots_field_match_type", "Match type"),
    ("bots_field_priority", "Priority"),
    ("bots_field_enabled", "Enabled"),
    ("bots_match_keyword", "Keyword"),
    ("bots_match_contains", "Contains"),
    ("bots_match_exact", "Exact"),
    ("bots_match_regex", "Regex"),
    ("bots_rule_create_success", "Rule created"),
    ("bots_rule_update_success", "Rule updated"),
    ("bots_rule_save_failed", "Failed to save rule"),
    ("bots_rule_delete_success", "Rule deleted"),
    ("bots_rule_delete_failed", "Failed to delete rule"),
    ("bots_rule_delete_confirm_title", "Delete rule?"),
    ("bots_rule_delete_confirm_body", "This cannot be undone."),
    ("bots_templates_title", "Templates"),
    ("bots_templates_empty_title", "No templates"),
    ("bots_templates_empty_body", "Create a reusable message template."),
    ("bots_template_new", "New template"),
    ("bots_template_delete", "Delete"),
    ("bots_template_create_title", "New template"),
    ("bots_template_create_action", "Create"),
    ("bots_field_template_name", "Name"),
    ("bots_field_template_text", "Text"),
    ("bots_field_category", "Category"),
    ("bots_category_greeting", "Greeting"),
    ("bots_category_support", "Support"),
    ("bots_category_promotion", "Promotion"),
    ("bots_category_farewell", "Farewell"),
    ("bots_category_away", "Away"),
    ("bots_category_custom", "Custom"),
    ("bots_template_create_success", "Template created"),
    ("bots_template_create_failed", "Failed to create template"),
    ("bots_template_delete_success", "Template deleted"),
    ("bots_template_delete_failed", "Failed to delete template"),
    ("bots_template_delete_confirm_body", "Delete %1$s? This cannot be undone."),
]
sx = ROOT + "/res/values/strings.xml"
with io.open(sx, encoding="utf-8") as f:
    sxt = f.read()
lines = ["    <!-- web-route parity batch: ideas / licenses / watch-parties / bots -->"]
added = 0
for k, v in STRINGS:
    if ('name="%s"' % k) in sxt:
        continue
    if "'" in v or "&" in v or "<" in v:
        sys.exit("ILLEGAL CHAR in string %s: %r" % (k, v))
    lines.append('    <string name="%s">%s</string>' % (k, v))
    added += 1
block = "\n".join(lines) + "\n</resources>"
if "</resources>" not in sxt:
    sys.exit("no </resources>")
sxt = sxt.replace("</resources>", block, 1)
with io.open(sx, "w", encoding="utf-8") as f:
    f.write(sxt)
print("  strings added:", added)
print("WIRE BATCH DONE")
