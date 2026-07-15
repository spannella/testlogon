#!/usr/bin/env python3
"""SUBX X5 — app deep-link patch (AlertsScreen event set + AlertsNavigation query-aware routing)."""
import sys, os, io
ROOT = sys.argv[1]

def rd(p):
    with io.open(os.path.join(ROOT, p), "r", encoding="utf-8") as f:
        return f.read()

def wr(p, s):
    with io.open(os.path.join(ROOT, p), "w", encoding="utf-8") as f:
        f.write(s)

def sub_once(s, old, new, tag):
    n = s.count(old)
    if n != 1:
        raise SystemExit("APP-PATCH-FAIL [%s]: expected 1, found %d" % (tag, n))
    return s.replace(old, new)

BASE = "app/src/main/java/com/testlogon/android"

# ---- AlertsScreen.kt: add the 3 new subscription lifecycle events ----
P1 = BASE + "/feature/alerts/AlertsScreen.kt"
a = rd(P1)
a = sub_once(a,
    '    "subscription_started", "subscription_new_subscriber", "subscription_renewed",\n'
    '    "subscription_renewal_failed", "subscription_expiring", "subscription_expired",\n'
    '    "subscription_canceled", "subscription_gifted",\n',
    '    "subscription_started", "subscription_new_subscriber", "subscription_renewed",\n'
    '    "subscription_renewal_failed", "subscription_expiring", "subscription_expired",\n'
    '    "subscription_canceled", "subscription_gifted",\n'
    '    // SUBX-51: plan-change / creator-removal / trial-conversion lifecycle alerts.\n'
    '    "subscription_changed", "subscription_removed", "subscription_converted",\n',
    "AlertsScreen:events")
wr(P1, a)
print("OK", P1)

# ---- AlertsNavigation.kt: import Uri + query-aware manage routing (SUBX-50) ----
P2 = BASE + "/navigation/AlertsNavigation.kt"
b = rd(P2)
b = sub_once(b,
    'package com.testlogon.android.navigation\n\n'
    'import androidx.navigation.NavGraphBuilder\n',
    'package com.testlogon.android.navigation\n\n'
    'import android.net.Uri\n'
    'import androidx.navigation.NavGraphBuilder\n',
    "AlertsNav:import")

b = sub_once(b,
    '            onOpenSubscription = { event, actionUrl ->  // SUB-E5: (event, actionUrl)\n'
    '                val path = actionUrl.substringBefore(\'?\').trimEnd(\'/\').lowercase()\n'
    '                val dest = when {\n'
    '                    // creator-side (new-subscriber / renewed / canceled / gifted) -> E4 Subscribers screen\n'
    '                    path.endsWith("/subscribers") -> CreatorSubscribersDest.ROUTE\n'
    '                    // subscriber-side (started / renewed / renewal-failed / expiring / expired / gifter) -> manage\n'
    '                    path.endsWith("/manage") -> ManageSubscriptionDest.ROUTE\n'
    '                    // bare "/subscriptions": a creator\'s new-subscriber alert -> Subscribers screen; a\n'
    '                    // gift-recipient\'s alert (subscription_gifted) falls through to manage their new sub.\n'
    '                    event == "subscription_started" || event == "subscription_new_subscriber" ->\n'
    '                        CreatorSubscribersDest.ROUTE\n'
    '                    else -> ManageSubscriptionDest.ROUTE\n'
    '                }\n'
    '                navController.navigate(dest) { launchSingleTop = true }\n'
    '            },\n',
    '            onOpenSubscription = { event, actionUrl ->  // SUB-E5 / SUBX-50: (event, actionUrl)\n'
    '                val path = actionUrl.substringBefore(\'?\').trimEnd(\'/\').lowercase()\n'
    '                // SUBX-50: pull subscriptionId/creatorId off the action_url query so a\n'
    '                // renewal-failed / cancel / removal / convert push lands on the SPECIFIC sub\'s\n'
    '                // Manage/PAST_DUE recovery screen (SUBX-21/22), not the arg-less manage list.\n'
    '                val query = actionUrl.substringAfter(\'?\', "")\n'
    '                val params = query.split(\'&\').mapNotNull { kv ->\n'
    '                    val i = kv.indexOf(\'=\')\n'
    '                    if (i <= 0) null else kv.substring(0, i) to Uri.decode(kv.substring(i + 1))\n'
    '                }.toMap()\n'
    '                val subscriptionId = params["subscriptionId"]?.takeIf { it.isNotBlank() }\n'
    '                val creatorId = params["creatorId"]?.takeIf { it.isNotBlank() }\n'
    '                val manageRoute = ManageSubscriptionDest.build(subscriptionId = subscriptionId, creatorId = creatorId)\n'
    '                val dest = when {\n'
    '                    // creator-side (new-subscriber / renewed / canceled / gifted) -> E4 Subscribers screen\n'
    '                    path.endsWith("/subscribers") -> CreatorSubscribersDest.ROUTE\n'
    '                    // subscriber-side (started / renewed / renewal-failed / expiring / expired / changed /\n'
    '                    // removed / converted / gifter) -> the SPECIFIC sub\'s manage/recovery screen\n'
    '                    path.endsWith("/manage") -> manageRoute\n'
    '                    // bare "/subscriptions": a creator\'s new-subscriber alert -> Subscribers screen; a\n'
    '                    // gift-recipient\'s alert (subscription_gifted) falls through to manage their new sub.\n'
    '                    event == "subscription_started" || event == "subscription_new_subscriber" ->\n'
    '                        CreatorSubscribersDest.ROUTE\n'
    '                    else -> manageRoute\n'
    '                }\n'
    '                navController.navigate(dest) { launchSingleTop = true }\n'
    '            },\n',
    "AlertsNav:routing")
wr(P2, b)
print("OK", P2)
print("APP PATCH DONE")
