base = "android/app/src/main/java/com/testlogon/android"

def patch(rel, edits):
    p = base + "/" + rel
    s = open(p, encoding="utf-8").read()
    orig = s
    for old, new in edits:
        n = s.count(old)
        if n < 1:
            raise SystemExit(f"[{rel}] ANCHOR NOT FOUND: {old[:70]!r}")
        s = s.replace(old, new, 1)
    open(p, "w", encoding="utf-8").write(s)
    print(f"PATCHED {rel}; delta {len(s)-len(orig)}")

# 1) FeedDtos.kt: two new wire fields
patch("data/feed/FeedDtos.kt", [
    (
        '    @Json(name = "subscriber_locked") val subscriberLocked: Boolean = false,\n',
        '    @Json(name = "subscriber_locked") val subscriberLocked: Boolean = false,\n'
        '    // SUBX-31: the minimum tier LEVEL this subscriber-only post requires (0 = any\n'
        '    // active sub - the pre-tier binary default) + the display NAME of that tier so\n'
        '    // the lock card can name the required tier and upsell to it.\n'
        '    @Json(name = "required_tier_level") val requiredTierLevel: Int = 0,\n'
        '    @Json(name = "required_tier_name") val requiredTierName: String? = null,\n',
    ),
])

# 2) FeedDomain.kt: carry tier on the paywall + map it
patch("data/feed/FeedDomain.kt", [
    (
        '    data class SubscriberLocked(val creatorId: String) : Paywall',
        '    data class SubscriberLocked(\n'
        '        val creatorId: String,\n'
        '        // SUBX-31: the tier the viewer must buy to unlock (0/null = any active sub).\n'
        '        val requiredTierLevel: Int = 0,\n'
        '        val requiredTierName: String? = null,\n'
        '    ) : Paywall',
    ),
    (
        '    if (subscriberLocked) {\n'
        '        return Paywall.SubscriberLocked(creatorId?.takeIf { it.isNotBlank() } ?: authorId)\n'
        '    }',
        '    if (subscriberLocked) {\n'
        '        return Paywall.SubscriberLocked(\n'
        '            creatorId = creatorId?.takeIf { it.isNotBlank() } ?: authorId,\n'
        '            requiredTierLevel = requiredTierLevel,\n'
        '            requiredTierName = requiredTierName?.takeIf { it.isNotBlank() },\n'
        '        )\n'
        '    }',
    ),
])

# 3) PostItem.kt: pass the tier through to the card
patch("feature/feed/PostItem.kt", [
    (
        '                is Paywall.SubscriberLocked -> SubscriberLockCard(\n'
        '                    creatorName = authorName?.takeIf { it.isNotBlank() } ?: paywall.creatorId,\n'
        '                    onSubscribeClick = { onSubscribeClick(paywall.creatorId) },\n'
        '                    style = PaywallStyle.Feed,\n'
        '                )',
        '                is Paywall.SubscriberLocked -> SubscriberLockCard(\n'
        '                    creatorName = authorName?.takeIf { it.isNotBlank() } ?: paywall.creatorId,\n'
        '                    onSubscribeClick = { onSubscribeClick(paywall.creatorId) },\n'
        '                    style = PaywallStyle.Feed,\n'
        '                    requiredTierName = paywall.requiredTierName,\n'
        '                    requiredTierLevel = paywall.requiredTierLevel,\n'
        '                )',
    ),
])

# 4) SubscriberLockCard.kt: show the required tier + upsell to it
patch("feature/feed/SubscriberLockCard.kt", [
    (
        'fun SubscriberLockCard(\n'
        '    creatorName: String,\n'
        '    onSubscribeClick: () -> Unit,\n'
        '    modifier: Modifier = Modifier,\n'
        '    style: PaywallStyle = PaywallStyle.Feed,\n'
        ') {\n'
        '    val label = "Subscribers only"\n'
        '    val sub = "Subscribe to $creatorName to unlock this content."\n'
        '    val cd = "Locked post. Subscribers only. Subscribe to $creatorName to unlock."',
        'fun SubscriberLockCard(\n'
        '    creatorName: String,\n'
        '    onSubscribeClick: () -> Unit,\n'
        '    modifier: Modifier = Modifier,\n'
        '    style: PaywallStyle = PaywallStyle.Feed,\n'
        '    // SUBX-31: when the post requires a specific tier LEVEL, name that tier and\n'
        '    // upsell to it (rather than a generic "subscribe"). 0/null = binary any-sub.\n'
        '    requiredTierName: String? = null,\n'
        '    requiredTierLevel: Int = 0,\n'
        ') {\n'
        '    val tier = requiredTierName?.takeIf { it.isNotBlank() }\n'
        '    val label = if (tier != null) "$tier tier required" else "Subscribers only"\n'
        '    val sub = if (tier != null) {\n'
        '        "This post is for $creatorName\'s $tier tier. Subscribe at that tier to unlock it."\n'
        '    } else {\n'
        '        "Subscribe to $creatorName to unlock this content."\n'
        '    }\n'
        '    val cd = if (tier != null) {\n'
        '        "Locked post. Requires the $tier tier. Subscribe to $creatorName at the $tier tier to unlock."\n'
        '    } else {\n'
        '        "Locked post. Subscribers only. Subscribe to $creatorName to unlock."\n'
        '    }',
    ),
    (
        '        TlButton(\n'
        '            text = "Subscribe to unlock",\n'
        '            onClick = onSubscribeClick,\n'
        '            modifier = Modifier.testTag(SubscriberLockTestTags.CTA),\n'
        '        )',
        '        TlButton(\n'
        '            text = if (tier != null) "Subscribe to $tier" else "Subscribe to unlock",\n'
        '            onClick = onSubscribeClick,\n'
        '            modifier = Modifier.testTag(SubscriberLockTestTags.CTA),\n'
        '        )',
    ),
    (
        '        Pill(text = "Subscribers only", modifier = Modifier.align(Alignment.TopStart).padding(8.dp))',
        '        Pill(text = "Subscribers only", modifier = Modifier.align(Alignment.TopStart).padding(8.dp))  // teaser overlay (tier named on the card below)',
    ),
])
print("ALL APP FILES PATCHED")
