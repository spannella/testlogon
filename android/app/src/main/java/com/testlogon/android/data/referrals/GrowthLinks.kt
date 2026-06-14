package com.testlogon.android.data.referrals

/**
 * AND-264/265 — the public web origin used to build user-shareable referral / affiliate links.
 *
 * The web client uses `window.location.origin`; there is no public origin in the OpenAPI/web sources
 * (UNVERIFIED-ASSUMPTION, mirrors PostShare's WEB_BASE). This MUST be the public HTTPS site, never the
 * cleartext dev API host (18.222.237.167:8000). Centralized here so referrals + affiliates share one
 * constant and a single unit test pins it.
 */
object GrowthLinks {
    const val WEB_ORIGIN: String = "https://app.testlogon.com"
}

/**
 * The referral dashboard payload carries no currency code (all amounts are USD cents on the web, which
 * renders `cents/100` with `$`). USD is the rendering default; money formatting still goes through the
 * reusable locale-aware [com.testlogon.android.feature.earnings.formatEarningsMoney].
 */
const val DEFAULT_CURRENCY_USD: String = "USD"
