package com.testlogon.android.navigation.applink

import javax.inject.Qualifier

/**
 * AND-396 — central App Links result + parser/router contract.
 *
 * This is the single, testable seam that turns an inbound verified HTTP(S) App Link into a typed
 * in-app navigation target (a Navigation-Compose route string produced by the AND-022 destination
 * `build(...)` helpers) or a typed failure. Per-feature `navDeepLink {}` registrations (AND-061,
 * 073, 190, 196, 272, 335, 392, 393, ...) still drive the actual NavController navigation when the
 * platform delivers a VIEW intent; this central parser is the pure, unit-testable mapping the spec
 * (FR-3) calls for plus the warm/cold buffering router (FR-4/5/6).
 *
 * The parser is intentionally I/O-free and operates on the URL string (parsed via java.net.URI), so
 * it is JVM-unit-testable WITHOUT Robolectric — the same dependency-free pattern used by the payment
 * / Google-Calendar / Drive return handlers (android.net.Uri is touched only at the Activity layer).
 */

/** A parsed App Link outcome. `parse` is total: every input yields exactly one of these. */
sealed interface DeepLink {
    /**
     * Host matched an allowlisted verified host AND the path mapped to a known native route.
     *
     * [route] is the Navigation-Compose route string (built by an AND-022 destination helper);
     * [requiresAuth] is true when the destination lives only in the authenticated graph.
     */
    data class Resolved(val route: String, val requiresAuth: Boolean) : DeepLink

    /** Resolved to an authenticated route but no session exists yet (router buffers + routes to auth). */
    data object RequiresAuth : DeepLink

    /** Host matched but the path is not mapped to any native route (router falls back to Home). */
    data object Unhandled : DeepLink

    /** Not parseable, wrong scheme, or a non-allowlisted host (security: never produces a route). */
    data object Malformed : DeepLink
}

/**
 * The set of verified hosts the parser accepts. Any other host yields [DeepLink.Malformed] (SEC-1).
 *
 * Injected as a [Set] so per-flavor `manifestPlaceholders` / build config can vary it (prod vs.
 * staging) without changing the parser (R-4 staging-hijack mitigation).
 */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class AppLinkHosts
