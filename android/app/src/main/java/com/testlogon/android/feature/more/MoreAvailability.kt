package com.testlogon.android.feature.more

import com.testlogon.android.R
import com.testlogon.android.navigation.MoreRoutes
import java.util.concurrent.atomic.AtomicBoolean
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-067 — the set of routes the authenticated nav graph actually registers, so the resolver's
 * "is registered" check is authoritative rather than guessed. Populated from [MoreRoutes].
 */
@Singleton
open class RouteRegistry @Inject constructor() {
    private val registered: Set<String> = MoreRoutes.REGISTERED

    open fun isRegistered(route: String): Boolean = route in registered
}

/**
 * B5 — process-wide admin-visibility flag for the More hub.
 *
 * Operator/admin-only entries were previously statically hidden because the cookie-session client had no role
 * signal. Batch-7 surfaced `GET /ui/me.is_admin`, so [MoreViewModel] resolves it once and sets [isAdmin] here;
 * the [MoreAvailabilityResolver] then reveals `operatorOnly` entries (the Admin hub) ONLY for a confirmed admin.
 * A non-admin (or unresolved) keeps them Hidden — and the backend 403 remains authoritative regardless.
 * Default is false (member view) so nothing is advertised until the admin check succeeds.
 */
@Singleton
class AdminVisibility @Inject constructor() {
    private val admin = AtomicBoolean(false)

    var isAdmin: Boolean
        get() = admin.get()
        set(value) = admin.set(value)
}

/**
 * AND-067 / B5 — pure availability resolver.
 *
 * Precedence: unregistered route → Hidden (never advertise an unbuilt feature); operator-only + not-admin →
 * Hidden; explicit coming-soon flag → Disabled(reason). Registered + (visible) + not coming-soon → Available.
 * An operator-only entry is Available ONLY when the resolved role is admin (B5 Admin hub reveal).
 */
@Singleton
class MoreAvailabilityResolver @Inject constructor(
    private val routeRegistry: RouteRegistry,
    private val adminVisibility: AdminVisibility = AdminVisibility(),
) {
    fun resolve(entry: MoreEntry): EntryAvailability = when {
        !routeRegistry.isRegistered(entry.route) -> EntryAvailability.Hidden
        entry.operatorOnly && !adminVisibility.isAdmin -> EntryAvailability.Hidden
        entry.comingSoon -> EntryAvailability.Disabled(R.string.more_unavailable_coming_soon)
        else -> EntryAvailability.Available
    }
}
