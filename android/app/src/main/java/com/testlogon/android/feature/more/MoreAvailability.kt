package com.testlogon.android.feature.more

import com.testlogon.android.R
import com.testlogon.android.navigation.MoreRoutes
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
 * AND-067 — pure availability resolver, unit-testable in isolation.
 *
 * Precedence: unregistered route → Hidden (never advertise an unbuilt feature); explicit
 * coming-soon flag → Disabled(reason). Registered + not coming-soon → Available.
 */
@Singleton
class MoreAvailabilityResolver @Inject constructor(
    private val routeRegistry: RouteRegistry,
) {
    fun resolve(entry: MoreEntry): EntryAvailability = when {
        !routeRegistry.isRegistered(entry.route) -> EntryAvailability.Hidden
        entry.operatorOnly -> EntryAvailability.Hidden
        entry.comingSoon -> EntryAvailability.Disabled(R.string.more_unavailable_coming_soon)
        else -> EntryAvailability.Available
    }
}
