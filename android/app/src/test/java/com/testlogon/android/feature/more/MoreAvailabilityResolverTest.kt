package com.testlogon.android.feature.more

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Person
import com.testlogon.android.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MoreAvailabilityResolverTest {

    private fun entry(route: String, comingSoon: Boolean = false) = MoreEntry(
        id = route,
        labelRes = R.string.more_entry_profile,
        icon = Icons.Outlined.Person,
        route = route,
        section = MoreSection.ACCOUNT,
        comingSoon = comingSoon,
    )

    private class FakeRegistry(private val routes: Set<String>) : RouteRegistry() {
        override fun isRegistered(route: String): Boolean = route in routes
    }

    private fun resolver(registered: Set<String>) =
        MoreAvailabilityResolver(FakeRegistry(registered))

    @Test
    fun registeredAndNotComingSoon_available() {
        assertEquals(EntryAvailability.Available, resolver(setOf("a")).resolve(entry("a")))
    }

    @Test
    fun unregistered_hidden() {
        assertEquals(EntryAvailability.Hidden, resolver(emptySet()).resolve(entry("a")))
    }

    @Test
    fun comingSoon_disabled() {
        val r = resolver(setOf("a")).resolve(entry("a", comingSoon = true))
        assertTrue(r is EntryAvailability.Disabled)
        assertEquals(R.string.more_unavailable_coming_soon, (r as EntryAvailability.Disabled).reasonRes)
    }

    @Test
    fun precedence_unregisteredBeatsComingSoon() {
        assertEquals(
            EntryAvailability.Hidden,
            resolver(emptySet()).resolve(entry("a", comingSoon = true)),
        )
    }

    @Test
    fun realRegistry_profileIsAvailable() {
        val resolver = MoreAvailabilityResolver(RouteRegistry())
        assertEquals(
            EntryAvailability.Available,
            resolver.resolve(entry(com.testlogon.android.navigation.MoreRoutes.PROFILE)),
        )
    }
}
