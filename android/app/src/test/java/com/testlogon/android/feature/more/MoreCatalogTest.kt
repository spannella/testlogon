package com.testlogon.android.feature.more

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Person
import com.testlogon.android.R
import com.testlogon.android.navigation.MoreRoutes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MoreCatalogTest {

    private class FakeRegistry(private val routes: Set<String>) : RouteRegistry() {
        override fun isRegistered(route: String): Boolean = route in routes
    }

    private fun entry(route: String, section: MoreSection, comingSoon: Boolean = false) = MoreEntry(
        id = route,
        labelRes = R.string.more_entry_profile,
        icon = Icons.Outlined.Person,
        route = route,
        hub = MoreHub.ACCOUNT,
        section = section,
        comingSoon = comingSoon,
    )

    @Test
    fun catalogIntegrity_everyRouteIsRegistered() {
        val registry = RouteRegistry()
        MoreCatalog().entries.forEach { e ->
            assertTrue("route not registered: ${e.route}", registry.isRegistered(e.route))
        }
    }

    @Test
    fun toUiState_filtersHidden_andSuppressesEmptySections() {
        val resolver = MoreAvailabilityResolver(FakeRegistry(setOf("a")))
        val entries = listOf(
            entry("a", MoreSection.ACCOUNT),       // Available
            entry("b", MoreSection.SECURITY),      // Hidden (unregistered) -> section suppressed
        )
        val state = entries.toUiState(resolver)
        assertTrue(state is MoreUiState.Content)
        val sections = (state as MoreUiState.Content).sections
        assertEquals(1, sections.size)
        assertEquals(MoreSection.ACCOUNT, sections.single().section)
    }

    @Test
    fun toUiState_disabledRemainsVisible() {
        val resolver = MoreAvailabilityResolver(FakeRegistry(setOf("a")))
        val state = listOf(entry("a", MoreSection.APP, comingSoon = true)).toUiState(resolver)
        assertTrue(state is MoreUiState.Content)
        val item = (state as MoreUiState.Content).sections.single().items.single()
        assertTrue(item.availability is EntryAvailability.Disabled)
    }

    @Test
    fun toUiState_allHidden_isEmpty() {
        val resolver = MoreAvailabilityResolver(FakeRegistry(emptySet()))
        val state = listOf(entry("a", MoreSection.APP)).toUiState(resolver)
        assertEquals(MoreUiState.Empty, state)
    }

    @Test
    fun operatorOnlyEntries_areFlaggedAndResolveHiddenForMembers() {
        val operatorIds = setOf(
            "admin_dashboard",
            "admin_email_dashboard",
            "admin_sms_dashboard",
            "billing_config",
            "bulk_payouts",
            "helpdesk_queue",
            "helpdesk_dashboard",
            "moderation_board",
            "video_review",
            "dmca_admin",
            "refund_admin",
            "dispute_admin",
            "appeal_admin",
            "fraud_admin",
            "incident_admin",
            "agent_configs",
        )
        val resolver = MoreAvailabilityResolver(RouteRegistry())
        val entries = MoreCatalog().entries
        operatorIds.forEach { id ->
            val e = entries.single { it.id == id }
            assertTrue("expected operatorOnly: \$id", e.operatorOnly)
            assertEquals(EntryAvailability.Hidden, resolver.resolve(e))
        }
        // The operator-only set has since grown (admin / KYC-admin / infra / remote parity added many),
        // so assert the listed core operator entries are a SUBSET of all operator-only entries rather than
        // pinning the exhaustive list (which would be brittle churn on every new admin surface).
        val allOperatorOnly = entries.filter { it.operatorOnly }.map { it.id }.toSet()
        assertTrue("listed operator ids must all be operator-only", allOperatorOnly.containsAll(operatorIds))
    }

    @Test
    fun realCatalog_resolvesToContent() {
        val resolver = MoreAvailabilityResolver(RouteRegistry())
        val state = MoreCatalog().entries.toUiState(resolver)
        assertTrue(state is MoreUiState.Content)
    }
}
