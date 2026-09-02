package com.testlogon.android.data.crm

import com.testlogon.android.data.crm.CrmPecMath.CapacityState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CRM-AND-PEC — JVM unit tests for the pure Projects / Events / Campaigns logic (status classification,
 * capacity state, money/rate formatting, epoch→date formatting). No Android types; degrade-on-bad-input
 * is asserted so the UI never crashes on a 404 (module disabled) or dev-host drift.
 */
class CrmPecMathTest {

    // ── Project status ────────────────────────────────────────────────────────

    @Test
    fun projectStatusLabel_knownKeys() {
        assertEquals("Draft", CrmPecMath.projectStatusLabel("draft"))
        assertEquals("In review", CrmPecMath.projectStatusLabel("in_review"))
        assertEquals("Underway", CrmPecMath.projectStatusLabel("underway"))
        assertEquals("Completed", CrmPecMath.projectStatusLabel("completed"))
        assertEquals("Deferred", CrmPecMath.projectStatusLabel("deferred"))
    }

    @Test
    fun projectStatusLabel_unknownAndNullDegrade() {
        assertEquals(CrmPecMath.EM_DASH, CrmPecMath.projectStatusLabel(null))
        assertEquals("On Hold", CrmPecMath.projectStatusLabel("on_hold"))
    }

    @Test
    fun projectClassification_closedActive() {
        assertTrue(CrmPecMath.isProjectClosed("completed"))
        assertTrue(CrmPecMath.isProjectClosed("deferred"))
        assertFalse(CrmPecMath.isProjectClosed("underway"))
        assertTrue(CrmPecMath.isProjectActive("underway"))
        assertTrue(CrmPecMath.isProjectActive("in_review"))
        assertFalse(CrmPecMath.isProjectActive("draft"))
    }

    @Test
    fun clampPercent_bounds() {
        assertEquals(0, CrmPecMath.clampPercent(-10))
        assertEquals(0, CrmPecMath.clampPercent(0))
        assertEquals(55, CrmPecMath.clampPercent(55))
        assertEquals(100, CrmPecMath.clampPercent(140))
    }

    // ── Event capacity ────────────────────────────────────────────────────────

    @Test
    fun capacityState_unlimitedWhenNoCap() {
        assertEquals(CapacityState.UNLIMITED, CrmPecMath.capacityState(null, 5, null))
        assertEquals(CapacityState.UNLIMITED, CrmPecMath.capacityState(0, 5, null))
        assertEquals(CapacityState.UNLIMITED, CrmPecMath.capacityState(-3, 5, null))
    }

    @Test
    fun capacityState_openAndFull() {
        assertEquals(CapacityState.OPEN, CrmPecMath.capacityState(10, 3, 7))
        assertEquals(CapacityState.FULL, CrmPecMath.capacityState(10, 10, 0))
        // availableSpots absent -> derived from cap - accepted
        assertEquals(CapacityState.OPEN, CrmPecMath.capacityState(10, 3, null))
        assertEquals(CapacityState.FULL, CrmPecMath.capacityState(10, 12, null))
    }

    @Test
    fun capacityLabel_formats() {
        assertEquals("3 going", CrmPecMath.capacityLabel(null, 3))
        assertEquals("3 / 10", CrmPecMath.capacityLabel(10, 3))
    }

    // ── Campaign labels ─────────────────────────────────────────────────────────

    @Test
    fun campaignTypeLabel_knownAndUnknown() {
        assertEquals("Email", CrmPecMath.campaignTypeLabel("email"))
        assertEquals("SMS", CrmPecMath.campaignTypeLabel("sms"))
        assertEquals("Mail", CrmPecMath.campaignTypeLabel("mail"))
        assertEquals(CrmPecMath.EM_DASH, CrmPecMath.campaignTypeLabel(null))
        assertEquals("Push Notify", CrmPecMath.campaignTypeLabel("push_notify"))
    }

    @Test
    fun campaignStatusLabel_blankDegrades() {
        assertEquals(CrmPecMath.EM_DASH, CrmPecMath.campaignStatusLabel(""))
        assertEquals(CrmPecMath.EM_DASH, CrmPecMath.campaignStatusLabel(null))
        assertEquals("In Progress", CrmPecMath.campaignStatusLabel("in_progress"))
    }

    // ── Money / rate formatting ─────────────────────────────────────────────────

    @Test
    fun formatCents_groupsAndPads() {
        assertEquals("$0.00", CrmPecMath.formatCents(0))
        assertEquals("$1.05", CrmPecMath.formatCents(105))
        assertEquals("$1,234.56", CrmPecMath.formatCents(123456))
        assertEquals("$1,000,000.00", CrmPecMath.formatCents(100_000_000))
        assertEquals("-$1.50", CrmPecMath.formatCents(-150))
    }

    @Test
    fun formatRate_handlesFractionAndPercentAndClamp() {
        assertEquals("42.5%", CrmPecMath.formatRate(0.425))
        assertEquals("50%", CrmPecMath.formatRate(0.5))
        assertEquals("0%", CrmPecMath.formatRate(0.0))
        // already-percent drift (> 1.0) is treated as percent
        assertEquals("73%", CrmPecMath.formatRate(73.0))
        // out of range clamps
        assertEquals("100%", CrmPecMath.formatRate(250.0))
    }

    // ── Date formatting ──────────────────────────────────────────────────────────

    @Test
    fun formatDate_epochSeconds() {
        // 2021-01-01T00:00:00Z = 1609459200
        assertEquals("2021-01-01", CrmPecMath.formatDate(1_609_459_200L))
        // 1970-01-01
        assertEquals("1970-01-01", CrmPecMath.formatDate(1L))
        // a leap-year date: 2020-02-29T12:00:00Z = 1582977600
        assertEquals("2020-02-29", CrmPecMath.formatDate(1_582_977_600L))
    }

    @Test
    fun formatDate_epochMillisTolerated() {
        // same instant expressed in millis must yield the same date
        assertEquals("2021-01-01", CrmPecMath.formatDate(1_609_459_200_000L))
    }

    @Test
    fun formatDate_nullAndNonPositiveDegrade() {
        assertEquals(CrmPecMath.EM_DASH, CrmPecMath.formatDate(null))
        assertEquals(CrmPecMath.EM_DASH, CrmPecMath.formatDate(0L))
        assertEquals(CrmPecMath.EM_DASH, CrmPecMath.formatDate(-5L))
    }

    @Test
    fun dateRange_formatsAndDegrades() {
        assertEquals(CrmPecMath.EM_DASH, CrmPecMath.dateRange(null, null))
        assertEquals("2021-01-01 → ${CrmPecMath.EM_DASH}", CrmPecMath.dateRange(1_609_459_200L, null))
        assertEquals("2021-01-01 → 2021-01-01", CrmPecMath.dateRange(1_609_459_200L, 1_609_459_200L))
    }
}
