package com.testlogon.android.feature.agents.feedback

import com.testlogon.android.core.network.agents.TerminalOutputDto
import com.testlogon.android.feature.agents.feedback.data.toDomain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AGENTS-BASICS - JVM tests for the TerminalOutput DTO -> domain mapper (web getTerminalLog / TerminalOutputOut),
 * including the isEmpty convenience used by the terminal-log dialog.
 */
class TerminalOutputMapperTest {

    @Test
    fun mapsFields() {
        val d = TerminalOutputDto(workerId = "w1", output = "hello\nworld", charCount = 11).toDomain()
        assertEquals("w1", d.workerId)
        assertEquals("hello\nworld", d.output)
        assertEquals(11, d.charCount)
    }

    @Test
    fun isEmpty_trueForBlankOutput() {
        assertTrue(TerminalOutputDto(workerId = "w", output = "   ", charCount = 0).toDomain().isEmpty)
    }

    @Test
    fun isEmpty_falseForRealOutput() {
        assertFalse(TerminalOutputDto(workerId = "w", output = "x", charCount = 1).toDomain().isEmpty)
    }

    @Test
    fun defaults_areEmpty() {
        val d = TerminalOutputDto().toDomain()
        assertEquals("", d.output)
        assertTrue(d.isEmpty)
    }
}
