package com.testlogon.android.feature.agents.prs

import com.testlogon.android.feature.agents.prs.data.PrsCompletionMath
import com.testlogon.android.feature.agents.prs.data.WorkSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AGENTS-BASICS - JVM unit tests for the PURE [PrsCompletionMath] logic (no Android / Moshi types). Covers
 * total/failing/passing counting (with negative clamping + case-insensitive failing keys), the all-passed
 * predicate (empty map is NOT green), and the deterministic summaryLabel choke point.
 */
class PrsCompletionMathTest {

    private fun summary(
        files: List<String> = emptyList(),
        tests: List<Pair<String, Int>> = emptyList(),
        decisions: List<String> = emptyList(),
    ) = WorkSummary(ticketId = "T-1", text = "did work", filesChanged = files, decisions = decisions, testResults = tests)

    @Test
    fun totalTests_sumsAllBuckets() {
        assertEquals(52, PrsCompletionMath.totalTests(listOf("passed" to 40, "failed" to 2, "skipped" to 10)))
    }

    @Test
    fun totalTests_emptyIsZero() {
        assertEquals(0, PrsCompletionMath.totalTests(emptyList()))
    }

    @Test
    fun totalTests_clampsNegativeCounts() {
        assertEquals(40, PrsCompletionMath.totalTests(listOf("passed" to 40, "weird" to -5)))
    }

    @Test
    fun failingTests_matchesFailingKeysCaseInsensitively() {
        val r = listOf("Passed" to 30, "FAILED" to 3, "Errors" to 2, "skipped" to 1)
        assertEquals(5, PrsCompletionMath.failingTests(r))
    }

    @Test
    fun failingTests_noneWhenNoFailingBuckets() {
        assertEquals(0, PrsCompletionMath.failingTests(listOf("passed" to 10, "skipped" to 2)))
    }

    @Test
    fun passingTests_isTotalMinusFailing() {
        val r = listOf("passed" to 40, "failed" to 2)
        assertEquals(40, PrsCompletionMath.passingTests(r))
    }

    @Test
    fun passingTests_neverNegative() {
        // failing exceeds accounted total only if keys overlap oddly; still clamps to 0
        val r = listOf("failed" to 5)
        assertEquals(0, PrsCompletionMath.passingTests(r))
    }

    @Test
    fun allPassed_trueWhenTestsRanAndNoneFailed() {
        assertTrue(PrsCompletionMath.allPassed(listOf("passed" to 12)))
    }

    @Test
    fun allPassed_falseWhenSomethingFailed() {
        assertFalse(PrsCompletionMath.allPassed(listOf("passed" to 12, "failed" to 1)))
    }

    @Test
    fun allPassed_falseForEmptyMap() {
        assertFalse(PrsCompletionMath.allPassed(emptyList()))
    }

    @Test
    fun summaryLabel_noFilesNoTests() {
        assertEquals("no files changed - no tests reported", PrsCompletionMath.summaryLabel(summary()))
    }

    @Test
    fun summaryLabel_oneFileSingular() {
        val s = summary(files = listOf("A.kt"), tests = listOf("passed" to 3))
        assertEquals("1 file - 3/3 tests passed", PrsCompletionMath.summaryLabel(s))
    }

    @Test
    fun summaryLabel_multipleFilesAndMixedTests() {
        val s = summary(files = listOf("A.kt", "B.kt", "C.kt"), tests = listOf("passed" to 40, "failed" to 2))
        assertEquals("3 files - 40/42 tests passed", PrsCompletionMath.summaryLabel(s))
    }
}
