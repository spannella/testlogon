package com.testlogon.android.feature.agents.prs.data

/**
 * AGENTS-BASICS (web-parity) - framework-free PURE logic for agent work-completion. No Android / coroutine deps
 * so it is unit-testable on the JVM. Mirrors how the web CompletionResult panel summarises a WorkSummary.
 *
 * The backend's WorkSummary.test_results is an opaque map of label -> count (e.g. {"passed":42,"failed":0}).
 * These helpers normalise it into a stable outcome without assuming any particular key set, degrading safely
 * when the map is empty or contains unexpected keys.
 */
object PrsCompletionMath {

    /** Keys (case-insensitively) treated as failing test buckets. */
    private val FAILING_KEYS = setOf("failed", "failing", "error", "errors", "broken")

    /** Sum of ALL test-result counts (negatives clamped to 0 so a bad server value can't underflow a total). */
    fun totalTests(testResults: List<Pair<String, Int>>): Int =
        testResults.sumOf { it.second.coerceAtLeast(0) }

    /** Sum of counts under any failing-bucket key. */
    fun failingTests(testResults: List<Pair<String, Int>>): Int =
        testResults.filter { it.first.trim().lowercase() in FAILING_KEYS }
            .sumOf { it.second.coerceAtLeast(0) }

    /** Passing = total - failing (never negative). */
    fun passingTests(testResults: List<Pair<String, Int>>): Int =
        (totalTests(testResults) - failingTests(testResults)).coerceAtLeast(0)

    /** True only when at least one test ran AND nothing failed. An empty map is NOT "green". */
    fun allPassed(testResults: List<Pair<String, Int>>): Boolean =
        totalTests(testResults) > 0 && failingTests(testResults) == 0

    /**
     * A compact human label for the completion, e.g. "3 files - 42/42 tests passed", "no tests reported".
     * Deterministic and locale-free so it is safe to assert on in a unit test.
     */
    fun summaryLabel(summary: WorkSummary): String {
        val fileCount = summary.filesChanged.size
        val filePart = when (fileCount) {
            0 -> "no files changed"
            1 -> "1 file"
            else -> "$fileCount files"
        }
        val total = totalTests(summary.testResults)
        val testPart = if (total == 0) {
            "no tests reported"
        } else {
            val passing = passingTests(summary.testResults)
            "$passing/$total tests passed"
        }
        return "$filePart - $testPart"
    }
}
