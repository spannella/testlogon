package com.testlogon.android.data.dmca

/**
 * AND-384 - an in-memory [DmcaDraftStore] for JVM unit tests (no Android DataStore / Robolectric).
 *
 * Records the calls so a test can assert that a successful submit clears the draft and that the
 * signature / attestations are never round-tripped (the [DmcaDraft] type structurally excludes them).
 */
class FakeDmcaDraftStore : DmcaDraftStore {

    private val drafts = mutableMapOf<String, DmcaDraft>()

    val savedKeys = mutableListOf<String>()
    val clearedKeys = mutableListOf<String>()
    var clearAllCount = 0
        private set

    /** Seeds a draft as if it had been persisted in a previous session. */
    fun seed(key: String, draft: DmcaDraft) {
        drafts[key] = draft
    }

    override suspend fun load(targetKey: String): DmcaDraft? = drafts[targetKey]

    override suspend fun save(targetKey: String, draft: DmcaDraft) {
        savedKeys += targetKey
        drafts[targetKey] = draft
    }

    override suspend fun clear(targetKey: String) {
        clearedKeys += targetKey
        drafts.remove(targetKey)
    }

    override suspend fun clearAll() {
        clearAllCount++
        drafts.clear()
    }
}
