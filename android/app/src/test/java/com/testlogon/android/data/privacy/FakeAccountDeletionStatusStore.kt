package com.testlogon.android.data.privacy

/**
 * AND-386 - an in-memory [AccountDeletionStatusStore] for repository contract tests (no DataStore / Android).
 * Records the last saved status; never persists any secret.
 */
class FakeAccountDeletionStatusStore(
    private var current: DeletionStatus? = null,
) : AccountDeletionStatusStore {

    val saved = mutableListOf<DeletionStatus>()

    override suspend fun load(): DeletionStatus? = current

    override suspend fun save(status: DeletionStatus) {
        saved += status
        current = status
    }

    override suspend fun clear() {
        current = null
    }
}
