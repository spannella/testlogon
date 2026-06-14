package com.testlogon.android.core.data.delegates

import com.testlogon.android.core.model.delegates.ManagingCreator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-359 - unit tests for the PARALLEL [DelegationStateStore] (the manage-as flag holder).
 *
 * The store is pure in-memory StateFlow state, so the tests read .value directly (no coroutine scope is
 * needed). Verifies the set / clear lifecycle that ENTER / EXIT drive locally - there is NO network here.
 */
class DelegationStateStoreTest {

    private val managing = ManagingCreator(
        creatorId = "cr_1",
        label = "Acme",
        permissions = listOf("read"),
    )

    @Test
    fun managingCreator_startsNull() {
        val store = DelegationStateStore()
        assertNull(store.managingCreator.value)
    }

    @Test
    fun setManagingCreator_updatesObservableState() {
        val store = DelegationStateStore()
        store.setManagingCreator(managing)
        assertEquals(managing, store.managingCreator.value)
    }

    @Test
    fun clear_resetsToNull() {
        val store = DelegationStateStore()
        store.setManagingCreator(managing)
        store.clear()
        assertNull(store.managingCreator.value)
    }

    @Test
    fun setManagingCreator_null_alsoClears() {
        val store = DelegationStateStore()
        store.setManagingCreator(managing)
        store.setManagingCreator(null)
        assertNull(store.managingCreator.value)
    }
}
