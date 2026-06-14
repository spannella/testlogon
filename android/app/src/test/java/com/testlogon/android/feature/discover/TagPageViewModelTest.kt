package com.testlogon.android.feature.discover

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class TagPageViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeTagRepository()

    private fun vm(tagArg: String): TagPageViewModel {
        val saved = SavedStateHandle(mapOf(TagPageViewModel.ARG_TAG to tagArg))
        return TagPageViewModel(repo, saved)
    }

    @Test
    fun decodesTagFromSavedState_andBuildsTitle() {
        val vm = vm("kotlin")
        assertEquals("kotlin", vm.tag)
        assertEquals("#kotlin", vm.uiState.titleDisplay)
    }

    @Test
    fun urlEncodedTag_isDecoded() {
        // c%2B%2B decodes to c++
        val vm = vm("c%2B%2B")
        assertEquals("c++", vm.tag)
        assertEquals("#c++", vm.uiState.titleDisplay)
    }

    @Test
    fun refresh_doesNotThrow() {
        val vm = vm("art")
        vm.refresh() // bumps the trigger; the pager is collected by the UI, not here
        assertEquals("art", vm.tag)
    }
}
