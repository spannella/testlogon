package com.testlogon.android.feature.settings

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.feature.auth.login.ServerUrlConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerUrlViewModelTest {

    private class FakeConfig(
        var stored: String = "http://18.222.237.167:8000/",
        val default: String = "http://18.222.237.167:8000/",
        val failOnUpdate: Boolean = false,
    ) : ServerUrlConfig {
        var updateCalls = 0
        override fun current() = stored
        override fun update(value: String) {
            updateCalls++
            if (failOnUpdate) throw java.io.IOException("disk")
            stored = if (value.endsWith("/")) value else "$value/"
        }
        override fun default() = default
        override fun reset() { stored = default }
    }

    private fun vm(config: ServerUrlConfig) = ServerUrlViewModel(config, SavedStateHandle())

    @Test
    fun init_seedsFromConfig_strippedOfTrailingSlash() {
        val s = vm(FakeConfig()).state.value
        assertEquals("http://18.222.237.167:8000", s.input)
        assertEquals("http://18.222.237.167:8000", s.persistedUrl)
        assertEquals("http://18.222.237.167:8000", s.defaultUrl)
        assertFalse(s.canSave)
        assertFalse(s.canReset)
    }

    @Test
    fun onInputChange_validChanged_enablesSave() {
        val vm = vm(FakeConfig())
        vm.onInputChange("https://staging.example.com")
        val s = vm.state.value
        assertNull(s.error)
        assertFalse(s.cleartextWarning)
        assertTrue(s.canSave)
    }

    @Test
    fun onInputChange_unchanged_doesNotEnableSave() {
        val vm = vm(FakeConfig())
        vm.onInputChange("http://18.222.237.167:8000")
        assertFalse(vm.state.value.canSave)
    }

    @Test
    fun onInputChange_invalid_disablesSave_andShowsError() {
        val vm = vm(FakeConfig())
        vm.onInputChange("ftp://h:21")
        val s = vm.state.value
        assertEquals(UrlError.BAD_SCHEME, s.error)
        assertFalse(s.canSave)
    }

    @Test
    fun onInputChange_http_setsCleartextWarning_butStillSavable() {
        val vm = vm(FakeConfig())
        vm.onInputChange("http://newhost:9000")
        val s = vm.state.value
        assertTrue(s.cleartextWarning)
        assertTrue(s.canSave)
    }

    @Test
    fun onSave_persistsNormalized_emitsSaved_reseeds() {
        val config = FakeConfig()
        val vm = vm(config)
        vm.onInputChange("https://staging.example.com/")
        vm.onSave()
        assertEquals(1, config.updateCalls)
        assertEquals("https://staging.example.com/", config.stored)
        val s = vm.state.value
        assertEquals(SettingsMessage.Saved, s.message)
        assertEquals("https://staging.example.com", s.persistedUrl)
        assertFalse(s.canSave)
    }

    @Test
    fun onSave_invalidInput_neverPersists() {
        val config = FakeConfig()
        val vm = vm(config)
        vm.onInputChange("http://") // NO_HOST
        vm.onSave()
        assertEquals(0, config.updateCalls)
        assertEquals(UrlError.NO_HOST, vm.state.value.error)
    }

    @Test
    fun onSave_ioFailure_emitsFailed_valueUnchanged() {
        val config = FakeConfig(failOnUpdate = true)
        val vm = vm(config)
        vm.onInputChange("https://staging.example.com")
        vm.onSave()
        val s = vm.state.value
        assertTrue(s.message is SettingsMessage.Failed)
        assertFalse(s.saving)
    }

    @Test
    fun onReset_restoresDefault_emitsResetDone_disablesReset() {
        val config = FakeConfig(stored = "https://staging.example.com/")
        val vm = vm(config)
        assertTrue(vm.state.value.canReset)
        vm.onResetToDefault()
        val s = vm.state.value
        assertEquals(SettingsMessage.ResetDone, s.message)
        assertEquals("http://18.222.237.167:8000", s.input)
        assertFalse(s.canReset)
    }
}
