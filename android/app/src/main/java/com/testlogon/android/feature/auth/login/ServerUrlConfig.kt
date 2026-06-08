package com.testlogon.android.feature.auth.login

import com.testlogon.android.core.network.SettingsStore
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The login screen's "server URL" affordance. The dev host is flaky, so the user can point the
 * client at a different base URL. Backed by [SettingsStore]; extracted behind an interface so the
 * ViewModel is unit-testable without Android `Context`.
 */
interface ServerUrlConfig {
    fun current(): String
    fun update(value: String)
}

@Singleton
class SettingsServerUrlConfig @Inject constructor(
    private val settingsStore: SettingsStore,
) : ServerUrlConfig {
    override fun current(): String = settingsStore.baseUrl

    override fun update(value: String) {
        val trimmed = value.trim()
        if (trimmed.isNotEmpty()) settingsStore.baseUrl = trimmed
    }
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ServerUrlConfigModule {
    @Binds
    @Singleton
    abstract fun bindServerUrlConfig(impl: SettingsServerUrlConfig): ServerUrlConfig
}
