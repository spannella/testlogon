package com.testlogon.android.feature.apikeys.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * B-APIKEY (batch 7) - Hilt wiring for the API-keys feature. Binds the repository seam to its default impl,
 * which consumes the [com.testlogon.android.core.network.apikeys.ApiKeysApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser]. NO new endpoint module, migration, or dependency is
 * added here. Mirrors the AND-398 WebhooksDataModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class ApiKeysDataModule {

    @Binds
    @Singleton
    abstract fun bindApiKeysRepository(impl: DefaultApiKeysRepository): ApiKeysRepository
}
