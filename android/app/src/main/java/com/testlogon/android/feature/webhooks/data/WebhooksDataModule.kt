package com.testlogon.android.feature.webhooks.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-398 - Hilt wiring for the webhooks (light) feature. Binds the repository seam to its default impl. The
 * impl consumes the AND-398 [com.testlogon.android.core.network.webhooks.WebhooksApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser]. NO new endpoint module, migration, or dependency
 * is added here. Mirrors the AND-372 TicketsDataModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class WebhooksDataModule {

    @Binds
    @Singleton
    abstract fun bindWebhooksRepository(impl: DefaultWebhooksRepository): WebhooksRepository
}
