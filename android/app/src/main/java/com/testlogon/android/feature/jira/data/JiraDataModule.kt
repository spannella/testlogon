package com.testlogon.android.feature.jira.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * JIRA-AND-1 - Hilt wiring for the Jira integration feature. Binds the repository seam to its default impl. The
 * impl consumes the [com.testlogon.android.core.network.jira.JiraApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser]. NO new endpoint module, migration, or dependency is
 * added here. Mirrors the AND-372 TicketsDataModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class JiraDataModule {

    @Binds
    @Singleton
    abstract fun bindJiraRepository(impl: JiraRepositoryImpl): JiraRepository
}
