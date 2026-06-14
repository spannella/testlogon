package com.testlogon.android.feature.projects.data

import com.testlogon.android.feature.projects.provider.CustomTabsProjectDriveTabLauncher
import com.testlogon.android.feature.projects.provider.ProjectDriveTabLauncher
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-374 - Hilt wiring for the PROJECTS feature. Binds the repository seam to its default impl and the Drive
 * Custom-Tab launcher to its androidx.browser impl. The repo consumes the AND-374
 * [com.testlogon.android.core.network.projects.ProjectsApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser]. NO new endpoint module, migration, or dependency
 * is added here. Mirrors the AND-372 TicketsDataModule / AND-273 GoogleCalendarTabLauncherModule patterns.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class ProjectsDataModule {

    @Binds
    @Singleton
    abstract fun bindProjectsRepository(impl: ProjectsRepositoryImpl): ProjectsRepository

    @Binds
    @Singleton
    abstract fun bindProjectDriveTabLauncher(impl: CustomTabsProjectDriveTabLauncher): ProjectDriveTabLauncher
}
