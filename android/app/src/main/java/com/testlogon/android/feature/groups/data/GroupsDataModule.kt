package com.testlogon.android.feature.groups.data

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-355 - Hilt wiring for the social-groups feature. Binds the repository seam to its default impl.
 * The impl consumes AND-355's [com.testlogon.android.core.network.groups.GroupsApi] and the shared
 * [com.testlogon.android.core.network.error.ApiErrorParser] (both provided by core-network). NO new
 * endpoint module, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class GroupsDataModule {

    @Binds
    @Singleton
    abstract fun bindGroupsRepository(impl: GroupsRepositoryImpl): GroupsRepository
}
