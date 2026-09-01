package com.testlogon.android.feature.maintenance

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * WOV — Hilt wiring for the Maintenance Work Orders feature repository seam. The impl consumes the
 * core-network [com.testlogon.android.core.network.maintenance.MaintenanceOrdersApi] + shared
 * ApiErrorParser; NO new endpoint module, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class MaintenanceModule {

    @Binds
    @Singleton
    abstract fun bindMaintenanceOrdersRepository(
        impl: MaintenanceOrdersRepositoryImpl,
    ): MaintenanceOrdersRepository
}
