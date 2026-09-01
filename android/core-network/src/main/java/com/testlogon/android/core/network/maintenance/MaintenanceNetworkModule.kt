package com.testlogon.android.core.network.maintenance

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * Hilt wiring for the Maintenance Work Orders transport layer. Provides [MaintenanceOrdersApi] from the
 * shared singleton [Retrofit] (reusing the production OkHttp / Moshi / converter config; no new Retrofit,
 * OkHttp, Moshi or dependency is introduced). The WOV DTOs use only String / Long / Boolean fields, so
 * the shared reflective Moshi decodes them without any new adapter. Mirrors SigningNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object MaintenanceNetworkModule {

    @Provides
    @Singleton
    fun provideMaintenanceOrdersApi(retrofit: Retrofit): MaintenanceOrdersApi =
        retrofit.create(MaintenanceOrdersApi::class.java)
}
