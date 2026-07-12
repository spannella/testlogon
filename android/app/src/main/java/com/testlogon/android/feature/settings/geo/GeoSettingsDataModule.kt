package com.testlogon.android.feature.settings.geo

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/** Hilt wiring for the geo-settings feature. Binds the repository seam to its default impl. */
@Module
@InstallIn(SingletonComponent::class)
abstract class GeoSettingsDataModule {

    @Binds
    @Singleton
    abstract fun bindGeoSettingsRepository(impl: DefaultGeoSettingsRepository): GeoSettingsRepository
}
