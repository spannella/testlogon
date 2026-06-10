package com.testlogon.android.data.catalog

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-204 — provides the dedicated [CatalogApi] on the shared Retrofit and binds the catalog
 * repository. Kept separate from gallery / vod wiring so this feature never touches their contracts.
 */
@Module
@InstallIn(SingletonComponent::class)
object CatalogApiModule {

    @Provides
    @Singleton
    fun provideCatalogApi(retrofit: Retrofit): CatalogApi =
        retrofit.create(CatalogApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class CatalogDataModule {

    @Binds
    @Singleton
    abstract fun bindCatalogRepository(impl: CatalogRepositoryImpl): CatalogRepository
}
