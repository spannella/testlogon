package com.testlogon.android.data.sellerstore

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * ECOM (seller store) — provides the seller CRUD + orders Retrofit APIs on the shared Retrofit and binds
 * the seller-store repositories.
 */
@Module
@InstallIn(SingletonComponent::class)
object SellerStoreApiModule {

    @Provides
    @Singleton
    fun provideSellerCatalogApi(retrofit: Retrofit): SellerCatalogApi =
        retrofit.create(SellerCatalogApi::class.java)

    @Provides
    @Singleton
    fun provideSellerOrdersApi(retrofit: Retrofit): SellerOrdersApi =
        retrofit.create(SellerOrdersApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class SellerStoreDataModule {

    @Binds
    @Singleton
    abstract fun bindSellerCatalogRepository(impl: SellerCatalogRepositoryImpl): SellerCatalogRepository

    @Binds
    @Singleton
    abstract fun bindSellerOrdersRepository(impl: SellerOrdersRepositoryImpl): SellerOrdersRepository
}
