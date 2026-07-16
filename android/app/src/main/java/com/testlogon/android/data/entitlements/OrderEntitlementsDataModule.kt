package com.testlogon.android.data.entitlements

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * ECOMX-43 (B5) — provides [OrderEntitlementsApi] on the shared Retrofit and binds the digital-library
 * repository. No new OkHttp/Retrofit/Moshi is constructed; no per-method cookie/CSRF headers.
 */
@Module
@InstallIn(SingletonComponent::class)
object OrderEntitlementsApiModule {

    @Provides
    @Singleton
    fun provideOrderEntitlementsApi(retrofit: Retrofit): OrderEntitlementsApi =
        retrofit.create(OrderEntitlementsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class OrderEntitlementsDataModule {

    @Binds
    @Singleton
    abstract fun bindOrderEntitlementsRepository(
        impl: OrderEntitlementsRepositoryImpl,
    ): OrderEntitlementsRepository
}
