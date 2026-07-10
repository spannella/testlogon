package com.testlogon.android.data.ordertracking

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** D4 - provides [OrderTrackingApi] on the shared Retrofit and binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object OrderTrackingApiModule {
    @Provides
    @Singleton
    fun provideOrderTrackingApi(retrofit: Retrofit): OrderTrackingApi =
        retrofit.create(OrderTrackingApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class OrderTrackingDataModule {
    @Binds
    @Singleton
    abstract fun bindOrderTrackingRepository(impl: OrderTrackingRepositoryImpl): OrderTrackingRepository
}
