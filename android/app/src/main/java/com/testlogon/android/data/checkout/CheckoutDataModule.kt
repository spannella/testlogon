package com.testlogon.android.data.checkout

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-213 — provides the [CheckoutApi] on the shared Retrofit and binds the checkout repository.
 */
@Module
@InstallIn(SingletonComponent::class)
object CheckoutApiModule {

    @Provides
    @Singleton
    fun provideCheckoutApi(retrofit: Retrofit): CheckoutApi =
        retrofit.create(CheckoutApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class CheckoutDataModule {

    @Binds
    @Singleton
    abstract fun bindCheckoutRepository(impl: CheckoutRepositoryImpl): CheckoutRepository
}
