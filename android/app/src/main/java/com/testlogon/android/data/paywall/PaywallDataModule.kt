package com.testlogon.android.data.paywall

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-177 — provides the [PaywallApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object PaywallApiModule {

    @Provides
    @Singleton
    fun providePaywallApi(retrofit: Retrofit): PaywallApi =
        retrofit.create(PaywallApi::class.java)
}

/** AND-177 — binds the paywall repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class PaywallDataModule {

    @Binds
    @Singleton
    abstract fun bindPaywallRepository(impl: PaywallRepositoryImpl): PaywallRepository
}
