package com.testlogon.android.data.subscriptions

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-234 — provides the [SubscriptionsApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object SubscriptionsApiModule {

    @Provides
    @Singleton
    fun provideSubscriptionsApi(retrofit: Retrofit): SubscriptionsApi =
        retrofit.create(SubscriptionsApi::class.java)
}

/** AND-234 — binds the subscriptions repository over [SubscriptionsApi]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class SubscriptionsDataModule {

    @Binds
    @Singleton
    abstract fun bindSubscriptionsRepository(impl: SubscriptionsRepositoryImpl): SubscriptionsRepository

    /**
     * AND-235 — checkout feature gate. Defaults to [DefaultSubscriptionFeatureFlags] (checkout
     * disabled). Swap this binding when the subscription checkout route lands.
     */
    @Binds
    @Singleton
    abstract fun bindSubscriptionFeatureFlags(
        impl: DefaultSubscriptionFeatureFlags,
    ): SubscriptionFeatureFlags
}
