package com.testlogon.android.data.alerts

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [AlertsApi] on the shared (authenticated) Retrofit. Named *Inbox* to stay distinct from the
 *  existing alert-preferences [AlertApiModule] in this package. */
@Module
@InstallIn(SingletonComponent::class)
object AlertsInboxApiModule {

    @Provides
    @Singleton
    fun provideAlertsApi(retrofit: Retrofit): AlertsApi =
        retrofit.create(AlertsApi::class.java)
}

/** Binds the alerts-inbox data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AlertsInboxDataModule {

    @Binds
    @Singleton
    abstract fun bindAlertsRepository(impl: AlertsRepositoryImpl): AlertsRepository
}
