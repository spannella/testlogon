package com.testlogon.android.data.alerts

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-086 / AND-087 — provides the email + SMS alert APIs on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object AlertApiModule {

    @Provides
    @Singleton
    fun provideEmailAlertApi(retrofit: Retrofit): EmailAlertApi =
        retrofit.create(EmailAlertApi::class.java)

    @Provides
    @Singleton
    fun provideSmsAlertApi(retrofit: Retrofit): SmsAlertApi =
        retrofit.create(SmsAlertApi::class.java)
}

/** AND-086 / AND-087 — binds the alert-target repositories to their implementations. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AlertDataModule {

    @Binds
    @Singleton
    abstract fun bindEmailAlertRepository(impl: EmailAlertRepositoryImpl): EmailAlertRepository

    @Binds
    @Singleton
    abstract fun bindSmsAlertRepository(impl: SmsAlertRepositoryImpl): SmsAlertRepository
}
