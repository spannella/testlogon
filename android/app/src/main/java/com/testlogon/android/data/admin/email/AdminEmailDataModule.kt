package com.testlogon.android.data.admin.email

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** Provides [AdminEmailApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object AdminEmailApiModule {

    @Provides
    @Singleton
    fun provideAdminEmailApi(retrofit: Retrofit): AdminEmailApi =
        retrofit.create(AdminEmailApi::class.java)
}

/** Binds the admin-email data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AdminEmailDataModule {

    @Binds
    @Singleton
    abstract fun bindAdminEmailRepository(impl: AdminEmailRepositoryImpl): AdminEmailRepository
}
