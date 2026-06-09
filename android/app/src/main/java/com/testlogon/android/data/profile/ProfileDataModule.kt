package com.testlogon.android.data.profile

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-070 — provides the [ProfileApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object ProfileApiModule {

    @Provides
    @Singleton
    fun provideProfileApi(retrofit: Retrofit): ProfileApi =
        retrofit.create(ProfileApi::class.java)
}

/** AND-070 / AND-074 — binds the profile repository and media uploader to their implementations. */
@Module
@InstallIn(SingletonComponent::class)
abstract class ProfileDataModule {

    @Binds
    @Singleton
    abstract fun bindProfileRepository(impl: ProfileRepositoryImpl): ProfileRepository

    @Binds
    @Singleton
    abstract fun bindProfileMediaUploader(impl: ProfileMediaUploaderImpl): ProfileMediaUploader
}
