package com.testlogon.android.data.gallery

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-201 — provides the dedicated [GalleryApi] on the shared Retrofit and binds the gallery
 * repository. Kept separate from feed / discover wiring so this feature never touches their contracts.
 */
@Module
@InstallIn(SingletonComponent::class)
object GalleryApiModule {

    @Provides
    @Singleton
    fun provideGalleryApi(retrofit: Retrofit): GalleryApi =
        retrofit.create(GalleryApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class GalleryDataModule {

    @Binds
    @Singleton
    abstract fun bindGalleryRepository(impl: GalleryRepositoryImpl): GalleryRepository
}
