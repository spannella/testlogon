package com.testlogon.android.feature.files.upload

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-333 - binds the upload-source seam. The [UploadCoordinator] and [FilesUploadViewModel] are
 * constructor-injected; FilesApi (AND-331 core-network), [com.testlogon.android.data.upload.StorageUploadClient]
 * (AND-129), ContentResolver / UriMetadata (AND-129 UploadModule) and the
 * [com.testlogon.android.feature.files.data.FolderRefreshBus] are all already on the graph. No new
 * dependency, no Room. Background / resumable uploads (WorkManager) are DEFERRED.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class FilesUploadModule {

    @Binds
    @Singleton
    abstract fun bindUploadSource(impl: ContentResolverUploadSource): UploadSource

    @Binds
    @Singleton
    abstract fun bindStoragePut(impl: DelegatingStoragePut): StoragePut
}
