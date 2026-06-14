package com.testlogon.android.data.files.download

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-334 - a simple content-addressed disk cache for downloaded files, under
 * cacheDir/fs-downloads/. NO Room and NO migration: the cache is plain files on disk (so it survives
 * process death) plus a small per-entry sidecar holding the display name + MIME type.
 *
 * KEYING: the cache key is a SHA-256 hash of (path + "@" + version), where version is the source
 * node's updatedAt epoch-millis (or "0" when absent). A new version produces a new key, so a changed
 * file naturally misses the stale entry rather than serving old bytes.
 *
 * LAYOUT per entry: "<key>.bin" (the bytes) and "<key>.meta" (a 2-line sidecar: displayName then
 * mimeType). The display name is preserved verbatim so the open-with intent and SaveToDownloads use
 * the real file name.
 *
 * BOUNDED LRU (best-effort): on [commit], if the directory's total size exceeds [maxBytes], the
 * oldest-accessed entries are deleted until it fits, never deleting the entry just written. Eviction
 * is best-effort and not transactional - a partially-evicted cache is still correct (a miss just
 * re-downloads). Concurrency across processes is not coordinated (single-process assumption); within
 * a process commits are serialized on a lock.
 */
@Singleton
class FileCacheStore(
    @ApplicationContext private val context: Context,
    private val maxBytes: Long,
) {

    /** Production constructor: the default LRU cap ([DEFAULT_MAX_BYTES]). */
    @Inject
    constructor(@ApplicationContext context: Context) : this(context, DEFAULT_MAX_BYTES)

    private val lock = Any()

    /** The cache root, created lazily on first use. */
    private val dir: File
        get() = File(context.cacheDir, DIR_NAME).apply { if (!exists()) mkdirs() }

    /** Stable cache key for [path] at [version] (the source node's updatedAt epoch-millis, or 0). */
    fun keyFor(path: String, version: Long): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest("$path@$version".toByteArray(Charsets.UTF_8))
        return bytes.joinToString(separator = "") { b -> "%02x".format(b) }
    }

    /**
     * Returns the committed [CachedFile] for ([key], [path]) if both the bytes and sidecar exist, else
     * null. [path] is supplied by the caller (the source node path) since it is not round-tripped from
     * disk. A cache hit touches the entry's lastModified so the LRU treats it as recently accessed.
     */
    fun get(key: String, path: String): CachedFile? = synchronized(lock) {
        val bin = binFile(key)
        val meta = metaFile(key)
        if (!bin.exists() || !meta.exists()) return null
        val lines = runCatching { meta.readLines() }.getOrNull() ?: return null
        if (lines.size < 2) return null
        bin.setLastModified(System.currentTimeMillis())
        CachedFile(
            path = path,
            file = bin,
            mimeType = lines[1],
            displayName = lines[0],
        )
    }

    /**
     * Commits [partFile]'s bytes as the entry [key], renaming it into place and writing the sidecar
     * from [displayName] / [mimeType]. Returns the resolved on-disk [File]. Runs an LRU sweep after,
     * never evicting [key]. [partFile] is consumed (moved); on a rename failure it is copied.
     */
    fun commit(key: String, partFile: File, displayName: String, mimeType: String): File =
        synchronized(lock) {
            val bin = binFile(key)
            if (bin.exists()) bin.delete()
            if (!partFile.renameTo(bin)) {
                partFile.copyTo(bin, overwrite = true)
                partFile.delete()
            }
            bin.setLastModified(System.currentTimeMillis())
            metaFile(key).writeText(displayName + "\n" + mimeType)
            evictIfNeeded(keep = key)
            bin
        }

    /** Allocates a fresh, unique .part scratch file (caller streams into it, then [commit]s). */
    fun newPartFile(key: String): File = File(dir, "$key.${System.nanoTime()}$PART_SUFFIX")

    /** Removes an entry (bytes + sidecar). Best-effort. */
    fun remove(key: String) = synchronized(lock) {
        binFile(key).delete()
        metaFile(key).delete()
        Unit
    }

    private fun binFile(key: String): File = File(dir, "$key$BIN_SUFFIX")

    private fun metaFile(key: String): File = File(dir, "$key$META_SUFFIX")

    /** Deletes oldest-accessed .bin entries (and sidecars) until under [maxBytes]; never touches [keep]. */
    private fun evictIfNeeded(keep: String) {
        val bins = dir.listFiles { f -> f.isFile && f.name.endsWith(BIN_SUFFIX) }?.toMutableList() ?: return
        var total = bins.sumOf { it.length() }
        if (total <= maxBytes) return
        bins.sortBy { it.lastModified() } // oldest first.
        for (bin in bins) {
            if (total <= maxBytes) break
            val name = bin.name.removeSuffix(BIN_SUFFIX)
            if (name == keep) continue
            val size = bin.length()
            if (bin.delete()) {
                File(dir, "$name$META_SUFFIX").delete()
                total -= size
            }
        }
    }

    companion object {
        const val DIR_NAME = "fs-downloads"
        const val DEFAULT_MAX_BYTES = 256L * 1024L * 1024L
        private const val BIN_SUFFIX = ".bin"
        private const val META_SUFFIX = ".meta"
        private const val PART_SUFFIX = ".part"
    }
}
