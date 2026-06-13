package com.testlogon.android.feature.signing.document

import android.graphics.Bitmap
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * AND-341 - a small LRU of rendered page bitmaps, keyed by (page index, target width px) so the zoomed
 * and unzoomed renders of a page are distinct entries.
 *
 * SIZE: budgeted from a fraction of the app's max heap (capped), measured in bytes via the bitmap byte
 * count. Bitmaps evicted by the LRU are recycled UNLESS they are still composed on screen (the screen
 * marks the visible keys via [retain]); a retained evictee is recycled later when it leaves the window.
 *
 * The LRU is a pure-Kotlin access-ordered [LinkedHashMap] (NOT android.util.LruCache) so the cache loads
 * + runs on the plain JVM unit classpath -- only the [Bitmap] type itself is android, and the unit test
 * passes Mockito mocks for it.
 *
 * DEDUPE: concurrent requests for the same key share ONE in-flight [Deferred], so a page is never
 * rendered twice at once (e.g. a scroll that re-requests a still-rendering page).
 */
class BitmapPageCache(
    private val maxMemoryBytes: Int = defaultBudgetBytes(),
) {
    /** Cache key: a page at a specific render width. */
    data class Key(val index: Int, val targetWidthPx: Int)

    private val mutex = Mutex()

    /** Access-ordered LRU; eldest entry is evicted first when over budget. */
    private val lru = object : LinkedHashMap<Key, Bitmap>(16, 0.75f, true) {
        // Eviction is driven manually by trimToBudget so we can route evictees through the recycle policy.
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Key, Bitmap>): Boolean = false
    }

    /** Keys the screen currently has composed; an evicted-but-retained bitmap is recycled on release. */
    private val retained = mutableSetOf<Key>()

    /** Bitmaps evicted while still retained on screen; recycled when [release] drops the last hold. */
    private val pendingRecycle = mutableMapOf<Key, Bitmap>()

    /** In-flight renders, deduped by key. */
    private val inFlight = mutableMapOf<Key, Deferred<Bitmap>>()

    private var sizeBytes = 0

    /** Returns a cached bitmap for [key], or null. */
    suspend fun get(key: Key): Bitmap? = mutex.withLock { lru[key]?.takeIf { !it.isRecycled } }

    /**
     * Returns the cached bitmap for [key], else renders it via [render] (deduping concurrent callers on
     * the same key), stores it, and returns it. The render runs in [scope] so a single in-flight job is
     * shared; the caller awaits the shared result.
     */
    suspend fun getOrRender(
        key: Key,
        scope: CoroutineScope,
        render: suspend () -> Bitmap,
    ): Bitmap {
        mutex.withLock {
            lru[key]?.let { if (!it.isRecycled) return it }
            inFlight[key]?.let { return@withLock it }
            val deferred = CompletableDeferred<Bitmap>()
            inFlight[key] = deferred
            scope.launch {
                try {
                    val bitmap = render()
                    mutex.withLock {
                        put(key, bitmap)
                        inFlight.remove(key)
                    }
                    deferred.complete(bitmap)
                } catch (t: Throwable) {
                    mutex.withLock { inFlight.remove(key) }
                    deferred.completeExceptionally(t)
                }
            }
            return@withLock deferred
        }.let { return it.await() }
    }

    /** Stores [bitmap] and trims the cache back to budget (caller holds the mutex). */
    private fun put(key: Key, bitmap: Bitmap) {
        lru.put(key, bitmap)?.let { prior ->
            sizeBytes -= byteCount(prior)
            if (prior !== bitmap && !prior.isRecycled && !retained.contains(key)) prior.recycle()
        }
        sizeBytes += byteCount(bitmap)
        trimToBudget()
    }

    /** Evicts eldest entries until within [maxMemoryBytes], routing each evictee through the recycle policy. */
    private fun trimToBudget() {
        val iterator = lru.entries.iterator()
        while (sizeBytes > maxMemoryBytes && iterator.hasNext()) {
            val entry = iterator.next()
            val bitmap = entry.value
            sizeBytes -= byteCount(bitmap)
            iterator.remove()
            if (bitmap.isRecycled) continue
            if (retained.contains(entry.key)) {
                pendingRecycle[entry.key] = bitmap
            } else {
                bitmap.recycle()
            }
        }
    }

    /** Marks [key] as composed on screen (so its bitmap is not recycled on eviction). */
    suspend fun retain(key: Key) = mutex.withLock { retained.add(key); Unit }

    /** Drops a screen hold on [key]; recycles the bitmap if it was evicted while retained. */
    suspend fun release(key: Key) = mutex.withLock {
        retained.remove(key)
        pendingRecycle.remove(key)?.let { if (!it.isRecycled) it.recycle() }
        Unit
    }

    /**
     * Clears the cache (on viewer teardown): recycles every held bitmap and forgets in-flight jobs.
     * Synchronous so it is safe to call from ViewModel.onCleared (where the viewModelScope is already
     * cancelled).
     */
    @Synchronized
    fun clear() {
        lru.values.forEach { if (!it.isRecycled) it.recycle() }
        lru.clear()
        pendingRecycle.values.forEach { if (!it.isRecycled) it.recycle() }
        pendingRecycle.clear()
        retained.clear()
        inFlight.clear()
        sizeBytes = 0
    }

    private fun byteCount(bitmap: Bitmap): Int = bitmap.allocationByteCount.coerceAtLeast(0)

    companion object {
        /** A conservative slice of max heap (eighth), capped, for the page-bitmap budget. */
        fun defaultBudgetBytes(): Int {
            val maxKb = (Runtime.getRuntime().maxMemory() / 1024L).toInt()
            val eighth = maxKb / 8
            return (eighth.coerceIn(MIN_BUDGET_KB, MAX_BUDGET_KB)) * 1024
        }

        private const val MIN_BUDGET_KB = 8 * 1024
        private const val MAX_BUDGET_KB = 64 * 1024
    }
}
