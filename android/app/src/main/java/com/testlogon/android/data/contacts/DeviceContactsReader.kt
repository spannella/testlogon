package com.testlogon.android.data.contacts

import android.content.Context
import android.provider.ContactsContract
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/** Raw identifiers read from the device address book (stays ON the device). */
data class DeviceContactIdentifiers(
    val emails: Set<String>,
    val phones: Set<String>,
)

/**
 * Contacts Feature 2 — reads the native Android address book via ContactsContract and
 * returns the raw email + phone strings. Callers MUST hash these on-device (via
 * [ContactMatchHasher]) before anything leaves the device; the raw strings are never
 * uploaded.
 *
 * Behind an interface so the sync ViewModel is JVM-unit-testable with a fake reader.
 */
interface DeviceContactsReader {
    /** Requires READ_CONTACTS to already be granted; runs off the main thread. */
    suspend fun read(): DeviceContactIdentifiers
}

@Singleton
class DeviceContactsReaderImpl @Inject constructor(
    @ApplicationContext private val context: Context,
) : DeviceContactsReader {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun read(): DeviceContactIdentifiers = withContext(io) {
        val emails = LinkedHashSet<String>()
        val phones = LinkedHashSet<String>()
        val resolver = context.contentResolver

        resolver.query(
            ContactsContract.CommonDataKinds.Email.CONTENT_URI,
            arrayOf(ContactsContract.CommonDataKinds.Email.ADDRESS),
            null, null, null,
        )?.use { c ->
            val col = c.getColumnIndex(ContactsContract.CommonDataKinds.Email.ADDRESS)
            if (col >= 0) while (c.moveToNext()) {
                c.getString(col)?.trim()?.takeIf { it.isNotEmpty() }?.let { emails += it }
            }
        }

        resolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            arrayOf(ContactsContract.CommonDataKinds.Phone.NUMBER),
            null, null, null,
        )?.use { c ->
            val col = c.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
            if (col >= 0) while (c.moveToNext()) {
                c.getString(col)?.trim()?.takeIf { it.isNotEmpty() }?.let { phones += it }
            }
        }

        DeviceContactIdentifiers(emails = emails, phones = phones)
    }
}
