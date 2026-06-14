package com.testlogon.android.data.messaging

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-153 / AND-156 — Moshi parse of the `/messaging/contacts/search` 200 body, which is a BARE JSON
 * array of `{user_id, display_name}` (no wrapper, no username/avatar/presence — verified against
 * OpenAPI components.schemas.Contact). Asserts the array parses and `toDomain()` maps the two fields.
 */
class ContactDtoTest {

    private val moshi = Moshi.Builder().build()
    private val listType = Types.newParameterizedType(List::class.java, ContactDto::class.java)
    private val adapter = moshi.adapter<List<ContactDto>>(listType)

    @Test
    fun parsesBareArray_andMapsToDomain() {
        val json = """[{"user_id":"u_1029","display_name":"Alice Nguyen"}]"""
        val dtos = adapter.fromJson(json)!!
        assertEquals(1, dtos.size)
        val contact = dtos.single().toDomain()
        assertEquals("u_1029", contact.id)
        assertEquals("Alice Nguyen", contact.displayName)
    }

    @Test
    fun parsesEmptyArray_toEmptyList() {
        val dtos = adapter.fromJson("[]")!!
        assertTrue(dtos.isEmpty())
    }
}
