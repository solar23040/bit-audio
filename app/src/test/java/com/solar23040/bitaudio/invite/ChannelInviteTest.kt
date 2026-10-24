package com.solar23040.bitaudio.invite

import com.solar23040.bitaudio.data.Channel
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ChannelInviteTest {
    private fun key(offset: Int = 0): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(
            ByteArray(32) { index -> (index + offset).toByte() },
        )

    private fun channel(key: String = key()): Channel {
        val id = requireNotNull(ChannelIdCodec.derive(key))
        return Channel(
            id = id,
            name = "Team & friends",
            key = key,
            alias = "Me",
            ttl = 5,
            createdAt = 1_700_000_000_000L,
        )
    }

    @Test
    fun inviteRoundTrips() {
        val original = channel()
        val parsed = ChannelInvite.parse(ChannelInvite.encode(original)).getOrThrow()

        assertEquals(original.id, parsed.id)
        assertEquals(original.name, parsed.name)
        assertEquals(original.key, parsed.key)
        assertEquals(16, parsed.id.length)
    }

    @Test
    fun wrongSchemeIsRejected() {
        assertTrue(ChannelInvite.parse("https://example.com/join?key=abc").isFailure)
    }

    @Test
    fun channelIdMustMatchKey() {
        val valid = channel()
        val payload = ChannelInvite.encode(valid)
            .replace("id=${valid.id}", "id=ffffffffffffffff")

        assertTrue(ChannelInvite.parse(payload).isFailure)
    }

    @Test
    fun shortChannelKeyIsRejected() {
        val shortKey = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(ByteArray(16) { it.toByte() })
        val payload = "bitaudio://join?v=1&id=0000000000000000&name=Test&key=$shortKey"

        assertTrue(ChannelInvite.parse(payload).isFailure)
    }

    @Test
    fun channelIdDerivationIsStableAndLowercaseHex() {
        val secret = key(42)
        val first = ChannelIdCodec.derive(secret)
        val second = ChannelIdCodec.derive(secret)

        assertEquals(first, second)
        assertFalse(first.isNullOrBlank())
        assertTrue(ChannelIdCodec.isValid(requireNotNull(first)))
    }
}
