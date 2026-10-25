package com.solar23040.bitaudio.mesh.cache

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SeenIdCacheTest {

    private var now = 1_700_000_000_000L

    @Test
    fun `duplicates are rejected until the entry expires`() {
        val cache = SeenIdCache(maxEntries = 8, expiryMs = 1_000L) { now }

        assertTrue(cache.markSeen("chunk"))
        assertFalse(cache.markSeen("chunk"))
        assertTrue(cache.isSeen("chunk"))

        now += 1_001L
        assertFalse(cache.isSeen("chunk"))
        assertTrue("expired entries may be seen again", cache.markSeen("chunk"))
    }

    @Test
    fun `least recently used entry is evicted`() {
        val cache = SeenIdCache(maxEntries = 2, expiryMs = 60_000L) { now }

        assertTrue(cache.markSeen("a"))
        assertTrue(cache.markSeen("b"))
        assertTrue(cache.isSeen("a")) // touch a, so b is now least recent
        assertTrue(cache.markSeen("c"))

        assertTrue(cache.isSeen("a"))
        assertTrue(cache.isSeen("c"))
        assertFalse(cache.isSeen("b"))
    }

    @Test
    fun `expired entries are swept without waiting for the bound`() {
        val cache = SeenIdCache(maxEntries = 1_000, expiryMs = 10L) { now }

        repeat(10) { cache.markSeen("old-$it") }
        now += 11L
        cache.markSeen("fresh")

        assertTrue(cache.isSeen("fresh"))
        assertFalse(cache.isSeen("old-0"))
        assertTrue("expired rows must not accumulate", cache.size() <= 2)
    }
}
