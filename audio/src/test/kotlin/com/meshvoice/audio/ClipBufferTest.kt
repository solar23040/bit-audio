package com.meshvoice.audio

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ClipBufferTest {

    @Test
    fun stopsAtCapacity() {
        val buffer = ClipBuffer(5)
        assertEquals(3, buffer.append(shortArrayOf(1, 2, 3)))
        assertEquals(2, buffer.append(shortArrayOf(4, 5, 6, 7)))
        assertTrue(buffer.isFull)
        assertEquals(5, buffer.size)
        assertArrayEquals(shortArrayOf(1, 2, 3, 4, 5), buffer.snapshot())
    }

    @Test
    fun appendCanBeLimited() {
        val buffer = ClipBuffer(10)
        assertEquals(2, buffer.append(shortArrayOf(1, 2, 3, 4), count = 2))
        assertEquals(2, buffer.size)
        assertFalse(buffer.isFull)
    }

    @Test
    fun zeroAppendIsAllowed() {
        val buffer = ClipBuffer(2)
        assertEquals(0, buffer.append(shortArrayOf(1, 2), count = 0))
        assertEquals(0, buffer.size)
    }

    @Test
    fun invalidInputIsRejected() {
        assertThrows(IllegalArgumentException::class.java) { ClipBuffer(0) }
        assertThrows(IllegalArgumentException::class.java) {
            ClipBuffer(2).append(shortArrayOf(1), count = 2)
        }
    }
}
