package com.solar23040.bitaudio.mesh.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RateLimiterTest {

    @Test
    fun `burst is allowed then refilled over time`() {
        var nowMs = 0L
        val limiter = RateLimiter(RateLimit(perSecond = 10.0, burst = 2.0)) { nowMs }

        assertTrue(limiter.tryAcquire("sender"))
        assertTrue(limiter.tryAcquire("sender"))
        assertFalse(limiter.tryAcquire("sender"))

        nowMs = 100
        assertTrue(limiter.tryAcquire("sender"))
        assertFalse(limiter.tryAcquire("sender"))

        // Independent buckets per key.
        assertTrue(limiter.tryAcquire("other"))
    }
}
