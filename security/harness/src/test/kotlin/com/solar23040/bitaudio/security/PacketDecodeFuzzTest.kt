package com.solar23040.bitaudio.security

import java.util.concurrent.CopyOnWriteArrayList
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Time-boxed parser fuzz (SEC-003/SEC-012). Feeds random, truncated, extended
 * and bit-flipped frames into the real `:mesh` receive path and proves the node
 * still decodes and delivers a valid clip afterwards.
 *
 * The wall-clock budget comes from `SECURITY_FUZZ_SECONDS` (CI sets 90 s per
 * implementation; the default keeps a local run short).
 */
class PacketDecodeFuzzTest {

    @Test
    fun `decoder survives a time-boxed fuzz run`() {
        val seconds = (System.getenv("SECURITY_FUZZ_SECONDS")?.toLongOrNull() ?: 20L)
            .coerceIn(5L, 300L)

        // Two implementations, so allow the whole test body well past the budget.
        runTest(timeout = (seconds * 3 + 60).seconds) {
            for (kind in MeshKind.entries) {
                val rig = Rig(this, kind, UnconfinedTestDispatcher(testScheduler))
                val uncaught = CopyOnWriteArrayList<Throwable>()
                val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
                Thread.setDefaultUncaughtExceptionHandler { _, error -> uncaught.add(error) }
                try {
                    val senderId = Frames.senderId(rig.channelKey, rig.alicePublicKey, Rig.NOW_MS)
                    val rng = java.util.Random(0x2026_1025L + kind.ordinal)
                    val corpus = Frames.build(
                        channelKey = rig.channelKey,
                        signingSeed = rig.aliceSeed,
                        senderId = senderId,
                        messageId = Frames.uniqueMessageId(0x8101),
                        counter = 1,
                        ttl = 5,
                        plaintext = "corpus".toByteArray(),
                    )

                    var iterations = 0
                    var resets = 0
                    val deadline = System.nanoTime() + seconds * 1_000_000_000L
                    while (System.nanoTime() < deadline && iterations < 250_000) {
                        rig.send("a", "b", generate(rng, corpus))
                        iterations++

                        if (iterations % 2_000 == 0) {
                            val before = rig.deliveredAt("b").size
                            rig.send("a", "b", resetFrame(rig, senderId, ++resets))
                            assertEquals(
                                "$kind: valid delivery stopped after $iterations fuzz frames",
                                before + 1,
                                rig.deliveredAt("b").size,
                            )
                        }
                    }

                    val before = rig.deliveredAt("b").size
                    rig.send("a", "b", resetFrame(rig, senderId, ++resets))
                    assertEquals(
                        "$kind: final valid frame was not delivered",
                        before + 1,
                        rig.deliveredAt("b").size,
                    )

                    println(
                        "[fuzz][$kind] $iterations frames in ${seconds}s " +
                            "(${iterations / seconds.coerceAtLeast(1)}/s), $resets valid resets delivered",
                    )
                    assertTrue("$kind: uncaught parser error: ${uncaught.firstOrNull()}", uncaught.isEmpty())
                } finally {
                    Thread.setDefaultUncaughtExceptionHandler(previousHandler)
                    rig.close()
                }
            }
        }
    }

    private fun resetFrame(rig: Rig, senderId: ByteArray, sequence: Int): ByteArray =
        Frames.build(
            channelKey = rig.channelKey,
            signingSeed = rig.aliceSeed,
            senderId = senderId,
            messageId = Frames.uniqueMessageId(0x82_0000 + sequence),
            counter = 1_000L + sequence,
            ttl = 1,
            plaintext = "reset-$sequence".toByteArray(),
        )

    private fun generate(rng: java.util.Random, corpus: ByteArray): ByteArray =
        when (rng.nextInt(5)) {
            0 -> ByteArray(rng.nextInt(600)) { rng.nextInt(256).toByte() }
            1 -> {
                val frame = corpus.copyOf()
                repeat(1 + rng.nextInt(8)) {
                    frame[rng.nextInt(frame.size)] = rng.nextInt(256).toByte()
                }
                frame
            }

            2 -> {
                val length = rng.nextInt(600)
                val frame = ByteArray(length) { rng.nextInt(256).toByte() }
                if (length > 2) {
                    frame[0] = 1
                    frame[1] = 1
                }
                frame
            }

            3 -> corpus.copyOfRange(0, rng.nextInt(corpus.size + 1))
            else -> {
                val extra = rng.nextInt(600)
                corpus + ByteArray(extra) { rng.nextInt(256).toByte() }
            }
        }
}
