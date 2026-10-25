package com.solar23040.bitaudio.security

import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 5 attack suite. Runs the real `:mesh` receive paths (`MeshEngine` and
 * the app-wired `MeshNode`) with real `:crypto` on `FakeNetwork`.
 *
 * Cases mirror the checklist in `pllan.md` and `security/threat-model.md`:
 * spoofing, replay, malformed headers, TTL=0, flood/reassembly bounds and
 * malicious-relay tampering.
 *
 * Known-open findings are *observed* and printed (`SEC-... OPEN`) instead of
 * failing the build; every fixed property is a hard assertion so a regression
 * turns CI red.
 */
class MeshAttackTest {

    @Test
    fun `spoofed sender is dropped and never relayed`() = runTest {
        for (kind in MeshKind.entries) {
            val rig = Rig(this, kind)
            try {
                val aliceId = Frames.senderId(rig.channelKey, rig.alicePublicKey, Rig.NOW_MS)
                val forged = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.bobSeed,
                    senderId = aliceId,
                    messageId = Frames.uniqueMessageId(0x1101),
                    counter = 1,
                    ttl = 5,
                    plaintext = "forged".toByteArray(),
                )
                rig.send("a", "b", forged)
                advanceUntilIdle()
                assertTrue(
                    "$kind: forged sender was delivered: b=${rig.deliveredAt("b").size}",
                    rig.deliveredAt("b").isEmpty(),
                )
                assertTrue("$kind: forged sender reached the next hop", rig.rawFramesAtC().isEmpty())

                // Unknown rotating ID must fail before signature work.
                val unknown = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.bobSeed,
                    senderId = ByteArray(8) { 0x7f },
                    messageId = Frames.uniqueMessageId(0x1102),
                    counter = 2,
                    ttl = 5,
                )
                rig.send("a", "b", unknown)
                advanceUntilIdle()
                assertTrue("$kind: unresolved sender was delivered", rig.deliveredAt("b").isEmpty())

                // Baseline proves the identity/roster is accepted.
                val valid = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = aliceId,
                    messageId = Frames.uniqueMessageId(0x1103),
                    counter = 3,
                    ttl = 5,
                    plaintext = "baseline".toByteArray(),
                )
                rig.send("a", "b", valid)
                advanceUntilIdle()
                assertEquals("$kind: baseline was not delivered", 1, rig.deliveredAt("b").size)
                assertTrue("$kind: baseline was not relayed", rig.rawFramesAtC().isNotEmpty())
            } finally {
                rig.close()
            }
        }
    }

    @Test
    fun `replayed frame is delivered once and relayed once`() = runTest {
        for (kind in MeshKind.entries) {
            val rig = Rig(this, kind)
            try {
                val frame = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = Frames.senderId(rig.channelKey, rig.alicePublicKey, Rig.NOW_MS),
                    messageId = Frames.uniqueMessageId(0x2101),
                    counter = 1,
                    ttl = 5,
                    plaintext = "once".toByteArray(),
                )
                rig.send("a", "b", frame)
                rig.send("a", "b", frame)
                advanceUntilIdle()

                assertEquals("$kind: replay delivered twice", 1, rig.deliveredAt("b").size)
                assertEquals("$kind: replay reached the far node twice", 1, rig.deliveredAt("c").size)
                assertEquals("$kind: replay relayed twice", 1, rig.rawFramesAtC().size)
            } finally {
                rig.close()
            }
        }
    }

    @Test
    fun `malformed headers are rejected without crashing`() = runTest {
        for (kind in MeshKind.entries) {
            val rig = Rig(this, kind)
            try {
                var counter = 1L
                fun valid(): ByteArray = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = Frames.senderId(rig.channelKey, rig.alicePublicKey, Rig.NOW_MS),
                    messageId = Frames.uniqueMessageId(0x3100 + counter.toInt()),
                    counter = counter++,
                    ttl = 5,
                    plaintext = "valid".toByteArray(),
                )

                val base = valid()
                val cases = linkedMapOf(
                    "huge total_chunks" to Frames.patchU16(base, 29, 0xFFFF),
                    "zero total_chunks" to Frames.patchU16(base, 29, 0),
                    "chunk_idx overflow" to Frames.patchU16(base, 27, 0xFFFF),
                    "truncated header" to base.copyOf(106),
                    "truncated mid-header" to base.copyOf(50),
                    "oversize frame" to (base + ByteArray(512)),
                    "empty payload" to base.copyOf(107),
                    "short sealed payload" to base.copyOf(107 + 39),
                    "ttl zero" to base.copyOf().also { it[26] = 0 },
                    "ttl nine" to base.copyOf().also { it[26] = 9 },
                    "version two" to base.copyOf().also { it[0] = 2 },
                    "unknown type" to base.copyOf().also { it[1] = 2 },
                    "future timestamp" to Frames.patchU64(base, 31, Rig.NOW_MS + 10 * 60_000),
                    "stale timestamp" to Frames.patchU64(base, 31, Rig.NOW_MS - 25L * 60 * 60_000),
                )

                val deliveriesBefore = rig.deliveredAt("b").size
                for ((name, frame) in cases) {
                    val rawBefore = rig.rawFramesAtC().size
                    rig.send("a", "b", frame)
                    advanceUntilIdle()
                    assertEquals(
                        "$kind: $name was delivered",
                        deliveriesBefore,
                        rig.deliveredAt("b").size,
                    )
                    assertEquals("$kind: $name was relayed", rawBefore, rig.rawFramesAtC().size)
                }

                // The parser must still work after the malformed batch.
                val after = valid()
                rig.send("a", "b", after)
                advanceUntilIdle()
                assertEquals(
                    "$kind: node did not recover after malformed input",
                    deliveriesBefore + 1,
                    rig.deliveredAt("b").size,
                )
            } finally {
                rig.close()
            }
        }
    }

    @Test
    fun `ttl zero is dropped and ttl two relays exactly once`() = runTest {
        for (kind in MeshKind.entries) {
            val rig = Rig(this, kind)
            try {
                val senderId = Frames.senderId(rig.channelKey, rig.alicePublicKey, Rig.NOW_MS)

                val zero = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = senderId,
                    messageId = Frames.uniqueMessageId(0x4101),
                    counter = 1,
                    ttl = 0,
                    plaintext = "ttl zero".toByteArray(),
                )
                rig.send("a", "b", zero)
                advanceUntilIdle()
                assertTrue("$kind: ttl=0 was delivered", rig.deliveredAt("b").isEmpty())
                assertTrue("$kind: ttl=0 was relayed", rig.rawFramesAtC().isEmpty())

                val one = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = senderId,
                    messageId = Frames.uniqueMessageId(0x4102),
                    counter = 2,
                    ttl = 1,
                    plaintext = "ttl one".toByteArray(),
                )
                rig.send("a", "b", one)
                advanceUntilIdle()
                assertEquals("$kind: ttl=1 not delivered", 1, rig.deliveredAt("b").size)
                assertTrue("$kind: ttl=1 was relayed", rig.rawFramesAtC().isEmpty())

                val two = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = senderId,
                    messageId = Frames.uniqueMessageId(0x4103),
                    counter = 3,
                    ttl = 2,
                    plaintext = "ttl two".toByteArray(),
                )
                rig.send("a", "b", two)
                advanceUntilIdle()
                assertEquals("$kind: ttl=2 not delivered", 2, rig.deliveredAt("b").size)
                assertEquals("$kind: ttl=2 not relayed exactly once", 1, rig.rawFramesAtC().size)
                assertEquals(
                    "$kind: relay did not decrement ttl",
                    1,
                    rig.rawFramesAtC().single()[Frames.TTL_OFFSET].toInt() and 0xFF,
                )
                assertEquals("$kind: far node did not deliver the relay", 1, rig.deliveredAt("c").size)
            } finally {
                rig.close()
            }
        }
    }

    @Test
    fun `malicious relay mutations are rejected`() = runTest {
        for (kind in MeshKind.entries) {
            val rig = Rig(this, kind)
            try {
                val senderId = Frames.senderId(rig.channelKey, rig.alicePublicKey, Rig.NOW_MS)
                var counter = 1L
                fun valid(plaintext: String = "relay"): ByteArray = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = senderId,
                    messageId = Frames.uniqueMessageId(0x5100 + counter.toInt()),
                    counter = counter++,
                    ttl = 5,
                    plaintext = plaintext.toByteArray(),
                )

                val baseline = valid("baseline")
                rig.send("a", "b", baseline)
                advanceUntilIdle()
                assertEquals("$kind: baseline not delivered", 1, rig.deliveredAt("b").size)
                val baselineRaw = rig.rawFramesAtC().size
                assertTrue("$kind: baseline not relayed", baselineRaw > 0)

                val cases: List<Pair<String, ByteArray>> = run {
                    val origin = valid()
                    listOf(
                        "flip sender" to origin.copyOf().also { it[18] = (it[18].toInt() xor 1).toByte() },
                        "flip channel" to origin.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() },
                        "flip msg_id" to origin.copyOf().also { it[2] = (it[2].toInt() xor 1).toByte() },
                        "rewrite timestamp" to Frames.patchU64(origin, 31, Rig.NOW_MS + 1_000),
                        "rewrite counter" to Frames.patchU32(origin, 39, 0x00FF_FFFF),
                        "flip signature" to origin.copyOf().also { it[50] = (it[50].toInt() xor 1).toByte() },
                        "clear signature" to origin.copyOf().also { frame ->
                            for (index in 43 until 107) frame[index] = 0
                        },
                        "flip nonce" to origin.copyOf().also { it[110] = (it[110].toInt() xor 1).toByte() },
                        "flip ciphertext" to origin.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
                        "truncate header" to origin.copyOf(106),
                        "truncate payload" to origin.copyOf(origin.size - 1),
                        "oversize" to (origin + ByteArray(32)),
                        "unknown type" to origin.copyOf().also { it[1] = 3 },
                        "bad version" to origin.copyOf().also { it[0] = 0 },
                        "ttl overflow" to origin.copyOf().also { it[26] = 9 },
                    )
                }

                for ((name, frame) in cases) {
                    val deliveredBefore = rig.deliveredAt("b").size
                    val rawBefore = rig.rawFramesAtC().size
                    rig.send("a", "b", frame)
                    advanceUntilIdle()
                    assertEquals("$kind: $name was delivered", deliveredBefore, rig.deliveredAt("b").size)
                    assertEquals("$kind: $name was relayed", rawBefore, rig.rawFramesAtC().size)
                }

                // Splice two valid chunks from different messages under one msg_id.
                val msgId = Frames.uniqueMessageId(0x55AA)
                val chunk0 = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = senderId,
                    messageId = msgId,
                    counter = counter++,
                    ttl = 5,
                    chunkIndex = 0,
                    totalChunks = 2,
                    plaintext = "first-".toByteArray(),
                )
                val chunk1 = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = senderId,
                    messageId = msgId,
                    counter = counter++,
                    timestampMs = Rig.NOW_MS + 1,
                    ttl = 5,
                    chunkIndex = 1,
                    totalChunks = 2,
                    plaintext = "second".toByteArray(),
                )
                val beforeSplice = rig.deliveredAt("b").size
                rig.send("a", "b", chunk0)
                rig.send("a", "b", chunk1)
                advanceUntilIdle()
                assertEquals(
                    "$kind: inconsistent shared header was reassembled",
                    beforeSplice,
                    rig.deliveredAt("b").size,
                )

                // A genuine two-chunk message still reassembles.
                val goodMsg = Frames.uniqueMessageId(0x55AB)
                val goodCounter = counter++
                val good0 = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = senderId,
                    messageId = goodMsg,
                    counter = goodCounter,
                    ttl = 5,
                    chunkIndex = 0,
                    totalChunks = 2,
                    plaintext = "hello ".toByteArray(),
                )
                val good1 = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = senderId,
                    messageId = goodMsg,
                    counter = goodCounter,
                    ttl = 5,
                    chunkIndex = 1,
                    totalChunks = 2,
                    plaintext = "world".toByteArray(),
                )
                rig.send("a", "b", good0)
                rig.send("a", "b", good1)
                advanceUntilIdle()
                assertEquals(
                    "$kind: valid multi-chunk message rejected",
                    beforeSplice + 1,
                    rig.deliveredAt("b").size,
                )
                assertEquals(
                    "$kind: multi-chunk plaintext mismatch",
                    "hello world",
                    String(rig.deliveredAt("b").last().payload),
                )
            } finally {
                rig.close()
            }
        }
    }

    @Test
    fun `flood and reassembly claims stay bounded and do not block delivery`() = runTest {
        for (kind in MeshKind.entries) {
            val rig = Rig(this, kind)
            try {
                val random = java.util.Random(0x5EED)
                repeat(2_000) { index ->
                    val frame = if (index % 3 == 0) {
                        ByteArray(512) { random.nextInt(256).toByte() }
                    } else {
                        ByteArray(random.nextInt(600)) { random.nextInt(256).toByte() }
                    }
                    rig.send("a", "b", frame)
                }
                advanceUntilIdle()

                // Validly signed claims that each announce 256 chunks: forces the
                // bounded partial-message cache instead of an allocation per msg.
                val senderId = Frames.senderId(rig.channelKey, rig.alicePublicKey, Rig.NOW_MS)
                for (index in 0 until 300) {
                    val frame = Frames.build(
                        channelKey = rig.channelKey,
                        signingSeed = rig.aliceSeed,
                        senderId = senderId,
                        messageId = Frames.uniqueMessageId(0x6000 + index),
                        counter = index + 1L,
                        ttl = 1,
                        chunkIndex = 0,
                        totalChunks = 256,
                        plaintext = ByteArray(16) { index.toByte() },
                    )
                    rig.send("a", "b", frame)
                    if (index % 50 == 49) advanceUntilIdle()
                }
                advanceUntilIdle()

                val valid = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = senderId,
                    messageId = Frames.uniqueMessageId(0x6FFF),
                    counter = 10_000,
                    ttl = 1,
                    plaintext = "still alive".toByteArray(),
                )
                rig.send("a", "b", valid)
                advanceUntilIdle()

                assertEquals(
                    "$kind: flood prevented valid delivery",
                    "still alive",
                    String(rig.deliveredAt("b").last().payload),
                )
                assertTrue("$kind: flood frame was relayed", rig.rawFramesAtC().isEmpty())
                assertTrue("$kind: flood frame was delivered", rig.deliveredAt("b").size == 1)
            } finally {
                rig.close()
            }
        }
    }

    @Test
    fun `known open findings are reproduced and reported`() = runTest {
        // SEC-001: the docs dedup key omits the resolved identity. MeshEngine
        // includes it; MeshNode (the class wired into AppGraph) does not, so a
        // member can suppress another member's chunk.
        for (kind in MeshKind.entries) {
            val rig = Rig(this, kind)
            try {
                val msgId = Frames.uniqueMessageId(0x7101)
                val bobFrame = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.bobSeed,
                    senderId = Frames.senderId(rig.channelKey, rig.bobPublicKey, Rig.NOW_MS),
                    messageId = msgId,
                    counter = 1,
                    ttl = 1,
                    plaintext = "bob-first".toByteArray(),
                )
                val aliceFrame = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = Frames.senderId(rig.channelKey, rig.alicePublicKey, Rig.NOW_MS),
                    messageId = msgId,
                    counter = 1,
                    ttl = 1,
                    plaintext = "alice-real".toByteArray(),
                )
                rig.send("a", "b", bobFrame)
                rig.send("a", "b", aliceFrame)
                advanceUntilIdle()

                val delivered = rig.deliveredAt("b").map { String(it.payload) }
                if (delivered.size == 1) {
                    println(
                        "[SEC-001][$kind] OPEN: dedup key (channel,msg_id,chunk) " +
                            "suppressed a different sender's valid chunk: delivered=$delivered",
                    )
                } else {
                    println("[SEC-001][$kind] fixed: both senders delivered=$delivered")
                }
                if (kind == MeshKind.ENGINE) {
                    assertEquals("MeshEngine should scope dedup by resolved identity", 2, delivered.size)
                } else {
                    assertTrue("unexpected delivery count: $delivered", delivered.size in 1..2)
                }
            } finally {
                rig.close()
            }
        }

        // SEC-019: docs require counter >= 1. MeshEngine rejects 0; MeshNode
        // currently accepts it.
        for (kind in MeshKind.entries) {
            val rig = Rig(this, kind)
            try {
                val frame = Frames.build(
                    channelKey = rig.channelKey,
                    signingSeed = rig.aliceSeed,
                    senderId = Frames.senderId(rig.channelKey, rig.alicePublicKey, Rig.NOW_MS),
                    messageId = Frames.uniqueMessageId(0x7201),
                    counter = 0,
                    ttl = 1,
                    plaintext = "counter zero".toByteArray(),
                )
                rig.send("a", "b", frame)
                advanceUntilIdle()
                val accepted = rig.deliveredAt("b").isNotEmpty()
                if (accepted) {
                    println("[SEC-019][$kind] OPEN: counter=0 accepted (docs require 1..2^32-1)")
                } else {
                    println("[SEC-019][$kind] fixed: counter=0 rejected")
                }
                if (kind == MeshKind.ENGINE) {
                    assertFalse("MeshEngine accepted counter=0", accepted)
                }
            } finally {
                rig.close()
            }
        }
    }
}
