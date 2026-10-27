package com.solar23040.bitaudio.security

import com.bitaudio.crypto.Ed25519
import com.bitaudio.crypto.RotatingSenderId
import com.meshvoice.transport.FakeNetwork
import com.meshvoice.transport.LinkConfig
import com.meshvoice.transport.Peer
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Threat cases for the proposed **Nearby** channel (SEC-018..SEC-021):
 *
 * 1. sybil flood of announces and public voice clips,
 * 2. nickname impersonation with a different key,
 * 3. tracking via a stable identity key or a fixed announce cadence,
 * 4. fake peer-count inflation and eclipse by a malicious relay.
 *
 * Nearby is not implemented on `main`; `MEMBER_ANNOUNCE` is still reserved. The
 * tests therefore attack the reference policy in [NearbyChannelModel] over the
 * real [FakeNetwork] and real `:crypto` Ed25519/rotating-ID code. They are the
 * executable acceptance criteria for the implementation, not a claim that the
 * shipped app already behaves this way. When the feature lands, retarget the
 * node to the production class and keep the assertions.
 */
open class NearbyChannelAttackTest {

    @Test
    fun `sybil announce and public clip flood stays bounded`() = runTest {
        val clock = AtomicLong(NOW_MS)
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            seed = 18L,
            externalScope = backgroundScope,
        )
        val victimTransport = network.addNode("victim")
        val attacker = network.addNode("attacker")
        network.connect("victim", "attacker")

        val limits = NearbyLimits(
            maxMembers = 64,
            perNeighbour = NearbyRate(perSecond = 50.0, burst = 100.0),
        )
        val victim = NearbyNode(victimTransport, CHANNEL_KEY, clock::get, limits)
        val aliceSeed = seed(1)
        val aliceIdentity = NearbyWire.epochPublicKey(aliceSeed, CHANNEL_KEY, epoch(clock.get()))

        // A real member gets in and publishes before the flood starts.
        attacker.send(
            Peer("victim"),
            NearbyWire.announce(
                channelKey = CHANNEL_KEY,
                stableSeed = aliceSeed,
                epoch = epoch(clock.get()),
                timestampMs = clock.get(),
                messageId = messageId(1),
                nickname = "Alice",
            ),
        )
        attacker.send(
            Peer("victim"),
            NearbyWire.voice(
                channelKey = CHANNEL_KEY,
                stableSeed = aliceSeed,
                epoch = epoch(clock.get()),
                timestampMs = clock.get(),
                messageId = messageId(2),
                body = "before flood".toByteArray(),
            ),
        )
        runCurrent()

        // 4,000 valid self-signed announces from distinct sybil keys at 200/s,
        // plus 500 public clips from the first wave. Every frame authenticates;
        // only the admission limits can contain them.
        var nextMessage = 100
        repeat(4_000) { index ->
            clock.addAndGet(5)
            val ts = clock.get()
            val sybilSeed = seed(1_000 + index)
            attacker.send(
                Peer("victim"),
                NearbyWire.announce(
                    channelKey = CHANNEL_KEY,
                    stableSeed = sybilSeed,
                    epoch = epoch(ts),
                    timestampMs = ts,
                    messageId = messageId(nextMessage++),
                    nickname = "bot$index",
                    claimedPeerCount = 0xFFFF,
                ),
            )
            if (index < 500) {
                attacker.send(
                    Peer("victim"),
                    NearbyWire.voice(
                        channelKey = CHANNEL_KEY,
                        stableSeed = sybilSeed,
                        epoch = epoch(ts),
                        timestampMs = ts,
                        messageId = messageId(nextMessage++),
                        body = ByteArray(32) { 0x42 },
                    ),
                )
            }
        }
        runCurrent()

        // The valid member is still usable after the flood; this is the part a
        // rate limiter must not break.
        clock.addAndGet(10_000)
        attacker.send(
            Peer("victim"),
            NearbyWire.voice(
                channelKey = CHANNEL_KEY,
                stableSeed = aliceSeed,
                epoch = epoch(clock.get()),
                timestampMs = clock.get(),
                messageId = messageId(nextMessage),
                body = "after flood".toByteArray(),
            ),
        )
        runCurrent()

        val aliceClips = victim.delivered.count { it.identityHex == aliceIdentity.toHex() }
        assertTrue("valid member's clip was starved by the flood", aliceClips >= 2)
        assertTrue(
            "registry grew past the cap: ${victim.memberCount()}",
            victim.memberCount() <= limits.maxMembers,
        )
        assertTrue("no announce was rate-limited", victim.droppedRate > 0)
        assertTrue("registry cap was never reached", victim.droppedCapacity > 0)
        assertTrue(
            "unbounded public clip delivery: ${victim.delivered.size}",
            victim.delivered.size <= limits.maxMembers * 5 + 2,
        )
        assertTrue(
            "a clip was attributed to an unadmitted identity",
            victim.delivered.all { victim.memberNickname(it.identityHex) != null },
        )
        println(
            "[SEC-018] announce/clip flood: members=${victim.memberCount()} " +
                "delivered=${victim.delivered.size} rateDrops=${victim.droppedRate} " +
                "capacityDrops=${victim.droppedCapacity} aliceClips=$aliceClips",
        )
        victim.close()
    }

    @Test
    fun `nickname spoof with a different key cannot overwrite an identity`() = runTest {
        val clock = AtomicLong(NOW_MS)
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            seed = 19L,
            externalScope = backgroundScope,
        )
        val victimTransport = network.addNode("victim")
        val peer = network.addNode("peer")
        network.connect("victim", "peer")
        val victim = NearbyNode(victimTransport, CHANNEL_KEY, clock::get)

        val aliceSeed = seed(2)
        val mallorySeed = seed(3)
        val aliceEpoch = NearbyWire.epochPublicKey(aliceSeed, CHANNEL_KEY, epoch(clock.get()))
        val malloryEpoch = NearbyWire.epochPublicKey(mallorySeed, CHANNEL_KEY, epoch(clock.get()))
        val aliceIdentity = aliceEpoch.toHex()
        val malloryIdentity = malloryEpoch.toHex()

        peer.send(Peer("victim"), announce(aliceSeed, clock.get(), messageId(11), "Alice"))
        clock.addAndGet(2_000)
        peer.send(Peer("victim"), announce(mallorySeed, clock.get(), messageId(12), "Alice"))
        runCurrent()

        assertEquals("two keys were merged", 2, victim.memberCount())
        assertEquals("Alice", victim.memberNickname(aliceIdentity))
        assertEquals("Alice", victim.memberNickname(malloryIdentity))
        val aliceLabel = victim.displayLabel(aliceIdentity)
        val malloryLabel = victim.displayLabel(malloryIdentity)
        assertNotEquals("duplicate nicknames rendered identically", aliceLabel, malloryLabel)
        assertTrue("label lost the chosen nickname", aliceLabel!!.startsWith("Alice"))
        assertTrue("label lost the chosen nickname", malloryLabel!!.startsWith("Alice"))

        // The key owner may rename themselves, but a different key cannot take
        // over the old entry or create a third identity.
        clock.addAndGet(2_000)
        peer.send(
            Peer("victim"),
            announce(aliceSeed, clock.get(), messageId(13), "Alice Cooper"),
        )
        runCurrent()
        assertEquals("rename created a new identity", 2, victim.memberCount())
        assertEquals("Alice Cooper", victim.memberNickname(aliceIdentity))
        assertEquals("Alice", victim.memberNickname(malloryIdentity))

        // A corrupted signature must never reach the registry.
        val forged = announce(mallorySeed, clock.get(), messageId(14), "Alice")
        forged[forged.lastIndex] = (forged.last().toInt() xor 1).toByte()
        val invalidBefore = victim.droppedInvalid
        peer.send(Peer("victim"), forged)
        runCurrent()
        assertEquals("forged nickname claim changed the registry", 2, victim.memberCount())
        assertTrue("forged frame was not counted as invalid", victim.droppedInvalid > invalidBefore)

        // Voice attribution follows the key, not the nickname.
        clock.addAndGet(2_000)
        peer.send(
            Peer("victim"),
            NearbyWire.voice(
                channelKey = CHANNEL_KEY,
                stableSeed = mallorySeed,
                epoch = epoch(clock.get()),
                timestampMs = clock.get(),
                messageId = messageId(15),
                body = "my clip".toByteArray(),
            ),
        )
        runCurrent()
        assertEquals(malloryIdentity, victim.delivered.last().identityHex)
        println(
            "[SEC-019] nickname binding: alice=$aliceLabel mallory=$malloryLabel " +
                "members=${victim.memberCount()}",
        )
        victim.close()
    }

    @Test
    fun `stable install key and fixed announce cadence are not exposed`() = runTest {
        val stableSeed = seed(4)
        val stablePublicKey = Ed25519.publicKeyFromSeed(stableSeed)
        val epoch0 = epoch(NOW_MS)
        val epoch1 = epoch0 + 1
        val frame0 = NearbyWire.announce(
            channelKey = CHANNEL_KEY,
            stableSeed = stableSeed,
            epoch = epoch0,
            timestampMs = epoch0 * RotatingSenderId.EPOCH_MILLIS + 1_000,
            messageId = messageId(21),
            nickname = "Alice",
        )
        val frame1 = NearbyWire.announce(
            channelKey = CHANNEL_KEY,
            stableSeed = stableSeed,
            epoch = epoch1,
            timestampMs = epoch1 * RotatingSenderId.EPOCH_MILLIS + 1_000,
            messageId = messageId(22),
            nickname = "Alice",
        )

        assertFalse(
            "stable install public key is present in an announce",
            frame0.containsSubsequence(stablePublicKey),
        )
        assertFalse(
            "stable install public key is present in the next epoch announce",
            frame1.containsSubsequence(stablePublicKey),
        )

        val parsed0 = requireNotNull(NearbyWire.decode(frame0, CHANNEL_KEY))
        val parsed1 = requireNotNull(NearbyWire.decode(frame1, CHANNEL_KEY))
        assertNotEquals("sender ID did not rotate across epochs", parsed0.senderIdHex, parsed1.senderIdHex)
        assertNotEquals(
            "epoch identity key did not rotate across epochs",
            parsed0.identityHex,
            parsed1.identityHex,
        )
        assertNotEquals(
            "same identity is linkable across epochs",
            NearbyWire.epochPublicKey(stableSeed, CHANNEL_KEY, epoch0).toHex(),
            NearbyWire.epochPublicKey(stableSeed, CHANNEL_KEY, epoch1).toHex(),
        )

        // A fixed 30 s beacon is a fingerprint even when the payload rotates.
        val firstRandom = Random(101)
        val secondRandom = Random(202)
        val first = (1..64).map { NearbySchedule.nextDelayMs(firstRandom) }
        val second = (1..64).map { NearbySchedule.nextDelayMs(secondRandom) }
        assertTrue(
            "announce delay left the jitter window",
            first.all { it in NearbySchedule.BASE_INTERVAL_MS..(NearbySchedule.BASE_INTERVAL_MS + NearbySchedule.JITTER_MS.last) },
        )
        assertTrue("announce cadence is constant", first.toSet().size > 8)
        assertNotEquals("two devices share the same cadence", first, second)

        println(
            "[SEC-020] tracking: sender0=${parsed0.senderIdHex} sender1=${parsed1.senderIdHex} " +
                "uniqueDelays=${first.toSet().size}",
        )
    }

    @Test
    fun `relay cannot inflate peer count or eclipse a direct peer`() = runTest {
        val clock = AtomicLong(NOW_MS)
        val network = FakeNetwork(
            defaultLink = LinkConfig(lossRate = 0.0, latencyMs = 0L..0L),
            seed = 20L,
            externalScope = backgroundScope,
        )
        val victimTransport = network.addNode("victim")
        val alice = network.addNode("alice")
        val mallory = network.addNode("mallory")
        val bob = network.addNode("bob")
        network.connect("victim", "alice")
        network.connect("victim", "mallory")
        network.connect("mallory", "bob")

        val victim = NearbyNode(
            victimTransport,
            CHANNEL_KEY,
            clock::get,
            NearbyLimits(maxMembers = 8, memberTtlMs = 60_000),
        )
        val aliceSeed = seed(5)
        val mallorySeed = seed(6)
        val bobSeed = seed(7)
        val aliceIdentity = NearbyWire.epochPublicKey(aliceSeed, CHANNEL_KEY, epoch(clock.get())).toHex()
        val bobIdentity = NearbyWire.epochPublicKey(bobSeed, CHANNEL_KEY, epoch(clock.get())).toHex()

        alice.send(Peer("victim"), announce(aliceSeed, clock.get(), messageId(31), "Alice"))
        clock.addAndGet(1_000)
        mallory.send(
            Peer("victim"),
            announce(mallorySeed, clock.get(), messageId(32), "Eve", claimedPeerCount = 0xFFFF),
        )
        runCurrent()

        assertEquals("honest peer was not admitted", 1, victim.memberCount() - 1)
        assertEquals("claimed peer count was trusted", 2, victim.verifiedPeerCount())
        assertTrue("attacker count leaked into the UI", victim.verifiedPeerCount() < 0xFFFF)

        // Repeating the claim, with fresh message IDs, cannot add identities or
        // push the count up; admission is per authenticated key.
        var next = 100
        repeat(200) {
            clock.addAndGet(2)
            mallory.send(
                Peer("victim"),
                announce(mallorySeed, clock.get(), messageId(next++), "Eve", claimedPeerCount = 0xFFFF),
            )
        }
        runCurrent()
        assertEquals("duplicate claims inflated the count", 2, victim.memberCount())

        // An invalid signature cannot inject a fake peer at all.
        val forged = announce(mallorySeed, clock.get(), messageId(next++), "Alice", 0xFFFF)
        forged[forged.lastIndex] = (forged.last().toInt() xor 1).toByte()
        mallory.send(Peer("victim"), forged)
        runCurrent()
        assertEquals("forged announce added a peer", 2, victim.memberCount())

        // A relay that drops Bob's announce cannot make Bob appear; equally, the
        // victim must not claim a crowd it cannot authenticate.
        bob.send(Peer("mallory"), announce(bobSeed, clock.get(), messageId(next++), "Bob"))
        runCurrent()
        assertNull("a relay invented a peer it did not forward", victim.memberNickname(bobIdentity))
        assertEquals("relay inflated the peer count", 2, victim.verifiedPeerCount())

        // A direct path still delivers Alice's clip while Mallory lies.
        clock.addAndGet(1_000)
        alice.send(
            Peer("victim"),
            NearbyWire.voice(
                channelKey = CHANNEL_KEY,
                stableSeed = aliceSeed,
                epoch = epoch(clock.get()),
                timestampMs = clock.get(),
                messageId = messageId(next++),
                body = "still here".toByteArray(),
            ),
        )
        runCurrent()
        assertEquals(aliceIdentity, victim.delivered.last().identityHex)

        // Once peers go silent the count decays to zero, not to the claimed
        // 65,535. The UI must label this as recently heard, not "network size".
        clock.addAndGet(61_000)
        victim.expire(clock.get())
        assertEquals("stale peers still counted", 0, victim.verifiedPeerCount())
        println(
            "[SEC-021] eclipse/count: verified=${victim.verifiedPeerCount()} " +
                "droppedInvalid=${victim.droppedInvalid} droppedDuplicate=${victim.droppedDuplicate}",
        )
        victim.close()
    }

    private fun announce(
        stableSeed: ByteArray,
        timestampMs: Long,
        messageId: ByteArray,
        nickname: String,
        claimedPeerCount: Int = 0,
    ): ByteArray = NearbyWire.announce(
        channelKey = CHANNEL_KEY,
        stableSeed = stableSeed,
        epoch = epoch(timestampMs),
        timestampMs = timestampMs,
        messageId = messageId,
        nickname = nickname,
        claimedPeerCount = claimedPeerCount,
    )

    private fun epoch(timestampMs: Long): Long = RotatingSenderId.epochFor(timestampMs)

    private fun seed(index: Int): ByteArray = MessageDigest.getInstance("SHA-256")
        .digest("nearby-test-seed-$index".toByteArray(Charsets.US_ASCII))

    private fun messageId(value: Int): ByteArray = ByteArray(8) { index ->
        val shift = (7 - index) * 8
        ((value.toLong() ushr shift) and 0xFF).toByte()
    }

    private companion object {
        const val NOW_MS = 1_700_000_000_000L
        val CHANNEL_KEY = ByteArray(32) { index -> (index * 11 + 3).toByte() }
    }
}
