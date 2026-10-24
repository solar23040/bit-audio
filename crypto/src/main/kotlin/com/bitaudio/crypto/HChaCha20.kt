package com.bitaudio.crypto

/**
 * HChaCha20 (draft-irtf-cfrg-xchacha, section 2.2): the 20-round ChaCha
 * permutation without the final addition, returning words 0..3 and 12..15.
 * Used only to derive XChaCha20 subkeys.
 */
object HChaCha20 {

    private const val KEY_SIZE = 32
    private const val NONCE_SIZE = 16
    private const val OUTPUT_SIZE = 32
    private const val ROUNDS = 20

    fun derive(key: ByteArray, nonce: ByteArray): ByteArray {
        require(key.size == KEY_SIZE) { "HChaCha20 key must be $KEY_SIZE bytes" }
        require(nonce.size == NONCE_SIZE) { "HChaCha20 nonce must be $NONCE_SIZE bytes" }

        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        for (i in 0 until 8) {
            state[4 + i] = readIntLe(key, i * 4)
        }
        for (i in 0 until 4) {
            state[12 + i] = readIntLe(nonce, i * 4)
        }

        repeat(ROUNDS / 2) {
            quarterRound(state, 0, 4, 8, 12)
            quarterRound(state, 1, 5, 9, 13)
            quarterRound(state, 2, 6, 10, 14)
            quarterRound(state, 3, 7, 11, 15)
            quarterRound(state, 0, 5, 10, 15)
            quarterRound(state, 1, 6, 11, 12)
            quarterRound(state, 2, 7, 8, 13)
            quarterRound(state, 3, 4, 9, 14)
        }

        val out = ByteArray(OUTPUT_SIZE)
        writeIntLe(out, 0, state[0])
        writeIntLe(out, 4, state[1])
        writeIntLe(out, 8, state[2])
        writeIntLe(out, 12, state[3])
        writeIntLe(out, 16, state[12])
        writeIntLe(out, 20, state[13])
        writeIntLe(out, 24, state[14])
        writeIntLe(out, 28, state[15])
        return out
    }

    private fun quarterRound(state: IntArray, a: Int, b: Int, c: Int, d: Int) {
        state[a] += state[b]
        state[d] = Integer.rotateLeft(state[d] xor state[a], 16)
        state[c] += state[d]
        state[b] = Integer.rotateLeft(state[b] xor state[c], 12)
        state[a] += state[b]
        state[d] = Integer.rotateLeft(state[d] xor state[a], 8)
        state[c] += state[d]
        state[b] = Integer.rotateLeft(state[b] xor state[c], 7)
    }

    private fun readIntLe(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)

    private fun writeIntLe(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = value.toByte()
        bytes[offset + 1] = (value ushr 8).toByte()
        bytes[offset + 2] = (value ushr 16).toByte()
        bytes[offset + 3] = (value ushr 24).toByte()
    }
}
