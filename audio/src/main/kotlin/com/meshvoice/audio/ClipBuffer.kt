package com.meshvoice.audio

/** Bounded PCM buffer used by the recorder. Kept separate from Android APIs so it is unit tested. */
internal class ClipBuffer(val capacity: Int) {

    init {
        require(capacity > 0) { "Capacity must be positive" }
    }

    private val data = ShortArray(capacity)

    var size: Int = 0
        private set

    val isFull: Boolean get() = size >= capacity

    /**
     * Copies up to [count] samples from [source] and returns how many were accepted.
     * Samples that do not fit in the remaining capacity are discarded.
     */
    fun append(source: ShortArray, count: Int = source.size): Int {
        require(count in 0..source.size) { "Count out of range: $count" }
        val accepted = minOf(count, capacity - size)
        if (accepted > 0) {
            source.copyInto(data, size, 0, accepted)
            size += accepted
        }
        return accepted
    }

    fun snapshot(): ShortArray = data.copyOf(size)
}
