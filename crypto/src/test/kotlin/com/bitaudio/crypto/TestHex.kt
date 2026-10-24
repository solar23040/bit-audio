package com.bitaudio.crypto

internal fun hex(value: String): ByteArray =
    value.filterNot { it.isWhitespace() }
        .chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

internal fun ByteArray.toHex(): String =
    joinToString(separator = "") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
