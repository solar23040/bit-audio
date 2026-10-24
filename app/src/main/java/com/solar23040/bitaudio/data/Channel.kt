package com.solar23040.bitaudio.data

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * A channel joined on this install.
 *
 * [key] is the base64url-encoded 32-byte channel secret from the QR invite. It
 * must never be logged or rendered in the UI. The public channel ID is derived
 * from it with the same domain-separated SHA-256 derivation used by `:crypto`.
 */
data class Channel(
    val id: String,
    val name: String,
    val key: String,
    val alias: String,
    val ttl: Int,
    val createdAt: Long,
)

class ChannelRepository(context: Context, private val scope: CoroutineScope) {
    private val file = File(context.filesDir, "channels.json")
    private val mutex = Mutex()
    private val _channels = MutableStateFlow(load())
    val channels: StateFlow<List<Channel>> = _channels.asStateFlow()

    fun get(id: String): Channel? = _channels.value.firstOrNull { it.id == id }

    fun add(channel: Channel) {
        if (get(channel.id) != null) return
        _channels.value = _channels.value + channel
        persist()
    }

    fun remove(id: String) {
        _channels.value = _channels.value.filterNot { it.id == id }
        persist()
    }

    private fun load(): List<Channel> = runCatching {
        if (!file.isFile) return@runCatching emptyList()
        val array = JSONArray(file.readText())
        buildList {
            for (index in 0 until array.length()) {
                val json = array.optJSONObject(index) ?: continue
                val channel = json.toChannel() ?: continue
                add(channel)
            }
        }
    }.getOrDefault(emptyList())

    private fun persist() {
        scope.launch {
            mutex.withLock {
                runCatching {
                    val array = JSONArray()
                    _channels.value.forEach { array.put(it.toJson()) }
                    val text = array.toString()
                    val temp = File(file.parentFile, "${file.name}.tmp")
                    temp.writeText(text)
                    if (!temp.renameTo(file)) {
                        file.writeText(text)
                        temp.delete()
                    }
                }
            }
        }
    }

    private fun Channel.toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("key", key)
        put("alias", alias)
        put("ttl", ttl)
        put("createdAt", createdAt)
    }

    private fun JSONObject.toChannel(): Channel? = runCatching {
        Channel(
            id = getString("id"),
            name = getString("name"),
            key = getString("key"),
            alias = optString("alias", "Me"),
            ttl = optInt("ttl", 5).coerceIn(1, 10),
            createdAt = optLong("createdAt", System.currentTimeMillis()),
        )
    }.getOrNull()?.takeIf { it.id.isNotBlank() && it.key.isNotBlank() }
}
