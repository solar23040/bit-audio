package com.solar23040.bitaudio.mesh.store

import android.content.ContentValues
import android.content.Context
import android.database.DatabaseUtils
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.solar23040.bitaudio.mesh.ChannelId

/**
 * SQLite-backed store-and-forward queue.
 *
 * One row per chunk keyed by `(channel, msg_id, chunk_idx)`; counters live in a
 * separate table so a publisher never reuses a counter after a restart. Only
 * sealed frames and routing metadata are written.
 */
class SqliteMeshStore(
    context: Context,
    databaseName: String = DEFAULT_DATABASE_NAME,
    private val maxPackets: Int = DEFAULT_MAX_PACKETS,
) : MeshStore {

    init {
        require(maxPackets > 0) { "maxPackets must be > 0" }
    }

    private val helper = object : SQLiteOpenHelper(context.applicationContext, databaseName, null, VERSION) {
        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL(
                """
                CREATE TABLE $TABLE_PACKETS (
                    $COL_CHANNEL TEXT NOT NULL,
                    $COL_MESSAGE_ID TEXT NOT NULL,
                    $COL_CHUNK_INDEX INTEGER NOT NULL,
                    $COL_TIMESTAMP INTEGER NOT NULL,
                    $COL_EXPIRES_AT INTEGER NOT NULL,
                    $COL_FRAME BLOB NOT NULL,
                    PRIMARY KEY ($COL_CHANNEL, $COL_MESSAGE_ID, $COL_CHUNK_INDEX)
                )
                """.trimIndent(),
            )
            db.execSQL("CREATE INDEX ${TABLE_PACKETS}_expiry ON $TABLE_PACKETS ($COL_EXPIRES_AT)")
            db.execSQL(
                """
                CREATE TABLE $TABLE_COUNTERS (
                    $COL_CHANNEL TEXT PRIMARY KEY NOT NULL,
                    $COL_COUNTER INTEGER NOT NULL
                )
                """.trimIndent(),
            )
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
            db.execSQL("DROP TABLE IF EXISTS $TABLE_PACKETS")
            db.execSQL("DROP TABLE IF EXISTS $TABLE_COUNTERS")
            onCreate(db)
        }
    }

    @Synchronized
    override fun save(packet: StoredPacket) {
        val values = ContentValues().apply {
            put(COL_CHANNEL, packet.channel.hex)
            put(COL_MESSAGE_ID, packet.messageId)
            put(COL_CHUNK_INDEX, packet.chunkIndex)
            put(COL_TIMESTAMP, packet.timestampMs)
            put(COL_EXPIRES_AT, packet.expiresAtMs)
            put(COL_FRAME, packet.frame)
        }
        val db = helper.writableDatabase
        db.insertWithOnConflict(TABLE_PACKETS, null, values, SQLiteDatabase.CONFLICT_REPLACE)
        trim(db)
    }

    @Synchronized
    override fun loadUnexpired(nowMs: Long): List<StoredPacket> {
        val out = ArrayList<StoredPacket>()
        helper.readableDatabase.query(
            TABLE_PACKETS,
            COLUMNS,
            "$COL_EXPIRES_AT > ?",
            arrayOf(nowMs.toString()),
            null,
            null,
            "$COL_TIMESTAMP ASC, $COL_CHUNK_INDEX ASC",
        ).use { cursor ->
            val channelIndex = cursor.getColumnIndexOrThrow(COL_CHANNEL)
            val messageIndex = cursor.getColumnIndexOrThrow(COL_MESSAGE_ID)
            val chunkIndex = cursor.getColumnIndexOrThrow(COL_CHUNK_INDEX)
            val timestampIndex = cursor.getColumnIndexOrThrow(COL_TIMESTAMP)
            val expiresIndex = cursor.getColumnIndexOrThrow(COL_EXPIRES_AT)
            val frameIndex = cursor.getColumnIndexOrThrow(COL_FRAME)

            while (cursor.moveToNext()) {
                val channel = runCatching { ChannelId.fromHex(cursor.getString(channelIndex)) }
                    .getOrNull() ?: continue
                val frame = cursor.getBlob(frameIndex) ?: continue
                if (frame.size !in 107..512) continue
                out.add(
                    StoredPacket(
                        channel = channel,
                        messageId = cursor.getString(messageIndex),
                        chunkIndex = cursor.getInt(chunkIndex),
                        timestampMs = cursor.getLong(timestampIndex),
                        expiresAtMs = cursor.getLong(expiresIndex),
                        frame = frame,
                    ),
                )
            }
        }
        return out
    }

    @Synchronized
    override fun deleteExpired(nowMs: Long): Int =
        helper.writableDatabase.delete(TABLE_PACKETS, "$COL_EXPIRES_AT <= ?", arrayOf(nowMs.toString()))

    @Synchronized
    override fun nextCounter(channel: ChannelId): Long {
        val db = helper.writableDatabase
        db.beginTransaction()
        return try {
            val current = db.rawQuery(
                "SELECT $COL_COUNTER FROM $TABLE_COUNTERS WHERE $COL_CHANNEL = ?",
                arrayOf(channel.hex),
            ).use { cursor -> if (cursor.moveToFirst()) cursor.getLong(0) else 0L }
            val next = current + 1L
            val values = ContentValues().apply {
                put(COL_CHANNEL, channel.hex)
                put(COL_COUNTER, next)
            }
            db.insertWithOnConflict(TABLE_COUNTERS, null, values, SQLiteDatabase.CONFLICT_REPLACE)
            db.setTransactionSuccessful()
            next
        } finally {
            db.endTransaction()
        }
    }

    @Synchronized
    override fun size(): Int =
        DatabaseUtils.queryNumEntries(helper.readableDatabase, TABLE_PACKETS).toInt()

    @Synchronized
    override fun close() {
        helper.close()
    }

    private fun trim(db: SQLiteDatabase) {
        val excess = DatabaseUtils.queryNumEntries(db, TABLE_PACKETS) - maxPackets
        if (excess <= 0) return
        db.execSQL(
            "DELETE FROM $TABLE_PACKETS WHERE rowid IN " +
                "(SELECT rowid FROM $TABLE_PACKETS ORDER BY rowid ASC LIMIT $excess)",
        )
    }

    private companion object {
        const val VERSION = 1
        const val DEFAULT_DATABASE_NAME = "bit-audio-mesh.db"
        const val DEFAULT_MAX_PACKETS = 4_096

        const val TABLE_PACKETS = "mesh_packets"
        const val TABLE_COUNTERS = "mesh_counters"
        const val COL_CHANNEL = "channel"
        const val COL_MESSAGE_ID = "message_id"
        const val COL_CHUNK_INDEX = "chunk_index"
        const val COL_TIMESTAMP = "timestamp_ms"
        const val COL_EXPIRES_AT = "expires_at_ms"
        const val COL_FRAME = "frame"
        const val COL_COUNTER = "counter"

        val COLUMNS = arrayOf(
            COL_CHANNEL,
            COL_MESSAGE_ID,
            COL_CHUNK_INDEX,
            COL_TIMESTAMP,
            COL_EXPIRES_AT,
            COL_FRAME,
        )
    }
}
