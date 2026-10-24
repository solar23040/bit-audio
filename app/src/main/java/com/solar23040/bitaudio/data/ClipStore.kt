package com.solar23040.bitaudio.data

import android.content.Context
import java.io.File
import java.util.UUID

/** Owns the app-private directory holding encoded voice clips. */
class ClipStore(context: Context) {
    private val directory = File(context.filesDir, DIRECTORY_NAME).apply { mkdirs() }

    fun newFile(): File = File(directory, "${UUID.randomUUID()}.wav")

    fun resolve(fileName: String): File? {
        if (fileName.isBlank() || fileName.contains('/') || fileName.contains('\\')) return null
        return File(directory, fileName).takeIf { it.isFile }
    }

    fun import(bytes: ByteArray): File {
        val file = newFile()
        file.writeBytes(bytes)
        return file
    }

    fun delete(fileName: String) {
        runCatching { resolve(fileName)?.delete() }
    }

    fun deleteChannel(notes: List<VoiceNote>) {
        notes.forEach { delete(it.fileName) }
    }

    private companion object {
        const val DIRECTORY_NAME = "clips"
    }
}
